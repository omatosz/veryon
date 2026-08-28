"""
Coleta de trafego de API.

O middleware nao escreve no banco. Ele empilha um dicionario numa fila em
memoria e devolve a resposta; quem grava e o flusher, em lote, fora do caminho
da requisicao. Sem isso, toda chamada da API pagaria um INSERT antes de
responder, e a ferramenta de observar viraria o gargalo do observado.

A fila e limitada de proposito. Se ela encher, a requisicao mais nova e
descartada e o contador de descarte sobe. Perder amostra de trafego e
aceitavel; segurar requisicao de usuario esperando espaco na fila nao e.
"""

import asyncio
import json
import logging
from datetime import datetime, timezone

from sqlalchemy import text

from app.core import api_signals
from app.db.session import async_session

log = logging.getLogger("veryon.api_traffic")

QUEUE_MAX = 5_000
BATCH_MAX = 200
FLUSH_SECONDS = 2.0

# Rotas que nao entram na coleta. /health e batido por healthcheck de container
# a cada poucos segundos e so encheria a tabela de ruido identico.
IGNORED_PATHS = {"/health", "/docs", "/redoc", "/openapi.json", "/favicon.ico"}

_queue: asyncio.Queue[dict] = asyncio.Queue(maxsize=QUEUE_MAX)
_dropped = 0

INSERT_REQUESTS = text(
    """
    INSERT INTO api_requests
        (ts, source, client_ip, method, path, route, status_code,
         duration_ms, response_bytes, user_agent, query, flags)
    VALUES
        (:ts, :source, :client_ip, :method, :path, :route, :status_code,
         :duration_ms, :response_bytes, :user_agent, :query, CAST(:flags AS jsonb))
    """
)

# O inventario e atualizado em lote junto com o trafego. is_documented fica de
# fora do UPDATE: quem marca rota como documentada e a carga inicial das rotas
# registradas na aplicacao, e um acesso qualquer nao pode desfazer isso.
UPSERT_ENDPOINT = text(
    """
    INSERT INTO api_endpoints
        (method, route, is_documented, is_sensitive, first_seen, last_seen,
         request_count, error_count, avg_response_bytes)
    VALUES
        (:method, :route, false, :is_sensitive, :seen, :seen,
         :count, :errors, :avg_bytes)
    ON CONFLICT (method, route) DO UPDATE SET
        last_seen = EXCLUDED.last_seen,
        request_count = api_endpoints.request_count + EXCLUDED.request_count,
        error_count = api_endpoints.error_count + EXCLUDED.error_count,
        avg_response_bytes = (
            (COALESCE(api_endpoints.avg_response_bytes, 0) * api_endpoints.request_count
             + COALESCE(EXCLUDED.avg_response_bytes, 0) * EXCLUDED.request_count)
            / NULLIF(api_endpoints.request_count + EXCLUDED.request_count, 0)
        )::int
    """
)


def should_ignore(path: str) -> bool:
    return path in IGNORED_PATHS


def enqueue(record: dict) -> None:
    """Chamado de dentro do caminho da requisicao. Nunca bloqueia."""
    global _dropped
    try:
        _queue.put_nowait(record)
    except asyncio.QueueFull:
        _dropped += 1
        if _dropped % 500 == 1:
            log.warning("fila de trafego cheia, %d requisicao(oes) descartada(s)", _dropped)


def stats() -> dict:
    return {"queued": _queue.qsize(), "dropped": _dropped}


async def _drain() -> list[dict]:
    """Espera o primeiro item e depois raspa o que ja estiver na fila."""
    first = await _queue.get()
    batch = [first]
    while len(batch) < BATCH_MAX:
        try:
            batch.append(_queue.get_nowait())
        except asyncio.QueueEmpty:
            break
    return batch


def _fold_endpoints(batch: list[dict]) -> list[dict]:
    """Junta o lote por (metodo, rota) antes de ir pro banco. Cem chamadas na
    mesma rota viram um UPDATE em vez de cem."""
    folded: dict[tuple[str, str], dict] = {}
    for rec in batch:
        key = (rec["method"], rec["route"])
        agg = folded.get(key)
        if agg is None:
            agg = folded[key] = {
                "method": rec["method"],
                "route": rec["route"],
                "is_sensitive": api_signals.is_sensitive(rec["route"]),
                "seen": rec["ts"],
                "count": 0,
                "errors": 0,
                "_bytes": 0,
            }
        agg["count"] += 1
        agg["seen"] = max(agg["seen"], rec["ts"])
        if (rec.get("status_code") or 0) >= 400:
            agg["errors"] += 1
        agg["_bytes"] += rec.get("response_bytes") or 0

    for agg in folded.values():
        agg["avg_bytes"] = agg.pop("_bytes") // max(agg["count"], 1)
    return list(folded.values())


async def _write(batch: list[dict]) -> None:
    rows = [
        {
            **rec,
            "flags": json.dumps(rec.get("flags") or {}),
        }
        for rec in batch
    ]
    async with async_session() as db:
        await db.execute(INSERT_REQUESTS, rows)
        endpoints = _fold_endpoints(batch)
        if endpoints:
            await db.execute(UPSERT_ENDPOINT, endpoints)
        await db.commit()


async def flush_loop() -> None:
    """Roda pra sempre gravando o que a fila junta. Erro de banco aqui nunca
    pode derrubar a tarefa, senao a coleta morre calada e ninguem nota ate
    alguem reparar que a tela de API esta vazia."""
    log.info("coletor de trafego de API iniciado")
    while True:
        try:
            batch = await _drain()
            await _write(batch)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            log.warning("falha gravando lote de trafego: %s", exc)
            await asyncio.sleep(FLUSH_SECONDS)


async def seed_documented_routes(routes: list[tuple[str, str]]) -> None:
    """Marca como documentadas as rotas que a aplicacao registra de verdade.

    E isso que da sentido ao sinal de API fantasma: o inventario passa a ter um
    lado declarado. Rota que aparece no trafego respondendo sem estar aqui e
    endpoint que subiu sem ninguem registrar."""
    if not routes:
        return
    now = datetime.now(timezone.utc)
    payload = [
        {"method": m, "route": r, "sensitive": api_signals.is_sensitive(r), "seen": now}
        for m, r in routes
    ]
    stmt = text(
        """
        INSERT INTO api_endpoints
            (method, route, is_documented, is_sensitive, first_seen, last_seen)
        VALUES (:method, :route, true, :sensitive, :seen, :seen)
        ON CONFLICT (method, route) DO UPDATE SET is_documented = true
        """
    )
    try:
        async with async_session() as db:
            await db.execute(stmt, payload)
            await db.commit()
        log.info("inventario: %d rota(s) marcada(s) como documentada(s)", len(payload))
    except Exception as exc:  # noqa: BLE001
        log.warning("nao consegui carregar o inventario de rotas: %s", exc)
