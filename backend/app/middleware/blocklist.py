"""
Middleware que recusa requisicao de IP bloqueado.

Escrito como middleware ASGI puro de proposito: o BaseHTTPMiddleware do
Starlette monta um par de streams por requisicao, e essa checagem roda em
todas elas. Aqui o custo e uma busca em set na memoria.
"""

import json
import logging
import time

from sqlalchemy import text
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from app.core import blocklist
from app.core.config import settings
from app.db.session import async_session

log = logging.getLogger("veryon.blocklist")

# Uma tentativa bloqueada por IP por minuto vira evento. Sem isso, um ataque
# em rajada escreveria milhares de linhas iguais em raw_events e o custo do
# bloqueio ficaria maior que o custo de atender.
LOG_THROTTLE_SECONDS = 60
# Teto do dicionario de controle, pra ele nao virar vazamento de memoria se
# a origem vier de muitos IPs distintos.
LOG_THROTTLE_MAX_KEYS = 10_000

_last_logged: dict[str, float] = {}

INSERT_EVENT = text(
    """
    INSERT INTO raw_events (ts, source, host, event_type, src_ip, payload)
    VALUES (now(), 'api', :host, 'api.blocked_request', :src_ip, CAST(:payload AS jsonb))
    """
)


def client_ip(scope: Scope) -> str | None:
    """Por padrao usa o endereco da conexao. X-Forwarded-For so e considerado
    quando trust_proxy_headers esta ligado, porque qualquer cliente consegue
    forjar esse cabecalho e escapar do bloqueio."""
    if settings.trust_proxy_headers:
        for name, value in scope.get("headers", []):
            if name == b"x-forwarded-for":
                first = value.decode("latin-1").split(",")[0].strip()
                if first:
                    return first
    client = scope.get("client")
    return client[0] if client else None


def _should_log(ip: str) -> bool:
    now = time.monotonic()
    last = _last_logged.get(ip)
    if last is not None and now - last < LOG_THROTTLE_SECONDS:
        return False
    if len(_last_logged) >= LOG_THROTTLE_MAX_KEYS:
        _last_logged.clear()
    _last_logged[ip] = now
    return True


async def record_attempt(ip: str, scope: Scope) -> None:
    """Registra a tentativa recusada como evento, pra ela aparecer na tela de
    Eventos e entrar no relatorio. Falha aqui nunca pode impedir o bloqueio,
    entao qualquer erro so vira log."""
    if not _should_log(ip):
        return

    headers = dict(scope.get("headers", []))
    payload = {
        "method": scope.get("method"),
        "path": scope.get("path"),
        "user_agent": headers.get(b"user-agent", b"").decode("latin-1")[:200] or None,
    }
    try:
        async with async_session() as db:
            await db.execute(
                INSERT_EVENT,
                {"host": "veryon-api", "src_ip": ip, "payload": json.dumps(payload)},
            )
            await db.commit()
    except Exception as exc:  # noqa: BLE001
        log.warning("nao consegui registrar a tentativa bloqueada de %s: %s", ip, exc)


class BlocklistMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        ip = client_ip(scope)
        if ip and blocklist.is_blocked(ip):
            await record_attempt(ip, scope)
            response = JSONResponse(
                {"detail": "Acesso bloqueado"},
                status_code=403,
            )
            await response(scope, receive, send)
            return

        await self.app(scope, receive, send)
