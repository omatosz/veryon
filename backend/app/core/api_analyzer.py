"""
Laco de analise de API.

A cada ciclo: pega a janela de trafego, agrupa por chamador, pontua com o
motor de sinais e escreve o resultado em api_findings. Quando a pontuacao
passa do limiar, abre alerta na tela de Alertas, que e onde o analista ja
olha; nao adianta criar uma tela nova que ninguem visita.

Um achado por chamador, atualizado no lugar. Empilhar linha nova a cada dez
segundos daria uma lista de milhares de itens dizendo a mesma coisa.
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import text

from app.core import api_signals
from app.db.session import async_session

log = logging.getLogger("veryon.api_analyzer")

ANALYZE_SECONDS = 10
# Teto de linhas lidas por ciclo. Rajada muito grande nao pode fazer o
# analisador puxar a janela inteira pra memoria.
MAX_ROWS = 20_000
# Abaixo disso nao vira achado. Um unico sinal de peso baixo, como bater numa
# rota sensivel, e o que todo usuario legitimo faz o dia inteiro.
MIN_FINDING_SCORE = 20
# Quanto tempo um achado marcado como benigno fica fora da analise.
MUTE_HOURS = 6
# Achado de pontuacao baixa e sem trafego novo some sozinho depois disso.
STALE_HOURS = 1

MITRE_BY_SIGNAL = {
    "injection": "T1190",
    "auth_burst": "T1110",
    "enumeration": "T1595.003",
    "shadow_api": "T1595.002",
    "object_walk": "T1190",
    "volume_anomaly": "T1213",
    "sensitive_hit": "T1087",
    "odd_method": "T1595",
}

FETCH_WINDOW = text(
    """
    SELECT client_ip, method, path, route, status_code, response_bytes, flags
      FROM api_requests
     WHERE ts >= :start
       AND client_ip IS NOT NULL
     ORDER BY ts DESC
     LIMIT :cap
    """
)

FETCH_MUTED = text(
    "SELECT client_ip FROM api_findings WHERE muted_until IS NOT NULL AND muted_until > now()"
)

FETCH_INVENTORY = text("SELECT method, route FROM api_endpoints WHERE is_documented")

# Referencia historica de tamanho de resposta por rota, usada so quando a
# janela atual tem amostra de menos pra calcular a propria mediana.
#
# Duas decisoes aqui, as duas pelo mesmo motivo: mediana em vez de media, e so
# o que veio ANTES da janela. Media e dado da janela atual deixariam o proprio
# pico entrar na conta da referencia que deveria julga-lo. A media acumulada em
# api_endpoints.avg_response_bytes continua existindo, mas so pra exibicao no
# inventario; deteccao nao usa mais ela.
FETCH_BASELINES = text(
    """
    SELECT method, route,
           percentile_cont(0.5) WITHIN GROUP (ORDER BY response_bytes)::int AS mediana
      FROM api_requests
     WHERE ts <  :start
       AND ts >= :floor
       AND response_bytes IS NOT NULL
     GROUP BY method, route
    HAVING count(*) >= 3
    """
)

UPSERT_FINDING = text(
    """
    INSERT INTO api_findings
        (client_ip, score, severity, signals, request_count, distinct_routes,
         top_routes, window_start, window_end, first_seen, last_seen, status)
    VALUES
        (:client_ip, :score, :severity, CAST(:signals AS jsonb), :request_count,
         :distinct_routes, CAST(:top_routes AS jsonb), :window_start, :window_end,
         :now, :now, 'open')
    ON CONFLICT (client_ip) DO UPDATE SET
        score = EXCLUDED.score,
        severity = EXCLUDED.severity,
        signals = EXCLUDED.signals,
        request_count = EXCLUDED.request_count,
        distinct_routes = EXCLUDED.distinct_routes,
        top_routes = EXCLUDED.top_routes,
        window_start = EXCLUDED.window_start,
        window_end = EXCLUDED.window_end,
        last_seen = EXCLUDED.last_seen,
        -- Quem esta em investigacao ou ja foi escalado mantem o estado; o
        -- resto volta pra aberto, inclusive o que foi marcado como benigno e
        -- teve o silencio expirado, porque ai o comportamento voltou.
        status = CASE
            WHEN api_findings.status IN ('investigating', 'escalated')
            THEN api_findings.status ELSE 'open'
        END,
        muted_until = CASE
            WHEN api_findings.muted_until > now() THEN api_findings.muted_until ELSE NULL
        END
    RETURNING id, alert_id, status
    """
)

INSERT_ALERT = text(
    """
    INSERT INTO alerts
        (ts, rule_id, title, level, mitre_technique, source_event_type,
         source_host, source_ip, description, status, payload)
    VALUES
        (now(), :rule_id, :title, :level, :mitre, 'api.analysis',
         'veryon-api', :src_ip, :description, 'open', CAST(:payload AS jsonb))
    RETURNING id
    """
)

UPDATE_ALERT = text(
    """
    UPDATE alerts
       SET level = :level, title = :title, description = :description,
           mitre_technique = :mitre, payload = CAST(:payload AS jsonb)
     WHERE id = :alert_id
    """
)

CLEAR_STALE = text(
    """
    UPDATE api_findings
       SET status = 'resolved'
     WHERE status = 'open'
       AND score < :threshold
       AND last_seen < :cutoff
    """
)


def _describe(ip: str, result: dict) -> str:
    linhas = [f"{result['request_count']} requisicoes de {ip} em {api_signals.WINDOW_MINUTES} minutos."]
    for sinal in result["signals"]:
        linhas.append(f"{sinal['label']} ({sinal['weight']} pts): {sinal['evidence']}")
    return "\n".join(linhas)


def _mitre(result: dict) -> str | None:
    if not result["signals"]:
        return None
    dominante = max(result["signals"], key=lambda s: s["weight"])
    return MITRE_BY_SIGNAL.get(dominante["id"])


async def analyze_once() -> dict:
    """Um ciclo completo. Devolve um resumo pro log e pros testes."""
    now = datetime.now(timezone.utc)
    start = now - timedelta(minutes=api_signals.WINDOW_MINUTES)

    async with async_session() as db:
        muted = {r[0] for r in (await db.execute(FETCH_MUTED)).all()}

        documented = {(m, r) for m, r in (await db.execute(FETCH_INVENTORY)).all()}

        historico = await db.execute(
            FETCH_BASELINES, {"start": start, "floor": now - timedelta(hours=24)}
        )
        baselines = {(m, r): mediana for m, r, mediana in historico.all() if mediana}

        rows = (await db.execute(FETCH_WINDOW, {"start": start, "cap": MAX_ROWS})).mappings().all()

        por_ip: dict[str, list[dict]] = {}
        for row in rows:
            ip = row["client_ip"]
            if ip in muted:
                continue
            por_ip.setdefault(ip, []).append(dict(row))

        analisados = 0
        com_achado = 0
        alertados = 0

        for ip, reqs in por_ip.items():
            analisados += 1
            result = api_signals.score_requests(reqs, documented, baselines)
            if result["score"] < MIN_FINDING_SCORE:
                continue
            com_achado += 1

            registro = (
                await db.execute(
                    UPSERT_FINDING,
                    {
                        "client_ip": ip,
                        "score": result["score"],
                        "severity": result["severity"],
                        "signals": json.dumps(result["signals"]),
                        "request_count": result["request_count"],
                        "distinct_routes": result["distinct_routes"],
                        "top_routes": json.dumps(result["top_routes"]),
                        "window_start": start,
                        "window_end": now,
                        "now": now,
                    },
                )
            ).first()

            if registro is None:
                continue
            finding_id, alert_id, status = registro

            if result["score"] < api_signals.ALERT_THRESHOLD or status in ("benign", "resolved"):
                continue

            titulo = f"Comportamento suspeito de API em {ip} (score {result['score']})"
            nivel = "critical" if result["score"] >= api_signals.PREVENTION_THRESHOLD else "high"
            payload = json.dumps(
                {
                    "finding_id": finding_id,
                    "score": result["score"],
                    "signals": result["signals"],
                    "top_routes": result["top_routes"],
                    "window_minutes": api_signals.WINDOW_MINUTES,
                }
            )
            comum = {
                "title": titulo,
                "level": nivel,
                "mitre": _mitre(result),
                "description": _describe(ip, result),
                "payload": payload,
            }

            if alert_id is None:
                novo = (
                    await db.execute(
                        INSERT_ALERT,
                        {**comum, "rule_id": "API-001", "src_ip": ip},
                    )
                ).scalar()
                await db.execute(
                    text("UPDATE api_findings SET alert_id = :a WHERE id = :i"),
                    {"a": novo, "i": finding_id},
                )
                alertados += 1
            else:
                # Alerta ja aberto pro mesmo chamador: atualiza em vez de criar
                # outro. Um atacante insistente nao pode virar cem alertas.
                await db.execute(UPDATE_ALERT, {**comum, "alert_id": alert_id})

        await db.execute(
            CLEAR_STALE,
            {"threshold": api_signals.ALERT_THRESHOLD, "cutoff": now - timedelta(hours=STALE_HOURS)},
        )
        await db.commit()

    return {"chamadores": analisados, "achados": com_achado, "alertas_novos": alertados}


async def analyze_loop() -> None:
    log.info("analisador de API iniciado (janela de %d min)", api_signals.WINDOW_MINUTES)
    while True:
        try:
            resumo = await analyze_once()
            if resumo["achados"]:
                log.info("analise de API: %s", resumo)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            log.warning("ciclo de analise de API falhou: %s", exc)
        await asyncio.sleep(ANALYZE_SECONDS)
