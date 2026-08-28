from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.db.models import Alert, RawEvent
from app.db.session import get_db
from app.schemas import GeoPoint, GeoSummaryOut, SeriesPoint, SummaryOut

router = APIRouter(prefix="/stats", tags=["stats"], dependencies=[Depends(get_current_user)])

# A categoria sai do tipo do evento que gerou o alerta, nao do rule_id: o
# rule_id das regras do motor de deteccao e um UUID, que nao diz nada pra quem
# esta olhando o grafico. O tipo do evento diz de onde a coisa veio.
CATEGORIA = """
    CASE
        WHEN source_event_type LIKE 'cowrie%%'  THEN 'honeypot'
        WHEN source_event_type LIKE 'api%%'     THEN 'api'
        WHEN source_event_type LIKE 'scanner%%' THEN 'scanner'
        WHEN source_event_type LIKE 'linux%%'   THEN 'host'
        ELSE 'outros'
    END
"""


@router.get("/summary", response_model=SummaryOut)
async def summary(db: AsyncSession = Depends(get_db)):
    total_events = (await db.execute(select(func.count()).select_from(RawEvent))).scalar_one()
    total_alerts = (await db.execute(select(func.count()).select_from(Alert))).scalar_one()

    events_by_source = dict(
        (await db.execute(select(RawEvent.source, func.count()).group_by(RawEvent.source))).all()
    )
    alerts_by_level = dict(
        (await db.execute(select(Alert.level, func.count()).group_by(Alert.level))).all()
    )

    top_ips_result = await db.execute(
        select(RawEvent.src_ip, func.count().label("n"))
        .where(RawEvent.src_ip.isnot(None))
        .group_by(RawEvent.src_ip)
        .order_by(func.count().desc())
        .limit(10)
    )
    top_src_ips = [{"src_ip": ip, "count": n} for ip, n in top_ips_result.all()]

    return SummaryOut(
        total_events=total_events,
        total_alerts=total_alerts,
        events_by_source=events_by_source,
        alerts_by_level=alerts_by_level,
        top_src_ips=top_src_ips,
    )


@router.get("/timeseries", response_model=list[SeriesPoint])
async def timeseries(
    days: int = Query(14, ge=1, le=90),
    bucket: str = Query("day", pattern="^(hour|day)$"),
    db: AsyncSession = Depends(get_db),
):
    """Alertas por periodo, quebrados por categoria e por nivel.

    Devolve uma linha por (periodo, categoria, nivel) e deixa o empilhamento
    pra tela. Fazer o pivot aqui obrigaria a API a conhecer as categorias que
    a tela quer mostrar, e ai cada filtro novo viraria mudanca no backend."""
    desde = datetime.now(timezone.utc) - timedelta(days=days)
    sql = text(
        f"""
        SELECT time_bucket(:passo, ts) AS periodo,
               {CATEGORIA} AS categoria,
               level,
               count(*) AS total
          FROM alerts
         WHERE ts >= :desde
         GROUP BY periodo, categoria, level
         ORDER BY periodo
        """
    )
    passo = timedelta(hours=1) if bucket == "hour" else timedelta(days=1)
    rows = (await db.execute(sql, {"desde": desde, "passo": passo})).all()
    return [
        SeriesPoint(ts=p.isoformat(), category=c, level=lvl, count=n)
        for p, c, lvl, n in rows
    ]


# De onde vem quem bate no sistema. O pais sai do enriquecimento de threat
# intel; IP privado nunca tem pais, entao ele e separado em 'rede interna' em
# vez de cair no mesmo balde de desconhecido. Sao coisas diferentes: um e
# trafego de dentro de casa, o outro e um IP publico que ninguem identificou
# ainda.
SQL_GEO = """
    WITH origens AS (
        -- As duas origens entram na mesma conta. Quem chama a API do cliente
        -- e uma origem tao real quanto quem bate no honeypot, e deixar so
        -- raw_events aqui esconderia todo o trafego que chega pela ingestao.
        SELECT ip, sum(eventos) AS eventos FROM (
            SELECT src_ip AS ip, count(*) AS eventos
              FROM raw_events
             WHERE src_ip IS NOT NULL AND ts >= :desde
             GROUP BY src_ip
            UNION ALL
            SELECT client_ip, count(*)
              FROM api_requests
             WHERE client_ip IS NOT NULL AND ts >= :desde
             GROUP BY client_ip
        ) tudo
        GROUP BY ip
    )
    SELECT o.ip,
           o.eventos,
           e.abuseipdb_country AS pais,
           e.abuseipdb_score   AS reputacao,
           (o.ip::inet << ANY (ARRAY[
                '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16',
                '127.0.0.0/8', '169.254.0.0/16'
            ]::inet[])) AS interno,
           EXISTS (
               SELECT 1 FROM blocked_ips b
                WHERE b.ip = o.ip AND b.unblocked_at IS NULL
                  AND (b.expires_at IS NULL OR b.expires_at > now())
           ) AS bloqueado
      FROM origens o
      LEFT JOIN ip_enrichment e ON e.ip = o.ip
     ORDER BY o.eventos DESC
     LIMIT :limite
"""


@router.get("/geo", response_model=GeoSummaryOut)
async def geo(
    days: int = Query(7, ge=1, le=90),
    limit: int = Query(200, le=500),
    db: AsyncSession = Depends(get_db),
):
    desde = datetime.now(timezone.utc) - timedelta(days=days)
    rows = (await db.execute(text(SQL_GEO), {"desde": desde, "limite": limit})).all()

    por_pais: dict[str, dict] = {}
    internos = 0
    nao_identificados = 0

    for ip, eventos, pais, reputacao, interno, bloqueado in rows:
        if interno:
            internos += eventos
            continue
        if not pais:
            nao_identificados += eventos
            continue
        alvo = por_pais.setdefault(
            pais, {"country": pais, "events": 0, "ips": 0, "blocked": 0, "worst_score": 0}
        )
        alvo["events"] += eventos
        alvo["ips"] += 1
        if bloqueado:
            alvo["blocked"] += 1
        if reputacao and reputacao > alvo["worst_score"]:
            alvo["worst_score"] = reputacao

    pontos = sorted(por_pais.values(), key=lambda p: p["events"], reverse=True)
    return GeoSummaryOut(
        points=[GeoPoint(**p) for p in pontos],
        internal_events=internos,
        unidentified_events=nao_identificados,
        total_ips=len(rows),
    )
