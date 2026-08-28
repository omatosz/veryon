from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core import api_analyzer, api_signals, api_traffic
from app.db.models import APIEndpoint, APIFinding, APIRequest
from app.db.session import get_db
from app.schemas import (
    APIEndpointOut,
    APIFindingOut,
    APIFindingUpdate,
    APIRequestOut,
    APISummaryOut,
)

router = APIRouter(
    prefix="/api-analysis",
    tags=["api-analysis"],
    dependencies=[Depends(get_current_user)],
)


@router.get("/summary", response_model=APISummaryOut)
async def summary(db: AsyncSession = Depends(get_db)):
    """Os numeros do topo da tela. Uma consulta por caixa, nenhuma varredura
    da tabela inteira: tudo e limitado pela janela ou pelo indice."""
    start = api_signals.window_start()

    totals = (
        await db.execute(
            select(
                func.count().label("total"),
                func.count(func.distinct(APIRequest.client_ip)).label("callers"),
                func.count().filter(APIRequest.status_code >= 400).label("errors"),
            ).where(APIRequest.ts >= start)
        )
    ).one()

    findings = (
        await db.execute(
            select(
                func.count().filter(APIFinding.status.in_(("open", "investigating"))).label("abertos"),
                func.count()
                .filter(
                    APIFinding.status.in_(("open", "investigating")),
                    APIFinding.severity == "critical",
                )
                .label("criticos"),
            )
        )
    ).one()

    endpoints = (
        await db.execute(
            select(
                func.count().filter(APIEndpoint.is_documented.is_(False)).label("fantasma"),
                func.count().filter(APIEndpoint.is_documented.is_(True)).label("documentado"),
            )
        )
    ).one()

    top = (
        await db.execute(
            select(APIFinding)
            .where(APIFinding.status.in_(("open", "investigating", "escalated")))
            .order_by(APIFinding.score.desc(), APIFinding.last_seen.desc())
            .limit(5)
        )
    ).scalars().all()

    total = totals.total or 0
    return APISummaryOut(
        window_minutes=api_signals.WINDOW_MINUTES,
        total_requests=total,
        error_rate=round((totals.errors or 0) / total * 100) if total else 0,
        distinct_callers=totals.callers or 0,
        open_findings=findings.abertos or 0,
        critical_findings=findings.criticos or 0,
        shadow_endpoints=endpoints.fantasma or 0,
        documented_endpoints=endpoints.documentado or 0,
        top_findings=[APIFindingOut.model_validate(f) for f in top],
        queue=api_traffic.stats(),
    )


@router.get("/findings", response_model=list[APIFindingOut])
async def list_findings(
    status: str | None = None,
    severity: str | None = None,
    limit: int = Query(100, le=500),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(APIFinding)
    if status:
        stmt = stmt.where(APIFinding.status == status)
    if severity:
        stmt = stmt.where(APIFinding.severity == severity)
    stmt = stmt.order_by(APIFinding.score.desc(), APIFinding.last_seen.desc()).limit(limit)
    return (await db.execute(stmt)).scalars().all()


@router.get("/findings/{finding_id}/requests", response_model=list[APIRequestOut])
async def finding_requests(
    finding_id: int,
    limit: int = Query(50, le=200),
    db: AsyncSession = Depends(get_db),
):
    """As requisicoes que geraram o achado. E o que transforma 'score 85' em
    algo que o analista consegue julgar."""
    finding = (
        await db.execute(select(APIFinding).where(APIFinding.id == finding_id))
    ).scalars().first()
    if finding is None:
        raise HTTPException(status_code=404, detail="Achado nao encontrado")

    stmt = (
        select(APIRequest)
        .where(APIRequest.client_ip == finding.client_ip, APIRequest.ts >= finding.window_start)
        .order_by(APIRequest.ts.desc())
        .limit(limit)
    )
    return (await db.execute(stmt)).scalars().all()


@router.patch("/findings/{finding_id}", response_model=APIFindingOut)
async def update_finding(
    finding_id: int,
    body: APIFindingUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: str = Depends(get_current_user),
):
    finding = (
        await db.execute(select(APIFinding).where(APIFinding.id == finding_id))
    ).scalars().first()
    if finding is None:
        raise HTTPException(status_code=404, detail="Achado nao encontrado")

    finding.status = body.status
    finding.note = body.note
    finding.updated_by = current_user

    if body.status == "benign":
        # Silencia o chamador por um tempo. Sem isso o motor reabriria o mesmo
        # achado no ciclo seguinte e o botao pareceria nao funcionar.
        finding.muted_until = datetime.now(timezone.utc) + timedelta(hours=api_analyzer.MUTE_HOURS)
    else:
        finding.muted_until = None

    await db.commit()
    await db.refresh(finding)
    return finding


@router.get("/endpoints", response_model=list[APIEndpointOut])
async def list_endpoints(
    shadow_only: bool = False,
    sensitive_only: bool = False,
    limit: int = Query(300, le=1000),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(APIEndpoint)
    if shadow_only:
        stmt = stmt.where(APIEndpoint.is_documented.is_(False))
    if sensitive_only:
        stmt = stmt.where(APIEndpoint.is_sensitive.is_(True))
    stmt = stmt.order_by(APIEndpoint.request_count.desc()).limit(limit)
    return (await db.execute(stmt)).scalars().all()


@router.post("/endpoints/{endpoint_id}/document", response_model=APIEndpointOut)
async def mark_documented(endpoint_id: int, db: AsyncSession = Depends(get_db)):
    """Nem toda rota fora do inventario e ataque. As vezes e coisa que o time
    subiu e esqueceu de registrar. Aqui o analista confirma que conhece, e ela
    para de pontuar como fantasma."""
    endpoint = (
        await db.execute(select(APIEndpoint).where(APIEndpoint.id == endpoint_id))
    ).scalars().first()
    if endpoint is None:
        raise HTTPException(status_code=404, detail="Rota nao encontrada")
    endpoint.is_documented = True
    await db.commit()
    await db.refresh(endpoint)
    return endpoint


@router.post("/analyze", response_model=dict)
async def analyze_now():
    """Roda um ciclo de analise na hora, sem esperar os dez segundos. Existe
    pro botao de atualizar na tela dar resposta imediata durante um teste."""
    return await api_analyzer.analyze_once()


@router.get("/traffic", response_model=list[APIRequestOut])
async def recent_traffic(
    client_ip: str | None = None,
    minutes: int = Query(10, ge=1, le=1440),
    limit: int = Query(100, le=500),
    db: AsyncSession = Depends(get_db),
):
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    stmt = select(APIRequest).where(APIRequest.ts >= cutoff)
    if client_ip:
        stmt = stmt.where(APIRequest.client_ip == client_ip)
    stmt = stmt.order_by(APIRequest.ts.desc()).limit(limit)
    return (await db.execute(stmt)).scalars().all()


@router.get("/timeline", response_model=list[dict])
async def timeline(minutes: int = Query(60, ge=10, le=1440), db: AsyncSession = Depends(get_db)):
    """Requisicoes por minuto, separando erro de sucesso. Alimenta o grafico
    pequeno no topo da tela."""
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    rows = (
        await db.execute(
            text(
                """
                SELECT time_bucket('1 minute', ts) AS minuto,
                       count(*) AS total,
                       count(*) FILTER (WHERE status_code >= 400) AS erros
                  FROM api_requests
                 WHERE ts >= :cutoff
                 GROUP BY minuto
                 ORDER BY minuto
                """
            ),
            {"cutoff": cutoff},
        )
    ).all()
    return [{"ts": r[0].isoformat(), "total": r[1], "errors": r[2]} for r in rows]
