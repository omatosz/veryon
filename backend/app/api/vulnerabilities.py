from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.db.models import ScanJob, Vulnerability
from app.db.session import get_db
from app.schemas import ScanJobOut, VulnerabilityOut, VulnerabilityUpdate, VulnSummaryOut

router = APIRouter(
    prefix="/vulnerabilities", tags=["vulnerabilities"], dependencies=[Depends(get_current_user)]
)

# Peso de cada severidade no score de risco do parque. A conta e proposital
# ser simples de explicar pro cliente: quatro criticas em aberto ja e risco
# maximo, porque quatro criticas em aberto e risco maximo mesmo.
RISK_WEIGHTS = {"critical": 25, "high": 10, "medium": 3, "low": 1, "info": 0}

# So o que ainda demanda alguma coisa entra no score.
OPEN_STATUSES = ("open", "in_progress")


@router.get("/summary", response_model=VulnSummaryOut)
async def summary(db: AsyncSession = Depends(get_db)):
    by_severity = dict(
        (
            await db.execute(
                select(Vulnerability.severity, func.count())
                .where(Vulnerability.status.in_(OPEN_STATUSES))
                .group_by(Vulnerability.severity)
            )
        ).all()
    )
    by_status = dict(
        (await db.execute(select(Vulnerability.status, func.count()).group_by(Vulnerability.status))).all()
    )

    raw = sum(RISK_WEIGHTS.get(sev, 0) * n for sev, n in by_severity.items())
    last_scan = (
        await db.execute(select(ScanJob).order_by(ScanJob.created_at.desc()).limit(1))
    ).scalars().first()

    return VulnSummaryOut(
        by_severity=by_severity,
        by_status=by_status,
        total_open=sum(by_severity.values()),
        risk_score=min(100, raw),
        last_scan=ScanJobOut.model_validate(last_scan) if last_scan else None,
    )


@router.get("", response_model=list[VulnerabilityOut])
async def list_vulnerabilities(
    status: str | None = None,
    severity: str | None = None,
    asset_type: str | None = None,
    asset: str | None = None,
    limit: int = Query(100, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    # Ordena por severidade antes de data: numa fila de correcao o que importa
    # e o que doi mais, nao o que chegou por ultimo.
    severity_rank = case(
        (Vulnerability.severity == "critical", 0),
        (Vulnerability.severity == "high", 1),
        (Vulnerability.severity == "medium", 2),
        (Vulnerability.severity == "low", 3),
        else_=4,
    )
    stmt = select(Vulnerability).order_by(severity_rank, Vulnerability.last_seen.desc())

    if status:
        stmt = stmt.where(Vulnerability.status == status)
    if severity:
        stmt = stmt.where(Vulnerability.severity == severity)
    if asset_type:
        stmt = stmt.where(Vulnerability.asset_type == asset_type)
    if asset:
        stmt = stmt.where(Vulnerability.asset == asset)

    result = await db.execute(stmt.offset(offset).limit(limit))
    return result.scalars().all()


@router.get("/{vuln_id}", response_model=VulnerabilityOut)
async def get_vulnerability(vuln_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
    vuln = result.scalars().first()
    if vuln is None:
        raise HTTPException(status_code=404, detail="Vulnerabilidade nao encontrada")
    return vuln


@router.patch("/{vuln_id}", response_model=VulnerabilityOut)
async def update_vulnerability(
    vuln_id: int,
    body: VulnerabilityUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: str = Depends(get_current_user),
):
    result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
    vuln = result.scalars().first()
    if vuln is None:
        raise HTTPException(status_code=404, detail="Vulnerabilidade nao encontrada")

    vuln.status = body.status
    vuln.updated_by = current_user
    # Justificativa e prazo so fazem sentido em risco aceito. Trocar pra outro
    # estado limpa os dois, senao fica sobra de decisao antiga na tela.
    vuln.justification = body.justification if body.status == "accepted_risk" else None
    vuln.review_at = body.review_at if body.status == "accepted_risk" else None
    vuln.resolved_at = datetime.now(timezone.utc) if body.status == "remediated" else None

    await db.commit()
    await db.refresh(vuln)
    return vuln
