from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.blocklist import guard_target
from app.api.deps import current_username, get_current_user, require_admin
from app.core import blocklist as blocklist_cache
from app.db.models import Alert, BlockedIP
from app.db.session import get_db
from app.schemas import AlertOut, AlertStatusUpdate, BlockedIPOut

router = APIRouter(prefix="/alerts", tags=["alerts"], dependencies=[Depends(get_current_user)])

VALID_STATUSES = {"open", "acknowledged", "closed"}


@router.get("", response_model=list[AlertOut])
async def list_alerts(
    level: str | None = None,
    rule_id: str | None = None,
    status: str | None = None,
    since: datetime | None = None,
    limit: int = Query(50, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(Alert).order_by(Alert.ts.desc()).offset(offset).limit(limit)
    if level:
        stmt = stmt.where(Alert.level == level)
    if rule_id:
        stmt = stmt.where(Alert.rule_id == rule_id)
    if status:
        stmt = stmt.where(Alert.status == status)
    if since:
        stmt = stmt.where(Alert.ts >= since)

    result = await db.execute(stmt)
    return result.scalars().all()


@router.get("/{alert_id}", response_model=AlertOut)
async def get_alert(alert_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalars().first()
    if alert is None:
        raise HTTPException(status_code=404, detail="Alerta nao encontrado")
    return alert


@router.patch("/{alert_id}", response_model=AlertOut)
async def update_alert_status(
    alert_id: int,
    body: AlertStatusUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: str = Depends(current_username),
):
    """Muda o estado do alerta e registra quem mudou, quando e por que.

    Fechar exige nota. Nao e burocracia: fechar sem motivo apaga a unica coisa
    que o proximo analista precisa saber, que e se aquilo ja foi investigado
    ou se alguem so quis limpar a tela. Reconhecer e reabrir aceitam nota, mas
    nao cobram, porque nenhum dos dois encerra nada.
    """
    if body.status not in VALID_STATUSES:
        raise HTTPException(status_code=422, detail=f"status deve ser um de: {sorted(VALID_STATUSES)}")

    nota = (body.note or "").strip()
    if body.status == "closed" and len(nota) < 3:
        raise HTTPException(
            status_code=422,
            detail="Para fechar um alerta, escreva o motivo no campo de nota",
        )

    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalars().first()
    if alert is None:
        raise HTTPException(status_code=404, detail="Alerta nao encontrado")

    alert.status = body.status
    # Nota vazia nao apaga a que ja existia: quem reconhece um alerta depois
    # de outra pessoa ter escrito algo nao deveria limpar aquele texto sem
    # querer. Para trocar, basta mandar a nota nova.
    if nota:
        alert.triage_note = nota
    alert.triaged_by = current_user
    alert.triaged_at = datetime.now(timezone.utc)

    await db.commit()
    await db.refresh(alert)
    return alert


@router.post("/{alert_id}/block", response_model=BlockedIPOut, dependencies=[Depends(require_admin)])
async def block_alert_ip(
    alert_id: int,
    request: Request,
    ttl_minutes: int | None = Query(None, ge=1, le=60 * 24 * 30),
    db: AsyncSession = Depends(get_db),
    current_user: str = Depends(current_username),
):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalars().first()
    if alert is None:
        raise HTTPException(status_code=404, detail="Alerta nao encontrado")
    if not alert.source_ip:
        raise HTTPException(status_code=422, detail="Alerta nao tem IP de origem pra bloquear")

    # Mesmas travas do bloqueio manual: allowlist, IP proprio e duplicata.
    # Uma funcao so pros dois caminhos, senao um dos dois acaba mais fraco.
    normalized = await guard_target(request, db, alert.source_ip)

    expires_at = None
    if ttl_minutes is not None:
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=ttl_minutes)

    blocked = BlockedIP(
        ip=normalized,
        alert_id=alert.id,
        reason=alert.title,
        blocked_by=current_user,
        expires_at=expires_at,
        source="manual",
    )
    db.add(blocked)
    await db.commit()
    await db.refresh(blocked)
    await blocklist_cache.refresh()
    return blocked
