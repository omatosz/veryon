from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.db.models import Alert
from app.db.session import get_db
from app.schemas import AlertOut, AlertStatusUpdate

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
async def update_alert_status(alert_id: int, body: AlertStatusUpdate, db: AsyncSession = Depends(get_db)):
    if body.status not in VALID_STATUSES:
        raise HTTPException(status_code=422, detail=f"status deve ser um de: {sorted(VALID_STATUSES)}")

    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalars().first()
    if alert is None:
        raise HTTPException(status_code=404, detail="Alerta nao encontrado")

    alert.status = body.status
    await db.commit()
    await db.refresh(alert)
    return alert
