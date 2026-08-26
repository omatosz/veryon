from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.db.models import RawEvent
from app.db.session import get_db
from app.schemas import EventOut

router = APIRouter(prefix="/events", tags=["events"], dependencies=[Depends(get_current_user)])


@router.get("", response_model=list[EventOut])
async def list_events(
    source: str | None = None,
    event_type: str | None = None,
    src_ip: str | None = None,
    since: datetime | None = None,
    limit: int = Query(50, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(RawEvent).order_by(RawEvent.ts.desc()).offset(offset).limit(limit)
    if source:
        stmt = stmt.where(RawEvent.source == source)
    if event_type:
        stmt = stmt.where(RawEvent.event_type == event_type)
    if src_ip:
        stmt = stmt.where(RawEvent.src_ip == src_ip)
    if since:
        stmt = stmt.where(RawEvent.ts >= since)

    result = await db.execute(stmt)
    return result.scalars().all()


@router.get("/{event_id}", response_model=EventOut)
async def get_event(event_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(RawEvent).where(RawEvent.id == event_id))
    event = result.scalars().first()
    if event is None:
        raise HTTPException(status_code=404, detail="Evento nao encontrado")
    return event
