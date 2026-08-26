from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.db.models import Alert, RawEvent
from app.db.session import get_db
from app.schemas import SummaryOut

router = APIRouter(prefix="/stats", tags=["stats"], dependencies=[Depends(get_current_user)])


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
