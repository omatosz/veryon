from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.db.models import BlockedIP
from app.db.session import get_db
from app.schemas import BlockedIPOut

router = APIRouter(prefix="/blocklist", tags=["blocklist"], dependencies=[Depends(get_current_user)])


@router.get("", response_model=list[BlockedIPOut])
async def list_blocklist(db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(BlockedIP).where(BlockedIP.unblocked_at.is_(None)).order_by(BlockedIP.blocked_at.desc())
    )
    return result.scalars().all()


@router.post("/{ip}/unblock", response_model=BlockedIPOut)
async def unblock_ip(
    ip: str,
    db: AsyncSession = Depends(get_db),
    current_user: str = Depends(get_current_user),
):
    result = await db.execute(select(BlockedIP).where(BlockedIP.ip == ip, BlockedIP.unblocked_at.is_(None)))
    blocked = result.scalars().first()
    if blocked is None:
        raise HTTPException(status_code=404, detail="Esse IP nao esta bloqueado")

    blocked.unblocked_at = datetime.now(timezone.utc)
    blocked.unblocked_by = current_user
    await db.commit()
    await db.refresh(blocked)
    return blocked
