from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.db.models import IPEnrichment
from app.db.session import get_db
from app.schemas import EnrichmentOut

router = APIRouter(prefix="/enrichment", tags=["enrichment"], dependencies=[Depends(get_current_user)])


@router.get("/{ip}", response_model=EnrichmentOut)
async def get_enrichment(ip: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(IPEnrichment).where(IPEnrichment.ip == ip))
    row = result.scalars().first()
    if row is None:
        raise HTTPException(status_code=404, detail="Sem dados de threat intel para esse IP")
    return row
