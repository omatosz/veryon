from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.db.models import ScanJob
from app.db.session import get_db
from app.schemas import ScanJobOut

router = APIRouter(prefix="/scans", tags=["scans"], dependencies=[Depends(get_current_user)])

PENDING = ("queued", "running")


@router.get("", response_model=list[ScanJobOut])
async def list_scans(limit: int = Query(20, le=100), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ScanJob).order_by(ScanJob.created_at.desc()).limit(limit))
    return result.scalars().all()


@router.post("", response_model=ScanJobOut, status_code=202)
async def request_scan(
    db: AsyncSession = Depends(get_db),
    current_user: str = Depends(get_current_user),
):
    """Enfileira uma varredura. O servico do scanner pega no proximo ciclo.

    Recusa se ja existe uma na fila ou rodando: uma varredura leva minutos, e
    sem essa trava o botao vira gerador de fila toda vez que alguem clica duas
    vezes por ansiedade."""
    existing = await db.execute(select(ScanJob).where(ScanJob.status.in_(PENDING)).limit(1))
    running = existing.scalars().first()
    if running is not None:
        raise HTTPException(
            status_code=409,
            detail=f"Ja existe uma varredura {running.status} (#{running.id}). Espere ela terminar.",
        )

    job = ScanJob(requested_by=current_user, status="queued")
    db.add(job)
    await db.commit()
    await db.refresh(job)
    return job


@router.get("/{job_id}", response_model=ScanJobOut)
async def get_scan(job_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ScanJob).where(ScanJob.id == job_id))
    job = result.scalars().first()
    if job is None:
        raise HTTPException(status_code=404, detail="Varredura nao encontrada")
    return job
