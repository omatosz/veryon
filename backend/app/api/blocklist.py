from datetime import datetime, timedelta, timezone
from ipaddress import ip_address

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core import blocklist as blocklist_cache
from app.db.models import BlockedIP, IPAllowlist
from app.db.session import get_db
from app.middleware.blocklist import client_ip
from app.schemas import AllowlistIn, AllowlistOut, BlockedIPOut, BlockIPIn

router = APIRouter(prefix="/blocklist", tags=["blocklist"], dependencies=[Depends(get_current_user)])


def _covers(net, value: str) -> bool:
    """Se a faixa contem o endereco. Devolve False pra entrada malformada em
    vez de estourar, porque isso e usado no meio de validacao."""
    try:
        return ip_address(value) in net
    except ValueError:
        return False


async def guard_target(request: Request, db: AsyncSession, target: str) -> str:
    """Validacoes que todo bloqueio passa, venha da tela de alertas ou da lista
    de IPs. Devolve o alvo normalizado."""
    exact, net = blocklist_cache.parse_target(target)
    if exact is None and net is None:
        raise HTTPException(status_code=422, detail=f"'{target}' nao e um IP nem uma faixa CIDR valida")
    normalized = exact or str(net)

    # Trava contra se trancar pra fora: bloquear o proprio IP derrubaria a
    # sessao de quem esta clicando, e a saida seria mexer no banco na mao.
    own = client_ip(request.scope)
    if own:
        if normalized == own:
            raise HTTPException(
                status_code=422,
                detail=f"{own} e o seu proprio IP. Bloquear ele te tirava do painel.",
            )
        if net is not None and _covers(net, own):
            raise HTTPException(
                status_code=422,
                detail=f"A faixa {normalized} inclui o seu proprio IP ({own}). Isso te tirava do painel.",
            )

    for entry in (await db.execute(select(IPAllowlist.cidr))).scalars().all():
        a_exact, a_net = blocklist_cache.parse_target(entry)
        if (a_exact and a_exact == normalized) or (a_net and exact and _covers(a_net, exact)):
            raise HTTPException(
                status_code=409,
                detail=f"{normalized} esta protegido pela allowlist ({entry}). Tire de la antes de bloquear.",
            )

    existing = await db.execute(
        select(BlockedIP).where(BlockedIP.ip == normalized, BlockedIP.unblocked_at.is_(None))
    )
    if existing.scalars().first() is not None:
        raise HTTPException(status_code=409, detail=f"{normalized} ja esta bloqueado")

    return normalized


@router.get("", response_model=list[BlockedIPOut])
async def list_blocklist(db: AsyncSession = Depends(get_db)):
    """So o que esta valendo agora: sem desbloqueio manual e dentro do prazo.
    Bloqueio vencido continua no banco pro historico, mas some daqui."""
    result = await db.execute(blocklist_cache.active_blocks().order_by(BlockedIP.blocked_at.desc()))
    return result.scalars().all()


@router.post("", response_model=BlockedIPOut, status_code=201)
async def block_ip(
    body: BlockIPIn,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: str = Depends(get_current_user),
):
    normalized = await guard_target(request, db, body.ip)

    expires_at = None
    if body.ttl_minutes is not None:
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=body.ttl_minutes)

    blocked = BlockedIP(
        ip=normalized,
        reason=body.reason,
        blocked_by=current_user,
        expires_at=expires_at,
        source="manual",
    )
    db.add(blocked)
    await db.commit()
    await db.refresh(blocked)
    # Recarrega na hora pra nao esperar o proximo ciclo de 5 segundos.
    await blocklist_cache.refresh()
    return blocked


@router.get("/allowlist", response_model=list[AllowlistOut])
async def list_allowlist(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(IPAllowlist).order_by(IPAllowlist.created_at.desc()))
    return result.scalars().all()


@router.post("/allowlist", response_model=AllowlistOut, status_code=201)
async def add_allowlist(
    body: AllowlistIn,
    db: AsyncSession = Depends(get_db),
    current_user: str = Depends(get_current_user),
):
    exact, net = blocklist_cache.parse_target(body.cidr)
    if exact is None and net is None:
        raise HTTPException(status_code=422, detail=f"'{body.cidr}' nao e um IP nem uma faixa CIDR valida")
    normalized = exact or str(net)

    entry = IPAllowlist(cidr=normalized, reason=body.reason, added_by=current_user)
    db.add(entry)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=409, detail=f"{normalized} ja esta na allowlist")
    await db.refresh(entry)
    await blocklist_cache.refresh()
    return entry


@router.delete("/allowlist/{entry_id}", status_code=204)
async def remove_allowlist(entry_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(IPAllowlist).where(IPAllowlist.id == entry_id))
    entry = result.scalars().first()
    if entry is None:
        raise HTTPException(status_code=404, detail="Entrada nao encontrada na allowlist")
    await db.delete(entry)
    await db.commit()
    await blocklist_cache.refresh()


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
    await blocklist_cache.refresh()
    return blocked
