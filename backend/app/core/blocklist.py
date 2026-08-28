"""
Blocklist do lado da API.

O `enforce-netns.sh` derruba pacote com iptables, mas so dentro do namespace
de rede do Cowrie e so nas portas 2222/2223. Requisicao de API nao passa por
la, entao o bloqueio precisava de um segundo atuador: e este modulo, junto do
middleware em app/middleware/blocklist.py.

Como funciona: uma tarefa em segundo plano recarrega a lista do banco a cada
poucos segundos e troca o retrato inteiro de uma vez. O middleware so consulta
o retrato que esta em memoria, sem ida ao banco nem ao Redis por requisicao.
O atraso maximo entre bloquear na tela e valer na API e o intervalo de
recarga, o mesmo dos dois scripts de enforcement.
"""

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network

from sqlalchemy import Select, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.cache import redis_client
from app.core.config import settings
from app.db.models import BlockedIP, IPAllowlist
from app.db.session import async_session

log = logging.getLogger("veryon.blocklist")

REDIS_KEY = "veryon:blocklist"

Network = IPv4Network | IPv6Network


@dataclass(frozen=True)
class BlocklistSnapshot:
    """Retrato imutavel da lista. Trocado inteiro a cada recarga, entao quem
    esta lendo no meio do caminho sempre ve um estado coerente.

    Endereco solto vai pro set (busca O(1)); faixa CIDR vai pra tupla, que e
    percorrida. Faixa e sempre pouca coisa, entao o custo nao pesa."""

    ips: frozenset[str] = frozenset()
    nets: tuple[Network, ...] = ()
    allow_ips: frozenset[str] = frozenset()
    allow_nets: tuple[Network, ...] = ()
    loaded_at: datetime | None = None

    @property
    def size(self) -> int:
        return len(self.ips) + len(self.nets)


_snapshot = BlocklistSnapshot()


def parse_target(value: str) -> tuple[str | None, Network | None]:
    """Aceita tanto '203.0.113.9' quanto '203.0.113.0/24'. Devolve o endereco
    solto na primeira posicao ou a faixa na segunda, nunca os dois."""
    value = value.strip()
    if not value:
        return None, None
    if "/" not in value:
        try:
            return str(ip_address(value)), None
        except ValueError:
            return None, None
    try:
        return None, ip_network(value, strict=False)
    except ValueError:
        return None, None


def is_valid_target(value: str) -> bool:
    exact, net = parse_target(value)
    return exact is not None or net is not None


def _matches(value: str, ips: frozenset[str], nets: tuple[Network, ...]) -> bool:
    if value in ips:
        return True
    if not nets:
        return False
    try:
        addr = ip_address(value)
    except ValueError:
        return False
    return any(addr in net for net in nets)


def is_blocked(value: str) -> bool:
    snap = _snapshot
    return _matches(value, snap.ips, snap.nets)


def is_allowlisted(value: str) -> bool:
    snap = _snapshot
    return _matches(value, snap.allow_ips, snap.allow_nets)


def snapshot() -> BlocklistSnapshot:
    return _snapshot


def active_blocks() -> Select:
    """Bloqueio vale enquanto ninguem desbloqueou na mao e o prazo nao venceu.
    E a mesma condicao que o poll-db.sh usa pro iptables, pra nao existir
    divergencia entre o que a API bloqueia e o que o honeypot bloqueia."""
    return select(BlockedIP).where(
        BlockedIP.unblocked_at.is_(None),
        or_(BlockedIP.expires_at.is_(None), BlockedIP.expires_at > datetime.now(timezone.utc)),
    )


async def load(db: AsyncSession) -> BlocklistSnapshot:
    blocked = (await db.execute(active_blocks().with_only_columns(BlockedIP.ip))).scalars().all()
    allowed = (await db.execute(select(IPAllowlist.cidr))).scalars().all()

    ips: set[str] = set()
    nets: list[Network] = []
    for value in blocked:
        exact, net = parse_target(value)
        if exact:
            ips.add(exact)
        elif net:
            nets.append(net)
        else:
            log.warning("entrada invalida em blocked_ips, ignorada: %r", value)

    allow_ips: set[str] = set()
    allow_nets: list[Network] = []
    for value in allowed:
        exact, net = parse_target(value)
        if exact:
            allow_ips.add(exact)
        elif net:
            allow_nets.append(net)
        else:
            log.warning("entrada invalida em ip_allowlist, ignorada: %r", value)

    return BlocklistSnapshot(
        ips=frozenset(ips),
        nets=tuple(nets),
        allow_ips=frozenset(allow_ips),
        allow_nets=tuple(allow_nets),
        loaded_at=datetime.now(timezone.utc),
    )


async def _mirror_to_redis(snap: BlocklistSnapshot) -> None:
    """Espelha a lista num set do Redis pra outros servicos poderem ler sem
    bater no banco. Melhor esforco: se o Redis cair, a API continua
    bloqueando normalmente pelo retrato em memoria."""
    targets = list(snap.ips) + [str(n) for n in snap.nets]
    try:
        async with redis_client.pipeline(transaction=True) as pipe:
            pipe.delete(REDIS_KEY)
            if targets:
                pipe.sadd(REDIS_KEY, *targets)
            await pipe.execute()
    except Exception as exc:  # noqa: BLE001
        log.warning("nao consegui espelhar a blocklist no redis: %s", exc)


async def refresh() -> BlocklistSnapshot:
    """Recarrega agora. Chamado pela tarefa periodica e tambem logo depois de
    bloquear ou desbloquear, pra tela nao precisar esperar o proximo ciclo."""
    global _snapshot
    async with async_session() as db:
        snap = await load(db)
    _snapshot = snap
    await _mirror_to_redis(snap)
    return snap


async def refresh_loop() -> None:
    interval = max(1, settings.blocklist_refresh_seconds)
    while True:
        try:
            snap = await refresh()
            log.debug("blocklist recarregada: %d entrada(s)", snap.size)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            # Erro de banco nao pode derrubar o laco: mantem o retrato antigo
            # e tenta de novo no proximo ciclo. Preferir bloquear a mais do que
            # abrir a porta porque o banco piscou.
            log.error("falha recarregando a blocklist, mantendo o retrato anterior: %s", exc)
        await asyncio.sleep(interval)
