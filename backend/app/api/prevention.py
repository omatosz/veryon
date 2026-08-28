from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core import blocklist as blocklist_cache, prevention
from app.db.models import BlockedIP, PreventionAction, PreventionPolicy
from app.db.session import get_db
from app.schemas import (
    PolicyOut,
    PolicyUpdate,
    PreventionActionOut,
    PreventionSummaryOut,
    QueueItem,
    SimulationOut,
)

router = APIRouter(
    prefix="/prevention",
    tags=["prevention"],
    dependencies=[Depends(get_current_user)],
)


@router.get("/policies", response_model=list[PolicyOut])
async def list_policies(db: AsyncSession = Depends(get_db)):
    stmt = select(PreventionPolicy).order_by(PreventionPolicy.priority)
    return (await db.execute(stmt)).scalars().all()


@router.patch("/policies/{policy_id}", response_model=PolicyOut)
async def update_policy(
    policy_id: int,
    body: PolicyUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: str = Depends(get_current_user),
):
    """Liga, desliga ou muda o modo de uma politica.

    Passar de observacao pra vigor e a unica mudanca que faz o sistema comecar
    a agir sozinho, entao ela e barrada quando a politica bloqueia e nao tem
    prazo: sem prazo o bloqueio nunca sairia, e isso quebra o trilho 4."""
    policy = (
        await db.execute(select(PreventionPolicy).where(PreventionPolicy.id == policy_id))
    ).scalars().first()
    if policy is None:
        raise HTTPException(status_code=404, detail="Politica nao encontrada")

    if body.ttl_minutes is not None:
        policy.ttl_minutes = body.ttl_minutes
    if body.cooldown_minutes is not None:
        policy.cooldown_minutes = body.cooldown_minutes
    if body.enabled is not None:
        policy.enabled = body.enabled

    if body.mode is not None:
        if body.mode == "enforce" and policy.action == "block_ip" and not policy.ttl_minutes:
            raise HTTPException(
                status_code=422,
                detail=(
                    "Politica de bloqueio precisa de prazo antes de entrar em vigor. "
                    "Bloqueio automatico sem data de saida vira dano permanente."
                ),
            )
        policy.mode = body.mode

    policy.updated_at = datetime.now(timezone.utc)
    policy.updated_by = current_user
    await db.commit()
    await db.refresh(policy)
    return policy


@router.post("/policies/{policy_id}/simulate", response_model=SimulationOut)
async def simulate_policy(policy_id: int, db: AsyncSession = Depends(get_db)):
    """Mostra o que a politica faria com os dados de agora, sem fazer nada.

    Existe pra ninguem ligar uma regra no escuro. A avaliacao roda inteira e
    e descartada no fim, entao o resultado e exatamente o que aconteceria."""
    exists = (
        await db.execute(select(PreventionPolicy.id).where(PreventionPolicy.id == policy_id))
    ).first()
    if exists is None:
        raise HTTPException(status_code=404, detail="Politica nao encontrada")
    return await prevention.evaluate_once(dry_run_policy_id=policy_id)


@router.get("/actions", response_model=list[PreventionActionOut])
async def list_actions(
    status: str | None = None,
    policy_id: int | None = None,
    limit: int = Query(100, le=500),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(PreventionAction)
    if status:
        stmt = stmt.where(PreventionAction.status == status)
    if policy_id:
        stmt = stmt.where(PreventionAction.policy_id == policy_id)
    stmt = stmt.order_by(PreventionAction.ts.desc()).limit(limit)
    return (await db.execute(stmt)).scalars().all()


@router.post("/actions/{action_id}/undo", response_model=PreventionActionOut)
async def undo_action(
    action_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: str = Depends(get_current_user),
):
    """Trilho 7: desfaz uma acao aplicada.

    Desfazer nao apaga a linha, marca ela. O registro de que o sistema
    bloqueou e de que alguem discordou tem o mesmo valor pra investigacao."""
    action = (
        await db.execute(select(PreventionAction).where(PreventionAction.id == action_id))
    ).scalars().first()
    if action is None:
        raise HTTPException(status_code=404, detail="Acao nao encontrada")
    if action.status != "applied":
        raise HTTPException(
            status_code=409,
            detail=f"So da pra desfazer acao aplicada. Essa esta como '{action.status}'.",
        )

    if action.action_type == "block_ip" and action.blocked_ip_id:
        bloqueio = (
            await db.execute(select(BlockedIP).where(BlockedIP.id == action.blocked_ip_id))
        ).scalars().first()
        if bloqueio is not None and bloqueio.unblocked_at is None:
            bloqueio.unblocked_at = datetime.now(timezone.utc)
            bloqueio.unblocked_by = current_user

    action.status = "undone"
    action.undone_at = datetime.now(timezone.utc)
    action.undone_by = current_user
    await db.commit()
    # Recarrega na hora pra o desbloqueio valer sem esperar o proximo ciclo.
    await blocklist_cache.refresh()
    await db.refresh(action)
    return action


# A fila critica junta as tres origens no mesmo formato. Um alerta critico, um
# chamador de API perigoso e uma vulnerabilidade critica sao coisas diferentes
# no banco, mas pro analista de plantao sao a mesma pergunta: o que eu trato
# primeiro.
#
# A uniao fica separada da ordenacao porque o Postgres so aceita ORDER BY por
# nome ou posicao de coluna em cima de UNION, nunca por expressao. Ordenar por
# CASE exige envolver tudo numa subconsulta. De quebra, o mesmo texto serve pra
# contar sem arrastar ORDER BY e LIMIT junto.
SQL_QUEUE_UNION = """
    SELECT 'alert' AS kind, id, title, level AS severity, source_ip AS target,
           ts, status, description AS detail
      FROM alerts
     WHERE level IN ('critical', 'high') AND status = 'open'

    UNION ALL

    SELECT 'api_finding', id,
           'Comportamento suspeito de API em ' || client_ip,
           severity, client_ip, last_seen, status,
           'score ' || score || ' com ' || jsonb_array_length(signals) || ' sinal(is)'
      FROM api_findings
     WHERE severity IN ('critical', 'high')
       AND status IN ('open', 'investigating', 'escalated')

    UNION ALL

    SELECT 'vulnerability', id, title, severity, asset, last_seen, status, description
      FROM vulnerabilities
     WHERE severity = 'critical' AND status = 'open'
"""

SQL_QUEUE = f"""
    SELECT * FROM ({SQL_QUEUE_UNION}) fila
     ORDER BY CASE severity WHEN 'critical' THEN 0 ELSE 1 END, ts DESC
     LIMIT :limit
"""

SQL_QUEUE_COUNT = f"SELECT count(*) FROM ({SQL_QUEUE_UNION}) fila"


@router.get("/queue", response_model=list[QueueItem])
async def critical_queue(limit: int = Query(100, le=300), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(text(SQL_QUEUE), {"limit": limit})).mappings().all()
    return [QueueItem(**dict(r)) for r in rows]


@router.get("/summary", response_model=PreventionSummaryOut)
async def summary(db: AsyncSession = Depends(get_db)):
    politicas = (
        await db.execute(
            text(
                """
                SELECT count(*) AS total,
                       count(*) FILTER (WHERE mode = 'enforce' AND enabled) AS vigor,
                       count(*) FILTER (WHERE mode = 'observe' AND enabled) AS observando
                  FROM prevention_policies
                """
            )
        )
    ).one()

    acoes = (
        await db.execute(
            text(
                """
                SELECT count(*) AS total,
                       count(*) FILTER (WHERE status = 'applied') AS aplicadas,
                       count(*) FILTER (WHERE status = 'held') AS seguradas
                  FROM prevention_actions
                 WHERE ts > now() - interval '24 hours'
                """
            )
        )
    ).one()

    ultima_hora = (
        await db.execute(
            text(
                """
                SELECT count(*) FROM prevention_actions
                 WHERE status = 'applied' AND action_type = 'block_ip'
                   AND policy_id IS NOT NULL AND ts > now() - interval '1 hour'
                """
            )
        )
    ).scalar() or 0

    fila = (await db.execute(text(SQL_QUEUE_COUNT))).scalar() or 0

    return PreventionSummaryOut(
        policies_total=politicas.total or 0,
        policies_enforcing=politicas.vigor or 0,
        policies_observing=politicas.observando or 0,
        actions_24h=acoes.total or 0,
        applied_24h=acoes.aplicadas or 0,
        held_24h=acoes.seguradas or 0,
        blocks_last_hour=ultima_hora,
        blocks_ceiling=prevention.MAX_AUTO_BLOCKS_PER_HOUR,
        queue_size=fila,
    )
