"""
Motor de prevencao de ameaca.

O que ele faz: le o que a deteccao e a analise ja produziram, decide se alguma
politica se aplica, passa a decisao por uma sequencia de trilhos de seguranca e
so entao age. Tudo o que acontece vira linha em prevention_actions, inclusive o
que nao aconteceu e por que.

Os sete trilhos, em ordem de avaliacao:

  1. Politica nasce em observacao. Nenhuma age antes de alguem ligar na mao,
     depois de ver o que ela teria feito.
  2. Allowlist ganha sempre. Alvo protegido nunca e bloqueado por politica,
     mesmo que a regra case perfeitamente.
  3. Nunca bloqueia endereco privado, de loopback ou reservado. Automacao que
     bloqueia 127.0.0.1 ou a rede interna tira o painel do ar.
  4. Bloqueio automatico sempre expira. Politica sem prazo nao bloqueia.
  5. Teto de 10 bloqueios automaticos por hora, somando todas as politicas.
     Regra ruim erra no maximo dez vezes antes de parar sozinha.
  6. Espera entre acoes no mesmo alvo, pra nao reagir em laco ao mesmo caso.
  7. Toda acao aplicada e desfeita com um clique e mantem o registro do que
     foi desfeito, por quem e quando.

O trilho 5 e o mais importante dos sete. Os outros impedem erro pontual; ele
impede que um erro sistematico vire incidente enquanto ninguem esta olhando.
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address

from sqlalchemy import text

from app.core import blocklist
from app.db.session import async_session

log = logging.getLogger("veryon.prevention")

EVALUATE_SECONDS = 15
# Trilho 5: teto global de bloqueios automaticos por hora.
MAX_AUTO_BLOCKS_PER_HOUR = 10
# Trilho 7: por quanto tempo a politica respeita um desfazer feito na mao.
# Quando um analista desfaz um bloqueio automatico, ele discordou da maquina.
# Sem essa janela o motor reaplicaria no ciclo seguinte e o botao de desfazer
# viraria enfeite.
UNDO_RESPECT_MINUTES = 60

RAIL_OBSERVE = "modo observacao"
RAIL_ALLOWLIST = "alvo na allowlist"
RAIL_PRIVATE = "endereco privado ou reservado"
RAIL_NO_TTL = "politica de bloqueio sem prazo"
RAIL_CEILING = "teto horario de bloqueios automaticos"
RAIL_COOLDOWN = "espera entre acoes no mesmo alvo"
RAIL_UNDONE = "desfeito por analista ha pouco"


class Match:
    """Um caso que uma politica reconheceu, antes de qualquer trilho."""

    __slots__ = ("target", "reason", "evidence", "source_kind", "source_id")

    def __init__(self, target, reason, evidence=None, source_kind=None, source_id=None):
        self.target = target
        self.reason = reason
        self.evidence = evidence or {}
        self.source_kind = source_kind
        self.source_id = source_id


# --- Avaliadores ------------------------------------------------------------
#
# Cada um recebe a conexao e os parametros da politica e devolve os casos que
# reconheceu. Sao funcoes fixas, nao regra interpretada: o conjunto do que o
# sistema consegue decidir sozinho e o conjunto do que esta escrito aqui.

SQL_API_SCORE = """
    SELECT client_ip, score, severity, id
      FROM api_findings
     WHERE score >= :min_score
       AND status IN ('open', 'investigating', 'escalated')
       AND last_seen > now() - interval '30 minutes'
"""

SQL_API_SIGNAL = """
    SELECT client_ip, score, id, s->>'evidence' AS evidencia
      FROM api_findings, jsonb_array_elements(signals) s
     WHERE s->>'id' = :signal
       AND status IN ('open', 'investigating', 'escalated')
       AND last_seen > now() - interval '30 minutes'
"""

# O filtro por origem entra so quando a politica pede. Deixar um
# "(:sources IS NULL OR ...)" fixo parece mais limpo, mas o asyncpg nao
# consegue inferir o tipo de um array nulo e a consulta quebra inteira.
SQL_ALERT_RULE = """
    SELECT source_ip, id, rule_id, title, level
      FROM alerts
     WHERE level = ANY(:levels)
       AND status = 'open'
       AND ts > now() - interval '60 minutes'
"""
SQL_ALERT_RULE_SOURCES = " AND source_event_type LIKE ANY(:sources)"

SQL_REPEAT = """
    SELECT ip, count(*) AS vezes
      FROM blocked_ips
     WHERE unblocked_at IS NOT NULL
     GROUP BY ip
    HAVING count(*) >= :min_blocks
"""

SQL_THREAT_INTEL = """
    SELECT DISTINCT e.ip, e.abuseipdb_score, e.abuseipdb_country
      FROM ip_enrichment e
      JOIN alerts a ON a.source_ip = e.ip
     WHERE e.abuseipdb_score >= :min_score
       AND a.status = 'open'
       AND a.ts > now() - interval '24 hours'
"""

SQL_VULN_CRIT = """
    SELECT asset, id, title, severity
      FROM vulnerabilities
     WHERE severity = ANY(:severities)
       AND status = 'open'
"""


async def _eval_api_score(db, params) -> list[Match]:
    rows = (await db.execute(text(SQL_API_SCORE), {"min_score": params.get("min_score", 90)})).all()
    return [
        Match(
            ip,
            f"pontuacao {score} na analise de API",
            {"score": score, "severity": sev},
            "api_finding",
            fid,
        )
        for ip, score, sev, fid in rows
    ]


async def _eval_api_signal(db, params) -> list[Match]:
    sinal = params.get("signal", "")
    rows = (await db.execute(text(SQL_API_SIGNAL), {"signal": sinal})).all()
    vistos: dict[str, Match] = {}
    for ip, score, fid, evidencia in rows:
        # Um chamador pode ter o mesmo sinal mais de uma vez na janela; o caso
        # e um so.
        if ip not in vistos:
            vistos[ip] = Match(
                ip,
                f"sinal '{sinal}' na analise de API: {evidencia}",
                {"score": score, "signal": sinal, "evidence": evidencia},
                "api_finding",
                fid,
            )
    return list(vistos.values())


async def _eval_alert_rule(db, params) -> list[Match]:
    levels = params.get("levels", ["critical"])
    sources = params.get("sources")
    sql = SQL_ALERT_RULE
    args: dict = {"levels": levels}
    if sources:
        sql += SQL_ALERT_RULE_SOURCES
        args["sources"] = [f"%{s}%" for s in sources]
    rows = (await db.execute(text(sql), args)).all()
    return [
        Match(
            ip or "sem-ip",
            f"alerta {level} em aberto: {title}",
            {"rule_id": rule, "level": level},
            "alert",
            aid,
        )
        for ip, aid, rule, title, level in rows
    ]


async def _eval_repeat_offender(db, params) -> list[Match]:
    rows = (await db.execute(text(SQL_REPEAT), {"min_blocks": params.get("min_blocks", 2)})).all()
    return [
        Match(ip, f"ja foi bloqueado e liberado {vezes} vez(es)", {"bloqueios": vezes})
        for ip, vezes in rows
    ]


async def _eval_threat_intel(db, params) -> list[Match]:
    rows = (
        await db.execute(text(SQL_THREAT_INTEL), {"min_score": params.get("min_abuse_score", 90)})
    ).all()
    return [
        Match(
            ip,
            f"nota {score} no AbuseIPDB e alerta aberto no periodo",
            {"abuseipdb_score": score, "pais": pais},
        )
        for ip, score, pais in rows
    ]


async def _eval_vuln_critical(db, params) -> list[Match]:
    rows = (
        await db.execute(text(SQL_VULN_CRIT), {"severities": params.get("severities", ["critical"])})
    ).all()
    return [
        Match(asset, f"vulnerabilidade {sev} sem tratativa: {title}", {"severity": sev}, "vulnerability", vid)
        for asset, vid, title, sev in rows
    ]


AVALIADORES = {
    "api_score": _eval_api_score,
    "api_signal": _eval_api_signal,
    "alert_rule": _eval_alert_rule,
    "repeat_offender": _eval_repeat_offender,
    "threat_intel": _eval_threat_intel,
    "vuln_critical": _eval_vuln_critical,
}


# --- Trilhos ----------------------------------------------------------------


def _e_privado(alvo: str) -> bool:
    """Trilho 3. Endereco que nunca pode ser bloqueado por automacao.

    Vale pra loopback, rede privada, link-local, multicast e reservado. Alvo
    que nem e endereco (nome de ativo, no caso de escalada) passa direto: nao
    ha o que bloquear nele."""
    try:
        addr = ip_address(alvo)
    except ValueError:
        return False
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


async def _bloqueios_na_ultima_hora(db) -> int:
    return (
        await db.execute(
            text(
                """
                SELECT count(*) FROM prevention_actions
                 WHERE status = 'applied'
                   AND action_type = 'block_ip'
                   AND policy_id IS NOT NULL
                   AND ts > now() - interval '1 hour'
                """
            )
        )
    ).scalar() or 0


async def _em_espera(db, policy_id: int, alvo: str, minutos: int, modo: str) -> bool:
    """Trilho 6. Nao registra o mesmo desfecho duas vezes no mesmo modo.

    A espera e por modo de operacao, e isso resolve dois problemas de uma vez.

    Se contasse tudo junto, ligar uma politica que estava observando a deixaria
    dormente exatamente nos alvos que ela vinha acompanhando: o analista aperta
    o botao e nada acontece por dez minutos. Simulacao nao fez nada, entao nao
    pode segurar uma acao de verdade depois.

    Se nao contasse nada, o motor escreveria a mesma linha a cada quinze
    segundos. Uma trilha de auditoria com duzentas linhas iguais por hora nao
    serve pra auditar coisa nenhuma.

    'failed' fica de fora de proposito: erro de execucao merece nova tentativa
    no proximo ciclo."""
    encontrado = (
        await db.execute(
            text(
                """
                SELECT 1 FROM prevention_actions
                 WHERE policy_id = :pid AND target = :alvo
                   AND mode = :modo AND status <> 'failed'
                   AND ts > now() - make_interval(mins => :mins)
                 LIMIT 1
                """
            ),
            {"pid": policy_id, "alvo": alvo, "mins": minutos, "modo": modo},
        )
    ).first()
    return encontrado is not None


async def _desfeito_ha_pouco(db, policy_id: int, alvo: str) -> bool:
    """Trilho 7, o lado que impede a reaplicacao.

    Desfazer e um analista dizendo que a maquina errou naquele caso. A politica
    respeita isso por uma hora e registra o motivo, em vez de reaplicar e virar
    briga entre o humano e o laco de quinze segundos."""
    achou = (
        await db.execute(
            text(
                """
                SELECT 1 FROM prevention_actions
                 WHERE policy_id = :pid AND target = :alvo
                   AND status = 'undone'
                   AND undone_at > now() - make_interval(mins => :mins)
                 LIMIT 1
                """
            ),
            {"pid": policy_id, "alvo": alvo, "mins": UNDO_RESPECT_MINUTES},
        )
    ).first()
    return achou is not None


# --- Execucao ---------------------------------------------------------------

INSERT_ACTION = text(
    """
    INSERT INTO prevention_actions
        (policy_id, policy_code, action_type, target, reason, evidence, mode,
         status, rail, blocked_ip_id, source_kind, source_id, created_by)
    VALUES
        (:policy_id, :policy_code, :action_type, :target, :reason,
         CAST(:evidence AS jsonb), :mode, :status, :rail, :blocked_ip_id,
         :source_kind, :source_id, :created_by)
    RETURNING id
    """
)

INSERT_BLOCK = text(
    """
    INSERT INTO blocked_ips (ip, reason, blocked_by, expires_at, source, policy_id)
    VALUES (:ip, :reason, 'politica', now() + make_interval(mins => :ttl), 'policy', :policy_id)
    RETURNING id
    """
)

JA_BLOQUEADO = text(
    """
    SELECT 1 FROM blocked_ips
     WHERE ip = :ip AND unblocked_at IS NULL
       AND (expires_at IS NULL OR expires_at > now())
     LIMIT 1
    """
)


async def _registrar(db, policy, m: Match, status: str, rail=None, blocked_id=None) -> int:
    return (
        await db.execute(
            INSERT_ACTION,
            {
                "policy_id": policy["id"],
                "policy_code": policy["code"],
                "action_type": policy["action"],
                "target": m.target,
                "reason": m.reason,
                "evidence": json.dumps(m.evidence),
                "mode": policy["mode"],
                "status": status,
                "rail": rail,
                "blocked_ip_id": blocked_id,
                "source_kind": m.source_kind,
                "source_id": m.source_id,
                "created_by": "veryon",
            },
        )
    ).scalar()


async def _aplicar(db, policy, m: Match, orcamento: list[int]) -> str:
    """Passa um caso pelos trilhos e age se todos deixarem.

    Devolve o status registrado. orcamento e uma lista de um elemento com o
    quanto ainda cabe no teto horario, passada assim de proposito pra ser
    decrementada dentro do ciclo sem reconsultar o banco a cada acao."""
    acao = policy["action"]

    # Trilho 6, antes de tudo: se ja produziu esse desfecho ha pouco, sai.
    if await _em_espera(db, policy["id"], m.target, policy["cooldown_minutes"], policy["mode"]):
        return "skip"

    # Trilho 1: em observacao, so anota o que faria.
    if policy["mode"] != "enforce":
        await _registrar(db, policy, m, "simulated", RAIL_OBSERVE)
        return "simulated"

    if acao == "escalate":
        # Escalada nao mexe em rede, entao pula os trilhos de bloqueio.
        await _registrar(db, policy, m, "applied")
        return "applied"

    # Trilho 7: analista desfez esse caso ha pouco, a decisao dele vale.
    if await _desfeito_ha_pouco(db, policy["id"], m.target):
        await _registrar(db, policy, m, "held", RAIL_UNDONE)
        return "held"

    # Trilho 2: allowlist ganha de qualquer regra.
    if blocklist.is_allowlisted(m.target):
        await _registrar(db, policy, m, "held", RAIL_ALLOWLIST)
        return "held"

    # Trilho 3: nunca automatiza bloqueio de endereco interno.
    if _e_privado(m.target):
        await _registrar(db, policy, m, "held", RAIL_PRIVATE)
        return "held"

    # Trilho 4: bloqueio de politica sempre expira.
    ttl = policy["ttl_minutes"]
    if not ttl:
        await _registrar(db, policy, m, "held", RAIL_NO_TTL)
        return "held"

    # Trilho 5: teto horario.
    if orcamento[0] <= 0:
        await _registrar(db, policy, m, "held", RAIL_CEILING)
        return "held"

    if (await db.execute(JA_BLOQUEADO, {"ip": m.target})).first() is not None:
        return "skip"

    try:
        # Savepoint pelo mesmo motivo do avaliador: sem ele, um INSERT que
        # falha aborta a transacao e ate o registro do proprio fracasso, logo
        # abaixo, quebraria junto.
        async with db.begin_nested():
            bloqueio_id = (
                await db.execute(
                    INSERT_BLOCK,
                    {
                        "ip": m.target,
                        "reason": f"{policy['code']}: {m.reason}"[:200],
                        "ttl": ttl,
                        "policy_id": policy["id"],
                    },
                )
            ).scalar()
    except Exception as exc:  # noqa: BLE001
        log.warning("politica %s falhou bloqueando %s: %s", policy["code"], m.target, exc)
        await _registrar(db, policy, m, "failed")
        return "failed"

    orcamento[0] -= 1
    await _registrar(db, policy, m, "applied", blocked_id=bloqueio_id)
    return "applied"


FETCH_POLICIES = text(
    """
    SELECT id, code, name, kind, params, action, ttl_minutes, mode, cooldown_minutes
      FROM prevention_policies
     WHERE enabled
     ORDER BY priority
    """
)


async def evaluate_once(dry_run_policy_id: int | None = None) -> dict:
    """Um ciclo. Com dry_run_policy_id, avalia so aquela politica e nao grava
    nada: e o que a tela usa pra mostrar o que a regra faria antes de alguem
    ligar ela."""
    resumo = {"casos": 0, "aplicadas": 0, "simuladas": 0, "seguradas": 0}
    simulacao: list[dict] = []

    async with async_session() as db:
        policies = [dict(r) for r in (await db.execute(FETCH_POLICIES)).mappings().all()]
        if dry_run_policy_id is not None:
            policies = [p for p in policies if p["id"] == dry_run_policy_id]

        usados = await _bloqueios_na_ultima_hora(db)
        orcamento = [max(0, MAX_AUTO_BLOCKS_PER_HOUR - usados)]

        for policy in policies:
            avaliador = AVALIADORES.get(policy["kind"])
            if avaliador is None:
                log.warning("politica %s tem kind desconhecido: %s", policy["code"], policy["kind"])
                continue

            try:
                # Savepoint por politica. Capturar a excecao em Python nao
                # basta: consulta que falha aborta a transacao do Postgres, e
                # dai TODA politica seguinte quebra com 'transaction is
                # aborted'. Uma regra com defeito derrubaria o motor inteiro
                # em silencio, logando aviso sobre uma so. O savepoint desfaz
                # so o que aquela politica fez e deixa a transacao usavel.
                async with db.begin_nested():
                    casos = await avaliador(db, policy["params"] or {})
            except Exception as exc:  # noqa: BLE001
                log.warning("avaliador da politica %s falhou: %s", policy["code"], exc)
                continue

            if not casos:
                continue
            resumo["casos"] += len(casos)

            if dry_run_policy_id is not None:
                for m in casos:
                    simulacao.append(
                        {
                            "target": m.target,
                            "reason": m.reason,
                            "acao": policy["action"],
                            "seria_segurado": _rail_previa(policy, m),
                        }
                    )
                continue

            for m in casos:
                status = await _aplicar(db, policy, m, orcamento)
                if status == "applied":
                    resumo["aplicadas"] += 1
                elif status == "simulated":
                    resumo["simuladas"] += 1
                elif status == "held":
                    resumo["seguradas"] += 1

            await db.execute(
                text(
                    """
                    UPDATE prevention_policies
                       SET match_count = match_count + :n, last_match_at = now()
                     WHERE id = :id
                    """
                ),
                {"n": len(casos), "id": policy["id"]},
            )

        if dry_run_policy_id is None:
            await db.commit()
        else:
            await db.rollback()

    if dry_run_policy_id is not None:
        return {"simulacao": simulacao, "total": len(simulacao)}
    return resumo


def _rail_previa(policy, m: Match) -> str | None:
    """Qual trilho seguraria esse caso, sem tocar no banco. Usado so na
    simulacao, pra tela conseguir mostrar 'isso aqui nao passaria'."""
    if policy["action"] == "escalate":
        return None
    if blocklist.is_allowlisted(m.target):
        return RAIL_ALLOWLIST
    if blocklist.is_blocked(m.target):
        return "ja bloqueado"
    if _e_privado(m.target):
        return RAIL_PRIVATE
    if not policy["ttl_minutes"]:
        return RAIL_NO_TTL
    return None


async def evaluate_loop() -> None:
    log.info("motor de prevencao iniciado (teto de %d bloqueios/hora)", MAX_AUTO_BLOCKS_PER_HOUR)
    while True:
        try:
            resumo = await evaluate_once()
            if resumo["aplicadas"] or resumo["seguradas"]:
                log.info("prevencao: %s", resumo)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            log.warning("ciclo de prevencao falhou: %s", exc)
        await asyncio.sleep(EVALUATE_SECONDS)
