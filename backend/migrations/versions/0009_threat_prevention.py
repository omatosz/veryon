"""prevencao de ameaca: politicas e trilha de acoes

Revision ID: 0009
Revises: 0008
Create Date: 2026-08-28

Duas tabelas e dez politicas de fabrica.

prevention_policies  o que o sistema tem permissao de fazer sozinho.
prevention_actions   tudo o que ele fez ou teria feito, com o porque.

A segunda existe pra que nenhuma acao automatica seja invisivel. Toda politica
que dispara escreve uma linha, inclusive quando esta em observacao e nao fez
nada, e inclusive quando um trilho de seguranca a impediu. Automacao de
seguranca sem trilha e como bloqueio sem motivo: funciona ate o dia em que
alguem precisa explicar o que aconteceu.

Todas as politicas nascem em modo 'observe'. Nenhuma bloqueia nada ate alguem
olhar o que ela teria feito e ligar na mao.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0009"
down_revision: Union[str, None] = "0008"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# code, nome, descricao, kind, params, action, ttl, prioridade
POLITICAS = [
    (
        "API-CRIT",
        "Comportamento critico de API",
        "Chamador com pontuacao 90 ou mais na analise de API. Nesse nivel a soma "
        "de sinais ja nao tem leitura inocente.",
        "api_score",
        {"min_score": 90},
        "block_ip",
        60,
        10,
    ),
    (
        "API-INJ",
        "Tentativa de injecao",
        "Requisicao com padrao de SQLi, XSS, traversal ou comando. Uma basta: "
        "ninguem manda UNION SELECT na query por engano.",
        "api_signal",
        {"signal": "injection"},
        "block_ip",
        30,
        20,
    ),
    (
        "API-ENUM",
        "Varredura de rotas",
        "Muitas rotas distintas em sequencia, a maioria voltando 404. E alguem "
        "procurando o que existe antes de atacar.",
        "api_signal",
        {"signal": "enumeration"},
        "block_ip",
        15,
        30,
    ),
    (
        "API-AUTH",
        "Rajada de falha de autenticacao",
        "Varias tentativas de login falhando do mesmo lugar. Prazo curto de "
        "proposito: usuario que esqueceu a senha cai aqui tambem.",
        "api_signal",
        {"signal": "auth_burst"},
        "block_ip",
        20,
        40,
    ),
    (
        "API-SHADOW",
        "API fantasma respondendo",
        "Rota que responde sem estar no inventario. Nao bloqueia: o problema e "
        "de dentro de casa, quem tem que agir e o time da aplicacao.",
        "api_signal",
        {"signal": "shadow_api"},
        "escalate",
        None,
        50,
    ),
    (
        "SSH-BRUTE",
        "Forca bruta em SSH",
        "Alerta critico originado do honeypot SSH. Prazo maior porque esse "
        "trafego nao tem versao legitima.",
        "alert_rule",
        {"levels": ["critical"], "sources": ["cowrie"]},
        "block_ip",
        120,
        15,
    ),
    (
        "ALERT-CRIT",
        "Alerta critico sem tratativa",
        "Qualquer alerta critico ainda aberto vai pra fila de tratamento. Nao "
        "bloqueia sozinho: alerta critico merece um par de olhos.",
        "alert_rule",
        {"levels": ["critical"]},
        "escalate",
        None,
        60,
    ),
    (
        "REINCIDENTE",
        "Reincidente",
        "IP que ja foi bloqueado e voltou duas vezes ou mais. Quem volta depois "
        "de bloqueado nao errou o caminho.",
        "repeat_offender",
        {"min_blocks": 2},
        "block_ip",
        1440,
        5,
    ),
    (
        "INTEL-ABUSE",
        "Reputacao pessima",
        "IP com nota 90 ou mais no AbuseIPDB envolvido em alerta aberto. A "
        "denuncia veio de fora, o alerta veio de dentro.",
        "threat_intel",
        {"min_abuse_score": 90},
        "block_ip",
        720,
        25,
    ),
    (
        "VULN-CRIT",
        "Vulnerabilidade critica em aberto",
        "Vulnerabilidade critica sem tratativa vai pra fila. Nao ha o que "
        "bloquear aqui: o risco esta no proprio parque.",
        "vuln_critical",
        {"severities": ["critical"]},
        "escalate",
        None,
        70,
    ),
]


def upgrade() -> None:
    op.create_table(
        "prevention_policies",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("code", sa.String(32), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        # Qual avaliador roda essa politica. Nao e linguagem de regra: cada
        # kind e uma funcao conhecida no codigo, com parametros ajustaveis. Um
        # motor de regra generico seria mais flexivel e muito mais facil de
        # transformar em bloqueio acidental do parque inteiro.
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("params", JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        # block_ip | escalate
        sa.Column("action", sa.String(24), nullable=False),
        # Prazo do bloqueio automatico. Bloqueio de politica sempre expira: e
        # o trilho que impede uma regra ruim de virar dano permanente.
        sa.Column("ttl_minutes", sa.Integer(), nullable=True),
        # observe = so registra o que faria. enforce = age de verdade.
        sa.Column("mode", sa.String(16), nullable=False, server_default="observe"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("priority", sa.Integer(), nullable=False, server_default="100"),
        # Nao reage duas vezes ao mesmo alvo dentro desse prazo.
        sa.Column("cooldown_minutes", sa.Integer(), nullable=False, server_default="10"),
        sa.Column("match_count", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("action_count", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("last_match_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_by", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("code", name="uq_prevention_policies_code"),
    )

    op.create_table(
        "prevention_actions",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        # NULL quando a acao foi manual, feita pelo analista na tela.
        sa.Column("policy_id", sa.BigInteger(), nullable=True),
        sa.Column("policy_code", sa.String(32), nullable=True),
        sa.Column("action_type", sa.String(24), nullable=False),
        sa.Column("target", sa.String(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("evidence", JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("mode", sa.String(16), nullable=False),
        # simulated  a politica estava em observacao, nada foi feito
        # applied    a acao foi executada
        # held       um trilho de seguranca impediu
        # undone     alguem desfez
        # failed     a execucao deu erro
        sa.Column("status", sa.String(16), nullable=False),
        # Qual trilho segurou, quando status = held.
        sa.Column("rail", sa.String(48), nullable=True),
        sa.Column("blocked_ip_id", sa.BigInteger(), nullable=True),
        sa.Column("source_kind", sa.String(24), nullable=True),
        sa.Column("source_id", sa.BigInteger(), nullable=True),
        sa.Column("undone_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("undone_by", sa.String(), nullable=True),
        sa.Column("created_by", sa.String(), nullable=False, server_default="veryon"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_prevention_actions_ts", "prevention_actions", ["ts"])
    op.create_index("ix_prevention_actions_target", "prevention_actions", ["target"])
    op.create_index("ix_prevention_actions_policy", "prevention_actions", ["policy_id"])

    politicas = sa.table(
        "prevention_policies",
        sa.column("code", sa.String),
        sa.column("name", sa.String),
        sa.column("description", sa.Text),
        sa.column("kind", sa.String),
        sa.column("params", JSONB),
        sa.column("action", sa.String),
        sa.column("ttl_minutes", sa.Integer),
        sa.column("priority", sa.Integer),
    )
    op.bulk_insert(
        politicas,
        [
            {
                "code": code,
                "name": nome,
                "description": desc,
                "kind": kind,
                "params": params,
                "action": action,
                "ttl_minutes": ttl,
                "priority": prio,
            }
            for code, nome, desc, kind, params, action, ttl, prio in POLITICAS
        ],
    )


def downgrade() -> None:
    op.drop_index("ix_prevention_actions_policy", table_name="prevention_actions")
    op.drop_index("ix_prevention_actions_target", table_name="prevention_actions")
    op.drop_index("ix_prevention_actions_ts", table_name="prevention_actions")
    op.drop_table("prevention_actions")
    op.drop_table("prevention_policies")
