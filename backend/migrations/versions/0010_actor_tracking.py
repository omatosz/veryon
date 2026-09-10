"""rastreamento de ator: identidade que sobrevive a troca de IP

Revision ID: 0010
Revises: 0009
Create Date: 2026-09-01

Duas tabelas e uma coluna.

actors      o ator, com os tracos que sustentam a identidade e o quanto se
            pode afirmar sobre ela.
actor_ips   por onde esse ator apareceu, com a semelhanca que justificou cada
            juncao. E a trilha: nenhuma fusao pode ser inexplicavel.

api_requests.header_sig  a materia-prima. Nome dos cabecalhos na ordem em que
            vieram, sem valor nenhum. O middleware ja tinha isso na mao e
            estava jogando fora.

O rastreador so olha chamador que o motor de sinais ja marcou como suspeito.
Nao e um sistema de identificar visitante: e um sistema de nao perder um
atacante conhecido quando ele troca de endereco.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0010"
down_revision: Union[str, None] = "0009"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Nome dos cabecalhos na ordem, separados por virgula. Nunca valor: valor
    # carrega cookie e token, nome nao carrega nada, e a assinatura funciona
    # igual com um e sem o outro.
    op.add_column("api_requests", sa.Column("header_sig", sa.String(600), nullable=True))

    op.create_table(
        "actors",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        # Identificador curto e legivel, do tipo que da pra falar em voz alta
        # numa reuniao: "o ator a4f2c1". Deriva dos tracos.
        sa.Column("ref", sa.String(12), nullable=False),
        # Os tracos canonicos do ator: header_sig, agente, ritmo, perfil.
        sa.Column("traits", JSONB(), nullable=False),
        # low | medium | high. Nunca significa "e a mesma pessoa", e sim "e a
        # mesma ferramenta com o mesmo padrao".
        sa.Column("confidence", sa.String(), nullable=False, server_default="low"),
        sa.Column("distinctiveness", sa.Float(), nullable=False, server_default="0"),
        sa.Column("ip_count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("request_count", sa.BigInteger(), nullable=False, server_default="0"),
        # Maior pontuacao de achado ja atribuida a esse ator. E por ela que a
        # lista ordena: quem fez a pior coisa aparece primeiro.
        sa.Column("max_score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        # active enquanto aparece trafego; dormant quando some. Ator dormente
        # continua existindo pra ser reconhecido se voltar.
        sa.Column("status", sa.String(), nullable=False, server_default="active"),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("updated_by", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("ref", name="uq_actors_ref"),
    )
    op.create_index("ix_actors_last_seen", "actors", ["last_seen"])
    op.create_index("ix_actors_max_score", "actors", ["max_score"])

    op.create_table(
        "actor_ips",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("actor_id", sa.BigInteger(), nullable=False),
        sa.Column("client_ip", sa.String(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("request_count", sa.BigInteger(), nullable=False, server_default="0"),
        # Com quanta semelhanca esse IP entrou no ator, e a quebra por traco.
        # Existe pra o analista poder discordar com dado na mao em vez de
        # aceitar um numero que apareceu sozinho.
        sa.Column("similarity", sa.Float(), nullable=False, server_default="1"),
        sa.Column("match_detail", JSONB(), nullable=True),
        # Ligado quando uma pessoa move ou separa o IP na mao. O rastreador nao
        # mexe mais nele depois disso: mesma ideia do desfazer da prevencao,
        # automacao nao pode desfazer decisao humana no ciclo seguinte.
        sa.Column("manual", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.PrimaryKeyConstraint("id"),
        # Um IP pertence a um ator por vez. Sem isso a linha do tempo do perfil
        # teria que decidir qual dono mostrar.
        sa.UniqueConstraint("client_ip", name="uq_actor_ips_client_ip"),
        sa.ForeignKeyConstraint(["actor_id"], ["actors.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_actor_ips_actor", "actor_ips", ["actor_id"])


def downgrade() -> None:
    op.drop_index("ix_actor_ips_actor", table_name="actor_ips")
    op.drop_table("actor_ips")
    op.drop_index("ix_actors_max_score", table_name="actors")
    op.drop_index("ix_actors_last_seen", table_name="actors")
    op.drop_table("actors")
    op.drop_column("api_requests", "header_sig")
