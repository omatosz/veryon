"""analise de API: trafego, inventario de rotas e achados

Revision ID: 0008
Revises: 0007
Create Date: 2026-08-28

Tres tabelas com papeis bem separados:

  api_requests   o trafego cru, uma linha por requisicao. Hypertable, porque
                 e o que mais cresce no sistema inteiro.
  api_endpoints  o inventario de rotas. E aqui que mora a diferenca entre
                 rota conhecida e rota fantasma.
  api_findings   o resultado da analise, ja agrupado por quem chamou.

O motor de pontuacao le a primeira, consulta a segunda e escreve na terceira.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0008"
down_revision: Union[str, None] = "0007"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "api_requests",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        # 'self' quando o proprio Veryon observou, 'ingest' quando veio do
        # gateway de um cliente pelo POST /ingest/api-logs.
        sa.Column("source", sa.String(), nullable=False, server_default="self"),
        sa.Column("client_ip", sa.String(), nullable=True),
        sa.Column("method", sa.String(8), nullable=False),
        # O caminho como veio, com os ids dentro.
        sa.Column("path", sa.String(), nullable=False),
        # O caminho com os ids trocados por {id}. E por ele que agrupo, senao
        # /users/1 e /users/2 virariam duas rotas diferentes no inventario.
        sa.Column("route", sa.String(), nullable=False),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("response_bytes", sa.Integer(), nullable=True),
        sa.Column("user_agent", sa.String(300), nullable=True),
        # Query string truncada. Guardo pra o analista ver a evidencia do que
        # marcou como injecao, nao pra reprocessar.
        sa.Column("query", sa.String(500), nullable=True),
        # Sinais detectados na hora da escrita, quando o texto da requisicao
        # ainda esta na mao. Ex: {"injection": ["sqli"]}
        sa.Column("flags", JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.PrimaryKeyConstraint("id", "ts"),
    )
    op.execute("SELECT create_hypertable('api_requests', 'ts')")
    op.create_index("ix_api_requests_client_ip", "api_requests", ["client_ip", "ts"])
    op.create_index("ix_api_requests_route", "api_requests", ["route"])

    # Trafego de API e o dado mais volumoso e o menos util depois de velho: a
    # analise so olha os ultimos minutos. Sete dias cobre investigacao pra tras
    # sem deixar o disco encher sozinho. Fica dentro de um bloco tolerante
    # porque um Postgres sem o agendador do Timescale ainda deve subir.
    op.execute(
        """
        DO $$
        BEGIN
            PERFORM add_retention_policy('api_requests', INTERVAL '7 days');
        EXCEPTION WHEN OTHERS THEN
            RAISE NOTICE 'retencao automatica indisponivel, seguindo sem ela';
        END $$
        """
    )

    op.create_table(
        "api_endpoints",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("method", sa.String(8), nullable=False),
        sa.Column("route", sa.String(), nullable=False),
        # Rota que o sistema declara ter. O que aparece no trafego sem estar
        # aqui e API fantasma: existe, responde, e ninguem documentou.
        sa.Column("is_documented", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        # Rota que mexe com credencial, usuario, exportacao ou administracao.
        sa.Column("is_sensitive", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("request_count", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("error_count", sa.BigInteger(), nullable=False, server_default="0"),
        # Media movel de bytes de resposta. O sinal de volume anormal compara
        # a requisicao contra ela.
        sa.Column("avg_response_bytes", sa.Integer(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("method", "route", name="uq_api_endpoints_method_route"),
    )
    op.create_index("ix_api_endpoints_documented", "api_endpoints", ["is_documented"])

    op.create_table(
        "api_findings",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("client_ip", sa.String(), nullable=False),
        sa.Column("score", sa.Integer(), nullable=False),
        sa.Column("severity", sa.String(), nullable=False),
        # Lista dos sinais que pontuaram, cada um com peso e evidencia:
        # [{"id": "injection", "label": ..., "weight": 40, "evidence": ...}]
        sa.Column("signals", JSONB(), nullable=False),
        sa.Column("request_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("distinct_routes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("top_routes", JSONB(), nullable=True),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        # open | investigating | benign | escalated | resolved
        sa.Column("status", sa.String(), nullable=False, server_default="open"),
        sa.Column("updated_by", sa.String(), nullable=True),
        sa.Column("note", sa.Text(), nullable=True),
        # Ate quando o motor deve ficar quieto sobre esse chamador. Marcar como
        # benigno sem isso faria o achado voltar no ciclo seguinte.
        sa.Column("muted_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("alert_id", sa.BigInteger(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        # Um achado aberto por chamador. O motor atualiza o que ja existe em
        # vez de empilhar linha nova a cada ciclo de dez segundos.
        sa.UniqueConstraint("client_ip", name="uq_api_findings_client_ip"),
    )
    op.create_index("ix_api_findings_status", "api_findings", ["status"])
    op.create_index("ix_api_findings_score", "api_findings", ["score"])


def downgrade() -> None:
    op.drop_index("ix_api_findings_score", table_name="api_findings")
    op.drop_index("ix_api_findings_status", table_name="api_findings")
    op.drop_table("api_findings")
    op.drop_index("ix_api_endpoints_documented", table_name="api_endpoints")
    op.drop_table("api_endpoints")
    op.drop_index("ix_api_requests_route", table_name="api_requests")
    op.drop_index("ix_api_requests_client_ip", table_name="api_requests")
    op.drop_table("api_requests")
