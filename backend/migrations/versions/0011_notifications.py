"""notificacoes: canais, fila duravel e checkpoint

Revision ID: 0011
Revises: 0010
Create Date: 2026-09-09

Tres tabelas. O objetivo e simples de dizer e chato de acertar: fazer um
alerta critico chegar em alguem que nao esta com a aba aberta.

notification_channels    para onde mandar, e a partir de qual severidade.
alert_notifications      a fila duravel: o que foi decidido e o que ja saiu.
notification_checkpoint  ate qual alerta o notificador ja olhou.

Por que uma fila em vez de mandar o webhook na hora que o alerta nasce:
os dois produtores de alerta rodam em processos separados. O detection/ e um
container proprio, com psycopg2 e SQL cru; o api_analyzer vive dentro do
backend, async e com SQLAlchemy. Botar envio de webhook nos dois significaria
escrever a mesma logica duas vezes, em dois estilos, e mante-las iguais pra
sempre. Com a fila, os dois continuam so escrevendo em alerts, sem saber que
notificacao existe, e um unico laco decide e entrega.

O checkpoint espelha detection_checkpoint, que ja faz esse papel para
raw_events. Padrao que ja existe no projeto vale mais que padrao novo.

Sem chave estrangeira para alerts de proposito: alerts e hypertable com chave
primaria composta (id, ts), e FK para hypertable custa caro em escrita e
atrapalha a politica de retencao que vem no proximo item do plano. Guardamos o
id solto e aceitamos que um alerta expirado deixa a linha da fila orfa, o que
nao tem consequencia: a mensagem ja foi entregue muito antes.

Todo canal nasce desligado, igual toda politica de prevencao nasce em
observacao. Nada sai daqui ate alguem preencher a URL e ligar na mao.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0011"
down_revision: Union[str, None] = "0010"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "notification_channels",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("name", sa.String, nullable=False, unique=True),
        # discord, slack, teams ou generic. So muda o formato do corpo; o
        # resto do caminho e igual para todos.
        sa.Column("kind", sa.String, nullable=False),
        sa.Column("url", sa.String, nullable=False),
        # Abaixo desta severidade o canal nem entra na conta. E o primeiro
        # filtro, antes de agrupamento e teto por hora.
        sa.Column("min_level", sa.String, nullable=False, server_default="high"),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.CheckConstraint(
            "kind IN ('discord', 'slack', 'teams', 'generic')",
            name="ck_notification_channels_kind",
        ),
        sa.CheckConstraint(
            "min_level IN ('informational', 'low', 'medium', 'high', 'critical')",
            name="ck_notification_channels_min_level",
        ),
    )

    op.create_table(
        "alert_notifications",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column(
            "channel_id",
            sa.Integer,
            sa.ForeignKey("notification_channels.id", ondelete="CASCADE"),
            nullable=False,
        ),
        # rule_id + ip hoje. Se o rastreamento de ator for descongelado, vira a
        # identidade do ator e o agrupamento passa a valer entre IPs diferentes
        # sem mudar mais nada aqui.
        sa.Column("group_key", sa.String, nullable=False),
        # pending  ainda vai sair
        # sent     entregue
        # failed   estourou o teto de tentativas, nao tenta mais
        # suppressed  um trilho barrou. Fica registrado, nao some.
        sa.Column("status", sa.String, nullable=False, server_default="pending"),
        sa.Column("suppressed_reason", sa.String),
        sa.Column("attempts", sa.Integer, nullable=False, server_default="0"),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("last_error", sa.String),
        # Quantos alertas do mesmo grupo esta mensagem representa. Dez
        # tentativas de SQL injection do mesmo IP viram uma mensagem dizendo
        # dez, nao dez mensagens.
        sa.Column("alert_count", sa.Integer, nullable=False, server_default="1"),
        sa.Column("first_alert_id", sa.BigInteger),
        sa.Column("last_alert_id", sa.BigInteger),
        sa.Column("level", sa.String, nullable=False),
        # Posicao da severidade na escala, gravada pelo notificador. Existe
        # para o UPDATE de agrupamento conseguir decidir se a severidade subiu
        # sem ter que repetir a ordem dos niveis dentro do SQL. A escala mora
        # em notify_adapters.NIVEIS e em nenhum outro lugar.
        sa.Column("level_weight", sa.SmallInteger, nullable=False, server_default="0"),
        sa.Column("title", sa.String, nullable=False),
        sa.Column("rule_id", sa.String),
        sa.Column("source_ip", sa.String),
        sa.Column("payload", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("sent_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint(
            "status IN ('pending', 'sent', 'failed', 'suppressed')",
            name="ck_alert_notifications_status",
        ),
    )

    # No maximo uma mensagem pendente por grupo em cada canal. E o que
    # transforma rajada em contador: o alerta numero dois do mesmo grupo cai
    # neste indice e vira UPDATE da linha que ja existe, em vez de INSERT.
    op.create_index(
        "ux_alert_notifications_pendente_por_grupo",
        "alert_notifications",
        ["channel_id", "group_key"],
        unique=True,
        postgresql_where=sa.text("status = 'pending'"),
    )
    # Usado pelo laco de entrega: pega o que esta pendente e ja pode tentar.
    op.create_index(
        "ix_alert_notifications_proxima_tentativa",
        "alert_notifications",
        ["status", "next_attempt_at"],
    )
    # Usado pelo trilho de silencio pos-envio e pelo teto por hora.
    op.create_index(
        "ix_alert_notifications_canal_enviado",
        "alert_notifications",
        ["channel_id", "sent_at"],
    )

    op.create_table(
        "notification_checkpoint",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("last_alert_id", sa.BigInteger, nullable=False, server_default="0"),
    )
    # Comeca no ultimo alerta que ja existe, nao em zero. Ligar o notificador
    # num banco com historico nao pode disparar uma avalanche de mensagens
    # sobre coisa que aconteceu semana passada.
    op.execute(
        "INSERT INTO notification_checkpoint (id, last_alert_id) "
        "VALUES (1, COALESCE((SELECT max(id) FROM alerts), 0))"
    )


def downgrade() -> None:
    op.drop_table("notification_checkpoint")
    op.drop_index("ix_alert_notifications_canal_enviado", table_name="alert_notifications")
    op.drop_index("ix_alert_notifications_proxima_tentativa", table_name="alert_notifications")
    op.drop_index("ux_alert_notifications_pendente_por_grupo", table_name="alert_notifications")
    op.drop_table("alert_notifications")
    op.drop_table("notification_channels")
