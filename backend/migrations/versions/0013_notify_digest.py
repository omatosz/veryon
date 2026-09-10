"""notificacao: terceiro caminho, o digest

Revision ID: 0013
Revises: 0012
Create Date: 2026-09-09

Fecha os tres caminhos por severidade previstos no plano.

Ate aqui existiam dois: ou o alerta virava mensagem, ou era descartado por
severidade baixa. Isso obriga a escolher entre ser interrompido por coisa
media ou nao saber dela nunca.

O terceiro caminho e o digest: o alerta entra na fila com status 'digest' e
espera. De tempos em tempos, tudo o que acumulou para aquele canal vira UMA
mensagem so, um resumo do periodo.

Como um alerta escolhe o caminho, do mais grave para o menos:

  nivel >= immediate_level   ->  'pending', sai na proxima entrega
  nivel >= min_level         ->  'digest', espera o resumo
  abaixo disso               ->  ignorado

Com o padrao (min_level 'high', immediate_level 'critical'), um alerta
critical interrompe, um high entra no resumo, e o resto nao aparece. Um canal
que queira ser interrompido por tudo e so igualar os dois niveis.

last_digest_at guarda quando o resumo daquele canal saiu pela ultima vez. Fica
no canal, e nao numa tabela separada, porque e um dado por canal e nada mais
consulta isso.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0013"
down_revision: Union[str, None] = "0012"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "notification_channels",
        sa.Column(
            "immediate_level",
            sa.String,
            nullable=False,
            server_default="critical",
        ),
    )
    op.create_check_constraint(
        "ck_notification_channels_immediate_level",
        "notification_channels",
        "immediate_level IN ('informational', 'low', 'medium', 'high', 'critical')",
    )
    op.add_column(
        "notification_channels",
        sa.Column("last_digest_at", sa.DateTime(timezone=True)),
    )

    op.drop_constraint(
        "ck_alert_notifications_status", "alert_notifications", type_="check"
    )
    op.create_check_constraint(
        "ck_alert_notifications_status",
        "alert_notifications",
        "status IN ('pending', 'sent', 'failed', 'suppressed', 'digest')",
    )

    # Como a mensagem saiu: sozinha ou dentro de um resumo.
    #
    # Existe por causa do teto por hora. Um resumo com vinte itens marca vinte
    # linhas como enviadas, e sem esta coluna o canal pareceria ter mandado
    # vinte mensagens, batendo o teto e travando o proximo alerta urgente. O
    # teto conta so o que saiu sozinho; o resumo e uma mensagem so, por
    # definicao, e nao pode competir com o urgente pelo mesmo limite.
    op.add_column(
        "alert_notifications",
        sa.Column("sent_as", sa.String, nullable=False, server_default="single"),
    )
    op.create_check_constraint(
        "ck_alert_notifications_sent_as",
        "alert_notifications",
        "sent_as IN ('single', 'digest')",
    )

    # Mesma ideia do indice de pendentes: um acumulador por grupo, por canal.
    # Sem isto, cem alertas do mesmo tipo virariam cem linhas esperando o
    # resumo, e o resumo teria cem itens iguais em vez de um item dizendo cem.
    op.create_index(
        "ux_alert_notifications_digest_por_grupo",
        "alert_notifications",
        ["channel_id", "group_key"],
        unique=True,
        postgresql_where=sa.text("status = 'digest'"),
    )


def downgrade() -> None:
    op.drop_index(
        "ux_alert_notifications_digest_por_grupo", table_name="alert_notifications"
    )
    op.drop_constraint(
        "ck_alert_notifications_sent_as", "alert_notifications", type_="check"
    )
    op.drop_column("alert_notifications", "sent_as")
    # As linhas em digest viram pending: a versao anterior nao conhece esse
    # status, e descartar seria perder alerta que ninguem viu ainda.
    op.execute("UPDATE alert_notifications SET status = 'pending' WHERE status = 'digest'")
    op.drop_constraint(
        "ck_alert_notifications_status", "alert_notifications", type_="check"
    )
    op.create_check_constraint(
        "ck_alert_notifications_status",
        "alert_notifications",
        "status IN ('pending', 'sent', 'failed', 'suppressed')",
    )
    op.drop_column("notification_channels", "last_digest_at")
    op.drop_constraint(
        "ck_notification_channels_immediate_level", "notification_channels", type_="check"
    )
    op.drop_column("notification_channels", "immediate_level")
