"""notificacao por e-mail: canal de tipo email e destino generico

Revision ID: 0012
Revises: 0011
Create Date: 2026-09-09

Duas mudancas pequenas com o mesmo motivo: e-mail nao tem URL.

url vira target. Para webhook continua sendo o endereco do gancho; para e-mail
passa a ser o destinatario, ou varios separados por virgula. Manter o nome
"url" guardando um endereco de e-mail seria mentir no schema, e schema que
mente e a primeira coisa que confunde quem chega depois.

O tipo 'email' entra na restricao de kind. A restricao existe para uma linha
digitada errada na mao ser recusada pelo banco, em vez de virar uma mensagem
que nunca sai e ninguem entende por que.

As credenciais de SMTP NAO ficam aqui. Servidor, usuario e senha ficam na
configuracao, ou seja, no .env, porque sao segredo de infraestrutura e nao
dado de canal. O banco guarda apenas para quem mandar.
"""
from typing import Sequence, Union

from alembic import op

revision: str = "0012"
down_revision: Union[str, None] = "0011"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.alter_column("notification_channels", "url", new_column_name="target")

    op.drop_constraint("ck_notification_channels_kind", "notification_channels", type_="check")
    op.create_check_constraint(
        "ck_notification_channels_kind",
        "notification_channels",
        "kind IN ('discord', 'slack', 'teams', 'generic', 'email')",
    )


def downgrade() -> None:
    # Volta a restricao antes de renomear: se existir canal de e-mail, o
    # downgrade falha aqui, de proposito. Melhor recusar do que deixar uma
    # linha invalida para a versao anterior do codigo.
    op.drop_constraint("ck_notification_channels_kind", "notification_channels", type_="check")
    op.create_check_constraint(
        "ck_notification_channels_kind",
        "notification_channels",
        "kind IN ('discord', 'slack', 'teams', 'generic')",
    )

    op.alter_column("notification_channels", "target", new_column_name="url")
