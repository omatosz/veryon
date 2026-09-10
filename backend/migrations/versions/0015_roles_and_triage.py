"""papeis de usuario e registro de triagem

Revision ID: 0015
Revises: 0014
Create Date: 2026-09-09

Duas coisas que parecem separadas e nao sao: as duas existem porque hoje o
Veryon nao consegue responder "quem fez isso".

O terceiro buraco do diagnostico: todo login pode tudo. Quem entra para triar
alerta tambem pode bloquear IP, ligar politica de prevencao e mexer em
retencao. Enquanto o unico usuario e o dono do projeto isso nao incomoda, mas
e exatamente o que impede entregar acesso a um cliente.

Dois papeis, e so dois:

  analyst   le tudo e tria: alerta, vulnerabilidade e achado de API.
  admin     tudo isso, mais o que muda o comportamento do sistema ou apaga
            dado: bloqueio de IP, politica de prevencao, canal de
            notificacao, retencao e gestao de usuario.

Usuario que ja existe vira admin. O contrario trancaria o dono para fora do
proprio sistema no instante em que a migration rodasse.

is_active existe no lugar de apagar usuario. Apagar quebraria o rastro: os
campos de auditoria espalhados pelo banco (`blocked_by`, `updated_by`,
`requested_by`, `unblocked_by`) guardam o nome de quem fez, e um nome sem dono
e pior que um usuario desligado.

## O registro de triagem

O segundo problema apareceu na pratica em 09/09/2026, ao triar os 12 alertas
do laboratorio. Dava para mover o alerta entre aberto, reconhecido e fechado,
e nada mais. Fechar apagava o **porque**, que e justamente o que o proximo
analista precisa saber.

Tres colunas em alerts, e elas so fazem sentido juntas: o texto, quem
escreveu e quando. Ficam nulas nos alertas fechados antes desta migration, e
essa lacuna e honesta: ninguem registrou nada porque nao havia onde.

A regra de "nota obrigatoria ao fechar" mora na API, e nao num CHECK, porque o
motor de deteccao e o de prevencao tambem escrevem em alerts sem passar por
ela.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0015"
down_revision: Union[str, None] = "0014"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # server_default 'analyst' vale para quem for criado daqui pra frente. O
    # UPDATE logo abaixo cuida de quem ja existia.
    op.add_column(
        "users",
        sa.Column("role", sa.String(16), nullable=False, server_default="analyst"),
    )
    op.create_check_constraint(
        "ck_users_role", "users", "role IN ('admin', 'analyst')"
    )
    op.add_column(
        "users",
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.true()),
    )

    # Quem ja estava no banco entrou quando papel nao existia, ou seja, com
    # poder total. Rebaixar em silencio deixaria o sistema sem nenhum admin.
    op.execute("UPDATE users SET role = 'admin'")

    op.add_column("alerts", sa.Column("triage_note", sa.Text))
    op.add_column("alerts", sa.Column("triaged_by", sa.String(80)))
    op.add_column(
        "alerts", sa.Column("triaged_at", sa.DateTime(timezone=True))
    )


def downgrade() -> None:
    op.drop_column("alerts", "triaged_at")
    op.drop_column("alerts", "triaged_by")
    op.drop_column("alerts", "triage_note")
    op.drop_column("users", "is_active")
    op.drop_constraint("ck_users_role", "users", type_="check")
    op.drop_column("users", "role")
