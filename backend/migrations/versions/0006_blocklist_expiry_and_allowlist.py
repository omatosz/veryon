"""blocklist com prazo, origem e allowlist

Revision ID: 0006
Revises: 0005
Create Date: 2026-08-27

Tres colunas novas em blocked_ips e a tabela de allowlist. Junto, essas duas
coisas sao o que permite bloqueio automatico sem risco: o bloqueio expira
sozinho e existe uma lista de quem nunca pode ser bloqueado.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: Union[str, None] = "0005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # NULL em expires_at significa "ate alguem desbloquear na mao".
    op.add_column("blocked_ips", sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True))
    # 'manual' ou 'policy'. Serve pra separar o que o humano fez do que a
    # automacao fez, tanto na tela quanto no relatorio.
    op.add_column(
        "blocked_ips",
        sa.Column("source", sa.String(), nullable=False, server_default="manual"),
    )
    op.add_column("blocked_ips", sa.Column("policy_id", sa.BigInteger(), nullable=True))

    # O poller consulta exatamente por esse par a cada 5 segundos.
    op.create_index(
        "ix_blocked_ips_active",
        "blocked_ips",
        ["unblocked_at", "expires_at"],
    )

    op.create_table(
        "ip_allowlist",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("cidr", sa.String(), nullable=False),
        sa.Column("reason", sa.String(), nullable=True),
        sa.Column("added_by", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("cidr", name="uq_ip_allowlist_cidr"),
    )


def downgrade() -> None:
    op.drop_table("ip_allowlist")
    op.drop_index("ix_blocked_ips_active", table_name="blocked_ips")
    op.drop_column("blocked_ips", "policy_id")
    op.drop_column("blocked_ips", "source")
    op.drop_column("blocked_ips", "expires_at")
