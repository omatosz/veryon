"""create blocked_ips table

Revision ID: 0005
Revises: 0004
Create Date: 2026-08-26

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: Union[str, None] = "0004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "blocked_ips",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("ip", sa.String(), nullable=False),
        sa.Column("alert_id", sa.BigInteger(), nullable=True),
        sa.Column("reason", sa.String(), nullable=True),
        sa.Column("blocked_by", sa.String(), nullable=False),
        sa.Column("blocked_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("unblocked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("unblocked_by", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_blocked_ips_ip", "blocked_ips", ["ip"])


def downgrade() -> None:
    op.drop_index("ix_blocked_ips_ip", table_name="blocked_ips")
    op.drop_table("blocked_ips")
