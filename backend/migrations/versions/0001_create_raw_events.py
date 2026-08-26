"""create raw_events hypertable

Revision ID: 0001
Revises:
Create Date: 2026-08-24

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "raw_events",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source", sa.String(), nullable=False),
        sa.Column("host", sa.String(), nullable=True),
        sa.Column("event_type", sa.String(), nullable=False),
        sa.Column("src_ip", sa.String(), nullable=True),
        sa.Column("payload", JSONB(), nullable=False),
        sa.PrimaryKeyConstraint("id", "ts"),
    )
    op.execute("SELECT create_hypertable('raw_events', 'ts')")
    op.create_index("ix_raw_events_event_type", "raw_events", ["event_type"])
    op.create_index("ix_raw_events_src_ip", "raw_events", ["src_ip"])


def downgrade() -> None:
    op.drop_table("raw_events")
