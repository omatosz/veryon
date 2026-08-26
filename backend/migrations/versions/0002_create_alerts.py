"""create alerts hypertable

Revision ID: 0002
Revises: 0001
Create Date: 2026-08-25

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "alerts",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("rule_id", sa.String(), nullable=False),
        sa.Column("title", sa.String(), nullable=False),
        sa.Column("level", sa.String(), nullable=False),
        sa.Column("mitre_technique", sa.String(), nullable=True),
        sa.Column("source_event_id", sa.BigInteger(), nullable=True),
        sa.Column("source_event_type", sa.String(), nullable=True),
        sa.Column("source_host", sa.String(), nullable=True),
        sa.Column("source_ip", sa.String(), nullable=True),
        sa.Column("description", sa.String(), nullable=True),
        sa.Column("status", sa.String(), nullable=False, server_default="open"),
        sa.Column("payload", JSONB(), nullable=False),
        sa.PrimaryKeyConstraint("id", "ts"),
    )
    op.execute("SELECT create_hypertable('alerts', 'ts')")
    op.create_index("ix_alerts_rule_id", "alerts", ["rule_id"])
    op.create_index("ix_alerts_level", "alerts", ["level"])
    op.create_index("ix_alerts_source_ip", "alerts", ["source_ip"])

    # Checkpoint do motor de deteccao: ate onde em raw_events.id ja foi
    # avaliado. Guardado no Postgres (nao em arquivo local) para sobreviver
    # a rebuilds/restarts do container do motor.
    op.create_table(
        "detection_checkpoint",
        sa.Column("id", sa.SmallInteger(), primary_key=True, server_default="1"),
        sa.Column("last_event_id", sa.BigInteger(), nullable=False, server_default="0"),
    )
    op.execute("INSERT INTO detection_checkpoint (id, last_event_id) VALUES (1, 0)")


def downgrade() -> None:
    op.drop_table("detection_checkpoint")
    op.drop_table("alerts")
