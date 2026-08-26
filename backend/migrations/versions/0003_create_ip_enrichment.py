"""create ip_enrichment table

Revision ID: 0003
Revises: 0002
Create Date: 2026-08-25

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "ip_enrichment",
        sa.Column("ip", sa.String(), nullable=False),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("abuseipdb_score", sa.Integer(), nullable=True),
        sa.Column("abuseipdb_country", sa.String(), nullable=True),
        sa.Column("abuseipdb_isp", sa.String(), nullable=True),
        sa.Column("abuseipdb_total_reports", sa.Integer(), nullable=True),
        sa.Column("virustotal_malicious", sa.Integer(), nullable=True),
        sa.Column("virustotal_total_engines", sa.Integer(), nullable=True),
        sa.Column("virustotal_reputation", sa.Integer(), nullable=True),
        sa.Column("otx_pulse_count", sa.Integer(), nullable=True),
        sa.Column("raw_payload", JSONB(), nullable=False),
        sa.PrimaryKeyConstraint("ip"),
    )


def downgrade() -> None:
    op.drop_table("ip_enrichment")
