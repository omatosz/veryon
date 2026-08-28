"""vulnerabilidades rastreadas e fila de varredura

Revision ID: 0007
Revises: 0006
Create Date: 2026-08-27

Ate aqui, achado de scan so existia como raw_event: uma foto solta do momento
da varredura, sem estado e sem historico. Estas duas tabelas transformam isso
em vulnerabilidade rastreada, com ciclo de vida e deduplicacao.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0007"
down_revision: Union[str, None] = "0006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "vulnerabilities",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        # Ativo afetado: rotulo do alvo, o mesmo que aparece em raw_events.host.
        sa.Column("asset", sa.String(), nullable=False),
        sa.Column("asset_type", sa.String(), nullable=False),
        # Assinatura estavel do achado. Junto com o ativo, e o que identifica a
        # mesma vulnerabilidade entre uma varredura e outra. Sem isso, cada
        # scan geraria a lista inteira de novo.
        sa.Column("signature", sa.String(), nullable=False),
        sa.Column("title", sa.String(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(), nullable=False),
        sa.Column("cvss", sa.Numeric(3, 1), nullable=True),
        sa.Column("cve", sa.String(), nullable=True),
        sa.Column("port", sa.Integer(), nullable=True),
        sa.Column("service", sa.String(), nullable=True),
        sa.Column("evidence", JSONB(), nullable=False),
        sa.Column("source", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False, server_default="open"),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_by", sa.String(), nullable=True),
        # Risco aceito sem justificativa e prazo de revisao vira desculpa pra
        # nunca corrigir, entao a API exige os dois nesse estado.
        sa.Column("justification", sa.Text(), nullable=True),
        sa.Column("review_at", sa.DateTime(timezone=True), nullable=True),
        # Quantas vezes voltou depois de marcada como corrigida. Numero alto
        # aqui quer dizer que estao fechando chamado sem consertar.
        sa.Column("reopened_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("source_event_id", sa.BigInteger(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("asset", "signature", name="uq_vulnerabilities_asset_signature"),
    )
    op.create_index("ix_vulnerabilities_status", "vulnerabilities", ["status"])
    op.create_index("ix_vulnerabilities_severity", "vulnerabilities", ["severity"])
    op.create_index("ix_vulnerabilities_last_seen", "vulnerabilities", ["last_seen"])

    op.create_table(
        "scan_jobs",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("status", sa.String(), nullable=False, server_default="queued"),
        sa.Column("requested_by", sa.String(), nullable=False),
        # NULL usa os alvos configurados no compose.
        sa.Column("targets", JSONB(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        # {found, novos, reabertos, sumiram}
        sa.Column("stats", JSONB(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_scan_jobs_status", "scan_jobs", ["status"])

    # Checkpoint proprio do normalizador, no mesmo formato do que o motor de
    # deteccao ja usa. Assim ele so le raw_event novo, em vez de varrer a
    # tabela inteira a cada ciclo.
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS vuln_checkpoint (
            id INT PRIMARY KEY,
            last_event_id BIGINT NOT NULL DEFAULT 0
        )
        """
    )
    op.execute("INSERT INTO vuln_checkpoint (id, last_event_id) VALUES (1, 0) ON CONFLICT DO NOTHING")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS vuln_checkpoint")
    op.drop_index("ix_scan_jobs_status", table_name="scan_jobs")
    op.drop_table("scan_jobs")
    op.drop_index("ix_vulnerabilities_last_seen", table_name="vulnerabilities")
    op.drop_index("ix_vulnerabilities_severity", table_name="vulnerabilities")
    op.drop_index("ix_vulnerabilities_status", table_name="vulnerabilities")
    op.drop_table("vulnerabilities")
