"""Add vendor AI contamination index tables.

Phase 8 — Dependent Patent Claim 5: Vendor AI Contamination Index.

Creates vendor_ai_contamination table for storing computed contamination
scores per vendor per organization, and vendor_dpa_records for tracking
data processing agreements and AI coverage.

vendor_ai_contamination:
  - one active record per (organization_id, vendor_id)
  - contamination_score NUMERIC(5,4) in [0.0000, 1.0000]
  - contamination_band in (critical, high, medium, low)
  - stores three signal sub-scores: internal, external, contractual
  - stores detected AI tools and external signal metadata

vendor_dpa_records:
  - one active record per (organization_id, vendor_id)
  - tracks dpa_exists and covers_ai_processing flags

Revision ID: i014
Revises: i013
Create Date: 2026-06-24 00:00:00
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "i014"
down_revision: Union[str, None] = "i013"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = inspector.get_table_names()

    # ── Create vendor_ai_contamination ───────────
    if "vendor_ai_contamination" not in existing_tables:
        op.create_table(
            "vendor_ai_contamination",
            sa.Column(
                "id",
                postgresql.UUID(as_uuid=True),
                primary_key=True,
                server_default=sa.text("gen_random_uuid()"),
            ),
            sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column("vendor_id", postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column("vendor_name", sa.String(255), nullable=False),
            sa.Column(
                "contamination_score",
                sa.Numeric(5, 4),
                nullable=False,
            ),
            sa.Column(
                "contamination_band",
                sa.String(20),
                nullable=False,
            ),
            sa.Column(
                "internal_signal_score",
                sa.Numeric(5, 4),
                nullable=False,
            ),
            sa.Column(
                "external_signal_score",
                sa.Numeric(5, 4),
                nullable=False,
            ),
            sa.Column(
                "contractual_gap_score",
                sa.Numeric(5, 4),
                nullable=False,
            ),
            sa.Column("ai_tools_detected", sa.Text, nullable=True),
            sa.Column("external_signals", sa.Text, nullable=True),
            sa.Column(
                "dpa_exists",
                sa.Boolean,
                nullable=False,
                server_default=sa.text("false"),
            ),
            sa.Column(
                "dpa_covers_ai",
                sa.Boolean,
                nullable=False,
                server_default=sa.text("false"),
            ),
            sa.Column("dpa_notes", sa.Text, nullable=True),
            sa.Column(
                "assessed_at",
                sa.DateTime(timezone=True),
                nullable=False,
            ),
            sa.Column(
                "assessment_version",
                sa.String(20),
                nullable=False,
                server_default=sa.text("'1.0.0'"),
            ),
            sa.Column(
                "external_scan_enabled",
                sa.Boolean,
                nullable=False,
                server_default=sa.text("false"),
            ),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("now()"),
            ),
            sa.Column(
                "updated_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("now()"),
            ),
            sa.UniqueConstraint(
                "organization_id", "vendor_id", name="uq_contamination_org_vendor"
            ),
        )
        op.create_index(
            "ix_contamination_org",
            "vendor_ai_contamination",
            ["organization_id"],
        )
        op.create_index(
            "ix_contamination_score",
            "vendor_ai_contamination",
            ["organization_id", sa.text("contamination_score DESC")],
        )
        op.create_index(
            "ix_contamination_band",
            "vendor_ai_contamination",
            ["organization_id", "contamination_band"],
        )

    # ── Create vendor_dpa_records ────────────────
    if "vendor_dpa_records" not in existing_tables:
        op.create_table(
            "vendor_dpa_records",
            sa.Column(
                "id",
                postgresql.UUID(as_uuid=True),
                primary_key=True,
                server_default=sa.text("gen_random_uuid()"),
            ),
            sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column("vendor_id", postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column("vendor_name", sa.String(255), nullable=False),
            sa.Column(
                "dpa_exists",
                sa.Boolean,
                nullable=False,
                server_default=sa.text("false"),
            ),
            sa.Column(
                "covers_ai_processing",
                sa.Boolean,
                nullable=False,
                server_default=sa.text("false"),
            ),
            sa.Column("dpa_reviewed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("notes", sa.Text, nullable=True),
            sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("now()"),
            ),
            sa.Column(
                "updated_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("now()"),
            ),
            sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
            sa.UniqueConstraint(
                "organization_id",
                "vendor_id",
                name="uq_dpa_org_vendor",
            ),
        )
        op.create_index(
            "ix_dpa_org",
            "vendor_dpa_records",
            ["organization_id"],
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = inspector.get_table_names()

    if "vendor_dpa_records" in existing_tables:
        op.drop_index("ix_dpa_org", table_name="vendor_dpa_records")
        op.drop_table("vendor_dpa_records")

    if "vendor_ai_contamination" in existing_tables:
        op.drop_index("ix_contamination_band", table_name="vendor_ai_contamination")
        op.drop_index("ix_contamination_score", table_name="vendor_ai_contamination")
        op.drop_index("ix_contamination_org", table_name="vendor_ai_contamination")
        op.drop_table("vendor_ai_contamination")
