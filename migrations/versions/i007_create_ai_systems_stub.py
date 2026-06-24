"""
INTEGRATION SEAM 5
At standalone: this table stores governance
artifacts created by Shadow AI Discovery.
At integration: this table is CompliVibe's
existing ai_systems table. The migration adds
source, source_detection_id, inferred_use_case,
regulatory_flags columns to the existing table.
The source_detection_id -> shadow_ai_detections FK
is a patent invariant and must be preserved.

Revision ID: i007
Revises: i006
Create Date: 2025-01-01 00:00:06
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "i007"
down_revision: Union[str, None] = "i006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = inspector.get_table_names()

    if "ai_systems" not in existing_tables:
        op.create_table(
            "ai_systems",
            sa.Column(
                "id",
                postgresql.UUID(as_uuid=True),
                primary_key=True,
                server_default=sa.text("gen_random_uuid()"),
            ),
            sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column("name", sa.String(255), nullable=False),
            sa.Column("vendor", sa.String(255), nullable=False),
            sa.Column("category", sa.String(50), nullable=False),
            sa.Column("system_type", sa.String(50), nullable=False),
            sa.Column(
                "deployment_status",
                sa.String(30),
                nullable=False,
                server_default=sa.text("'unknown'"),
            ),
            sa.Column("risk_level", sa.String(20), nullable=True),
            sa.Column(
                "source",
                sa.String(50),
                nullable=False,
                server_default=sa.text("'shadow_ai_discovery'"),
            ),
            sa.Column("source_detection_id", postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column("inferred_use_case", sa.String(255), nullable=True),
            sa.Column("regulatory_flags", sa.Text, nullable=True),
            sa.Column("owner_id", postgresql.UUID(as_uuid=True), nullable=True),
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
            sa.CheckConstraint(
                "system_type IN ('model', 'use_case', 'agent', 'application', 'data_pipeline')",
                name="ck_ai_systems_system_type",
            ),
            sa.CheckConstraint(
                "deployment_status IN ('unknown', 'development', 'staging', 'production', 'decommissioned')",
                name="ck_ai_systems_deployment_status",
            ),
        )

    if "ai_systems" in inspector.get_table_names():
        existing_indexes = {
            idx["name"] for idx in inspector.get_indexes("ai_systems")
        }
        if "ix_ai_systems_org" not in existing_indexes:
            op.create_index("ix_ai_systems_org", "ai_systems", ["organization_id"])
        if "ix_ai_systems_source_detection" not in existing_indexes:
            op.create_index(
                "ix_ai_systems_source_detection",
                "ai_systems",
                ["source_detection_id"],
                unique=True,
            )
        if "ix_ai_systems_org_name" not in existing_indexes:
            op.create_index(
                "ix_ai_systems_org_name",
                "ai_systems",
                ["organization_id", "name"],
            )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "ai_systems" in inspector.get_table_names():
        op.drop_table("ai_systems")
