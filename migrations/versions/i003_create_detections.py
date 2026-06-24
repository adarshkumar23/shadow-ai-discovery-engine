"""Create shadow_ai_detections table.

Stores detected undeclared AI systems. Each detection is created
when telemetry signals match a signature above the confidence
threshold. Detections flow through a lifecycle:
  new → reviewed → dismissed | escalated → registered

Revision ID: i003
Revises: i002
Create Date: 2025-01-01 00:00:02
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "i003"
down_revision: Union[str, None] = "i002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = inspector.get_table_names()

    if "shadow_ai_detections" not in existing_tables:
        op.create_table(
            "shadow_ai_detections",
            sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
            sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column(
                "signature_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey(
                    "ai_signature_registry.id",
                    ondelete="SET NULL",
                ),
                nullable=True,
            ),
            sa.Column("provider_name", sa.String(255), nullable=False),
            sa.Column("confidence_score", sa.Numeric(5, 4), nullable=False),
            sa.Column("confidence_band", sa.String(10), nullable=False),
            sa.Column("detection_basis_json", sa.Text, nullable=False),
            sa.Column("attributed_owner_id", postgresql.UUID(as_uuid=True), nullable=True),
            sa.Column("attribution_confidence", sa.Numeric(4, 3), nullable=True),
            sa.Column("status", sa.String(20), nullable=False, server_default=sa.text("'new'")),
            sa.Column("first_detected_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_observed_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("reviewed_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
            sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("dismissed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("dismissed_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
            sa.Column("dismissal_reason", sa.Text, nullable=True),
            sa.Column("escalated_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("escalated_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
            sa.Column("escalation_notes", sa.Text, nullable=True),
            sa.Column("registered_ai_system_id", postgresql.UUID(as_uuid=True), nullable=True),
            sa.Column("suppressed", sa.Boolean, nullable=False, server_default=sa.text("false")),
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
        )

        existing_indexes = {idx["name"] for idx in inspector.get_indexes("shadow_ai_detections")}
        if "uq_detection_org_sig_active" not in existing_indexes:
            op.create_index(
                "uq_detection_org_sig_active",
                "shadow_ai_detections",
                ["organization_id", "signature_id"],
                unique=True,
                postgresql_where=sa.text(
                    "status NOT IN ('dismissed', 'registered') "
                    "AND deleted_at IS NULL"
                ),
            )
        if "ix_detection_org_status" not in existing_indexes:
            op.create_index(
                "ix_detection_org_status",
                "shadow_ai_detections",
                ["organization_id", "status"],
            )
        if "ix_detection_org_sig" not in existing_indexes:
            op.create_index(
                "ix_detection_org_sig",
                "shadow_ai_detections",
                ["organization_id", "signature_id"],
            )
        if "ix_detection_org_confidence" not in existing_indexes:
            op.create_index(
                "ix_detection_org_confidence",
                "shadow_ai_detections",
                ["organization_id", "confidence_band"],
            )
        if "ix_detection_last_observed" not in existing_indexes:
            op.create_index(
                "ix_detection_last_observed",
                "shadow_ai_detections",
                ["last_observed_at"],
            )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "shadow_ai_detections" in inspector.get_table_names():
        op.drop_table("shadow_ai_detections")
