"""Create suppressed_detections table.

Stores suppression records created when a detection is dismissed.
Prevents re-detection of dismissed tools via the same method.
Once dismissed, that tool + method combination is suppressed for
that org permanently unless explicitly lifted.

Revision ID: i008
Revises: i007
Create Date: 2025-01-01 00:00:07
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "i008"
down_revision: Union[str, None] = "i007"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = inspector.get_table_names()

    if "suppressed_detections" not in existing_tables:
        op.create_table(
            "suppressed_detections",
            sa.Column(
                "id",
                postgresql.UUID(as_uuid=True),
                primary_key=True,
                server_default=sa.text("gen_random_uuid()"),
            ),
            sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column("tool_slug", sa.String(100), nullable=False),
            sa.Column("detection_method", sa.String(50), nullable=False),
            sa.Column("suppressed_by", postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column("reason", sa.Text, nullable=False),
            sa.Column("source_detection_id", postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("now()"),
            ),
            sa.Column("lifted_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("lifted_by", postgresql.UUID(as_uuid=True), nullable=True),
            sa.CheckConstraint(
                "detection_method IN ('questionnaire', 'network_scan', 'idp_log', "
                "'manual_report', 'integration_analysis', 'behavioral_inference')",
                name="ck_suppression_detection_method",
            ),
        )

    if "suppressed_detections" in inspector.get_table_names():
        existing_indexes = {
            idx["name"] for idx in inspector.get_indexes("suppressed_detections")
        }

        if "ix_suppression_org" not in existing_indexes:
            op.create_index(
                "ix_suppression_org",
                "suppressed_detections",
                ["organization_id"],
            )
        if "ix_suppression_org_slug" not in existing_indexes:
            op.create_index(
                "ix_suppression_org_slug",
                "suppressed_detections",
                ["organization_id", "tool_slug"],
            )
        if "uq_suppression_org_slug_method_active" not in existing_indexes:
            op.create_index(
                "uq_suppression_org_slug_method_active",
                "suppressed_detections",
                ["organization_id", "tool_slug", "detection_method"],
                unique=True,
                postgresql_where=sa.text("lifted_at IS NULL"),
            )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "suppressed_detections" in inspector.get_table_names():
        op.drop_table("suppressed_detections")
