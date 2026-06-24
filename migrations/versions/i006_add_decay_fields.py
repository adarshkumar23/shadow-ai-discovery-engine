"""Add decay fields and needs_review status to shadow_ai_detections.

Adds four columns for temporal confidence decay (Dependent Claim 6):
  base_confidence_score — original score at first detection, never changes
  decay_lambda          — category-specific decay coefficient, set at creation
  decayed_at            — timestamp of last decay computation
  is_stale              — TRUE when current confidence drops below 0.40

Adds 'needs_review' to the detection status check constraint.
Adds partial index on is_stale and index on decayed_at.

Revision ID: i006
Revises: i005
Create Date: 2025-01-01 00:00:05
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "i006"
down_revision: Union[str, None] = "i005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    existing_columns = {col["name"] for col in inspector.get_columns("shadow_ai_detections")}
    existing_indexes = {idx["name"] for idx in inspector.get_indexes("shadow_ai_detections")}
    existing_constraints = {
        cst["name"] for cst in inspector.get_check_constraints("shadow_ai_detections")
    }

    if "base_confidence_score" not in existing_columns:
        op.add_column(
            "shadow_ai_detections",
            sa.Column("base_confidence_score", sa.Numeric(5, 4), nullable=True),
        )

    if "decay_lambda" not in existing_columns:
        op.add_column(
            "shadow_ai_detections",
            sa.Column("decay_lambda", sa.Numeric(6, 5), nullable=True),
        )

    if "decayed_at" not in existing_columns:
        op.add_column(
            "shadow_ai_detections",
            sa.Column("decayed_at", sa.DateTime(timezone=True), nullable=True),
        )

    if "is_stale" not in existing_columns:
        op.add_column(
            "shadow_ai_detections",
            sa.Column(
                "is_stale",
                sa.Boolean,
                nullable=False,
                server_default=sa.text("false"),
            ),
        )

    if "ck_detection_status" not in existing_constraints:
        op.create_check_constraint(
            "ck_detection_status",
            "shadow_ai_detections",
            "status IN ('new', 'reviewed', 'dismissed', 'escalated', "
            "'registered', 'needs_review')",
        )

    if "ix_detection_stale" not in existing_indexes:
        op.create_index(
            "ix_detection_stale",
            "shadow_ai_detections",
            ["is_stale"],
            postgresql_where=sa.text("is_stale = TRUE"),
        )

    if "ix_detection_decayed" not in existing_indexes:
        op.create_index(
            "ix_detection_decayed",
            "shadow_ai_detections",
            ["decayed_at"],
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    existing_indexes = {idx["name"] for idx in inspector.get_indexes("shadow_ai_detections")}
    existing_constraints = {
        cst["name"] for cst in inspector.get_check_constraints("shadow_ai_detections")
    }
    existing_columns = {col["name"] for col in inspector.get_columns("shadow_ai_detections")}

    if "ix_detection_decayed" in existing_indexes:
        op.drop_index("ix_detection_decayed", table_name="shadow_ai_detections")
    if "ix_detection_stale" in existing_indexes:
        op.drop_index("ix_detection_stale", table_name="shadow_ai_detections")
    if "ck_detection_status" in existing_constraints:
        op.drop_constraint(
            "ck_detection_status",
            "shadow_ai_detections",
            type_="check",
        )
    for col in ("is_stale", "decayed_at", "decay_lambda", "base_confidence_score"):
        if col in existing_columns:
            op.drop_column("shadow_ai_detections", col)
