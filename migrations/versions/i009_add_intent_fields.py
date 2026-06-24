"""Add intent classification fields to shadow_ai_detections.

Implements Dependent Patent Claim 7:
Intent Classification from Linguistic Context.

Adds six columns for deterministic intent classification:
  intent_action           - e.g. "evaluating", "processing", "drafting"
  intent_data_subject     - e.g. "candidates", "customers", "employees"
  intent_business_context - e.g. "hr", "legal", "finance"
  inferred_use_case       - Human-readable use case description
  use_case_risk_json      - JSON object with regulatory risk assessment
  intent_classified_at    - Timestamp when intent classification ran

Revision ID: i009
Revises: i008
Create Date: 2025-01-01 00:00:08
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "i009"
down_revision: Union[str, None] = "i008"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    existing_columns = {
        col["name"] for col in inspector.get_columns("shadow_ai_detections")
    }
    existing_indexes = {
        idx["name"] for idx in inspector.get_indexes("shadow_ai_detections")
    }

    if "intent_action" not in existing_columns:
        op.add_column(
            "shadow_ai_detections",
            sa.Column("intent_action", sa.String(100), nullable=True),
        )

    if "intent_data_subject" not in existing_columns:
        op.add_column(
            "shadow_ai_detections",
            sa.Column("intent_data_subject", sa.String(100), nullable=True),
        )

    if "intent_business_context" not in existing_columns:
        op.add_column(
            "shadow_ai_detections",
            sa.Column("intent_business_context", sa.String(100), nullable=True),
        )

    if "inferred_use_case" not in existing_columns:
        op.add_column(
            "shadow_ai_detections",
            sa.Column("inferred_use_case", sa.String(255), nullable=True),
        )

    if "use_case_risk_json" not in existing_columns:
        op.add_column(
            "shadow_ai_detections",
            sa.Column("use_case_risk_json", sa.Text, nullable=True),
        )

    if "intent_classified_at" not in existing_columns:
        op.add_column(
            "shadow_ai_detections",
            sa.Column("intent_classified_at", sa.DateTime(timezone=True), nullable=True),
        )

    if "ix_detection_intent_context" not in existing_indexes:
        op.create_index(
            "ix_detection_intent_context",
            "shadow_ai_detections",
            ["organization_id", "intent_business_context"],
            postgresql_where=sa.text("intent_business_context IS NOT NULL"),
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    existing_indexes = {
        idx["name"] for idx in inspector.get_indexes("shadow_ai_detections")
    }
    existing_columns = {
        col["name"] for col in inspector.get_columns("shadow_ai_detections")
    }

    if "ix_detection_intent_context" in existing_indexes:
        op.drop_index("ix_detection_intent_context", table_name="shadow_ai_detections")

    for col in (
        "intent_classified_at",
        "use_case_risk_json",
        "inferred_use_case",
        "intent_business_context",
        "intent_data_subject",
        "intent_action",
    ):
        if col in existing_columns:
            op.drop_column("shadow_ai_detections", col)
