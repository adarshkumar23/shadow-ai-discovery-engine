"""Add dark AI side channel classification fields.

Phase 10 — Dependent Patent Claim 10: Dark AI Detection via Side Channels.

Adds flow-level metadata columns to shadow_ai_detections to distinguish
and score detections that are identified from timing and side channel
patterns rather than hostname signature matches.

Optional connector flow metric fields are added to the
ConnectorSignalPayload schema but stored in raw_signal_json on
telemetry_events; no new telemetry table columns are required.

Revision ID: i016
Revises: i014
Create Date: 2026-06-24 00:00:00
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "i016"
down_revision: Union[str, None] = "i014"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_columns = {c["name"] for c in inspector.get_columns("shadow_ai_detections")}
    existing_indexes = {idx["name"] for idx in inspector.get_indexes("shadow_ai_detections")}

    # ── Detection method marker ─────────────────
    # Required by Patent Invariant 38: dark AI detections are marked
    # detection_method = "dark_ai_side_channel".
    if "detection_method" not in existing_columns:
        op.add_column(
            "shadow_ai_detections",
            sa.Column(
                "detection_method",
                sa.String(50),
                nullable=True,
            ),
        )

    # ── Dark AI classification flag ─────────────
    if "is_dark_ai" not in existing_columns:
        op.add_column(
            "shadow_ai_detections",
            sa.Column(
                "is_dark_ai",
                sa.Boolean,
                nullable=False,
                server_default=sa.text("false"),
            ),
        )

    # ── Dark AI feature vector (patent evidence) ─
    if "dark_ai_features_json" not in existing_columns:
        op.add_column(
            "shadow_ai_detections",
            sa.Column(
                "dark_ai_features_json",
                sa.Text,
                nullable=True,
            ),
        )

    # ── Dark AI composite score ─────────────────
    if "dark_ai_score" not in existing_columns:
        op.add_column(
            "shadow_ai_detections",
            sa.Column(
                "dark_ai_score",
                sa.Numeric(5, 4),
                nullable=True,
            ),
        )

    # ── Proxy inference flag ────────────────────
    if "dark_ai_proxy_detected" not in existing_columns:
        op.add_column(
            "shadow_ai_detections",
            sa.Column(
                "dark_ai_proxy_detected",
                sa.Boolean,
                nullable=True,
            ),
        )

    # ── Partial index for dark AI detections ────
    if "ix_detection_dark_ai" not in existing_indexes:
        op.create_index(
            "ix_detection_dark_ai",
            "shadow_ai_detections",
            ["organization_id", "is_dark_ai"],
            postgresql_where=sa.text("is_dark_ai = TRUE"),
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_indexes = {idx["name"] for idx in inspector.get_indexes("shadow_ai_detections")}

    if "ix_detection_dark_ai" in existing_indexes:
        op.drop_index("ix_detection_dark_ai", table_name="shadow_ai_detections")

    for column_name in (
        "dark_ai_proxy_detected",
        "dark_ai_score",
        "dark_ai_features_json",
        "is_dark_ai",
        "detection_method",
    ):
        try:
            op.drop_column("shadow_ai_detections", column_name)
        except Exception:
            pass
