"""Add zero-day behavioral classification fields and zero_day_candidates table.

Phase 6 — Dependent Patent Claim 4: Zero-Day AI Detection via
Behavioral Classification.

Adds to shadow_ai_detections:
  is_zero_day              BOOLEAN NOT NULL DEFAULT FALSE
    True when detection came from behavioral classifier, not registry match.
  zero_day_hostname        VARCHAR(500) nullable
    The unknown hostname that triggered the zero-day classifier.
  behavioral_features_json TEXT nullable
    JSON object storing the computed behavioral features that triggered
    classification. Schema:
      {
        "call_frequency_score": float [0.0, 1.0],
        "payload_asymmetry_score": float [0.0, 1.0],
        "endpoint_pattern_score": float [0.0, 1.0],
        "service_type_probability": float [0.0, 1.0],
        "recency_score": float [0.0, 1.0],
        "composite_score": float [0.0, 1.0],
        "classifier_version": "1.0.0"
      }
  classifier_version       VARCHAR(20) nullable
    Version of the zero-day classifier that produced this detection.

Creates zero_day_candidates table for tracking unknown hostnames observed
across signals, pending human review for potential registry addition.

Also creates ix_detection_zero_day partial index for fast zero-day lookups.

Revision ID: i012
Revises: i011
Create Date: 2026-06-24 00:00:00
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "i012"
down_revision: Union[str, None] = "i011"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = inspector.get_table_names()

    # ── Add columns to shadow_ai_detections ──────
    if "shadow_ai_detections" in existing_tables:
        existing_columns = {
            col["name"] for col in inspector.get_columns("shadow_ai_detections")
        }
        existing_indexes = {
            idx["name"] for idx in inspector.get_indexes("shadow_ai_detections")
        }

        if "is_zero_day" not in existing_columns:
            op.add_column(
                "shadow_ai_detections",
                sa.Column(
                    "is_zero_day",
                    sa.Boolean,
                    nullable=False,
                    server_default=sa.text("false"),
                ),
            )
        if "zero_day_hostname" not in existing_columns:
            op.add_column(
                "shadow_ai_detections",
                sa.Column("zero_day_hostname", sa.String(500), nullable=True),
            )
        if "behavioral_features_json" not in existing_columns:
            op.add_column(
                "shadow_ai_detections",
                sa.Column("behavioral_features_json", sa.Text, nullable=True),
            )
        if "classifier_version" not in existing_columns:
            op.add_column(
                "shadow_ai_detections",
                sa.Column("classifier_version", sa.String(20), nullable=True),
            )

        if "ix_detection_zero_day" not in existing_indexes:
            op.create_index(
                "ix_detection_zero_day",
                "shadow_ai_detections",
                ["organization_id", "is_zero_day"],
                postgresql_where=sa.text("is_zero_day = TRUE"),
            )

    # ── Create zero_day_candidates table ─────────
    if "zero_day_candidates" not in existing_tables:
        op.create_table(
            "zero_day_candidates",
            sa.Column(
                "id",
                postgresql.UUID(as_uuid=True),
                primary_key=True,
                server_default=sa.text("gen_random_uuid()"),
            ),
            sa.Column(
                "organization_id", postgresql.UUID(as_uuid=True), nullable=False
            ),
            sa.Column("hostname", sa.String(500), nullable=False),
            sa.Column(
                "first_observed_at",
                sa.DateTime(timezone=True),
                nullable=False,
            ),
            sa.Column(
                "last_observed_at",
                sa.DateTime(timezone=True),
                nullable=False,
            ),
            sa.Column(
                "observation_count",
                sa.Integer,
                nullable=False,
                server_default=sa.text("1"),
            ),
            sa.Column("signal_ids", sa.Text, nullable=True),
            sa.Column("behavioral_score", sa.Numeric(5, 4), nullable=False),
            sa.Column("feature_summary", sa.Text, nullable=True),
            sa.Column(
                "status",
                sa.String(30),
                nullable=False,
                server_default=sa.text("'pending_review'"),
            ),
            sa.Column("reviewed_by", postgresql.UUID(as_uuid=True), nullable=True),
            sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("review_notes", sa.Text, nullable=True),
            sa.Column(
                "detection_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("shadow_ai_detections.id", ondelete="SET NULL"),
                nullable=True,
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
            sa.CheckConstraint(
                "status IN ('pending_review', 'added_to_registry', "
                "'dismissed', 'monitoring')",
                name="ck_zero_day_candidate_status",
            ),
        )

    if "zero_day_candidates" in inspector.get_table_names():
        existing_zd_indexes = {
            idx["name"] for idx in inspector.get_indexes("zero_day_candidates")
        }
        if "uq_zero_day_candidate_org_hostname" not in existing_zd_indexes:
            op.create_index(
                "uq_zero_day_candidate_org_hostname",
                "zero_day_candidates",
                ["organization_id", "hostname"],
                unique=True,
                postgresql_where=sa.text(
                    "status NOT IN ('added_to_registry', 'dismissed')"
                ),
            )
        if "ix_zero_day_candidate_org" not in existing_zd_indexes:
            op.create_index(
                "ix_zero_day_candidate_org",
                "zero_day_candidates",
                ["organization_id"],
            )
        if "ix_zero_day_candidate_score" not in existing_zd_indexes:
            op.create_index(
                "ix_zero_day_candidate_score",
                "zero_day_candidates",
                ["behavioral_score"],
                postgresql_where=sa.text("status = 'pending_review'"),
            )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = inspector.get_table_names()

    if "zero_day_candidates" in existing_tables:
        existing_indexes = {
            idx["name"] for idx in inspector.get_indexes("zero_day_candidates")
        }
        for idx_name in (
            "ix_zero_day_candidate_score",
            "ix_zero_day_candidate_org",
            "uq_zero_day_candidate_org_hostname",
        ):
            if idx_name in existing_indexes:
                op.drop_index(idx_name, table_name="zero_day_candidates")
        op.drop_table("zero_day_candidates")

    if "shadow_ai_detections" in existing_tables:
        existing_indexes = {
            idx["name"] for idx in inspector.get_indexes("shadow_ai_detections")
        }
        if "ix_detection_zero_day" in existing_indexes:
            op.drop_index("ix_detection_zero_day", table_name="shadow_ai_detections")

        existing_columns = {
            col["name"] for col in inspector.get_columns("shadow_ai_detections")
        }
        for col in (
            "classifier_version",
            "behavioral_features_json",
            "zero_day_hostname",
            "is_zero_day",
        ):
            if col in existing_columns:
                op.drop_column("shadow_ai_detections", col)
