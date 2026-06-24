"""Add regulatory jurisdiction graph fields and tables.

Phase 7 — Dependent Patent Claim 9: Regulatory Jurisdiction Graph Traversal.

Adds to shadow_ai_detections:
  jurisdiction_assessment_json  TEXT nullable
    Complete output of the regulatory graph traversal engine, including
    applicable regulations, articles, missing governance actions, and
    assessment basis.
  applicable_regulations_count  INTEGER nullable
    Denormalized count of applicable regulation IDs for dashboard display.
  jurisdiction_assessed_at      TIMESTAMPTZ nullable
    Timestamp of last jurisdiction assessment.
  highest_regulatory_risk       VARCHAR(20) nullable
    Highest risk level across all applicable regulations
    (low, medium, high, critical).
  jurisdiction_graph_version    VARCHAR(20) nullable
    Version of the regulatory graph used to produce this assessment.

Creates regulation_nodes table:
  Graph node store for regulation definitions.

Creates regulation_articles table:
  Graph node store for individual articles/sections within regulations.

Creates supporting indexes for fast lookups by jurisdiction, regulation
_type, and regulation_id.

Revision ID: i013
Revises: i012
Create Date: 2026-06-24 00:00:00
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "i013"
down_revision: Union[str, None] = "i012"
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

        if "jurisdiction_assessment_json" not in existing_columns:
            op.add_column(
                "shadow_ai_detections",
                sa.Column(
                    "jurisdiction_assessment_json",
                    sa.Text,
                    nullable=True,
                ),
            )
        if "applicable_regulations_count" not in existing_columns:
            op.add_column(
                "shadow_ai_detections",
                sa.Column(
                    "applicable_regulations_count",
                    sa.Integer,
                    nullable=True,
                ),
            )
        if "jurisdiction_assessed_at" not in existing_columns:
            op.add_column(
                "shadow_ai_detections",
                sa.Column(
                    "jurisdiction_assessed_at",
                    sa.DateTime(timezone=True),
                    nullable=True,
                ),
            )
        if "highest_regulatory_risk" not in existing_columns:
            op.add_column(
                "shadow_ai_detections",
                sa.Column(
                    "highest_regulatory_risk",
                    sa.String(20),
                    nullable=True,
                ),
            )
        if "jurisdiction_graph_version" not in existing_columns:
            op.add_column(
                "shadow_ai_detections",
                sa.Column(
                    "jurisdiction_graph_version",
                    sa.String(20),
                    nullable=True,
                ),
            )

    # ── Create regulation_nodes table ────────────
    if "regulation_nodes" not in existing_tables:
        op.create_table(
            "regulation_nodes",
            sa.Column("id", sa.String(50), primary_key=True),
            sa.Column("short_name", sa.String(100), nullable=False),
            sa.Column("full_name", sa.String(500), nullable=False),
            sa.Column("jurisdiction", sa.String(100), nullable=False),
            sa.Column("effective_date", sa.Date, nullable=True),
            sa.Column(
                "regulation_type",
                sa.String(50),
                nullable=False,
            ),
            sa.Column("risk_categories", sa.Text, nullable=False),
            sa.Column("base_url", sa.String(500), nullable=True),
            sa.Column(
                "is_active",
                sa.Boolean,
                nullable=False,
                server_default=sa.text("true"),
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
        )
        op.create_index(
            "ix_regulation_jurisdiction", "regulation_nodes", ["jurisdiction"]
        )
        op.create_index(
            "ix_regulation_type", "regulation_nodes", ["regulation_type"]
        )

    # ── Create regulation_articles table ─────────
    if "regulation_articles" not in existing_tables:
        op.create_table(
            "regulation_articles",
            sa.Column("id", sa.String(100), primary_key=True),
            sa.Column(
                "regulation_id",
                sa.String(50),
                sa.ForeignKey("regulation_nodes.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("article_number", sa.String(50), nullable=False),
            sa.Column("article_title", sa.String(500), nullable=False),
            sa.Column("obligation_type", sa.String(50), nullable=False),
            sa.Column("applies_to_risk", sa.Text, nullable=False),
            sa.Column("trigger_conditions", sa.Text, nullable=False),
            sa.Column("plain_english", sa.Text, nullable=False),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("now()"),
            ),
        )
        op.create_index(
            "ix_article_regulation", "regulation_articles", ["regulation_id"]
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = inspector.get_table_names()

    if "regulation_articles" in existing_tables:
        op.drop_index("ix_article_regulation", table_name="regulation_articles")
        op.drop_table("regulation_articles")

    if "regulation_nodes" in existing_tables:
        op.drop_index("ix_regulation_type", table_name="regulation_nodes")
        op.drop_index("ix_regulation_jurisdiction", table_name="regulation_nodes")
        op.drop_table("regulation_nodes")

    if "shadow_ai_detections" in existing_tables:
        existing_columns = {
            col["name"] for col in inspector.get_columns("shadow_ai_detections")
        }
        for col in (
            "jurisdiction_graph_version",
            "highest_regulatory_risk",
            "jurisdiction_assessed_at",
            "applicable_regulations_count",
            "jurisdiction_assessment_json",
        ):
            if col in existing_columns:
                op.drop_column("shadow_ai_detections", col)
