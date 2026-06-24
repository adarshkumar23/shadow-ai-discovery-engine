"""Create telemetry_events table.

Stores raw telemetry signals across three tiers:
  Tier 1 — text mentions from questionnaires
  Tier 2 — IdP OAuth grant/revoke events
  Tier 3 — network/API signals from connectors

Revision ID: i002
Revises: i001
Create Date: 2025-01-01 00:00:01
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "i002"
down_revision: Union[str, None] = "i001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = inspector.get_table_names()

    if "telemetry_events" not in existing_tables:
        op.create_table(
            "telemetry_events",
            sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
            sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column("tier", sa.SmallInteger, nullable=False),
            sa.Column("event_type", sa.String(50), nullable=False),
            sa.Column("source_system_label", sa.String(255), nullable=True),
            sa.Column(
                "matched_signature_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey(
                    "ai_signature_registry.id",
                    ondelete="SET NULL",
                ),
                nullable=True,
            ),
            sa.Column("raw_signal_json", sa.Text, nullable=False),
            sa.Column("signal_hash", sa.String(64), nullable=False),
            sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column(
                "ingested_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("now()"),
            ),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("now()"),
            ),
            sa.CheckConstraint("tier IN (1, 2, 3)", name="ck_telemetry_tier"),
            sa.UniqueConstraint(
                "organization_id", "signal_hash", name="uq_telemetry_org_signal_hash"
            ),
        )

        existing_indexes = {idx["name"] for idx in inspector.get_indexes("telemetry_events")}
        if "ix_telemetry_org_id" not in existing_indexes:
            op.create_index("ix_telemetry_org_id", "telemetry_events", ["organization_id"])
        if "ix_telemetry_org_tier" not in existing_indexes:
            op.create_index(
                "ix_telemetry_org_tier", "telemetry_events", ["organization_id", "tier"]
            )
        if "ix_telemetry_org_sig" not in existing_indexes:
            op.create_index(
                "ix_telemetry_org_sig",
                "telemetry_events",
                ["organization_id", "matched_signature_id"],
            )
        if "ix_telemetry_observed" not in existing_indexes:
            op.create_index("ix_telemetry_observed", "telemetry_events", ["observed_at"])


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "telemetry_events" in inspector.get_table_names():
        op.drop_table("telemetry_events")
