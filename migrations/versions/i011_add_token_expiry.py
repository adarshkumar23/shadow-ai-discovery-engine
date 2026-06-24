"""Add token expiry, heartbeat monitoring, and rate-limit columns to connector_tokens.

Phase 5 — Core Patent Claim 2: Edge Processing Architecture.

Adds to connector_tokens:
  expires_at          — 365-day token expiry (patent invariant 18)
  connector_version   — last connector version that used this token
  last_ingest_at      — timestamp of last successful signal ingest
  signals_total       — running total of signals received via this token
  is_active           — False if manually deactivated
  requests_this_hour  — rate-limit counter (1000/hour per token)
  hour_window_start   — start of the current rate-limit hour window

Creates:
  connector_heartbeats — latest heartbeat per connector token

Revision ID: i011
Revises: i010
Create Date: 2025-01-01 00:00:10
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "i011"
down_revision: Union[str, None] = "i010"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = inspector.get_table_names()

    # ── Add columns to connector_tokens ──────────
    if "connector_tokens" in existing_tables:
        existing_columns = {
            col["name"] for col in inspector.get_columns("connector_tokens")
        }

        if "expires_at" not in existing_columns:
            op.add_column(
                "connector_tokens",
                sa.Column(
                    "expires_at",
                    sa.DateTime(timezone=True),
                    nullable=False,
                    server_default=sa.text("now() + INTERVAL '365 days'"),
                ),
            )

        if "connector_version" not in existing_columns:
            op.add_column(
                "connector_tokens",
                sa.Column("connector_version", sa.String(20), nullable=True),
            )

        if "last_ingest_at" not in existing_columns:
            op.add_column(
                "connector_tokens",
                sa.Column("last_ingest_at", sa.DateTime(timezone=True), nullable=True),
            )

        if "signals_total" not in existing_columns:
            op.add_column(
                "connector_tokens",
                sa.Column(
                    "signals_total",
                    sa.Integer,
                    nullable=False,
                    server_default=sa.text("0"),
                ),
            )

        if "is_active" not in existing_columns:
            op.add_column(
                "connector_tokens",
                sa.Column(
                    "is_active",
                    sa.Boolean,
                    nullable=False,
                    server_default=sa.text("true"),
                ),
            )

        if "requests_this_hour" not in existing_columns:
            op.add_column(
                "connector_tokens",
                sa.Column(
                    "requests_this_hour",
                    sa.Integer,
                    nullable=False,
                    server_default=sa.text("0"),
                ),
            )

        if "hour_window_start" not in existing_columns:
            op.add_column(
                "connector_tokens",
                sa.Column(
                    "hour_window_start",
                    sa.DateTime(timezone=True),
                    nullable=True,
                ),
            )

    # ── connector_heartbeats ─────────────────────
    if "connector_heartbeats" not in existing_tables:
        op.create_table(
            "connector_heartbeats",
            sa.Column(
                "id",
                postgresql.UUID(as_uuid=True),
                primary_key=True,
                server_default=sa.text("gen_random_uuid()"),
            ),
            sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column(
                "token_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("connector_tokens.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("connector_version", sa.String(20), nullable=False),
            sa.Column(
                "signals_last_hour",
                sa.Integer,
                nullable=False,
                server_default=sa.text("0"),
            ),
            sa.Column("sources_active", sa.Text, nullable=True),
            sa.Column("status", sa.String(20), nullable=False),
            sa.Column(
                "reported_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("now()"),
            ),
        )

    if "connector_heartbeats" in inspector.get_table_names() or "connector_heartbeats" not in existing_tables:
        existing_hb_indexes = {
            idx["name"]
            for idx in inspector.get_indexes("connector_heartbeats")
        } if "connector_heartbeats" in existing_tables else set()

        if "ix_heartbeat_org" not in existing_hb_indexes:
            op.create_index(
                "ix_heartbeat_org", "connector_heartbeats", ["organization_id"]
            )
        if "ix_heartbeat_token" not in existing_hb_indexes:
            op.create_index(
                "ix_heartbeat_token", "connector_heartbeats", ["token_id"]
            )
        if "ix_heartbeat_reported" not in existing_hb_indexes:
            op.create_index(
                "ix_heartbeat_reported", "connector_heartbeats", ["reported_at"]
            )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = inspector.get_table_names()

    if "connector_heartbeats" in existing_tables:
        existing_indexes = {
            idx["name"] for idx in inspector.get_indexes("connector_heartbeats")
        }
        for idx_name in (
            "ix_heartbeat_reported",
            "ix_heartbeat_token",
            "ix_heartbeat_org",
        ):
            if idx_name in existing_indexes:
                op.drop_index(idx_name, table_name="connector_heartbeats")
        op.drop_table("connector_heartbeats")

    if "connector_tokens" in existing_tables:
        existing_columns = {
            col["name"] for col in inspector.get_columns("connector_tokens")
        }
        for col in (
            "hour_window_start",
            "requests_this_hour",
            "is_active",
            "signals_total",
            "last_ingest_at",
            "connector_version",
            "expires_at",
        ):
            if col in existing_columns:
                op.drop_column("connector_tokens", col)
