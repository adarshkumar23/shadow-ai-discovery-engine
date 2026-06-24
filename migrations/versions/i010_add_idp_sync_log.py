"""Add idp_sync_logs table and extend idp_connections with sync tracking columns.

Phase 4 — Tier 2 Connected Discovery via IdP OAuth log analysis.

Creates:
  idp_sync_logs — audit trail of every IdP sync operation

Adds to idp_connections:
  sync_window_hours — how many hours back each sync fetches
  total_syncs       — incremented on each successful sync
  total_signals     — running total of signals produced

Revision ID: i010
Revises: i009
Create Date: 2025-01-01 00:00:09
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "i010"
down_revision: Union[str, None] = "i009"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = inspector.get_table_names()

    # ── Add columns to idp_connections ──────────
    if "idp_connections" in existing_tables:
        existing_columns = {
            col["name"] for col in inspector.get_columns("idp_connections")
        }

        if "sync_window_hours" not in existing_columns:
            op.add_column(
                "idp_connections",
                sa.Column(
                    "sync_window_hours",
                    sa.Integer,
                    nullable=False,
                    server_default=sa.text("24"),
                ),
            )

        if "total_syncs" not in existing_columns:
            op.add_column(
                "idp_connections",
                sa.Column(
                    "total_syncs",
                    sa.Integer,
                    nullable=False,
                    server_default=sa.text("0"),
                ),
            )

        if "total_signals" not in existing_columns:
            op.add_column(
                "idp_connections",
                sa.Column(
                    "total_signals",
                    sa.Integer,
                    nullable=False,
                    server_default=sa.text("0"),
                ),
            )

    # ── idp_sync_logs ───────────────────────────
    if "idp_sync_logs" not in existing_tables:
        op.create_table(
            "idp_sync_logs",
            sa.Column(
                "id",
                postgresql.UUID(as_uuid=True),
                primary_key=True,
                server_default=sa.text("gen_random_uuid()"),
            ),
            sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column(
                "connection_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("idp_connections.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("idp_provider", sa.String(30), nullable=False),
            sa.Column("events_fetched", sa.Integer, nullable=False, server_default=sa.text("0")),
            sa.Column("events_matched", sa.Integer, nullable=False, server_default=sa.text("0")),
            sa.Column("signals_created", sa.Integer, nullable=False, server_default=sa.text("0")),
            sa.Column("signals_duplicate", sa.Integer, nullable=False, server_default=sa.text("0")),
            sa.Column("detections_created", sa.Integer, nullable=False, server_default=sa.text("0")),
            sa.Column("detections_updated", sa.Integer, nullable=False, server_default=sa.text("0")),
            sa.Column("sync_from", sa.DateTime(timezone=True), nullable=True),
            sa.Column("sync_to", sa.DateTime(timezone=True), nullable=True),
            sa.Column(
                "started_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("now()"),
            ),
            sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("status", sa.String(20), nullable=False, server_default=sa.text("'running'")),
            sa.Column("error_message", sa.Text, nullable=True),
            sa.Column("triggered_by", postgresql.UUID(as_uuid=True), nullable=True),
        )

    if "idp_sync_logs" in inspector.get_table_names() or "idp_sync_logs" not in existing_tables:
        existing_indexes = {
            idx["name"]
            for idx in inspector.get_indexes("idp_sync_logs")
        } if "idp_sync_logs" in existing_tables else set()

        if "ix_idp_sync_org" not in existing_indexes:
            op.create_index("ix_idp_sync_org", "idp_sync_logs", ["organization_id"])
        if "ix_idp_sync_connection" not in existing_indexes:
            op.create_index("ix_idp_sync_connection", "idp_sync_logs", ["connection_id"])
        if "ix_idp_sync_started" not in existing_indexes:
            op.create_index("ix_idp_sync_started", "idp_sync_logs", ["started_at"])


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = inspector.get_table_names()

    if "idp_sync_logs" in existing_tables:
        existing_indexes = {
            idx["name"] for idx in inspector.get_indexes("idp_sync_logs")
        }
        for idx_name in (
            "ix_idp_sync_started",
            "ix_idp_sync_connection",
            "ix_idp_sync_org",
        ):
            if idx_name in existing_indexes:
                op.drop_index(idx_name, table_name="idp_sync_logs")
        op.drop_table("idp_sync_logs")

    if "idp_connections" in existing_tables:
        existing_columns = {
            col["name"] for col in inspector.get_columns("idp_connections")
        }
        for col in ("total_signals", "total_syncs", "sync_window_hours"):
            if col in existing_columns:
                op.drop_column("idp_connections", col)
