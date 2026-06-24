"""Create idp_connections, audit_logs, and connector_tokens tables.

idp_connections  — encrypted IdP OAuth tokens per organization
audit_logs       — identical schema to CompliVibe's audit_logs (seam 3)
connector_tokens — API tokens for Tier 3 connector authentication

Revision ID: i004
Revises: i003
Create Date: 2025-01-01 00:00:03
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "i004"
down_revision: Union[str, None] = "i003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = inspector.get_table_names()

    # ── idp_connections ──────────────────────────
    if "idp_connections" not in existing_tables:
        op.create_table(
            "idp_connections",
            sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
            sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column("idp_provider", sa.String(30), nullable=False),
            sa.Column("access_token_enc", sa.Text, nullable=False),
            sa.Column("refresh_token_enc", sa.Text, nullable=True),
            sa.Column("token_expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("idp_domain", sa.String(255), nullable=True),
            sa.Column("scopes_granted", sa.Text, nullable=True),
            sa.Column("last_synced_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("sync_status", sa.String(20), nullable=False, server_default=sa.text("'pending'")),
            sa.Column("sync_error", sa.Text, nullable=True),
            sa.Column("connected_by_user_id", postgresql.UUID(as_uuid=True), nullable=False),
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

    if "idp_connections" in inspector.get_table_names():
        existing_idp_indexes = {
            idx["name"] for idx in inspector.get_indexes("idp_connections")
        }
        if "uq_idp_org_provider_active" not in existing_idp_indexes:
            op.create_index(
                "uq_idp_org_provider_active",
                "idp_connections",
                ["organization_id", "idp_provider"],
                unique=True,
                postgresql_where=sa.text("deleted_at IS NULL"),
            )

    # ── audit_logs ───────────────────────────────
    if "audit_logs" not in existing_tables:
        op.create_table(
            "audit_logs",
            sa.Column(
                "id",
                postgresql.UUID(as_uuid=True),
                primary_key=True,
                server_default=sa.text("gen_random_uuid()"),
            ),
            sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=True),
            sa.Column("action", sa.String(255), nullable=False),
            sa.Column("entity_type", sa.String(100), nullable=False),
            sa.Column("entity_id", postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column("context_json", sa.Text, nullable=False, server_default=sa.text("'{}'")),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("now()"),
            ),
        )

        existing_audit_indexes = {
            idx["name"] for idx in inspector.get_indexes("audit_logs")
        }
        if "ix_audit_org_id" not in existing_audit_indexes:
            op.create_index("ix_audit_org_id", "audit_logs", ["organization_id"])
        if "ix_audit_action" not in existing_audit_indexes:
            op.create_index("ix_audit_action", "audit_logs", ["action"])
        if "ix_audit_created" not in existing_audit_indexes:
            op.create_index("ix_audit_created", "audit_logs", ["created_at"])

    # ── connector_tokens ─────────────────────────
    if "connector_tokens" not in existing_tables:
        op.create_table(
            "connector_tokens",
            sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
            sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column("token_hash", sa.String(64), nullable=False),
            sa.Column("label", sa.String(255), nullable=False),
            sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("now()"),
            ),
            sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
            sa.UniqueConstraint(
                "organization_id", "token_hash", name="uq_connector_org_token_hash"
            ),
        )

        existing_conn_indexes = {
            idx["name"] for idx in inspector.get_indexes("connector_tokens")
        }
        if "ix_connector_token_hash" not in existing_conn_indexes:
            op.create_index("ix_connector_token_hash", "connector_tokens", ["token_hash"])


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = inspector.get_table_names()
    if "connector_tokens" in existing_tables:
        op.drop_table("connector_tokens")
    if "audit_logs" in existing_tables:
        op.drop_table("audit_logs")
    if "idp_connections" in existing_tables:
        op.drop_table("idp_connections")
