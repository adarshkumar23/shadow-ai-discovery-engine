"""Add federated registry intelligence network tables.

Phase 9 — Dependent Patent Claim 8: Federated Registry Intelligence Network.

Creates federated_registry_contributions for opt-in, anonymized
contributions of probable AI service hostnames observed across customer
organizations. When a hostname is reported by PROMOTION_THRESHOLD distinct
organizations it is promoted into the global ai_signature_registry.

Organization identity is never stored in plaintext; only a SHA256 hash of
the organization UUID is persisted.

Revision ID: i017
Revises: i016
Create Date: 2026-06-24 00:00:00
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "i017"
down_revision: Union[str, None] = "i016"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

PROMOTION_THRESHOLD = 3


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = inspector.get_table_names()

    if "federated_registry_contributions" not in existing_tables:
        op.create_table(
            "federated_registry_contributions",
            sa.Column(
                "id",
                postgresql.UUID(as_uuid=True),
                primary_key=True,
                server_default=sa.text("gen_random_uuid()"),
            ),
            sa.Column("hostname", sa.String(500), nullable=False),
            sa.Column(
                "hostname_hash",
                sa.String(64),
                nullable=False,
            ),
            sa.Column(
                "organization_hash",
                sa.String(64),
                nullable=False,
            ),
            sa.Column(
                "contributions_count",
                sa.Integer,
                nullable=False,
                server_default=sa.text("1"),
            ),
            sa.Column(
                "first_contributed_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("now()"),
            ),
            sa.Column(
                "last_contributed_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("now()"),
            ),
            sa.Column(
                "promoted_to_registry_at",
                sa.DateTime(timezone=True),
                nullable=True,
            ),
            sa.UniqueConstraint(
                "hostname_hash",
                "organization_hash",
                name="uq_federated_host_org_hash",
            ),
        )
        op.create_index(
            "ix_federated_hostname_hash",
            "federated_registry_contributions",
            ["hostname_hash"],
        )
        op.create_index(
            "ix_federated_org_hash",
            "federated_registry_contributions",
            ["organization_hash"],
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = inspector.get_table_names()

    if "federated_registry_contributions" in existing_tables:
        op.drop_index(
            "ix_federated_org_hash", table_name="federated_registry_contributions"
        )
        op.drop_index(
            "ix_federated_hostname_hash",
            table_name="federated_registry_contributions",
        )
        op.drop_table("federated_registry_contributions")
