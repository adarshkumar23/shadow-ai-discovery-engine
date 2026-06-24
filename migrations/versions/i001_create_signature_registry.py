"""Create ai_signature_registry table.

Stores AI provider signatures used to detect shadow AI usage.
Each signature contains endpoint, keyword, and OAuth app patterns
plus confidence weights for scoring detections.

Revision ID: i001
Revises:
Create Date: 2025-01-01 00:00:00
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "i001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = inspector.get_table_names()

    if "ai_signature_registry" not in existing_tables:
        op.create_table(
            "ai_signature_registry",
            sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
            sa.Column("slug", sa.String(100), nullable=False),
            sa.Column("provider_name", sa.String(255), nullable=False),
            sa.Column("category", sa.String(50), nullable=False),
            sa.Column("endpoint_patterns", sa.Text, nullable=False),
            sa.Column("keyword_patterns", sa.Text, nullable=False),
            sa.Column("oauth_app_patterns", sa.Text, nullable=False),
            sa.Column("data_egress_indicators", sa.Text, nullable=True),
            sa.Column("confidence_weights", sa.Text, nullable=False),
            sa.Column("risk_level", sa.String(20), nullable=False),
            sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.text("true")),
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
            sa.UniqueConstraint("slug", name="uq_signature_slug"),
        )

        existing_indexes = {idx["name"] for idx in inspector.get_indexes("ai_signature_registry")}
        if "ix_signature_slug" not in existing_indexes:
            op.create_index("ix_signature_slug", "ai_signature_registry", ["slug"])
        if "ix_signature_category" not in existing_indexes:
            op.create_index("ix_signature_category", "ai_signature_registry", ["category"])
        if "ix_signature_active" not in existing_indexes:
            op.create_index("ix_signature_active", "ai_signature_registry", ["is_active"])


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "ai_signature_registry" in inspector.get_table_names():
        op.drop_table("ai_signature_registry")
