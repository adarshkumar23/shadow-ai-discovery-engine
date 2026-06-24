"""Create questionnaire_responses table.

Formalises the questionnaire_responses table that was previously
created ad-hoc by the seed script outside of Alembic. Drops the
old table (which had different columns) and recreates with the
correct schema.

Revision ID: i005
Revises: i004
Create Date: 2025-01-01 00:00:04
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "i005"
down_revision: Union[str, None] = "i004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = inspector.get_table_names()

    if "questionnaire_responses" in existing_tables:
        op.drop_table("questionnaire_responses")

    op.create_table(
        "questionnaire_responses",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("submitted_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("vendor_name", sa.String(255), nullable=True),
        sa.Column("question_text", sa.Text, nullable=True),
        sa.Column("answer_text", sa.Text, nullable=False),
        sa.Column(
            "submitted_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
    )

    existing_indexes = {
        idx["name"] for idx in inspector.get_indexes("questionnaire_responses")
    }
    if "ix_questionnaire_org_id" not in existing_indexes:
        op.create_index(
            "ix_questionnaire_org_id",
            "questionnaire_responses",
            ["organization_id"],
        )
    if "ix_questionnaire_org_deleted" not in existing_indexes:
        op.create_index(
            "ix_questionnaire_org_deleted",
            "questionnaire_responses",
            ["organization_id", "deleted_at"],
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "questionnaire_responses" in inspector.get_table_names():
        op.drop_table("questionnaire_responses")
