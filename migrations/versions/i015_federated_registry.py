"""Add federated registry intelligence network tables.

Phase 9 — Dependent Patent Claim 8: Federated Registry Intelligence Network.

Creates two new tables:

  * federated_hostname_observations
    The privacy-preserving aggregation table. Contains NO organization_id
    column and no column that can identify the submitting organization.
    This is Patent Invariant 32.

  * federated_submission_log
    Audit log that stores organization_id for compliance auditing ONLY.
    It is intentionally separated from the aggregation table and must
    never be joined back to it to reveal which organization submitted
    which hostname.

Adds per-token opt-in flags to connector_tokens:

  * federated_submissions_enabled  (Boolean, default False)
  * federated_submissions_count    (Integer, default 0)

Revision ID: i015
Revises: i017
Create Date: 2026-06-24 00:00:00
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "i015"
down_revision: Union[str, None] = "i017"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = inspector.get_table_names()

    # ── Federated hostname observations (aggregation table) ───────────────
    # PATENT INVARIANT 32: This table intentionally has no organization_id
    # column and no column that can identify which organization submitted a
    # hostname. Only hostname_hash and the hostname itself are stored here.
    if "federated_hostname_observations" not in existing_tables:
        op.create_table(
            "federated_hostname_observations",
            sa.Column(
                "id",
                postgresql.UUID(as_uuid=True),
                primary_key=True,
                server_default=sa.text("gen_random_uuid()"),
            ),
            sa.Column(
                "hostname_hash",
                sa.String(64),
                nullable=False,
            ),
            sa.Column(
                "hostname",
                sa.String(500),
                nullable=False,
            ),
            sa.Column(
                "observation_count",
                sa.Integer,
                nullable=False,
                server_default=sa.text("1"),
            ),
            sa.Column(
                "first_observed_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("now()"),
            ),
            sa.Column(
                "last_observed_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("now()"),
            ),
            sa.Column(
                "behavioral_score",
                sa.Numeric(5, 4),
                nullable=True,
            ),
            sa.Column(
                "status",
                sa.String(30),
                nullable=False,
                server_default=sa.text("'observing'"),
            ),
            sa.Column(
                "promoted_at",
                sa.DateTime(timezone=True),
                nullable=True,
            ),
            sa.Column(
                "signature_id",
                sa.String(50),
                nullable=True,
            ),
            sa.Column(
                "reviewed_by_admin",
                sa.Boolean,
                nullable=False,
                server_default=sa.text("false"),
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
            sa.UniqueConstraint(
                "hostname_hash",
                name="uq_federated_hostname_hash",
            ),
        )
        op.create_index(
            "ix_federated_obs_hostname_hash",
            "federated_hostname_observations",
            ["hostname_hash"],
        )
        op.create_index(
            "ix_federated_obs_status",
            "federated_hostname_observations",
            ["status"],
        )
        op.create_index(
            "ix_federated_obs_observation_count",
            "federated_hostname_observations",
            ["observation_count"],
            postgresql_where=sa.text("status = 'candidate'"),
        )
        op.create_index(
            "ix_federated_obs_score",
            "federated_hostname_observations",
            ["behavioral_score"],
            postgresql_where=sa.text("status IN ('observing', 'candidate')"),
        )

    # ── Federated submission log (audit table) ────────────────────────────
    # Stores organization_id ONLY for compliance auditing. It is intentionally
    # separated from federated_hostname_observations and must never be joined
    # back to reveal submitter identity.
    if "federated_submission_log" not in existing_tables:
        op.create_table(
            "federated_submission_log",
            sa.Column(
                "id",
                postgresql.UUID(as_uuid=True),
                primary_key=True,
                server_default=sa.text("gen_random_uuid()"),
            ),
            sa.Column(
                "organization_id",
                postgresql.UUID(as_uuid=True),
                nullable=False,
            ),
            sa.Column(
                "submission_token",
                sa.String(64),
                nullable=False,
            ),
            sa.Column(
                "hostname_hash",
                sa.String(64),
                nullable=False,
            ),
            sa.Column(
                "submitted_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("now()"),
            ),
            sa.Column(
                "behavioral_score",
                sa.Numeric(5, 4),
                nullable=True,
            ),
            sa.Column(
                "was_duplicate",
                sa.Boolean,
                nullable=False,
                server_default=sa.text("false"),
            ),
            sa.UniqueConstraint(
                "submission_token",
                name="uq_federated_submission_token",
            ),
        )
        op.create_index(
            "ix_federated_log_org",
            "federated_submission_log",
            ["organization_id"],
        )
        op.create_index(
            "ix_federated_log_hostname",
            "federated_submission_log",
            ["hostname_hash"],
        )

    # ── Connector token opt-in columns ────────────────────────────────────
    # PATENT INVARIANT 34: Federated submission is OPT-IN only. Default False.
    existing_columns = {
        c["name"] for c in inspector.get_columns("connector_tokens")
    }

    if "federated_submissions_enabled" not in existing_columns:
        op.add_column(
            "connector_tokens",
            sa.Column(
                "federated_submissions_enabled",
                sa.Boolean,
                nullable=False,
                server_default=sa.text("false"),
            ),
        )

    if "federated_submissions_count" not in existing_columns:
        op.add_column(
            "connector_tokens",
            sa.Column(
                "federated_submissions_count",
                sa.Integer,
                nullable=False,
                server_default=sa.text("0"),
            ),
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = inspector.get_table_names()
    existing_columns = {
        c["name"] for c in inspector.get_columns("connector_tokens")
    }

    for column_name in ("federated_submissions_count", "federated_submissions_enabled"):
        if column_name in existing_columns:
            try:
                op.drop_column("connector_tokens", column_name)
            except Exception:
                pass

    if "federated_submission_log" in existing_tables:
        op.drop_index(
            "ix_federated_log_hostname", table_name="federated_submission_log"
        )
        op.drop_index("ix_federated_log_org", table_name="federated_submission_log")
        op.drop_table("federated_submission_log")

    if "federated_hostname_observations" in existing_tables:
        op.drop_index(
            "ix_federated_obs_score", table_name="federated_hostname_observations"
        )
        op.drop_index(
            "ix_federated_obs_observation_count",
            table_name="federated_hostname_observations",
        )
        op.drop_index(
            "ix_federated_obs_status", table_name="federated_hostname_observations"
        )
        op.drop_index(
            "ix_federated_obs_hostname_hash",
            table_name="federated_hostname_observations",
        )
        op.drop_table("federated_hostname_observations")
