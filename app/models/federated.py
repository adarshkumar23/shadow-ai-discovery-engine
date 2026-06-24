"""
PATENT NOTICE
Module: models/federated
Part of: Shadow AI Discovery Engine
Patent: System and Method for Inferring Undeclared
Artificial Intelligence Systems and Generating AI
Governance Artifacts from Enterprise Telemetry
Status: Provisional filing in preparation

Dependent Patent Claim 8: Federated Registry Intelligence Network.

Stores opt-in, anonymized contributions of zero-day AI hostnames from
participating organizations.

PRIVACY INVARIANT 32:
  FederatedHostnameObservation intentionally has NO organization_id column
  and no column that can identify the submitting organization. The
  aggregation table only stores hostname_hash, hostname, and the count of
  independent observations. This is the privacy-preserving guarantee and
  must be preserved exactly.

The FederatedSubmissionLog stores organization_id for compliance auditing
ONLY. It is architecturally separated from the aggregation table and must
never be joined back to reveal which organization submitted which hostname.
"""

from uuid import uuid4

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Index,
    Integer,
    Numeric,
    String,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import UUID

from app.core.database import Base


class FederatedHostnameObservation(Base):
    """
    Central aggregation table for the Federated Registry Intelligence Network.

    This model intentionally has no organization_id column. Patent Invariant 32.
    The observation_count tracks how many independent organizations observed
    the same hostname, without storing which organizations contributed.

    When observation_count reaches PROMOTION_THRESHOLD (3), the hostname is
    automatically promoted to 'candidate' status for human review.
    """

    __tablename__ = "federated_hostname_observations"
    __table_args__ = (
        UniqueConstraint(
            "hostname_hash",
            name="uq_federated_hostname_hash",
        ),
        Index("ix_federated_obs_hostname_hash", "hostname_hash"),
        Index("ix_federated_obs_status", "status"),
        Index(
            "ix_federated_obs_observation_count",
            "observation_count",
            postgresql_where=text("status = 'candidate'"),
        ),
        Index(
            "ix_federated_obs_score",
            "behavioral_score",
            postgresql_where=text("status IN ('observing', 'candidate')"),
        ),
    )

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        server_default=text("gen_random_uuid()"),
    )
    hostname_hash = Column(String(64), nullable=False)
    hostname = Column(String(500), nullable=False)
    observation_count = Column(
        Integer,
        nullable=False,
        default=1,
        server_default=text("1"),
    )
    first_observed_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("now()"),
    )
    last_observed_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("now()"),
    )
    behavioral_score = Column(Numeric(5, 4), nullable=True)
    status = Column(
        String(30),
        nullable=False,
        default="observing",
        server_default=text("'observing'"),
    )
    promoted_at = Column(DateTime(timezone=True), nullable=True)
    signature_id = Column(String(50), nullable=True)
    reviewed_by_admin = Column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
    )
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("now()"),
    )
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("now()"),
    )

    def __repr__(self) -> str:
        return (
            f"<FederatedHostnameObservation(hostname={self.hostname}, "
            f"hostname_hash={self.hostname_hash}, "
            f"observation_count={self.observation_count}, "
            f"status={self.status})>"
        )


class FederatedSubmissionLog(Base):
    """
    Audit log of federated hostname submissions.

    organization_id is stored here for compliance auditing ONLY. It must
    never be used to join back to federated_hostname_observations and reveal
    which organization submitted which hostname. The link between tables is
    hostname_hash only, which does not expose organization identity.
    """

    __tablename__ = "federated_submission_log"
    __table_args__ = (
        UniqueConstraint(
            "submission_token",
            name="uq_federated_submission_token",
        ),
        Index("ix_federated_log_org", "organization_id"),
        Index("ix_federated_log_hostname", "hostname_hash"),
    )

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        server_default=text("gen_random_uuid()"),
    )
    organization_id = Column(UUID(as_uuid=True), nullable=False)
    submission_token = Column(String(64), nullable=False)
    hostname_hash = Column(String(64), nullable=False)
    submitted_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("now()"),
    )
    behavioral_score = Column(Numeric(5, 4), nullable=True)
    was_duplicate = Column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
    )

    def __repr__(self) -> str:
        return (
            f"<FederatedSubmissionLog(org={self.organization_id}, "
            f"hostname_hash={self.hostname_hash}, "
            f"was_duplicate={self.was_duplicate})>"
        )
