"""
PATENT NOTICE
Module: models/zero_day
Part of: Shadow AI Discovery Engine
Implements Dependent Patent Claim 4:
Zero-Day AI Detection via Behavioral Classification.

Stores zero-day AI candidates detected through behavioral analysis
of network signal metadata. Candidate hostnames are unknown AI
services identified by statistical behavioral patterns rather than
registry matches. Human review is required before promotion to the
formal AI signature registry.
"""

from uuid import uuid4

from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import UUID

from app.core.database import Base


class ZeroDayCandidate(Base):
    """
    A zero-day AI candidate represents an unknown hostname observed
    in network traffic whose statistical behavioral properties match
    those of an AI inference service. The classifier never inspects
    packet payload contents — it operates only on network envelope
    metadata (hostname pattern, call frequency, timing signals).

    Review workflow:
      pending_review     → human has not yet reviewed
      added_to_registry  → promoted to AISignatureRegistry
      dismissed          → false positive, suppressed
      monitoring         → under continued observation
    """

    __tablename__ = "zero_day_candidates"
    __table_args__ = (
        Index(
            "uq_zero_day_candidate_org_hostname",
            "organization_id",
            "hostname",
            unique=True,
            postgresql_where=text(
                "status NOT IN ('added_to_registry', 'dismissed')"
            ),
        ),
        Index(
            "ix_zero_day_candidate_org",
            "organization_id",
        ),
        Index(
            "ix_zero_day_candidate_score",
            "behavioral_score",
            postgresql_where=text("status = 'pending_review'"),
        ),
    )

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        server_default=text("gen_random_uuid()"),
    )
    organization_id = Column(UUID(as_uuid=True), nullable=False)
    hostname = Column(String(500), nullable=False)
    first_observed_at = Column(DateTime(timezone=True), nullable=False)
    last_observed_at = Column(DateTime(timezone=True), nullable=False)
    observation_count = Column(
        Integer, nullable=False, default=1, server_default=text("1")
    )
    signal_ids = Column(Text, nullable=True)
    behavioral_score = Column(Numeric(5, 4), nullable=False)
    feature_summary = Column(Text, nullable=True)
    status = Column(
        String(30),
        nullable=False,
        default="pending_review",
        server_default=text("'pending_review'"),
    )
    reviewed_by = Column(UUID(as_uuid=True), nullable=True)
    reviewed_at = Column(DateTime(timezone=True), nullable=True)
    review_notes = Column(Text, nullable=True)
    detection_id = Column(
        UUID(as_uuid=True),
        ForeignKey("shadow_ai_detections.id", ondelete="SET NULL"),
        nullable=True,
    )
    created_at = Column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )
    updated_at = Column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )

    def __repr__(self) -> str:
        return (
            f"<ZeroDayCandidate(id={self.id}, org={self.organization_id}, "
            f"hostname={self.hostname}, score={self.behavioral_score}, "
            f"status={self.status}, observations={self.observation_count})>"
        )
