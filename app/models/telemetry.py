"""
PATENT NOTICE
Module: models/telemetry
Part of: Shadow AI Discovery Engine
Patent: System and Method for Inferring Undeclared
Artificial Intelligence Systems and Generating AI
Governance Artifacts from Enterprise Telemetry
Status: Provisional filing in preparation
"""

from uuid import uuid4

from sqlalchemy import Column, DateTime, ForeignKey, SmallInteger, String, Text, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import UUID

from app.core.database import Base


class TelemetryEvent(Base):
    __tablename__ = "telemetry_events"
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "signal_hash", name="uq_telemetry_org_signal_hash"
        ),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    organization_id = Column(UUID(as_uuid=True), nullable=False)
    tier = Column(SmallInteger, nullable=False)
    event_type = Column(String(50), nullable=False)
    source_system_label = Column(String(255), nullable=True)
    matched_signature_id = Column(
        UUID(as_uuid=True),
        ForeignKey("ai_signature_registry.id", ondelete="SET NULL"),
        nullable=True,
    )
    raw_signal_json = Column(Text, nullable=False)
    signal_hash = Column(String(64), nullable=False)
    observed_at = Column(DateTime(timezone=True), nullable=False)
    ingested_at = Column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )
    created_at = Column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )

    def __repr__(self) -> str:
        return (
            f"<TelemetryEvent(id={self.id}, org={self.organization_id}, "
            f"tier={self.tier}, event_type={self.event_type}, "
            f"observed_at={self.observed_at})>"
        )
