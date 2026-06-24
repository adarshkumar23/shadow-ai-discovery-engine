"""
PATENT NOTICE
Module: models/suppression
Part of: Shadow AI Discovery Engine
Patent: System and Method for Inferring Undeclared
Artificial Intelligence Systems and Generating AI
Governance Artifacts from Enterprise Telemetry
Status: Provisional filing in preparation

PATENT INVARIANT 9: Dismissed detections are never hard deleted.
deleted_at remains NULL on dismissed records. dismissed_at is set.
The record is retained permanently for audit trail purposes.

PATENT INVARIANT 10: The suppression table prevents re-detection
of dismissed tools via the same method. Once dismissed, that
tool + method combination is suppressed for that org permanently
unless explicitly lifted.
"""

from uuid import uuid4

from sqlalchemy import Column, DateTime, Index, String, Text, text
from sqlalchemy.dialects.postgresql import UUID

from app.core.database import Base


class SuppressedDetection(Base):
    __tablename__ = "suppressed_detections"
    __table_args__ = (
        Index(
            "uq_suppression_org_slug_method_active",
            "organization_id",
            "tool_slug",
            "detection_method",
            unique=True,
            postgresql_where=text("lifted_at IS NULL"),
        ),
    )

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        server_default=text("gen_random_uuid()"),
    )
    organization_id = Column(UUID(as_uuid=True), nullable=False)
    tool_slug = Column(String(100), nullable=False)
    detection_method = Column(String(50), nullable=False)
    suppressed_by = Column(UUID(as_uuid=True), nullable=False)
    reason = Column(Text, nullable=False)
    source_detection_id = Column(UUID(as_uuid=True), nullable=False)
    created_at = Column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )
    lifted_at = Column(DateTime(timezone=True), nullable=True)
    lifted_by = Column(UUID(as_uuid=True), nullable=True)

    def __repr__(self) -> str:
        return (
            f"<SuppressedDetection(id={self.id}, org={self.organization_id}, "
            f"tool_slug={self.tool_slug}, method={self.detection_method}, "
            f"active={self.lifted_at is None})>"
        )
