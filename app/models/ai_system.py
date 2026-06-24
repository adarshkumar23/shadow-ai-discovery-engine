"""
PATENT NOTICE
Module: models/ai_system
Part of: Shadow AI Discovery Engine
Patent: System and Method for Inferring Undeclared
Artificial Intelligence Systems and Generating AI
Governance Artifacts from Enterprise Telemetry
Status: Provisional filing in preparation

Integration Seam 5 — at integration this model is replaced by
CompliVibe's existing AISystem model with additional
source_detection_id column added via migration.
"""

from uuid import uuid4

from sqlalchemy import Column, DateTime, String, Text, text
from sqlalchemy.dialects.postgresql import UUID

from app.core.database import Base


class AISystem(Base):
    __tablename__ = "ai_systems"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        server_default=text("gen_random_uuid()"),
    )
    organization_id = Column(UUID(as_uuid=True), nullable=False)
    name = Column(String(255), nullable=False)
    vendor = Column(String(255), nullable=False)
    category = Column(String(50), nullable=False)
    system_type = Column(String(50), nullable=False)
    deployment_status = Column(
        String(30), nullable=False, server_default=text("'unknown'")
    )
    risk_level = Column(String(20), nullable=True)
    source = Column(
        String(50), nullable=False, server_default=text("'shadow_ai_discovery'")
    )
    source_detection_id = Column(UUID(as_uuid=True), nullable=False)
    inferred_use_case = Column(String(255), nullable=True)
    regulatory_flags = Column(Text, nullable=True)
    owner_id = Column(UUID(as_uuid=True), nullable=True)
    created_by = Column(UUID(as_uuid=True), nullable=False)
    created_at = Column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )
    updated_at = Column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )
    deleted_at = Column(DateTime(timezone=True), nullable=True)

    def __repr__(self) -> str:
        return (
            f"<AISystem(id={self.id}, org={self.organization_id}, "
            f"name={self.name}, system_type={self.system_type}, "
            f"source={self.source})>"
        )
