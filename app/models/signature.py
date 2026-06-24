"""
PATENT NOTICE
Module: models/signature
Part of: Shadow AI Discovery Engine
Patent: System and Method for Inferring Undeclared
Artificial Intelligence Systems and Generating AI
Governance Artifacts from Enterprise Telemetry
Status: Provisional filing in preparation
"""

from uuid import uuid4

from sqlalchemy import Boolean, Column, DateTime, String, Text, text
from sqlalchemy.dialects.postgresql import UUID

from app.core.database import Base


class AISignatureRegistry(Base):
    __tablename__ = "ai_signature_registry"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    slug = Column(String(100), unique=True, nullable=False)
    provider_name = Column(String(255), nullable=False)
    category = Column(String(50), nullable=False)
    endpoint_patterns = Column(Text, nullable=False)
    keyword_patterns = Column(Text, nullable=False)
    oauth_app_patterns = Column(Text, nullable=False)
    data_egress_indicators = Column(Text, nullable=True)
    confidence_weights = Column(Text, nullable=False)
    risk_level = Column(String(20), nullable=False)
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )
    updated_at = Column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )

    def __repr__(self) -> str:
        return (
            f"<AISignatureRegistry(id={self.id}, slug={self.slug}, "
            f"provider={self.provider_name}, category={self.category}, "
            f"risk={self.risk_level}, active={self.is_active})>"
        )
