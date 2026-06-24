"""
STANDALONE DEVELOPMENT MODEL
Module: models/vendor

These models represent CompliVibe's vendor management tables.
In the integrated CompliVibe application, these tables are owned by
CompliVibe's core schema. In standalone Shadow AI Discovery Engine
development mode, we define lightweight versions here so the
contamination engine can operate without the full CompliVibe stack.
"""

from uuid import uuid4

from sqlalchemy import Boolean, Column, DateTime, String, text
from sqlalchemy.dialects.postgresql import UUID

from app.core.database import Base


class Vendor(Base):
    __tablename__ = "vendors"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    organization_id = Column(UUID(as_uuid=True), nullable=False)
    name = Column(String(255), nullable=False)
    vendor_type = Column(String(50), nullable=True)
    risk_tier = Column(String(20), nullable=True)
    status = Column(String(20), nullable=True)
    owner_user_id = Column(UUID(as_uuid=True), nullable=True)
    data_access = Column(String(255), nullable=True)
    processes_personal_data = Column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    sub_processor = Column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    created_at = Column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )

    def __repr__(self) -> str:
        return (
            f"<Vendor(id={self.id}, org={self.organization_id}, "
            f"name={self.name}, risk_tier={self.risk_tier})>"
        )


class VendorAssessment(Base):
    __tablename__ = "vendor_assessments"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    organization_id = Column(UUID(as_uuid=True), nullable=False)
    vendor_id = Column(UUID(as_uuid=True), nullable=False)
    status = Column(String(50), nullable=True)
    created_at = Column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )

    def __repr__(self) -> str:
        return (
            f"<VendorAssessment(id={self.id}, org={self.organization_id}, "
            f"vendor={self.vendor_id}, status={self.status})>"
        )
