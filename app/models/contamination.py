"""
PATENT NOTICE
Module: models/contamination
Implements Dependent Patent Claim 5:
Vendor AI Contamination Index.

Models for storing computed vendor contamination scores and
Data Processing Agreement (DPA) coverage records.

PATENT INVARIANT 28: contamination_score is a numeric value
between 0.0000 and 1.0000.

PATENT INVARIANT 31: contractual_gap_score is determined by
DPA existence and AI coverage:
  - No DPA record: 1.0 (maximum gap)
  - DPA exists, no AI coverage: 0.5
  - DPA exists, covers AI: 0.0
"""

from uuid import uuid4

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Index,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import UUID

from app.core.database import Base


class VendorAIContamination(Base):
    __tablename__ = "vendor_ai_contamination"
    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "vendor_id",
            name="uq_contamination_org_vendor",
        ),
        Index("ix_contamination_org", "organization_id"),
        Index(
            "ix_contamination_score",
            "organization_id",
            "contamination_score",
            postgresql_using=None,
        ),
        Index("ix_contamination_band", "organization_id", "contamination_band"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    organization_id = Column(UUID(as_uuid=True), nullable=False)
    vendor_id = Column(UUID(as_uuid=True), nullable=False)
    vendor_name = Column(String(255), nullable=False)
    contamination_score = Column(Numeric(5, 4), nullable=False)
    contamination_band = Column(String(20), nullable=False)
    internal_signal_score = Column(Numeric(5, 4), nullable=False)
    external_signal_score = Column(Numeric(5, 4), nullable=False)
    contractual_gap_score = Column(Numeric(5, 4), nullable=False)
    ai_tools_detected = Column(Text, nullable=True)
    external_signals = Column(Text, nullable=True)
    dpa_exists = Column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    dpa_covers_ai = Column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    dpa_notes = Column(Text, nullable=True)
    assessed_at = Column(DateTime(timezone=True), nullable=False)
    assessment_version = Column(
        String(20), nullable=False, default="1.0.0", server_default=text("'1.0.0'")
    )
    external_scan_enabled = Column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    created_at = Column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )
    updated_at = Column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )

    def __repr__(self) -> str:
        return (
            f"<VendorAIContamination(id={self.id}, org={self.organization_id}, "
            f"vendor={self.vendor_name}, score={self.contamination_score}, "
            f"band={self.contamination_band})>"
        )


class VendorDPARecord(Base):
    __tablename__ = "vendor_dpa_records"
    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "vendor_id",
            name="uq_dpa_org_vendor",
        ),
        Index("ix_dpa_org", "organization_id"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    organization_id = Column(UUID(as_uuid=True), nullable=False)
    vendor_id = Column(UUID(as_uuid=True), nullable=False)
    vendor_name = Column(String(255), nullable=False)
    dpa_exists = Column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    covers_ai_processing = Column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    dpa_reviewed_at = Column(DateTime(timezone=True), nullable=True)
    notes = Column(Text, nullable=True)
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
            f"<VendorDPARecord(id={self.id}, org={self.organization_id}, "
            f"vendor={self.vendor_name}, dpa={self.dpa_exists}, "
            f"covers_ai={self.covers_ai_processing})>"
        )
