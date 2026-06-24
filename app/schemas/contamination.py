"""
Pydantic schemas for Vendor AI Contamination Index.
Dependent Patent Claim 5.
"""

import json
from datetime import datetime
from decimal import Decimal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, field_validator


class VendorContaminationRead(BaseModel):
    id: UUID
    organization_id: UUID
    vendor_id: UUID
    vendor_name: str
    contamination_score: Decimal
    contamination_band: str
    internal_signal_score: Decimal
    external_signal_score: Decimal
    contractual_gap_score: Decimal
    ai_tools_detected: list[str] | None = None
    external_signals: dict | None = None
    dpa_exists: bool
    dpa_covers_ai: bool
    dpa_notes: str | None = None
    assessed_at: datetime
    external_scan_enabled: bool

    model_config = ConfigDict(from_attributes=True)

    @field_validator("ai_tools_detected", mode="before")
    @classmethod
    def parse_ai_tools_detected(cls, v):
        if isinstance(v, str):
            try:
                return json.loads(v) if v else None
            except json.JSONDecodeError:
                return None
        return v

    @field_validator("external_signals", mode="before")
    @classmethod
    def parse_external_signals(cls, v):
        if isinstance(v, str):
            try:
                return json.loads(v) if v else None
            except json.JSONDecodeError:
                return None
        return v


class VendorContaminationSummary(BaseModel):
    total_vendors_assessed: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    vendors_without_dpa: int
    vendors_with_dpa_no_ai_coverage: int
    top_contaminated: list[VendorContaminationRead]


class VendorDPAUpdate(BaseModel):
    vendor_id: UUID
    vendor_name: str
    dpa_exists: bool
    covers_ai_processing: bool
    notes: str | None = None


class ContaminationAssessmentRequest(BaseModel):
    vendor_ids: list[UUID] | None = None
    enable_external_scan: bool = False
