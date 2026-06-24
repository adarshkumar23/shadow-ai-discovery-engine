"""
Pydantic schemas for shadow AI detections.
Field declarations matching the detection table.
Validators will be implemented in Phase 2.
"""

import json
from datetime import datetime
from decimal import Decimal
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field, field_validator


DetectionStatus = Literal[
    "new", "reviewed", "dismissed", "escalated", "registered", "needs_review"
]
ConfidenceBand = Literal["high", "medium"]


class DetectionBasis(BaseModel):
    tier1_signals: int
    tier2_signals: int
    tier3_signals: int
    signal_ids: list[str]
    score_breakdown: dict[str, float]


class ShadowAIDetectionRead(BaseModel):
    id: UUID
    organization_id: UUID
    signature_id: UUID | None = None
    provider_name: str
    confidence_score: float
    confidence_band: ConfidenceBand
    detection_basis_json: str
    attributed_owner_id: UUID | None = None
    attribution_confidence: float | None = None
    status: DetectionStatus
    first_detected_at: datetime
    last_observed_at: datetime
    reviewed_by_user_id: UUID | None = None
    reviewed_at: datetime | None = None
    dismissed_at: datetime | None = None
    dismissed_by_user_id: UUID | None = None
    dismissal_reason: str | None = None
    escalated_at: datetime | None = None
    escalated_by_user_id: UUID | None = None
    escalation_notes: str | None = None
    registered_ai_system_id: UUID | None = None
    suppressed: bool
    base_confidence_score: Decimal | None = None
    decay_lambda: Decimal | None = None
    decayed_at: datetime | None = None
    is_stale: bool
    intent_action: str | None = None
    intent_data_subject: str | None = None
    intent_business_context: str | None = None
    inferred_use_case: str | None = None
    intent_classified_at: datetime | None = None
    detection_method: str | None = None
    is_zero_day: bool = False
    zero_day_hostname: str | None = None
    behavioral_features_json: str | None = None
    classifier_version: str | None = None
    is_dark_ai: bool = False
    dark_ai_features_json: str | None = None
    dark_ai_score: float | None = None
    dark_ai_proxy_detected: bool | None = None
    jurisdiction_assessment_json: str | None = None
    applicable_regulations_count: int | None = None
    jurisdiction_assessed_at: datetime | None = None
    highest_regulatory_risk: str | None = None
    jurisdiction_graph_version: str | None = None
    created_at: datetime
    updated_at: datetime
    deleted_at: datetime | None = None

    model_config = {"from_attributes": True}


class ShadowAIDetectionDetail(ShadowAIDetectionRead):
    use_case_risk_json: dict | None = None
    contributing_signals: list[dict] | None = None

    @field_validator("use_case_risk_json", mode="before")
    @classmethod
    def parse_risk_json(cls, v):
        if isinstance(v, str):
            try:
                return json.loads(v) if v else None
            except json.JSONDecodeError:
                return None
        return v


class ShadowAIDetectionCreate(BaseModel):
    organization_id: UUID
    signature_id: UUID | None = None
    provider_name: str
    confidence_score: float
    confidence_band: ConfidenceBand
    detection_basis_json: str
    first_detected_at: datetime
    last_observed_at: datetime


class ScanSummaryResponse(BaseModel):
    records_scanned: int
    new_signals: int
    duplicates_skipped: int
    detections_created: int
    detections_updated: int
    scan_duration_ms: int
    scan_type: str


class TopDetectedTool(BaseModel):
    provider_name: str
    confidence_score: float
    confidence_band: str
    first_detected_at: datetime
    is_stale: bool


class DetectionSummaryResponse(BaseModel):
    total_active: int
    by_status: dict[str, int]
    by_confidence_band: dict[str, int]
    stale_count: int
    top_detected_tools: list[TopDetectedTool]


class DismissRequest(BaseModel):
    reason: str = Field(..., min_length=10)
    notes: str | None = None


class EscalateRequest(BaseModel):
    system_type: Literal["model", "use_case", "agent", "application", "data_pipeline"]
    owner_id: UUID | None = None
    notes: str | None = None


class BulkActionRequest(BaseModel):
    detection_ids: list[UUID]
    reason: str | None = None


class BulkActionResponse(BaseModel):
    succeeded: list[UUID]
    failed: list[dict]
    total_succeeded: int
    total_failed: int
