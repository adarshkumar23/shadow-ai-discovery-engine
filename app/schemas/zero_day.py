"""
Pydantic schemas for zero-day AI candidates.

Zero-day candidates are unknown hostnames that exhibit AI service
behavioral characteristics based on statistical analysis of network
envelope metadata (Dependent Patent Claim 4).
"""

import json
from datetime import datetime
from decimal import Decimal
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, field_validator


class ZeroDayCandidateRead(BaseModel):
    id: UUID
    organization_id: UUID
    hostname: str
    first_observed_at: datetime
    last_observed_at: datetime
    observation_count: int
    signal_ids: list[str] | None = None
    behavioral_score: Decimal
    feature_summary: dict | None = None
    status: str
    reviewed_by: UUID | None = None
    reviewed_at: datetime | None = None
    review_notes: str | None = None
    detection_id: UUID | None = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)

    @field_validator("signal_ids", mode="before")
    @classmethod
    def parse_signal_ids(cls, v):
        if isinstance(v, str):
            try:
                parsed = json.loads(v)
                return parsed if isinstance(parsed, list) else []
            except json.JSONDecodeError:
                return []
        return v

    @field_validator("feature_summary", mode="before")
    @classmethod
    def parse_feature_summary(cls, v):
        if isinstance(v, str):
            try:
                return json.loads(v) if v else None
            except json.JSONDecodeError:
                return None
        return v


class ZeroDayCandidateReview(BaseModel):
    action: Literal["add_to_registry", "dismiss", "monitor"]
    review_notes: str | None = None
    # If add_to_registry:
    provider_name: str | None = None
    category: str | None = None
