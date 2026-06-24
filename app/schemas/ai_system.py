"""
Pydantic schemas for AI System governance records.
"""

import json
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, field_validator

from app.schemas.detection import ShadowAIDetectionRead


class AISystemRead(BaseModel):
    id: UUID
    organization_id: UUID
    name: str
    vendor: str
    category: str
    system_type: str
    deployment_status: str
    risk_level: str | None = None
    source: str
    source_detection_id: UUID
    inferred_use_case: str | None = None
    regulatory_flags: list[str] | None = None
    owner_id: UUID | None = None
    created_by: UUID
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

    @field_validator("regulatory_flags", mode="before")
    @classmethod
    def parse_regulatory_flags(cls, v):
        if isinstance(v, str):
            try:
                return json.loads(v) if v else None
            except json.JSONDecodeError:
                return None
        return v


class EscalationResponse(BaseModel):
    detection: ShadowAIDetectionRead
    ai_system: AISystemRead
    message: str
