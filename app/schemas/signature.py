"""
Pydantic schemas for AI signature registry — used for reading
signatures and seed data verification.
"""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel


class AISignatureRead(BaseModel):
    id: UUID
    slug: str
    provider_name: str
    category: str
    endpoint_patterns: str
    keyword_patterns: str
    oauth_app_patterns: str
    data_egress_indicators: str | None = None
    confidence_weights: str
    risk_level: str
    is_active: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class AISignatureCreate(BaseModel):
    slug: str
    provider_name: str
    category: str
    endpoint_patterns: str
    keyword_patterns: str
    oauth_app_patterns: str
    data_egress_indicators: str | None = None
    confidence_weights: str
    risk_level: str
    is_active: bool = True
