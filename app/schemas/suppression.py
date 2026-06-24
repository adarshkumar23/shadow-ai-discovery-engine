"""
Pydantic schemas for detection suppressions.
"""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class SuppressionRead(BaseModel):
    id: UUID
    organization_id: UUID
    tool_slug: str
    detection_method: str
    suppressed_by: UUID
    reason: str
    source_detection_id: UUID
    created_at: datetime
    lifted_at: datetime | None = None
    lifted_by: UUID | None = None

    model_config = ConfigDict(from_attributes=True)
