"""
Reusable Pydantic types and base response schemas.
"""

from datetime import datetime
from typing import Generic, TypeVar

from pydantic import BaseModel

T = TypeVar("T")


class PaginatedResponse(BaseModel, Generic[T]):
    items: list[T]
    total: int
    page: int
    page_size: int
    has_next: bool


class ErrorResponse(BaseModel):
    error: str
    detail: str | None = None
    request_id: str | None = None


class HealthResponse(BaseModel):
    status: str
    version: str
    environment: str
    checks: dict[str, str]
    timestamp: datetime


class ScanSummary(BaseModel):
    records_scanned: int
    new_signals: int
    duplicates_skipped: int
    detections_created: int
    detections_updated: int
    scan_duration_ms: int
    scan_type: str
