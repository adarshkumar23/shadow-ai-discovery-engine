"""
PATENT DESIGN INVARIANT — Connector Signal Payload

The ConnectorSignalPayload schema enforces a critical patent design
invariant: raw telemetry fields are NEVER accepted by this endpoint.
Only pre-processed signals may be ingested. This prevents the system
from becoming a repository for raw network traffic, log lines, or PII.

The FORBIDDEN_FIELDS set and model_validator below are a structural
guard rail. Any attempt to submit a payload containing one of these
field names is rejected with a descriptive error. This invariant must
be preserved across all phases and integrations.

Patent: System and Method for Inferring Undeclared Artificial
Intelligence Systems and Generating AI Governance Artifacts from
Enterprise Telemetry — Provisional filing in preparation.
"""

import re
from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

FORBIDDEN_FIELDS = {
    "raw_log",
    "log_line",
    "ip_address",
    "internal_ip",
    "user_id",
    "user_email",
    "payload_content",
    "request_body",
    "response_body",
    "packet_data",
    "source_ip",
    "dest_ip",
    "full_url",
    "query_string",
    "http_headers",
}

_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")


class ConnectorSignalPayload(BaseModel):
    """Schema for Tier 3 connector pre-processed signals.

    This endpoint processes pre-processed signals only.
    Raw telemetry fields are not accepted.

    PATENT INVARIANT 15: Any payload containing a forbidden field is
    rejected at HTTP 400 before any database write occurs. The
    FORBIDDEN_FIELDS check is a structural guard rail that must never
    be relaxed.
    """

    model_config = ConfigDict(extra="allow")

    # ── New Phase 5 required fields ──────────────
    org_id: str = Field(..., description="Organization UUID (string format)")
    signal_type: Literal[
        "network_match",
        "cloudtrail_match",
        "azure_activity_match",
        "gcp_audit_match",
        "local_file_match",
    ]
    matched_tool: str = Field(..., max_length=255)
    hostname_pattern: str = Field(..., max_length=500)
    call_count_24h: int = Field(..., ge=0)
    source_system_label: str = Field(..., max_length=255)
    first_seen: datetime
    last_seen: datetime
    connector_version: str

    # ── Phase 10 optional flow metadata (side channel signals) ──
    # These fields are network envelope metadata only. They contain no
    # payload content and are not in FORBIDDEN_FIELDS.
    avg_response_time_ms: int | None = Field(default=None, ge=0)
    response_time_variance_ms: int | None = Field(default=None, ge=0)
    avg_request_bytes: int | None = Field(default=None, ge=0)
    avg_response_bytes: int | None = Field(default=None, ge=0)
    connection_reuse_ratio: float | None = Field(default=None, ge=0.0, le=1.0)
    inter_request_gap_ms: int | None = Field(default=None, ge=0)

    # ── Legacy fields (optional, for backward compat) ──
    organization_id: UUID | None = None
    tier: int = Field(default=3, ge=1, le=3)
    event_type: str | None = None
    matched_signature_slug: str | None = None
    observed_at: datetime | None = None
    endpoint_matched: str | None = None
    keyword_matched: str | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    volume_bytes: int | None = None
    frequency_count: int | None = None
    signal_metadata: dict | None = None

    @field_validator("first_seen", "last_seen")
    @classmethod
    def _ensure_timezone(cls, v: datetime) -> datetime:
        """Ensure datetimes are timezone-aware."""
        if v.tzinfo is None:
            from datetime import timezone

            return v.replace(tzinfo=timezone.utc)
        return v

    @model_validator(mode="after")
    def check_forbidden_fields(self):
        """Reject any forbidden raw telemetry field names in the payload.

        PATENT INVARIANT 15: This validator enforces payload exclusion
        at the schema layer. Forbidden fields (raw logs, IPs, user
        identities, payload contents) are rejected before any
        processing or database write occurs.
        """
        extra = self.__pydantic_extra__ or {}
        forbidden_found = sorted(k for k in extra if k in FORBIDDEN_FIELDS)
        if forbidden_found:
            raise ValueError(
                "Raw telemetry fields are not accepted. "
                "This endpoint processes pre-processed signals only. "
                f"Forbidden fields detected: {', '.join(forbidden_found)}"
            )
        return self

    @model_validator(mode="after")
    def validate_signal_fields(self):
        """Validate connector_version semver and first_seen <= last_seen."""
        if not _SEMVER_RE.match(self.connector_version):
            raise ValueError(
                "connector_version must be semver format (e.g. 1.0.0)"
            )
        if self.first_seen > self.last_seen:
            raise ValueError(
                "first_seen must be earlier than or equal to last_seen"
            )
        return self


# ── Connector token schemas ───────────────────


class ConnectorTokenCreate(BaseModel):
    label: str = Field(..., min_length=3, max_length=100)
    expires_in_days: int = Field(default=365, ge=1, le=730)


class ConnectorTokenRead(BaseModel):
    id: UUID
    organization_id: UUID
    label: str
    created_by: UUID
    created_at: datetime
    expires_at: datetime
    last_used_at: datetime | None = None
    last_ingest_at: datetime | None = None
    connector_version: str | None = None
    signals_total: int
    is_active: bool
    revoked_at: datetime | None = None
    federated_submissions_enabled: bool = False
    federated_submissions_count: int = 0
    # token_hash is NEVER included in responses
    model_config = ConfigDict(from_attributes=True)


class ConnectorTokenCreatedResponse(BaseModel):
    """Only returned once at creation time. The raw token is never stored."""

    token: str
    token_id: UUID
    label: str
    expires_at: datetime
    warning: str = (
        "Store this token securely. "
        "It will not be shown again."
    )


# ── Connector heartbeat schemas ───────────────


class ConnectorHeartbeatPayload(BaseModel):
    connector_version: str
    signals_last_hour: int = 0
    sources_active: list[str] = []
    status: Literal["online", "degraded", "offline"] = "online"


class ConnectorHeartbeatRead(BaseModel):
    token_id: UUID
    connector_version: str
    signals_last_hour: int
    sources_active: list[str]
    status: str
    reported_at: datetime
    model_config = ConfigDict(from_attributes=True)


# ── Ingest response ───────────────────────────


class IngestResponse(BaseModel):
    accepted: bool
    signal_id: UUID | None = None
    duplicate: bool = False
    message: str
