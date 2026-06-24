"""
PATENT NOTICE
Module: routers/connector
Implements Core Patent Claim 2:
The Edge Processing Architecture.

ARCHITECTURE INVARIANTS (patent-specified):
1. The connector sends signals only — never
   raw telemetry. CompliVibe NEVER initiates
   connection into the customer environment.
   The connector is always the initiator.

2. Token-authenticated endpoints (ingest,
   heartbeat) use X-Connector-Token header
   ONLY. JWT auth is NOT used for these
   endpoints. The connector is a non-human
   caller. org_id comes from the token record.

3. The ingest endpoint enforces payload
   exclusion at the HTTP layer (patent
   invariant 15). Forbidden fields are
   rejected with HTTP 400 before any database
   write occurs.

Patent: System and Method for Inferring Undeclared
Artificial Intelligence Systems and Generating AI
Governance Artifacts from Enterprise Telemetry.
Status: Provisional filing in preparation.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import get_current_user, get_organization_id, require_permission
from app.core.logging_config import request_id_var
from app.models.detection import ConnectorHeartbeat, ConnectorToken
from app.schemas.telemetry import (
    FORBIDDEN_FIELDS,
    ConnectorHeartbeatPayload,
    ConnectorHeartbeatRead,
    ConnectorSignalPayload,
    ConnectorTokenCreate,
    ConnectorTokenCreatedResponse,
    ConnectorTokenRead,
    IngestResponse,
)
from app.services.capability_service import require_shadow_ai_enabled
from app.services.tier3_ingestor import Tier3Ingestor

router = APIRouter()

RATE_LIMIT_PER_HOUR = 1000


def _build_token_read(token: ConnectorToken) -> ConnectorTokenRead:
    """Build ConnectorTokenRead from ORM. token_hash is never included."""
    return ConnectorTokenRead(
        id=token.id,
        organization_id=token.organization_id,
        label=token.label,
        created_by=token.created_by,
        created_at=token.created_at,
        expires_at=token.expires_at,
        last_used_at=token.last_used_at,
        last_ingest_at=token.last_ingest_at,
        connector_version=token.connector_version,
        signals_total=token.signals_total or 0,
        is_active=token.is_active,
        revoked_at=token.revoked_at,
    )


def _build_heartbeat_read(hb: ConnectorHeartbeat) -> ConnectorHeartbeatRead:
    """Build ConnectorHeartbeatRead from ORM, parsing sources_active JSON."""
    sources: list[str] = []
    if hb.sources_active:
        try:
            sources = json.loads(hb.sources_active)
        except (json.JSONDecodeError, TypeError):
            sources = []
    return ConnectorHeartbeatRead(
        token_id=hb.token_id,
        connector_version=hb.connector_version,
        signals_last_hour=hb.signals_last_hour,
        sources_active=sources,
        status=hb.status,
        reported_at=hb.reported_at,
    )


# ═══════════════════════════════════════════════
# USER-AUTHENTICATED ENDPOINTS
# (X-Organization-ID + X-User-ID + capability flag)
# ═══════════════════════════════════════════════


@router.post(
    "/connector/tokens",
    summary="Generate Connector Token",
    description=(
        "Generates a new connector API token for authenticating the open "
        "source Tier 3 connector. The raw token is only shown once at "
        "creation — it is not stored in plaintext anywhere. Store it "
        "securely before leaving this page."
    ),
    response_model=ConnectorTokenCreatedResponse,
)
def generate_token(
    body: ConnectorTokenCreate,
    db: Session = Depends(get_db),
    organization_id: UUID = Depends(get_organization_id),
    user_id: UUID = Depends(get_current_user),
    _: None = Depends(require_shadow_ai_enabled),
    __: None = Depends(require_permission("shadow_ai:admin")),
):
    raw_token, token = Tier3Ingestor.generate_connector_token(
        organization_id=organization_id,
        label=body.label,
        created_by=user_id,
        expires_in_days=body.expires_in_days,
        db=db,
    )
    expires_at = token.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return ConnectorTokenCreatedResponse(
        token=raw_token,
        token_id=token.id,
        label=token.label,
        expires_at=expires_at,
    )


@router.get(
    "/connector/tokens",
    summary="List Connector Tokens",
    description=(
        "Returns all connector tokens for the organization. "
        "Token values are never included in responses."
    ),
    response_model=list[ConnectorTokenRead],
)
def list_tokens(
    db: Session = Depends(get_db),
    organization_id: UUID = Depends(get_organization_id),
    user_id: UUID = Depends(get_current_user),
    _: None = Depends(require_shadow_ai_enabled),
    __: None = Depends(require_permission("shadow_ai:read")),
):
    tokens = Tier3Ingestor.list_tokens(organization_id, db)
    return [_build_token_read(t) for t in tokens]


@router.delete(
    "/connector/tokens/{token_id}",
    summary="Revoke Connector Token",
    description=(
        "Permanently revokes a connector token. The connector using this "
        "token will receive 401 errors on next ingest attempt. This "
        "action cannot be undone."
    ),
    response_model=ConnectorTokenRead,
)
def revoke_token(
    token_id: UUID,
    db: Session = Depends(get_db),
    organization_id: UUID = Depends(get_organization_id),
    user_id: UUID = Depends(get_current_user),
    _: None = Depends(require_shadow_ai_enabled),
    __: None = Depends(require_permission("shadow_ai:admin")),
):
    token = Tier3Ingestor.revoke_token(
        token_id=token_id,
        organization_id=organization_id,
        revoked_by=user_id,
        db=db,
    )
    return _build_token_read(token)


@router.get(
    "/connector/status",
    summary="Connector Status Dashboard",
    description=(
        "Returns aggregated status of all connectors for the organization. "
        "Shows online, stale, and offline connectors based on heartbeat timing."
    ),
)
def get_connector_status(
    db: Session = Depends(get_db),
    organization_id: UUID = Depends(get_organization_id),
    user_id: UUID = Depends(get_current_user),
    _: None = Depends(require_shadow_ai_enabled),
    __: None = Depends(require_permission("shadow_ai:read")),
):
    return Tier3Ingestor.get_connector_status(organization_id, db)


@router.get(
    "/connector/heartbeats",
    summary="List Connector Heartbeats",
    description=(
        "Returns the latest heartbeat from each active connector token."
    ),
    response_model=list[ConnectorHeartbeatRead],
)
def list_heartbeats(
    db: Session = Depends(get_db),
    organization_id: UUID = Depends(get_organization_id),
    user_id: UUID = Depends(get_current_user),
    _: None = Depends(require_shadow_ai_enabled),
    __: None = Depends(require_permission("shadow_ai:read")),
):
    heartbeats = db.execute(
        select(ConnectorHeartbeat).where(
            ConnectorHeartbeat.organization_id == organization_id
        ).order_by(ConnectorHeartbeat.reported_at.desc())
    ).scalars().all()
    return [_build_heartbeat_read(hb) for hb in heartbeats]


# ═══════════════════════════════════════════════
# TOKEN-AUTHENTICATED ENDPOINTS
# (X-Connector-Token header ONLY — NO JWT, NO X-Organization-ID)
# ═══════════════════════════════════════════════


@router.post(
    "/connector/ingest",
    summary="Ingest Network Signal",
    description=(
        "Receives a pre-processed network signal from the open source "
        "connector. Raw telemetry never reaches this endpoint — only "
        "matched results from edge processing.\n\n"
        "PATENT NOTICE: This endpoint implements the network boundary "
        "enforcement layer of Core Patent Claim 2 (Edge Processing "
        "Architecture). The payload validator enforces that only "
        "pre-processed signals are accepted. Any payload containing raw "
        "telemetry fields (raw_log, ip_address, user_id, etc.) is "
        "rejected at HTTP 400 before any database write occurs. This "
        "is a patent design invariant and must never be relaxed."
    ),
    response_model=IngestResponse,
)
async def ingest_signal(
    request: Request,
    x_connector_token: str | None = Header(default=None, alias="X-Connector-Token"),
    db: Session = Depends(get_db),
):
    # 1. Extract X-Connector-Token header.
    if not x_connector_token:
        raise HTTPException(
            status_code=401,
            detail="X-Connector-Token header required",
        )

    # 2. Validate connector token (org_id comes from token record).
    connector_token = Tier3Ingestor.validate_connector_token(
        x_connector_token, None, db
    )

    # 3. Rate limit check (1000 requests per hour per token).
    now = datetime.now(timezone.utc)
    window_start = connector_token.hour_window_start
    if window_start is not None:
        if window_start.tzinfo is None:
            window_start = window_start.replace(tzinfo=timezone.utc)
    if window_start is None or window_start < now - timedelta(hours=1):
        connector_token.hour_window_start = now
        connector_token.requests_this_hour = 0

    if connector_token.requests_this_hour >= RATE_LIMIT_PER_HOUR:
        db.commit()
        return JSONResponse(
            status_code=429,
            content={
                "error": "rate_limited",
                "detail": (
                    "Rate limit exceeded. "
                    f"{RATE_LIMIT_PER_HOUR} signals per hour per connector."
                ),
                "request_id": request_id_var.get() or None,
            },
            headers={"Retry-After": "3600"},
        )

    connector_token.requests_this_hour = (connector_token.requests_this_hour or 0) + 1
    db.commit()

    # 4. Parse request body.
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="Request body must be a JSON object")

    # 5. FORBIDDEN FIELDS check — patent invariant 15.
    #    Rejected at HTTP 400 before any database write.
    forbidden_found = sorted(k for k in body if k in FORBIDDEN_FIELDS)
    if forbidden_found:
        return JSONResponse(
            status_code=400,
            content={
                "error": "forbidden_fields",
                "detail": (
                    "Raw telemetry fields are not accepted. This endpoint "
                    "processes pre-processed signals only. Forbidden fields "
                    f"detected: {', '.join(forbidden_found)}"
                ),
                "forbidden_fields": forbidden_found,
                "request_id": request_id_var.get() or None,
            },
        )

    # 6. Pydantic validation.
    try:
        payload = ConnectorSignalPayload(**body)
    except ValidationError as exc:
        return JSONResponse(
            status_code=422,
            content={
                "error": "validation_error",
                "detail": str(exc.errors()),
                "request_id": request_id_var.get() or None,
            },
        )

    # 7. Verify org_id in payload matches the token's org.
    if UUID(payload.org_id) != connector_token.organization_id:
        raise HTTPException(
            status_code=401,
            detail="Invalid connector token",
        )

    # 8. Ingest the signal.
    signal_id, duplicate = Tier3Ingestor.ingest_signal(
        payload, connector_token, db
    )

    # 9. Return response.
    if duplicate:
        return IngestResponse(
            accepted=True,
            signal_id=None,
            duplicate=True,
            message="Duplicate signal — already recorded",
        )
    return IngestResponse(
        accepted=True,
        signal_id=signal_id,
        duplicate=False,
        message="Signal accepted",
    )


@router.post(
    "/connector/heartbeat",
    summary="Connector Heartbeat",
    description=(
        "Receives a periodic heartbeat from the connector indicating it "
        "is operational. Used for connector health monitoring in the "
        "dashboard."
    ),
    response_model=ConnectorHeartbeatRead,
)
async def post_heartbeat(
    request: Request,
    x_connector_token: str | None = Header(default=None, alias="X-Connector-Token"),
    db: Session = Depends(get_db),
):
    if not x_connector_token:
        raise HTTPException(
            status_code=401,
            detail="X-Connector-Token header required",
        )

    connector_token = Tier3Ingestor.validate_connector_token(
        x_connector_token, None, db
    )

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="Request body must be a JSON object")

    forbidden_found = sorted(k for k in body if k in FORBIDDEN_FIELDS)
    if forbidden_found:
        return JSONResponse(
            status_code=400,
            content={
                "error": "forbidden_fields",
                "detail": (
                    "Raw telemetry fields are not accepted. "
                    f"Forbidden fields detected: {', '.join(forbidden_found)}"
                ),
                "forbidden_fields": forbidden_found,
                "request_id": request_id_var.get() or None,
            },
        )

    try:
        payload = ConnectorHeartbeatPayload(**body)
    except ValidationError as exc:
        return JSONResponse(
            status_code=422,
            content={
                "error": "validation_error",
                "detail": str(exc.errors()),
                "request_id": request_id_var.get() or None,
            },
        )

    heartbeat = Tier3Ingestor.process_heartbeat(payload, connector_token, db)
    return _build_heartbeat_read(heartbeat)


# ═══════════════════════════════════════════════
# NO-AUTH ENDPOINT
# ═══════════════════════════════════════════════


@router.get(
    "/connector/schema",
    summary="Connector Signal Schema",
    description=(
        "Returns the exact JSON schema the connector must use for signal "
        "payloads. This is the public contract between the open source "
        "connector and the CompliVibe ingest API. No authentication "
        "required."
    ),
)
def get_connector_schema():
    return {
        "schema_version": "1.0.0",
        "endpoint": "POST /connector/ingest",
        "authentication": "X-Connector-Token header",
        "required_fields": {
            "org_id": "string (UUID format)",
            "signal_type": (
                "one of: network_match, cloudtrail_match, "
                "azure_activity_match, gcp_audit_match, local_file_match"
            ),
            "matched_tool": "string (max 255 chars)",
            "hostname_pattern": "string (max 500 chars)",
            "call_count_24h": "integer >= 0",
            "source_system_label": "string (max 255 chars)",
            "first_seen": "ISO 8601 datetime",
            "last_seen": "ISO 8601 datetime",
            "connector_version": "semver string (e.g. 1.0.0)",
        },
        "forbidden_fields": sorted(FORBIDDEN_FIELDS),
        "forbidden_fields_policy": (
            "Any payload containing these fields will be rejected with "
            "HTTP 400. This is a patent design invariant of the edge "
            "processing architecture."
        ),
        "rate_limit": f"{RATE_LIMIT_PER_HOUR} requests per hour per token",
        "duplicate_handling": (
            "Duplicate signals return 200 with duplicate=true. Do not retry."
        ),
        "hostname_signatures": {
            "openai": "api.openai.com",
            "anthropic": "api.anthropic.com",
            "cohere": "api.cohere.ai",
            "mistral": "api.mistral.ai",
            "huggingface": "api-inference.huggingface.co",
            "stability": "api.stability.ai",
            "groq": "api.groq.com",
            "perplexity": "api.perplexity.ai",
            "azure_openai": "*.openai.azure.com",
            "aws_bedrock": "bedrock-runtime.*.amazonaws.com",
            "google_ai": "generativelanguage.googleapis.com",
            "vertex_ai": "us-central1-aiplatform.googleapis.com",
        },
    }
