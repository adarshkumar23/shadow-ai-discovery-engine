"""
PATENT NOTICE
Module: routers/idp
Part of: Shadow AI Discovery Engine
Patent: System and Method for Inferring Undeclared
Artificial Intelligence Systems and Generating AI
Governance Artifacts from Enterprise Telemetry
Status: Provisional filing in preparation

IdP OAuth connection management endpoints.

PATENT INVARIANT 11: Access tokens are NEVER included in
API responses. The IdpConnectionRead schema deliberately
omits access_token_enc and refresh_token_enc.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.core.dependencies import get_current_user, get_organization_id, require_permission
from app.models.idp import IdpConnection, IdpSyncLog
from app.schemas.common import PaginatedResponse
from app.schemas.idp import (
    IdpConnectionCreate,
    IdpConnectionRead,
    IdpConnectionRequiredScopes,
    IdpSyncLogRead,
)
from app.services.capability_service import require_shadow_ai_enabled
from app.services.tier2_scanner import Tier2Scanner

router = APIRouter()


def _build_connection_read(conn: IdpConnection) -> IdpConnectionRead:
    """Build IdpConnectionRead from ORM, parsing scopes."""
    scopes = None
    if conn.scopes_granted:
        scopes = conn.scopes_granted.split()
    return IdpConnectionRead(
        id=conn.id,
        organization_id=conn.organization_id,
        idp_provider=conn.idp_provider,
        idp_domain=conn.idp_domain,
        scopes_granted=scopes,
        last_synced_at=conn.last_synced_at,
        sync_status=conn.sync_status,
        sync_error=conn.sync_error,
        connected_by_user_id=conn.connected_by_user_id,
        created_at=conn.created_at,
        total_syncs=conn.total_syncs or 0,
        total_signals=conn.total_signals or 0,
    )


REQUIRED_SCOPES_DATA: list[dict] = [
    {
        "provider": "okta",
        "scopes": ["okta.logs.read"],
        "reason": (
            "Read-only access to Okta system log API for "
            "OAuth token grant events"
        ),
        "documentation_url": (
            "https://developer.okta.com/docs/reference/api/system-log/"
        ),
    },
    {
        "provider": "azure_ad",
        "scopes": ["AuditLog.Read.All", "offline_access"],
        "reason": (
            "Read-only access to Azure AD sign-in logs for OAuth grant "
            "detection. offline_access required for token refresh."
        ),
        "documentation_url": (
            "https://learn.microsoft.com/en-us/graph/api/resources/signin"
        ),
    },
    {
        "provider": "google_ws",
        "scopes": [
            "https://www.googleapis.com/auth/admin.reports.audit.readonly"
        ],
        "reason": (
            "Read-only access to Google Workspace token audit report "
            "for OAuth authorization events"
        ),
        "documentation_url": (
            "https://developers.google.com/admin-sdk/reports/v1/"
            "guides/manage-audit-token"
        ),
    },
]


@router.post(
    "/idp/connect",
    summary="Initiate IdP OAuth Connection",
    description=(
        "Starts the OAuth consent flow for connecting an identity provider. "
        "Returns the authorization URL to redirect the customer's "
        "administrator to. Requires shadow_ai:admin permission."
    ),
)
def connect_idp(
    body: IdpConnectionCreate,
    db: Session = Depends(get_db),
    organization_id: UUID = Depends(get_organization_id),
    user_id: UUID = Depends(get_current_user),
    _: None = Depends(require_shadow_ai_enabled),
    __: None = Depends(require_permission("shadow_ai:admin")),
):
    result = Tier2Scanner.initiate_oauth_flow(
        organization_id=organization_id,
        idp_provider=body.idp_provider,
        idp_domain=body.idp_domain,
        redirect_uri=body.redirect_uri,
        connected_by_user_id=user_id,
        db=db,
    )
    return result


@router.get(
    "/idp/callback",
    summary="OAuth Callback Handler",
    description=(
        "Receives the OAuth callback from the IdP after administrator "
        "consent. Exchanges authorization code for tokens, encrypts and "
        "stores them, triggers initial IdP sync."
    ),
)
def oauth_callback(
    code: str = Query(...),
    state: str = Query(...),
    provider: str = Query(...),
    request: Request = None,
    db: Session = Depends(get_db),
):
    redirect_uri = str(request.url).split("?")[0]
    try:
        connection = Tier2Scanner.handle_oauth_callback(
            code=code,
            state=state,
            idp_provider=provider,
            redirect_uri=redirect_uri,
            db=db,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    return _build_connection_read(connection)


@router.get(
    "/idp/connections",
    summary="List IdP Connections",
    description=(
        "Returns all configured IdP connections for the organization. "
        "Access tokens are never included in responses."
    ),
    response_model=list[IdpConnectionRead],
)
def list_connections(
    db: Session = Depends(get_db),
    organization_id: UUID = Depends(get_organization_id),
    user_id: UUID = Depends(get_current_user),
    _: None = Depends(require_shadow_ai_enabled),
    __: None = Depends(require_permission("shadow_ai:read")),
):
    connections = db.execute(
        select(IdpConnection).where(
            IdpConnection.organization_id == organization_id,
            IdpConnection.deleted_at.is_(None),
        )
    ).scalars().all()
    return [_build_connection_read(c) for c in connections]


@router.get(
    "/idp/connections/{connection_id}",
    summary="Get IdP Connection Detail",
    response_model=IdpConnectionRead,
)
def get_connection(
    connection_id: UUID,
    db: Session = Depends(get_db),
    organization_id: UUID = Depends(get_organization_id),
    user_id: UUID = Depends(get_current_user),
    _: None = Depends(require_shadow_ai_enabled),
    __: None = Depends(require_permission("shadow_ai:read")),
):
    conn = db.execute(
        select(IdpConnection).where(
            IdpConnection.id == connection_id,
            IdpConnection.organization_id == organization_id,
            IdpConnection.deleted_at.is_(None),
        )
    ).scalar_one_or_none()
    if conn is None:
        raise HTTPException(status_code=404, detail="Connection not found")
    return _build_connection_read(conn)


@router.delete(
    "/idp/connections/{connection_id}",
    summary="Disconnect IdP",
    description=(
        "Removes an IdP connection. Soft deletes the connection record. "
        "Does not delete telemetry events or detections already created "
        "from this connection's signals."
    ),
)
def disconnect_connection(
    connection_id: UUID,
    db: Session = Depends(get_db),
    organization_id: UUID = Depends(get_organization_id),
    user_id: UUID = Depends(get_current_user),
    _: None = Depends(require_shadow_ai_enabled),
    __: None = Depends(require_permission("shadow_ai:admin")),
):
    conn = db.execute(
        select(IdpConnection).where(
            IdpConnection.id == connection_id,
            IdpConnection.organization_id == organization_id,
            IdpConnection.deleted_at.is_(None),
        )
    ).scalar_one_or_none()
    if conn is None:
        raise HTTPException(status_code=404, detail="Connection not found")

    conn.deleted_at = datetime.now(timezone.utc)
    conn.sync_status = "expired"
    db.commit()

    return {"disconnected": True, "connection_id": connection_id}


@router.post(
    "/idp/connections/{connection_id}/sync",
    summary="Trigger IdP Sync",
    description=(
        "Manually triggers an IdP audit log sync for the specified "
        "connection. Fetches OAuth events since last sync and updates "
        "detections."
    ),
    response_model=IdpSyncLogRead,
)
def trigger_sync(
    connection_id: UUID,
    db: Session = Depends(get_db),
    organization_id: UUID = Depends(get_organization_id),
    user_id: UUID = Depends(get_current_user),
    _: None = Depends(require_shadow_ai_enabled),
    __: None = Depends(require_permission("shadow_ai:write")),
):
    conn = db.execute(
        select(IdpConnection).where(
            IdpConnection.id == connection_id,
            IdpConnection.organization_id == organization_id,
            IdpConnection.deleted_at.is_(None),
        )
    ).scalar_one_or_none()
    if conn is None:
        raise HTTPException(status_code=404, detail="Connection not found")

    sync_log = Tier2Scanner.sync_connection(
        connection_id=connection_id,
        organization_id=organization_id,
        triggered_by=user_id,
        db=db,
    )
    return sync_log


@router.post(
    "/idp/connections/{connection_id}/test",
    summary="Test IdP Connection",
    description=(
        "Tests whether the stored credentials are valid and the "
        "required scopes are granted."
    ),
)
def test_connection(
    connection_id: UUID,
    db: Session = Depends(get_db),
    organization_id: UUID = Depends(get_organization_id),
    user_id: UUID = Depends(get_current_user),
    _: None = Depends(require_shadow_ai_enabled),
    __: None = Depends(require_permission("shadow_ai:read")),
):
    conn = db.execute(
        select(IdpConnection).where(
            IdpConnection.id == connection_id,
            IdpConnection.organization_id == organization_id,
            IdpConnection.deleted_at.is_(None),
        )
    ).scalar_one_or_none()
    if conn is None:
        raise HTTPException(status_code=404, detail="Connection not found")

    error = None
    connected = False
    try:
        connector = Tier2Scanner.get_connector(conn, settings)
        connected = connector.test_connection()
    except PermissionError:
        connected = False
        error = "Token lacks required scopes"
    except (ConnectionError, Exception) as e:
        connected = False
        error = str(e)

    return {
        "connected": connected,
        "provider": conn.idp_provider,
        "error": error,
    }


@router.get(
    "/idp/connections/{connection_id}/sync-logs",
    summary="List Sync Logs",
    description=(
        "Returns the audit trail of all sync operations for this "
        "connection."
    ),
    response_model=PaginatedResponse[IdpSyncLogRead],
)
def list_sync_logs(
    connection_id: UUID,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    organization_id: UUID = Depends(get_organization_id),
    user_id: UUID = Depends(get_current_user),
    _: None = Depends(require_shadow_ai_enabled),
    __: None = Depends(require_permission("shadow_ai:read")),
):
    conn = db.execute(
        select(IdpConnection).where(
            IdpConnection.id == connection_id,
            IdpConnection.organization_id == organization_id,
            IdpConnection.deleted_at.is_(None),
        )
    ).scalar_one_or_none()
    if conn is None:
        raise HTTPException(status_code=404, detail="Connection not found")

    from sqlalchemy import func

    base_q = select(IdpSyncLog).where(
        IdpSyncLog.connection_id == connection_id,
        IdpSyncLog.organization_id == organization_id,
    )
    total = db.execute(
        select(func.count()).select_from(base_q.subquery())
    ).scalar() or 0

    offset = (page - 1) * page_size
    items = list(
        db.execute(
            base_q.order_by(IdpSyncLog.started_at.desc())
            .offset(offset)
            .limit(page_size)
        ).scalars().all()
    )

    return PaginatedResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        has_next=(page * page_size) < total,
    )


@router.get(
    "/idp/required-scopes",
    summary="Required OAuth Scopes",
    description=(
        "Returns the exact OAuth scopes required for each IdP provider. "
        "Use this to inform your IT administrator before granting access. "
        "This endpoint requires no authentication — it is a transparency "
        "document."
    ),
    response_model=list[IdpConnectionRequiredScopes],
)
def get_required_scopes(
    provider: str | None = Query(None),
):
    data = REQUIRED_SCOPES_DATA
    if provider is not None:
        data = [d for d in data if d["provider"] == provider]
    return data
