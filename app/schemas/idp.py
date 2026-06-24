"""
Pydantic schemas for IdP connections and sync logs.
"""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict

IdpProvider = Literal["okta", "azure_ad", "google_ws"]
SyncStatus = Literal["pending", "active", "error", "expired"]


class IdpConnectionCreate(BaseModel):
    idp_provider: IdpProvider
    idp_domain: str | None = None
    redirect_uri: str


class IdpOAuthCallbackParams(BaseModel):
    code: str
    state: str
    provider: IdpProvider


class IdpConnectionRead(BaseModel):
    id: UUID
    organization_id: UUID
    idp_provider: str
    idp_domain: str | None = None
    scopes_granted: list[str] | None = None
    last_synced_at: datetime | None = None
    sync_status: str
    sync_error: str | None = None
    connected_by_user_id: UUID
    created_at: datetime
    total_syncs: int = 0
    total_signals: int = 0
    # NOTE: access_token_enc and refresh_token_enc
    # are NEVER included in API responses.
    # This is a patent invariant (11).

    model_config = ConfigDict(from_attributes=True)

    @classmethod
    def from_orm_connection(cls, conn) -> "IdpConnectionRead":
        """Build from an IdpConnection ORM instance.

        Parses scopes_granted from space-separated string to list.
        """
        scopes = None
        if conn.scopes_granted:
            scopes = conn.scopes_granted.split()
        return cls(
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


class IdpConnectionRequiredScopes(BaseModel):
    provider: str
    scopes: list[str]
    reason: str
    documentation_url: str


class IdpSyncLogRead(BaseModel):
    id: UUID
    organization_id: UUID
    connection_id: UUID
    idp_provider: str
    events_fetched: int
    events_matched: int
    signals_created: int
    signals_duplicate: int
    detections_created: int
    detections_updated: int
    sync_from: datetime | None = None
    sync_to: datetime | None = None
    started_at: datetime
    completed_at: datetime | None = None
    status: str
    error_message: str | None = None

    model_config = ConfigDict(from_attributes=True)
