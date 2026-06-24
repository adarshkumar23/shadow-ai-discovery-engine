"""
Tests for the IdP API endpoints.

All connector HTTP calls are mocked. Never makes real API calls.
"""

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.database import get_db
from app.core.security import encrypt_value
from app.main import app
from app.models.idp import IdpConnection, IdpSyncLog
from app.models.signature import AISignatureRegistry
from app.services.idp_connectors.base import OAuthEvent
from app.services.tier2_scanner import Tier2Scanner
from tests.conftest import make_signature

ORG_ID = UUID("11111111-1111-1111-1111-111111111111")
USER_ID = UUID("11111111-1111-1111-1111-111111111101")


def make_mock_connector(
    events=None,
    token_data=None,
    test_result=True,
):
    """Create a comprehensive mock connector."""
    mock = MagicMock()
    mock.get_authorization_url.return_value = (
        "https://test.okta.com/oauth2/v1/authorize?client_id=test&scope=okta.logs.read"
    )
    mock.exchange_code_for_tokens.return_value = token_data or {
        "access_token": "raw_access_token_123",
        "refresh_token": "raw_refresh_token_456",
        "expires_in": 3600,
        "scope": "okta.logs.read",
    }
    mock.fetch_oauth_events.return_value = events or []
    mock.test_connection.return_value = test_result
    return mock


def create_connection_directly(db, provider="okta", status="active"):
    """Create an IdpConnection directly in the DB."""
    conn = IdpConnection(
        id=uuid4(),
        organization_id=ORG_ID,
        idp_provider=provider,
        idp_domain="test.okta.com",
        access_token_enc=encrypt_value("test_access_token"),
        refresh_token_enc=encrypt_value("test_refresh_token"),
        token_expires_at=None,
        sync_status=status,
        connected_by_user_id=USER_ID,
        sync_window_hours=24,
        total_syncs=0,
        total_signals=0,
    )
    db.add(conn)
    db.commit()
    return conn


def test_connect_returns_authorization_url(client, seeded_db):
    """POST /idp/connect returns authorization_url, connection_id, provider."""
    with patch.object(Tier2Scanner, "get_connector", return_value=make_mock_connector()):
        response = client.post(
            "/api/v1/shadow-ai/idp/connect",
            json={
                "idp_provider": "okta",
                "idp_domain": "test.okta.com",
                "redirect_uri": "http://testserver/api/v1/shadow-ai/idp/callback",
            },
        )
    assert response.status_code == 200
    data = response.json()
    assert "authorization_url" in data
    assert "connection_id" in data
    assert data["provider"] == "okta"


def test_callback_stores_encrypted_tokens(client, seeded_db):
    """Verify access_token_enc != raw token after callback."""
    with patch.object(Tier2Scanner, "get_connector", return_value=make_mock_connector()):
        # Step 1: initiate OAuth flow
        connect_resp = client.post(
            "/api/v1/shadow-ai/idp/connect",
            json={
                "idp_provider": "okta",
                "idp_domain": "test.okta.com",
                "redirect_uri": "http://testserver/api/v1/shadow-ai/idp/callback",
            },
        )
        assert connect_resp.status_code == 200
        state = str(ORG_ID)

        # Step 2: callback
        callback_resp = client.get(
            "/api/v1/shadow-ai/idp/callback",
            params={"code": "test_code", "state": state, "provider": "okta"},
        )
    assert callback_resp.status_code == 200

    # Verify the stored token is encrypted, not raw
    conn = seeded_db.execute(
        select(IdpConnection).where(
            IdpConnection.organization_id == ORG_ID,
            IdpConnection.idp_provider == "okta",
        )
    ).scalar_one()
    assert conn.access_token_enc != "raw_access_token_123"
    assert conn.access_token_enc != ""
    assert "raw_access_token" not in conn.access_token_enc


def test_callback_triggers_initial_sync(client, seeded_db):
    """Verify sync_connection is called after callback."""
    with patch.object(Tier2Scanner, "get_connector", return_value=make_mock_connector()), \
         patch.object(Tier2Scanner, "sync_connection") as mock_sync:
        mock_sync.return_value = IdpSyncLog(
            id=uuid4(),
            organization_id=ORG_ID,
            connection_id=uuid4(),
            idp_provider="okta",
            status="completed",
            events_fetched=0,
            started_at=datetime.now(timezone.utc),
        )
        client.post(
            "/api/v1/shadow-ai/idp/connect",
            json={
                "idp_provider": "okta",
                "idp_domain": "test.okta.com",
                "redirect_uri": "http://testserver/api/v1/shadow-ai/idp/callback",
            },
        )
        client.get(
            "/api/v1/shadow-ai/idp/callback",
            params={"code": "test_code", "state": str(ORG_ID), "provider": "okta"},
        )

    mock_sync.assert_called_once()


def test_list_connections_excludes_tokens(client, seeded_db):
    """access_token_enc never in response."""
    create_connection_directly(seeded_db, provider="okta")
    create_connection_directly(seeded_db, provider="azure_ad")

    response = client.get("/api/v1/shadow-ai/idp/connections")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 2
    for conn in data:
        assert "access_token_enc" not in conn
        assert "refresh_token_enc" not in conn
        assert "token_expires_at" not in conn


def test_test_connection_returns_true(client, seeded_db):
    """POST /idp/connections/{id}/test returns connected=true."""
    conn = create_connection_directly(seeded_db)
    with patch.object(Tier2Scanner, "get_connector", return_value=make_mock_connector(test_result=True)):
        response = client.post(f"/api/v1/shadow-ai/idp/connections/{conn.id}/test")
    assert response.status_code == 200
    data = response.json()
    assert data["connected"] is True
    assert data["provider"] == "okta"


def test_sync_returns_sync_log(client, seeded_db):
    """POST /idp/connections/{id}/sync returns IdpSyncLogRead."""
    conn = create_connection_directly(seeded_db)
    sig = make_signature(seeded_db, slug="api-sync-test", provider_name="OpenAI ChatGPT")
    sig.oauth_app_patterns = json.dumps(["OpenAI ChatGPT"])
    seeded_db.commit()

    events = [OAuthEvent(
        app_name="OpenAI ChatGPT",
        app_id="app_123",
        oauth_scopes=["openid"],
        event_time=datetime.now(timezone.utc),
        event_type="grant",
        actor_id="a" * 64,
        idp_provider="okta",
    )]

    with patch.object(Tier2Scanner, "get_connector", return_value=make_mock_connector(events=events)):
        response = client.post(f"/api/v1/shadow-ai/idp/connections/{conn.id}/sync")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "completed"
    assert data["idp_provider"] == "okta"
    assert data["events_fetched"] == 1


def test_required_scopes_no_auth(test_db):
    """Endpoint accessible without headers."""
    def override_get_db():
        yield test_db

    app.dependency_overrides[get_db] = override_get_db
    try:
        with TestClient(app) as c:
            response = c.get("/api/v1/shadow-ai/idp/required-scopes")
            assert response.status_code == 200
    finally:
        app.dependency_overrides.clear()


def test_required_scopes_all_providers(client):
    """Verify all 3 providers returned with correct scope strings."""
    response = client.get("/api/v1/shadow-ai/idp/required-scopes")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 3
    providers = {d["provider"] for d in data}
    assert providers == {"okta", "azure_ad", "google_ws"}

    okta = next(d for d in data if d["provider"] == "okta")
    assert okta["scopes"] == ["okta.logs.read"]

    azure = next(d for d in data if d["provider"] == "azure_ad")
    assert azure["scopes"] == ["AuditLog.Read.All", "offline_access"]

    google = next(d for d in data if d["provider"] == "google_ws")
    assert "admin.reports.audit.readonly" in google["scopes"][0]


def test_delete_connection_soft_deletes(client, seeded_db):
    """Verify deleted_at set, not DB DELETE."""
    conn = create_connection_directly(seeded_db)

    response = client.delete(f"/api/v1/shadow-ai/idp/connections/{conn.id}")
    assert response.status_code == 200
    data = response.json()
    assert data["disconnected"] is True

    # Verify soft delete — record still exists with deleted_at set
    db_conn = seeded_db.execute(
        select(IdpConnection).where(IdpConnection.id == conn.id)
    ).scalar_one()
    assert db_conn.deleted_at is not None

    # Verify it's not listed anymore
    list_resp = client.get("/api/v1/shadow-ai/idp/connections")
    assert list_resp.status_code == 200
    conn_ids = [c["id"] for c in list_resp.json()]
    assert str(conn.id) not in conn_ids


def test_sync_logs_paginated(client, seeded_db):
    """Verify sync logs are paginated."""
    conn = create_connection_directly(seeded_db)

    # Create 5 sync log records
    for i in range(5):
        log = IdpSyncLog(
            id=uuid4(),
            organization_id=ORG_ID,
            connection_id=conn.id,
            idp_provider="okta",
            events_fetched=i,
            signals_created=i,
            status="completed",
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
        )
        seeded_db.add(log)
    seeded_db.commit()

    response = client.get(
        f"/api/v1/shadow-ai/idp/connections/{conn.id}/sync-logs",
        params={"page": 1, "page_size": 2},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 5
    assert len(data["items"]) == 2
    assert data["has_next"] is True
    assert data["page"] == 1
    assert data["page_size"] == 2
