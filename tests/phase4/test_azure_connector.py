"""
Tests for the Azure AD IdP connector.

All HTTP calls are mocked. Never makes real API calls.
"""

import hashlib
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from uuid import UUID, uuid4

import pytest

from app.core.config import settings
from app.core.security import encrypt_value
from app.models.idp import IdpConnection
from app.services.idp_connectors.azure_ad import AzureADConnector


ORG_ID = UUID("11111111-1111-1111-1111-111111111111")
USER_ID = UUID("11111111-1111-1111-1111-111111111101")


class MockResponse:
    """Mock httpx.Response for testing."""

    def __init__(self, json_data, status_code=200, headers=None):
        self._json_data = json_data
        self.status_code = status_code
        self.headers = headers or {}

    def json(self):
        return self._json_data


def make_azure_connection(**kwargs):
    """Create an Azure AD IdpConnection instance for testing."""
    defaults = {
        "id": uuid4(),
        "organization_id": ORG_ID,
        "idp_provider": "azure_ad",
        "idp_domain": "tenant-id-123",
        "access_token_enc": encrypt_value("test_access_token"),
        "refresh_token_enc": encrypt_value("test_refresh_token"),
        "token_expires_at": None,
        "sync_status": "active",
        "connected_by_user_id": USER_ID,
        "sync_window_hours": 24,
        "total_syncs": 0,
        "total_signals": 0,
    }
    defaults.update(kwargs)
    return IdpConnection(**defaults)


def test_authorization_url_format():
    """Verify URL contains correct scope, client_id, redirect_uri."""
    with patch.object(settings, "azure_ad_client_id", "azure_client_123"):
        conn = make_azure_connection()
        connector = AzureADConnector(conn, settings)
        url = connector.get_authorization_url(
            state="my_state_789",
            redirect_uri="https://app.example.com/callback",
        )
        assert "login.microsoftonline.com" in url
        assert "tenant-id-123" in url
        assert "azure_client_123" in url
        assert "AuditLog.Read.All" in url
        assert "offline_access" in url
        assert "my_state_789" in url


def test_fetch_signin_logs_parses_correctly():
    """Mock Azure AD response, verify OAuthEvent fields extracted."""
    conn = make_azure_connection()
    connector = AzureADConnector(conn, settings)

    mock_data = {
        "value": [
            {
                "appDisplayName": "OpenAI ChatGPT",
                "appId": "app-uuid-123",
                "createdDateTime": "2025-06-01T12:00:00Z",
                "status": {"errorCode": 0},
                "userPrincipalName": "user@company.com",
                "resourceDisplayName": "OpenAI",
            }
        ]
    }

    with patch("app.services.idp_connectors.azure_ad.httpx.get") as mock_get:
        mock_get.return_value = MockResponse(mock_data)
        events = connector.fetch_oauth_events(
            since=datetime(2025, 6, 1, tzinfo=timezone.utc),
            until=datetime(2025, 6, 2, tzinfo=timezone.utc),
        )

    assert len(events) == 1
    e = events[0]
    assert e.app_name == "OpenAI ChatGPT"
    assert e.app_id == "app-uuid-123"
    assert e.event_type == "access"
    assert e.idp_provider == "azure_ad"


def test_failed_signins_excluded():
    """status.errorCode != 0 → skip."""
    conn = make_azure_connection()
    connector = AzureADConnector(conn, settings)

    mock_data = {
        "value": [
            {
                "appDisplayName": "App1",
                "appId": "a1",
                "createdDateTime": "2025-06-01T12:00:00Z",
                "status": {"errorCode": 50126},
                "userPrincipalName": "user@company.com",
            },
            {
                "appDisplayName": "App2",
                "appId": "a2",
                "createdDateTime": "2025-06-01T13:00:00Z",
                "status": {"errorCode": 0},
                "userPrincipalName": "user2@company.com",
            },
        ]
    }

    with patch("app.services.idp_connectors.azure_ad.httpx.get") as mock_get:
        mock_get.return_value = MockResponse(mock_data)
        events = connector.fetch_oauth_events(
            since=datetime(2025, 6, 1, tzinfo=timezone.utc),
            until=datetime(2025, 6, 2, tzinfo=timezone.utc),
        )

    assert len(events) == 1
    assert events[0].app_name == "App2"


def test_actor_id_is_hashed():
    """Raw email never in OAuthEvent.actor_id, SHA256 hash present."""
    conn = make_azure_connection()
    connector = AzureADConnector(conn, settings)

    email = "user@company.com"
    expected_hash = hashlib.sha256(email.encode()).hexdigest()

    mock_data = {
        "value": [
            {
                "appDisplayName": "App1",
                "appId": "a1",
                "createdDateTime": "2025-06-01T12:00:00Z",
                "status": {"errorCode": 0},
                "userPrincipalName": email,
            }
        ]
    }

    with patch("app.services.idp_connectors.azure_ad.httpx.get") as mock_get:
        mock_get.return_value = MockResponse(mock_data)
        events = connector.fetch_oauth_events(
            since=datetime(2025, 6, 1, tzinfo=timezone.utc),
            until=datetime(2025, 6, 2, tzinfo=timezone.utc),
        )

    assert len(events) == 1
    assert events[0].actor_id == expected_hash
    assert "@" not in (events[0].actor_id or "")
    assert events[0].actor_id != email


def test_pagination_follows_odata_next_link():
    """Mock two pages via @odata.nextLink."""
    conn = make_azure_connection()
    connector = AzureADConnector(conn, settings)

    page1 = {
        "value": [
            {
                "appDisplayName": "App1",
                "appId": "a1",
                "createdDateTime": "2025-06-01T12:00:00Z",
                "status": {"errorCode": 0},
            }
        ],
        "@odata.nextLink": "https://graph.microsoft.com/v1.0/auditLogs/signIns?$skip=1000",
    }
    page2 = {
        "value": [
            {
                "appDisplayName": "App2",
                "appId": "a2",
                "createdDateTime": "2025-06-01T13:00:00Z",
                "status": {"errorCode": 0},
            }
        ]
    }

    with patch("app.services.idp_connectors.azure_ad.httpx.get") as mock_get:
        mock_get.side_effect = [MockResponse(page1), MockResponse(page2)]
        events = connector.fetch_oauth_events(
            since=datetime(2025, 6, 1, tzinfo=timezone.utc),
            until=datetime(2025, 6, 2, tzinfo=timezone.utc),
        )

    assert len(events) == 2
    assert events[0].app_name == "App1"
    assert events[1].app_name == "App2"
    assert mock_get.call_count == 2


def test_scope_list_is_empty_for_signins():
    """Azure signIn endpoint doesn't return scopes — verify oauth_scopes=[]."""
    conn = make_azure_connection()
    connector = AzureADConnector(conn, settings)

    mock_data = {
        "value": [
            {
                "appDisplayName": "App1",
                "appId": "a1",
                "createdDateTime": "2025-06-01T12:00:00Z",
                "status": {"errorCode": 0},
                "userPrincipalName": "user@company.com",
            }
        ]
    }

    with patch("app.services.idp_connectors.azure_ad.httpx.get") as mock_get:
        mock_get.return_value = MockResponse(mock_data)
        events = connector.fetch_oauth_events(
            since=datetime(2025, 6, 1, tzinfo=timezone.utc),
            until=datetime(2025, 6, 2, tzinfo=timezone.utc),
        )

    assert len(events) == 1
    assert events[0].oauth_scopes == []
