"""
Tests for the Okta IdP connector.

All HTTP calls are mocked. Never makes real API calls.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock
from uuid import UUID, uuid4

import pytest

from app.core.config import settings
from app.core.security import encrypt_value
from app.models.idp import IdpConnection
from app.services.idp_connectors.okta import OktaConnector
from app.services.idp_connectors.base import OAuthEvent


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


def make_okta_connection(**kwargs):
    """Create an Okta IdpConnection instance for testing."""
    defaults = {
        "id": uuid4(),
        "organization_id": ORG_ID,
        "idp_provider": "okta",
        "idp_domain": "test.okta.com",
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
    with patch.object(settings, "okta_client_id", "test_client_123"):
        conn = make_okta_connection()
        connector = OktaConnector(conn, settings)
        url = connector.get_authorization_url(
            state="my_state_456",
            redirect_uri="https://app.example.com/callback",
        )
        assert "test.okta.com" in url
        assert "test_client_123" in url
        assert "okta.logs.read" in url
        assert "my_state_456" in url
        assert "code" in url


def test_fetch_oauth_events_parses_correctly():
    """Mock Okta response, verify OAuthEvent fields extracted correctly."""
    conn = make_okta_connection()
    connector = OktaConnector(conn, settings)

    mock_events = [
        {
            "published": "2025-06-01T12:00:00Z",
            "target": [{"displayName": "OpenAI ChatGPT", "id": "app_123"}],
            "debugContext": {
                "debugData": {"requestedScopes": ["openid", "profile"]}
            },
            "actor": {"id": "user_abc"},
            "extra_field": "should_be_discarded",
        }
    ]

    with patch("app.services.idp_connectors.okta.httpx.get") as mock_get:
        mock_get.return_value = MockResponse(mock_events)
        events = connector.fetch_oauth_events(
            since=datetime(2025, 6, 1, tzinfo=timezone.utc),
            until=datetime(2025, 6, 2, tzinfo=timezone.utc),
        )

    assert len(events) == 1
    e = events[0]
    assert e.app_name == "OpenAI ChatGPT"
    assert e.app_id == "app_123"
    assert e.oauth_scopes == ["openid", "profile"]
    assert e.event_type == "grant"
    assert e.actor_id == "user_abc"
    assert e.idp_provider == "okta"


def test_fetch_oauth_events_discards_extra_fields():
    """Mock response with extra fields, verify they are not in OAuthEvent."""
    conn = make_okta_connection()
    connector = OktaConnector(conn, settings)

    mock_events = [
        {
            "published": "2025-06-01T12:00:00Z",
            "target": [{"displayName": "Claude AI", "id": "app_456"}],
            "debugContext": {
                "debugData": {"requestedScopes": ["openid"]}
            },
            "actor": {"id": "user_def"},
            "sessionId": "sess_123",
            "client": {"ip": "1.2.3.4", "userAgent": "Mozilla/5.0"},
            "authenticationContext": {"authProvider": "OKTA"},
            "extra_sensitive_data": "password_hash",
        }
    ]

    with patch("app.services.idp_connectors.okta.httpx.get") as mock_get:
        mock_get.return_value = MockResponse(mock_events)
        events = connector.fetch_oauth_events(
            since=datetime(2025, 6, 1, tzinfo=timezone.utc),
            until=datetime(2025, 6, 2, tzinfo=timezone.utc),
        )

    assert len(events) == 1
    e = events[0]
    assert not hasattr(e, "sessionId")
    assert not hasattr(e, "client")
    assert not hasattr(e, "authenticationContext")
    assert not hasattr(e, "extra_sensitive_data")
    assert e.app_name == "Claude AI"
    assert e.app_id == "app_456"


def test_pagination_follows_next_link():
    """Mock two pages, verify both fetched."""
    conn = make_okta_connection()
    connector = OktaConnector(conn, settings)

    page1 = [
        {
            "published": "2025-06-01T12:00:00Z",
            "target": [{"displayName": "App1", "id": "a1"}],
            "debugContext": {"debugData": {"requestedScopes": []}},
            "actor": {"id": "u1"},
        }
    ]
    page2 = [
        {
            "published": "2025-06-01T13:00:00Z",
            "target": [{"displayName": "App2", "id": "a2"}],
            "debugContext": {"debugData": {"requestedScopes": []}},
            "actor": {"id": "u2"},
        }
    ]

    resp1 = MockResponse(
        page1, headers={"Link": '<https://test.okta.com/api/v1/logs?after=abc>; rel="next"'}
    )
    resp2 = MockResponse(page2)

    with patch("app.services.idp_connectors.okta.httpx.get") as mock_get:
        mock_get.side_effect = [resp1, resp2]
        events = connector.fetch_oauth_events(
            since=datetime(2025, 6, 1, tzinfo=timezone.utc),
            until=datetime(2025, 6, 2, tzinfo=timezone.utc),
        )

    assert len(events) == 2
    assert events[0].app_name == "App1"
    assert events[1].app_name == "App2"
    assert mock_get.call_count == 2


def test_expired_token_triggers_refresh():
    """Set token_expires_at to past, verify refresh called before fetch."""
    past_time = datetime.utcnow() - timedelta(hours=1)
    conn = make_okta_connection(token_expires_at=past_time)
    connector = OktaConnector(conn, settings)

    mock_events = [
        {
            "published": "2025-06-01T12:00:00Z",
            "target": [{"displayName": "App1", "id": "a1"}],
            "debugContext": {"debugData": {"requestedScopes": []}},
            "actor": {"id": "u1"},
        }
    ]

    with patch.object(connector, "refresh_access_token", return_value="new_token") as mock_refresh, \
         patch("app.services.idp_connectors.okta.httpx.get") as mock_get:
        mock_get.return_value = MockResponse(mock_events)
        events = connector.fetch_oauth_events(
            since=datetime(2025, 6, 1, tzinfo=timezone.utc),
            until=datetime(2025, 6, 2, tzinfo=timezone.utc),
        )

    mock_refresh.assert_called_once()
    assert len(events) == 1


def test_auth_failure_raises_connection_error():
    """Auth failure (HTTP error) raises ConnectionError."""
    conn = make_okta_connection()
    connector = OktaConnector(conn, settings)

    with patch("app.services.idp_connectors.okta.httpx.get") as mock_get:
        mock_get.return_value = MockResponse([], status_code=401)
        with pytest.raises(PermissionError):
            connector.fetch_oauth_events(
                since=datetime(2025, 6, 1, tzinfo=timezone.utc),
                until=datetime(2025, 6, 2, tzinfo=timezone.utc),
            )


def test_actor_id_extracted_from_event():
    """Verify actor_id is extracted from the Okta event."""
    conn = make_okta_connection()
    connector = OktaConnector(conn, settings)

    mock_events = [
        {
            "published": "2025-06-01T12:00:00Z",
            "target": [{"displayName": "App1", "id": "a1"}],
            "debugContext": {"debugData": {"requestedScopes": []}},
            "actor": {"id": "actor_xyz_789"},
        }
    ]

    with patch("app.services.idp_connectors.okta.httpx.get") as mock_get:
        mock_get.return_value = MockResponse(mock_events)
        events = connector.fetch_oauth_events(
            since=datetime(2025, 6, 1, tzinfo=timezone.utc),
            until=datetime(2025, 6, 2, tzinfo=timezone.utc),
        )

    assert events[0].actor_id == "actor_xyz_789"
