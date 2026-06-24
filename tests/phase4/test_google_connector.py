"""
Tests for the Google Workspace IdP connector.

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
from app.services.idp_connectors.google_ws import GoogleWSConnector


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


def make_google_connection(**kwargs):
    """Create a Google WS IdpConnection instance for testing."""
    defaults = {
        "id": uuid4(),
        "organization_id": ORG_ID,
        "idp_provider": "google_ws",
        "idp_domain": None,
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


def test_authorization_url_contains_offline_access():
    """Verify URL contains access_type=offline and correct scope."""
    with patch.object(settings, "google_client_id", "google_client_123"):
        conn = make_google_connection()
        connector = GoogleWSConnector(conn, settings)
        url = connector.get_authorization_url(
            state="my_state_g",
            redirect_uri="https://app.example.com/callback",
        )
        assert "accounts.google.com" in url
        assert "google_client_123" in url
        assert "admin.reports.audit.readonly" in url
        assert "access_type=offline" in url
        assert "prompt=consent" in url
        assert "my_state_g" in url


def test_fetch_token_events_parses_correctly():
    """Mock Google response, verify OAuthEvent fields extracted."""
    conn = make_google_connection()
    connector = GoogleWSConnector(conn, settings)

    mock_data = {
        "items": [
            {
                "id": {"time": "2025-06-01T12:00:00.000Z"},
                "actor": {"email": "admin@company.com"},
                "events": [
                    {
                        "name": "authorize",
                        "parameters": [
                            {"name": "app_name", "value": "OpenAI ChatGPT"},
                            {"name": "client_id", "value": "gapp_123"},
                            {
                                "name": "scope",
                                "multiValue": ["openid", "profile"],
                            },
                        ],
                    }
                ],
            }
        ]
    }

    with patch("app.services.idp_connectors.google_ws.httpx.get") as mock_get:
        mock_get.return_value = MockResponse(mock_data)
        events = connector.fetch_oauth_events(
            since=datetime(2025, 6, 1, tzinfo=timezone.utc),
            until=datetime(2025, 6, 2, tzinfo=timezone.utc),
        )

    assert len(events) == 1
    e = events[0]
    assert e.app_name == "OpenAI ChatGPT"
    assert e.app_id == "gapp_123"
    assert e.oauth_scopes == ["openid", "profile"]
    assert e.event_type == "grant"
    assert e.idp_provider == "google_ws"


def test_actor_email_is_hashed():
    """Raw email never stored; SHA256 hash present."""
    conn = make_google_connection()
    connector = GoogleWSConnector(conn, settings)

    email = "admin@company.com"
    expected_hash = hashlib.sha256(email.encode()).hexdigest()

    mock_data = {
        "items": [
            {
                "id": {"time": "2025-06-01T12:00:00.000Z"},
                "actor": {"email": email},
                "events": [
                    {
                        "name": "authorize",
                        "parameters": [
                            {"name": "app_name", "value": "App1"},
                        ],
                    }
                ],
            }
        ]
    }

    with patch("app.services.idp_connectors.google_ws.httpx.get") as mock_get:
        mock_get.return_value = MockResponse(mock_data)
        events = connector.fetch_oauth_events(
            since=datetime(2025, 6, 1, tzinfo=timezone.utc),
            until=datetime(2025, 6, 2, tzinfo=timezone.utc),
        )

    assert len(events) == 1
    assert events[0].actor_id == expected_hash
    assert "@" not in (events[0].actor_id or "")
    assert events[0].actor_id != email


def test_scope_list_extracted_from_parameters():
    """Verify scopes are extracted from parameters multiValue."""
    conn = make_google_connection()
    connector = GoogleWSConnector(conn, settings)

    mock_data = {
        "items": [
            {
                "id": {"time": "2025-06-01T12:00:00.000Z"},
                "actor": {"email": "user@company.com"},
                "events": [
                    {
                        "name": "authorize",
                        "parameters": [
                            {"name": "app_name", "value": "App1"},
                            {"name": "client_id", "value": "cid"},
                            {
                                "name": "scope",
                                "multiValue": [
                                    "https://www.googleapis.com/auth/userinfo.email",
                                    "openid",
                                ],
                            },
                        ],
                    }
                ],
            }
        ]
    }

    with patch("app.services.idp_connectors.google_ws.httpx.get") as mock_get:
        mock_get.return_value = MockResponse(mock_data)
        events = connector.fetch_oauth_events(
            since=datetime(2025, 6, 1, tzinfo=timezone.utc),
            until=datetime(2025, 6, 2, tzinfo=timezone.utc),
        )

    assert len(events) == 1
    assert len(events[0].oauth_scopes) == 2
    assert "openid" in events[0].oauth_scopes


def test_pagination_handles_next_page_token():
    """Mock two pages via nextPageToken."""
    conn = make_google_connection()
    connector = GoogleWSConnector(conn, settings)

    page1 = {
        "items": [
            {
                "id": {"time": "2025-06-01T12:00:00.000Z"},
                "actor": {"email": "u1@company.com"},
                "events": [
                    {
                        "name": "authorize",
                        "parameters": [{"name": "app_name", "value": "App1"}],
                    }
                ],
            }
        ],
        "nextPageToken": "token_abc",
    }
    page2 = {
        "items": [
            {
                "id": {"time": "2025-06-01T13:00:00.000Z"},
                "actor": {"email": "u2@company.com"},
                "events": [
                    {
                        "name": "authorize",
                        "parameters": [{"name": "app_name", "value": "App2"}],
                    }
                ],
            }
        ]
    }

    with patch("app.services.idp_connectors.google_ws.httpx.get") as mock_get:
        mock_get.side_effect = [MockResponse(page1), MockResponse(page2)]
        events = connector.fetch_oauth_events(
            since=datetime(2025, 6, 1, tzinfo=timezone.utc),
            until=datetime(2025, 6, 2, tzinfo=timezone.utc),
        )

    assert len(events) == 2
    assert events[0].app_name == "App1"
    assert events[1].app_name == "App2"
    assert mock_get.call_count == 2


def test_only_authorize_events_are_grants():
    """event_type='grant' for authorize, 'access' for others."""
    conn = make_google_connection()
    connector = GoogleWSConnector(conn, settings)

    mock_data = {
        "items": [
            {
                "id": {"time": "2025-06-01T12:00:00.000Z"},
                "actor": {"email": "u1@company.com"},
                "events": [
                    {
                        "name": "authorize",
                        "parameters": [{"name": "app_name", "value": "App1"}],
                    },
                    {
                        "name": "revoke",
                        "parameters": [{"name": "app_name", "value": "App2"}],
                    },
                ],
            }
        ]
    }

    with patch("app.services.idp_connectors.google_ws.httpx.get") as mock_get:
        mock_get.return_value = MockResponse(mock_data)
        events = connector.fetch_oauth_events(
            since=datetime(2025, 6, 1, tzinfo=timezone.utc),
            until=datetime(2025, 6, 2, tzinfo=timezone.utc),
        )

    assert len(events) == 2
    grant_events = [e for e in events if e.event_type == "grant"]
    access_events = [e for e in events if e.event_type == "access"]
    assert len(grant_events) == 1
    assert len(access_events) == 1
    assert grant_events[0].app_name == "App1"
    assert access_events[0].app_name == "App2"
