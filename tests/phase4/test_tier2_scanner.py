"""
Tests for the Tier 2 IdP scanner.

All connector HTTP calls are mocked. Never makes real API calls.
"""

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select

from app.core.security import encrypt_value
from app.models.idp import IdpConnection, IdpSyncLog
from app.models.telemetry import TelemetryEvent
from app.services.idp_connectors.base import OAuthEvent
from app.services.tier2_scanner import Tier2Scanner
from tests.conftest import make_signature

ORG_ID = UUID("11111111-1111-1111-1111-111111111111")
WRONG_ORG_ID = UUID("99999999-9999-9999-9999-999999999999")
USER_ID = UUID("11111111-1111-1111-1111-111111111101")


def make_idp_connection(db, provider="okta", **kwargs):
    """Create and persist an IdpConnection for testing."""
    defaults = {
        "id": uuid4(),
        "organization_id": ORG_ID,
        "idp_provider": provider,
        "idp_domain": "test.okta.com" if provider == "okta" else "tenant-123",
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
    conn = IdpConnection(**defaults)
    db.add(conn)
    db.commit()
    return conn


def make_oauth_event(
    app_name="OpenAI ChatGPT",
    app_id="app_123",
    actor_id="hash_abc",
    event_type="grant",
    days_ago=0,
):
    """Create an OAuthEvent for testing."""
    return OAuthEvent(
        app_name=app_name,
        app_id=app_id,
        oauth_scopes=["openid", "profile"],
        event_time=datetime.now(timezone.utc) - timedelta(days=days_ago),
        event_type=event_type,
        actor_id=actor_id,
        idp_provider="okta",
    )


def _mock_connector(events):
    """Create a mock connector that returns the given events."""
    mock = MagicMock()
    mock.fetch_oauth_events.return_value = events
    return mock


def test_sync_creates_telemetry_events(test_db, seeded_db):
    """Mock connector returning 3 events, verify 3 telemetry_events created."""
    conn = make_idp_connection(seeded_db)
    sig = make_signature(seeded_db, slug="sync-test-1", provider_name="OpenAI ChatGPT")
    sig.oauth_app_patterns = json.dumps(["OpenAI ChatGPT"])
    seeded_db.commit()

    events = [make_oauth_event(days_ago=i) for i in range(3)]

    with patch.object(Tier2Scanner, "get_connector", return_value=_mock_connector(events)):
        Tier2Scanner.sync_connection(conn.id, ORG_ID, None, seeded_db)

    telemetry = seeded_db.execute(
        select(TelemetryEvent).where(
            TelemetryEvent.organization_id == ORG_ID,
            TelemetryEvent.tier == 2,
        )
    ).scalars().all()

    assert len(telemetry) == 3
    for t in telemetry:
        assert t.tier == 2
        assert t.event_type == "identity_match"
        assert t.source_system_label == "idp:okta"
        raw = json.loads(t.raw_signal_json)
        assert raw["app_name"] == "OpenAI ChatGPT"
        assert raw["idp_provider"] == "okta"


def test_duplicate_events_not_stored(test_db, seeded_db):
    """Same signal_hash → duplicate count incremented."""
    conn = make_idp_connection(seeded_db)
    sig = make_signature(seeded_db, slug="sync-test-dup", provider_name="OpenAI ChatGPT")
    sig.oauth_app_patterns = json.dumps(["OpenAI ChatGPT"])
    seeded_db.commit()

    events = [make_oauth_event(days_ago=i) for i in range(3)]

    with patch.object(Tier2Scanner, "get_connector", return_value=_mock_connector(events)):
        sync_log1 = Tier2Scanner.sync_connection(conn.id, ORG_ID, None, seeded_db)

    assert sync_log1.signals_created == 3
    assert sync_log1.signals_duplicate == 0

    # Second sync with same events → all duplicates
    with patch.object(Tier2Scanner, "get_connector", return_value=_mock_connector(events)):
        sync_log2 = Tier2Scanner.sync_connection(conn.id, ORG_ID, None, seeded_db)

    assert sync_log2.signals_duplicate == 3
    assert sync_log2.signals_created == 0


def test_sync_log_created_and_completed(test_db, seeded_db):
    """Verify sync log record has status='completed'."""
    conn = make_idp_connection(seeded_db)
    sig = make_signature(seeded_db, slug="sync-test-log", provider_name="OpenAI ChatGPT")
    sig.oauth_app_patterns = json.dumps(["OpenAI ChatGPT"])
    seeded_db.commit()

    events = [make_oauth_event()]

    with patch.object(Tier2Scanner, "get_connector", return_value=_mock_connector(events)):
        sync_log = Tier2Scanner.sync_connection(conn.id, ORG_ID, None, seeded_db)

    assert sync_log.status == "completed"
    assert sync_log.completed_at is not None
    assert sync_log.events_fetched == 1
    assert sync_log.events_matched == 1
    assert sync_log.signals_created == 1
    assert sync_log.idp_provider == "okta"


def test_sync_log_shows_failed_on_error(test_db, seeded_db):
    """ConnectionError → sync log status='failed'."""
    conn = make_idp_connection(seeded_db)
    sig = make_signature(seeded_db, slug="sync-test-fail", provider_name="OpenAI ChatGPT")
    sig.oauth_app_patterns = json.dumps(["OpenAI ChatGPT"])
    seeded_db.commit()

    mock_connector = MagicMock()
    mock_connector.fetch_oauth_events.side_effect = ConnectionError("Auth failed")

    with patch.object(Tier2Scanner, "get_connector", return_value=mock_connector):
        sync_log = Tier2Scanner.sync_connection(conn.id, ORG_ID, None, seeded_db)

    assert sync_log.status == "failed"
    assert sync_log.error_message is not None
    assert "Auth failed" in sync_log.error_message
    assert sync_log.completed_at is not None


def test_attribution_runs_after_sync(test_db, seeded_db):
    """Verify AttributionEngine.run_attribution_pass is called."""
    conn = make_idp_connection(seeded_db)
    sig = make_signature(seeded_db, slug="sync-test-attr", provider_name="OpenAI ChatGPT")
    sig.oauth_app_patterns = json.dumps(["OpenAI ChatGPT"])
    seeded_db.commit()

    events = [make_oauth_event(actor_id="a" * 64)]

    with patch.object(Tier2Scanner, "get_connector", return_value=_mock_connector(events)), \
         patch("app.services.tier2_scanner.AttributionEngine.run_attribution_pass") as mock_attr:
        mock_attr.return_value = {
            "detections_evaluated": 1,
            "detections_attributed": 0,
            "detections_no_attribution": 1,
        }
        Tier2Scanner.sync_connection(conn.id, ORG_ID, None, seeded_db)

    mock_attr.assert_called_once()


def test_token_never_logged(test_db, seeded_db):
    """Verify no token value appears in any log call."""
    conn = make_idp_connection(seeded_db)
    sig = make_signature(seeded_db, slug="sync-test-nolog", provider_name="OpenAI ChatGPT")
    sig.oauth_app_patterns = json.dumps(["OpenAI ChatGPT"])
    seeded_db.commit()

    events = [make_oauth_event()]

    with patch.object(Tier2Scanner, "get_connector", return_value=_mock_connector(events)), \
         patch("app.services.tier2_scanner.logger") as mock_logger:
        Tier2Scanner.sync_connection(conn.id, ORG_ID, None, seeded_db)

        token_value = "test_access_token"
        for call_args in mock_logger.debug.call_args_list + \
                         mock_logger.info.call_args_list + \
                         mock_logger.warning.call_args_list + \
                         mock_logger.error.call_args_list:
            call_str = str(call_args)
            assert token_value not in call_str, (
                f"Token value found in log call: {call_str}"
            )


def test_raw_idp_response_never_stored(test_db, seeded_db):
    """Verify raw_signal_json only contains OAuthEvent fields."""
    conn = make_idp_connection(seeded_db)
    sig = make_signature(seeded_db, slug="sync-test-raw", provider_name="OpenAI ChatGPT")
    sig.oauth_app_patterns = json.dumps(["OpenAI ChatGPT"])
    seeded_db.commit()

    events = [make_oauth_event()]

    with patch.object(Tier2Scanner, "get_connector", return_value=_mock_connector(events)):
        Tier2Scanner.sync_connection(conn.id, ORG_ID, None, seeded_db)

    telemetry = seeded_db.execute(
        select(TelemetryEvent).where(
            TelemetryEvent.organization_id == ORG_ID,
            TelemetryEvent.tier == 2,
        )
    ).scalars().all()

    allowed_keys = {
        "idp_provider", "app_name", "app_id",
        "oauth_scopes", "event_type", "actor_id",
    }
    for t in telemetry:
        raw = json.loads(t.raw_signal_json)
        assert set(raw.keys()) == allowed_keys, (
            f"Unexpected keys in raw_signal_json: {set(raw.keys()) - allowed_keys}"
        )


def test_wrong_org_raises_value_error(test_db, seeded_db):
    """Wrong org → ValueError."""
    conn = make_idp_connection(seeded_db)
    with pytest.raises(ValueError, match="does not belong"):
        Tier2Scanner.sync_connection(conn.id, WRONG_ORG_ID, None, seeded_db)
