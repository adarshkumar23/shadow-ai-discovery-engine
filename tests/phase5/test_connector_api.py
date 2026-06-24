"""
Tests for the connector API endpoints.

Tests both user-authenticated endpoints (token management, status)
and token-authenticated endpoints (ingest, heartbeat).
"""

import json
from datetime import datetime, timedelta, timezone
from uuid import UUID

from sqlalchemy import select

from app.core.database import get_db
from app.main import app
from app.models.detection import ConnectorHeartbeat, ConnectorToken
from tests.conftest import ACME_ADMIN_ID, ACME_ORG_ID

ORG_ID = ACME_ORG_ID
USER_ID = ACME_ADMIN_ID


def _create_token_via_api(client, label="test-connector"):
    """Generate a connector token via the API. Returns (raw_token, token_id)."""
    response = client.post(
        "/api/v1/shadow-ai/connector/tokens",
        json={"label": label, "expires_in_days": 365},
    )
    assert response.status_code == 200, response.text
    data = response.json()
    return data["token"], UUID(data["token_id"])


def _make_signal(org_id=ORG_ID, **overrides):
    """Build a valid signal payload dict for the ingest API."""
    now = datetime.now(timezone.utc)
    payload = {
        "org_id": str(org_id),
        "signal_type": "network_match",
        "matched_tool": "OpenAI API",
        "hostname_pattern": "api.openai.com",
        "call_count_24h": 5,
        "source_system_label": "test-vpc-flow",
        "first_seen": (now - timedelta(hours=1)).isoformat(),
        "last_seen": now.isoformat(),
        "connector_version": "1.0.0",
    }
    payload.update(overrides)
    return payload


# ═══════════════════════════════════════════════
# USER-AUTHENTICATED ENDPOINT TESTS
# ═══════════════════════════════════════════════


def test_generate_token_endpoint(client, seeded_db):
    """POST /connector/tokens returns a raw token and token_id."""
    raw_token, token_id = _create_token_via_api(client, "api-test")
    assert raw_token is not None
    assert len(raw_token) > 20
    assert token_id is not None


def test_token_shown_once_in_response(client, seeded_db):
    """The raw token appears in the creation response but not in list."""
    raw_token, token_id = _create_token_via_api(client, "once-only")

    list_resp = client.get("/api/v1/shadow-ai/connector/tokens")
    assert list_resp.status_code == 200
    tokens = list_resp.json()
    assert len(tokens) == 1
    assert "token" not in tokens[0]
    assert "token_hash" not in tokens[0]
    assert tokens[0]["label"] == "once-only"


def test_revoke_token_endpoint(client, seeded_db):
    """DELETE /connector/tokens/{id} revokes the token."""
    raw_token, token_id = _create_token_via_api(client, "to-revoke")

    resp = client.delete(f"/api/v1/shadow-ai/connector/tokens/{token_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["is_active"] is False
    assert data["revoked_at"] is not None


def test_connector_status_online_offline(client, seeded_db):
    """GET /connector/status returns aggregated status."""
    raw_token, token_id = _create_token_via_api(client, "status-test")

    resp = client.get("/api/v1/shadow-ai/connector/status")
    assert resp.status_code == 200
    data = resp.json()
    assert "active_tokens" in data
    assert "total_tokens" in data
    assert "connectors_online" in data
    assert "connectors_offline" in data
    assert data["active_tokens"] >= 1


# ═══════════════════════════════════════════════
# TOKEN-AUTHENTICATED ENDPOINT TESTS
# ═══════════════════════════════════════════════


def test_ingest_valid_signal_200(client, seeded_db):
    """POST /connector/ingest with a valid signal returns 200."""
    raw_token, _ = _create_token_via_api(client, "ingest-test")

    resp = client.post(
        "/api/v1/shadow-ai/connector/ingest",
        json=_make_signal(),
        headers={"X-Connector-Token": raw_token},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["accepted"] is True
    assert data["duplicate"] is False
    assert data["signal_id"] is not None


def test_ingest_forbidden_field_400(client, seeded_db):
    """POST /connector/ingest with 'raw_log' field returns 400 naming the field."""
    raw_token, _ = _create_token_via_api(client, "forbidden-test")

    payload = _make_signal()
    payload["raw_log"] = "sensitive raw log data"

    resp = client.post(
        "/api/v1/shadow-ai/connector/ingest",
        json=payload,
        headers={"X-Connector-Token": raw_token},
    )
    assert resp.status_code == 400
    body = resp.json()
    assert "raw_log" in json.dumps(body)


def test_ingest_without_token_401(client, seeded_db):
    """POST /connector/ingest without X-Connector-Token returns 401."""
    resp = client.post(
        "/api/v1/shadow-ai/connector/ingest",
        json=_make_signal(),
    )
    assert resp.status_code == 401


def test_ingest_rate_limit_429(client, seeded_db):
    """After 1000 requests in an hour, the next returns 429."""
    raw_token, token_id = _create_token_via_api(client, "rate-limit-test")

    token = seeded_db.execute(
        select(ConnectorToken).where(ConnectorToken.id == token_id)
    ).scalar_one()
    token.requests_this_hour = 1000
    token.hour_window_start = datetime.now(timezone.utc)
    seeded_db.commit()

    resp = client.post(
        "/api/v1/shadow-ai/connector/ingest",
        json=_make_signal(),
        headers={"X-Connector-Token": raw_token},
    )
    assert resp.status_code == 429
    assert "Retry-After" in resp.headers


def test_heartbeat_creates_record(client, seeded_db):
    """POST /connector/heartbeat creates a heartbeat record."""
    raw_token, token_id = _create_token_via_api(client, "hb-test")

    resp = client.post(
        "/api/v1/shadow-ai/connector/heartbeat",
        json={
            "connector_version": "1.0.0",
            "signals_last_hour": 5,
            "sources_active": ["vpc_flow"],
            "status": "online",
        },
        headers={"X-Connector-Token": raw_token},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["status"] == "online"
    assert data["signals_last_hour"] == 5

    heartbeats = seeded_db.execute(
        select(ConnectorHeartbeat).where(
            ConnectorHeartbeat.token_id == token_id
        )
    ).scalars().all()
    assert len(heartbeats) == 1


def test_heartbeat_replaces_previous(client, seeded_db):
    """Sending two heartbeats results in only one record in the DB."""
    raw_token, token_id = _create_token_via_api(client, "hb-replace")

    for i in range(2):
        resp = client.post(
            "/api/v1/shadow-ai/connector/heartbeat",
            json={
                "connector_version": "1.0.0",
                "signals_last_hour": i,
                "sources_active": ["vpc_flow"],
                "status": "online",
            },
            headers={"X-Connector-Token": raw_token},
        )
        assert resp.status_code == 200

    heartbeats = seeded_db.execute(
        select(ConnectorHeartbeat).where(
            ConnectorHeartbeat.token_id == token_id
        )
    ).scalars().all()
    assert len(heartbeats) == 1
    assert heartbeats[0].signals_last_hour == 1


# ═══════════════════════════════════════════════
# NO-AUTH ENDPOINT TESTS
# ═══════════════════════════════════════════════


def test_schema_endpoint_no_auth(test_db):
    """GET /connector/schema requires no authentication."""
    def override_get_db():
        yield test_db

    app.dependency_overrides[get_db] = override_get_db
    try:
        from fastapi.testclient import TestClient

        with TestClient(app) as c:
            resp = c.get("/api/v1/shadow-ai/connector/schema")
            assert resp.status_code == 200
            data = resp.json()
            assert data["schema_version"] == "1.0.0"
            assert data["endpoint"] == "POST /connector/ingest"
            assert data["authentication"] == "X-Connector-Token header"
    finally:
        app.dependency_overrides.clear()


def test_schema_contains_forbidden_fields(test_db):
    """The schema endpoint lists all forbidden fields."""
    def override_get_db():
        yield test_db

    app.dependency_overrides[get_db] = override_get_db
    try:
        from fastapi.testclient import TestClient

        with TestClient(app) as c:
            resp = c.get("/api/v1/shadow-ai/connector/schema")
            assert resp.status_code == 200
            data = resp.json()
            forbidden = data["forbidden_fields"]
            assert "raw_log" in forbidden
            assert "ip_address" in forbidden
            assert "user_id" in forbidden
            assert "http_headers" in forbidden
            assert len(forbidden) == 15
    finally:
        app.dependency_overrides.clear()
