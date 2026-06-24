"""
Integration tests for dark AI side channel detection via Tier 3 ingest.
"""

from datetime import datetime, timedelta, timezone
from uuid import UUID

from sqlalchemy import select

from app.models.detection import ShadowAIDetection

ORG_ID = UUID("11111111-1111-1111-1111-111111111111")


def _now():
    return datetime.now(timezone.utc)


def _make_signal_dict(
    hostname: str = "proxy.company.internal",
    matched_tool: str = "OpenAI API",
    call_count_24h: int = 250,
    include_timing: bool = True,
):
    now = _now()
    signal = {
        "org_id": str(ORG_ID),
        "signal_type": "network_match",
        "matched_tool": matched_tool,
        "hostname_pattern": hostname,
        "call_count_24h": call_count_24h,
        "source_system_label": "test-vpc-flow",
        "first_seen": (now - timedelta(hours=1)).isoformat(),
        "last_seen": now.isoformat(),
        "connector_version": "1.0.0",
    }
    if include_timing:
        signal.update(
            {
                "avg_response_time_ms": 800,
                "response_time_variance_ms": 1200,
                "avg_request_bytes": 100,
                "avg_response_bytes": 8000,
                "connection_reuse_ratio": 0.9,
                "inter_request_gap_ms": 12000,
            }
        )
    return signal


def _generate_connector_token(client):
    resp = client.post(
        "/api/v1/shadow-ai/connector/tokens",
        json={"label": "phase10-test", "expires_in_days": 1},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["token"]


def test_proxied_traffic_with_timing_data(client, seeded_db):
    """Known AI traffic through a proxy hostname creates a dark AI detection."""
    raw_token = _generate_connector_token(client)

    resp = client.post(
        "/api/v1/shadow-ai/connector/ingest",
        json=_make_signal_dict(hostname="proxy.company.internal"),
        headers={"X-Connector-Token": raw_token},
    )
    assert resp.status_code == 200, resp.text

    detection = seeded_db.execute(
        select(ShadowAIDetection).where(
            ShadowAIDetection.organization_id == ORG_ID,
            ShadowAIDetection.is_dark_ai.is_(True),
        )
    ).scalar_one_or_none()
    assert detection is not None
    assert detection.detection_method == "dark_ai_side_channel"
    assert detection.dark_ai_proxy_detected is True
    assert float(detection.dark_ai_score) >= 0.60


def test_timing_only_unknown_hostname(client, seeded_db):
    """Unknown hostname with strong timing creates both zero-day and dark AI detections."""
    raw_token = _generate_connector_token(client)

    resp = client.post(
        "/api/v1/shadow-ai/connector/ingest",
        json=_make_signal_dict(
            hostname="dark.unknown.ai",
            matched_tool="UnknownAITool",
        ),
        headers={"X-Connector-Token": raw_token},
    )
    assert resp.status_code == 200, resp.text

    zero_day = seeded_db.execute(
        select(ShadowAIDetection).where(
            ShadowAIDetection.organization_id == ORG_ID,
            ShadowAIDetection.is_zero_day.is_(True),
        )
    ).scalar_one_or_none()
    assert zero_day is not None

    dark_ai = seeded_db.execute(
        select(ShadowAIDetection).where(
            ShadowAIDetection.organization_id == ORG_ID,
            ShadowAIDetection.is_dark_ai.is_(True),
        )
    ).scalar_one_or_none()
    assert dark_ai is not None
    assert dark_ai.detection_method == "dark_ai_side_channel"


def test_dark_ai_detection_in_list(client, seeded_db):
    """GET /detections surfaces is_dark_ai flag."""
    raw_token = _generate_connector_token(client)
    client.post(
        "/api/v1/shadow-ai/connector/ingest",
        json=_make_signal_dict(hostname="proxy.list.ai"),
        headers={"X-Connector-Token": raw_token},
    )

    resp = client.get("/api/v1/shadow-ai/detections")
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert any(item.get("is_dark_ai") is True for item in data["items"])


def test_dark_ai_jurisdiction_assessed(client, seeded_db):
    """Dark AI detections receive jurisdiction assessment like all others."""
    raw_token = _generate_connector_token(client)
    client.post(
        "/api/v1/shadow-ai/connector/ingest",
        json=_make_signal_dict(hostname="proxy.jurisdiction.ai"),
        headers={"X-Connector-Token": raw_token},
    )

    detection = seeded_db.execute(
        select(ShadowAIDetection).where(
            ShadowAIDetection.organization_id == ORG_ID,
            ShadowAIDetection.is_dark_ai.is_(True),
        )
    ).scalar_one_or_none()
    assert detection is not None
    assert detection.jurisdiction_assessed_at is not None
    assert detection.jurisdiction_assessment_json is not None


def test_status_endpoint_shows_dark_ai(client):
    """GET /shadow-ai/status lists dark_ai_side_channel as a detection method."""
    resp = client.get("/api/v1/shadow-ai/status")
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["patent_claims_implemented"] == 10
    assert data["build_phases_complete"] == 10
    assert "dark_ai_side_channel" in data["detection_methods"]


def test_trust_document_version_2_0(client):
    """GET /trust returns document_version 2.0.0."""
    resp = client.get("/api/v1/shadow-ai/trust")
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["document_version"] == "2.0.0"
    assert data["dark_ai_detection"]["payload_inspection"] is False
    assert data["dark_ai_detection"]["tls_decryption"] is False
    assert "federated_network" in data
