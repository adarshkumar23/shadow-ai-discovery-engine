"""
Integration tests for zero-day behavioral classification.

Tests the full flow from connector ingest through candidate creation,
API retrieval, review actions, and metrics.
"""

from datetime import datetime, timedelta, timezone
from uuid import UUID

from sqlalchemy import select

from app.models.detection import ShadowAIDetection
from app.models.signature import AISignatureRegistry
from app.models.suppression import SuppressedDetection
from app.models.zero_day import ZeroDayCandidate

ORG_ID = UUID("11111111-1111-1111-1111-111111111111")
USER_ID = UUID("11111111-1111-1111-1111-111111111101")


def _now():
    return datetime.now(timezone.utc)


def _make_signal_dict(
    hostname="api.unknownai.ai",
    matched_tool="UnknownAI",
    call_count_24h=250,
):
    now = _now()
    return {
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


def _generate_connector_token(client):
    resp = client.post(
        "/api/v1/shadow-ai/connector/tokens",
        json={"label": "phase6-test", "expires_in_days": 1},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["token"]


def test_ingest_unknown_hostname_triggers_classifier(client, seeded_db):
    """Ingest of an unknown AI-like hostname creates a zero-day candidate."""
    raw_token = _generate_connector_token(client)

    resp = client.post(
        "/api/v1/shadow-ai/connector/ingest",
        json=_make_signal_dict(),
        headers={"X-Connector-Token": raw_token},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["accepted"] is True
    assert data["duplicate"] is False

    candidate = seeded_db.execute(
        select(ZeroDayCandidate).where(ZeroDayCandidate.organization_id == ORG_ID)
    ).scalar_one_or_none()
    assert candidate is not None
    assert candidate.hostname == "api.unknownai.ai"


def test_ingest_known_hostname_skips_classifier(client, seeded_db):
    """Ingest of a known AI hostname creates a normal detection, no candidate."""
    raw_token = _generate_connector_token(client)

    resp = client.post(
        "/api/v1/shadow-ai/connector/ingest",
        json=_make_signal_dict(
            hostname="api.openai.com",
            matched_tool="OpenAI API",
            call_count_24h=100,
        ),
        headers={"X-Connector-Token": raw_token},
    )
    assert resp.status_code == 200, resp.text

    candidate = seeded_db.execute(
        select(ZeroDayCandidate).where(ZeroDayCandidate.organization_id == ORG_ID)
    ).scalar_one_or_none()
    assert candidate is None

    detection = seeded_db.execute(
        select(ShadowAIDetection).where(
            ShadowAIDetection.organization_id == ORG_ID,
            ShadowAIDetection.is_zero_day.is_(False),
        )
    ).scalar_one_or_none()
    assert detection is not None
    assert detection.signature_id is not None


def test_ingest_below_threshold_no_candidate(client, seeded_db):
    """Unknown hostname with low behavioral score does not create a candidate."""
    raw_token = _generate_connector_token(client)

    resp = client.post(
        "/api/v1/shadow-ai/connector/ingest",
        json=_make_signal_dict(
            hostname="cdn.example.com",
            matched_tool="cdnexample",
            call_count_24h=5,
        ),
        headers={"X-Connector-Token": raw_token},
    )
    assert resp.status_code == 200, resp.text

    candidate = seeded_db.execute(
        select(ZeroDayCandidate).where(ZeroDayCandidate.organization_id == ORG_ID)
    ).scalar_one_or_none()
    assert candidate is None


def test_zero_day_endpoint_returns_candidates(client, seeded_db):
    """GET /detections/zero-day/candidates returns created candidates."""
    raw_token = _generate_connector_token(client)
    client.post(
        "/api/v1/shadow-ai/connector/ingest",
        json=_make_signal_dict(),
        headers={"X-Connector-Token": raw_token},
    )

    resp = client.get("/api/v1/shadow-ai/detections/zero-day/candidates")
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert len(data) >= 1
    assert data[0]["hostname"] == "api.unknownai.ai"
    assert data[0]["status"] == "pending_review"


def test_review_endpoint_add_to_registry(client, seeded_db):
    """POST review with add_to_registry creates a signature."""
    raw_token = _generate_connector_token(client)
    client.post(
        "/api/v1/shadow-ai/connector/ingest",
        json=_make_signal_dict(),
        headers={"X-Connector-Token": raw_token},
    )

    list_resp = client.get("/api/v1/shadow-ai/detections/zero-day/candidates")
    candidate = list_resp.json()[0]

    review_resp = client.post(
        f"/api/v1/shadow-ai/detections/zero-day/candidates/{candidate['id']}/review",
        json={
            "action": "add_to_registry",
            "provider_name": "Unknown AI Tool",
            "category": "llm",
            "review_notes": "Approved",
        },
    )
    assert review_resp.status_code == 200, review_resp.text
    assert review_resp.json()["status"] == "added_to_registry"

    signature = seeded_db.execute(
        select(AISignatureRegistry).where(
            AISignatureRegistry.provider_name == "Unknown AI Tool"
        )
    ).scalar_one_or_none()
    assert signature is not None
    assert signature.category == "llm"


def test_review_endpoint_dismiss(client, seeded_db):
    """POST review with dismiss creates a suppression."""
    raw_token = _generate_connector_token(client)
    client.post(
        "/api/v1/shadow-ai/connector/ingest",
        json=_make_signal_dict(hostname="api.dismissme.ai"),
        headers={"X-Connector-Token": raw_token},
    )

    list_resp = client.get("/api/v1/shadow-ai/detections/zero-day/candidates")
    candidate = next(
        c for c in list_resp.json() if c["hostname"] == "api.dismissme.ai"
    )

    review_resp = client.post(
        f"/api/v1/shadow-ai/detections/zero-day/candidates/{candidate['id']}/review",
        json={
            "action": "dismiss",
            "review_notes": "False positive",
        },
    )
    assert review_resp.status_code == 200, review_resp.text
    assert review_resp.json()["status"] == "dismissed"

    suppression = seeded_db.execute(
        select(SuppressedDetection).where(
            SuppressedDetection.organization_id == ORG_ID,
            SuppressedDetection.detection_method == "behavioral_inference",
        )
    ).scalar_one_or_none()
    assert suppression is not None


def test_review_endpoint_monitor(client, seeded_db):
    """POST review with monitor sets status to monitoring."""
    raw_token = _generate_connector_token(client)
    client.post(
        "/api/v1/shadow-ai/connector/ingest",
        json=_make_signal_dict(hostname="api.monitorthis.ai"),
        headers={"X-Connector-Token": raw_token},
    )

    list_resp = client.get("/api/v1/shadow-ai/detections/zero-day/candidates")
    candidate = next(
        c for c in list_resp.json() if c["hostname"] == "api.monitorthis.ai"
    )

    review_resp = client.post(
        f"/api/v1/shadow-ai/detections/zero-day/candidates/{candidate['id']}/review",
        json={
            "action": "monitor",
            "review_notes": "Keep watching",
        },
    )
    assert review_resp.status_code == 200, review_resp.text
    assert review_resp.json()["status"] == "monitoring"


def test_metrics_includes_zero_day_count(client, seeded_db):
    """GET /metrics includes zero_day_candidates_pending count."""
    raw_token = _generate_connector_token(client)
    client.post(
        "/api/v1/shadow-ai/connector/ingest",
        json=_make_signal_dict(hostname="api.metrics.ai"),
        headers={"X-Connector-Token": raw_token},
    )

    resp = client.get("/api/v1/shadow-ai/metrics")
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert "zero_day_candidates_pending" in data
    assert data["zero_day_candidates_pending"] >= 1


def test_zero_day_detection_basis_json_has_features(client, seeded_db):
    """Zero-day detections populated via ingest have feature JSON."""
    raw_token = _generate_connector_token(client)
    client.post(
        "/api/v1/shadow-ai/connector/ingest",
        json=_make_signal_dict(),
        headers={"X-Connector-Token": raw_token},
    )

    detection = seeded_db.execute(
        select(ShadowAIDetection).where(
            ShadowAIDetection.organization_id == ORG_ID,
            ShadowAIDetection.is_zero_day.is_(True),
        )
    ).scalar_one()

    assert detection.behavioral_features_json is not None
    assert detection.classifier_version == "1.0.0"
    assert detection.zero_day_hostname == "api.unknownai.ai"
