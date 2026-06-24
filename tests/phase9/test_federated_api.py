"""
Tests for the Federated Registry Intelligence Network API endpoints.

Dependent Patent Claim 8.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID

from sqlalchemy import select

from app.core.database import get_db
from app.main import app
from app.models.detection import ConnectorToken
from app.models.federated import FederatedHostnameObservation
from app.models.signature import AISignatureRegistry
from app.services.tier3_ingestor import Tier3Ingestor
from tests.conftest import ACME_ADMIN_ID, ACME_ORG_ID

ORG_ID = ACME_ORG_ID
USER_ID = ACME_ADMIN_ID
HOSTNAME = "api.federated.example.com"


def _create_token_via_api(client, label="test-connector", enabled: bool = False):
    """Generate a connector token via the API."""
    response = client.post(
        "/api/v1/shadow-ai/connector/tokens",
        json={"label": label, "expires_in_days": 365},
    )
    assert response.status_code == 200, response.text
    data = response.json()
    token_id = UUID(data["token_id"])

    if enabled:
        enable_resp = client.post(
            f"/api/v1/shadow-ai/federated/tokens/{token_id}/enable"
        )
        assert enable_resp.status_code == 200, enable_resp.text

    return data["token"], token_id


def _submit(client, raw_token, hostname=HOSTNAME, score=0.75):
    return client.post(
        "/api/v1/shadow-ai/federated/submit",
        json={
            "hostname": hostname,
            "behavioral_score": score,
            "connector_version": "1.0.0",
        },
        headers={"X-Connector-Token": raw_token},
    )


def test_submit_requires_connector_token(client, seeded_db):
    """POST /federated/submit without X-Connector-Token returns 401."""
    resp = client.post(
        "/api/v1/shadow-ai/federated/submit",
        json={
            "hostname": HOSTNAME,
            "behavioral_score": 0.75,
            "connector_version": "1.0.0",
        },
    )
    assert resp.status_code == 401


def test_submit_disabled_token_returns_rejected(client, seeded_db):
    """Token with federated disabled returns accepted=False."""
    raw_token, _ = _create_token_via_api(client, "disabled-fed", enabled=False)

    resp = _submit(client, raw_token)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["accepted"] is False
    assert "not enabled" in data["message"]


def test_enable_federated_endpoint(client, seeded_db):
    """POST /federated/tokens/{id}/enable sets federated_submissions_enabled=True."""
    raw_token, token_id = _create_token_via_api(client, "enable-fed", enabled=False)

    resp = client.post(f"/api/v1/shadow-ai/federated/tokens/{token_id}/enable")
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["federated_submissions_enabled"] is True


def test_submit_after_enable_accepted(client, seeded_db):
    """After enabling, federated submission is accepted."""
    raw_token, _ = _create_token_via_api(client, "enabled-fed", enabled=True)

    resp = _submit(client, raw_token)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["accepted"] is True
    assert data["was_duplicate"] is False
    assert data["current_observation_count"] == 1


def test_list_candidates_requires_auth(test_db):
    """GET /federated/candidates requires auth headers."""
    from fastapi.testclient import TestClient

    def override_get_db():
        yield test_db

    app.dependency_overrides[get_db] = override_get_db
    try:
        with TestClient(app) as c:
            resp = c.get("/api/v1/shadow-ai/federated/candidates")
            assert resp.status_code in (400, 422)
    finally:
        app.dependency_overrides.clear()


def test_promote_candidate_creates_registry_entry(client, seeded_db):
    """POST .../promote creates an AISignatureRegistry entry."""
    org_b = UUID("22222222-2222-2222-2222-222222222222")
    org_c = UUID("33333333-3333-3333-3333-333333333333")

    # Create 3 tokens for 3 orgs and enable them.
    tokens = []
    for org_id in (ORG_ID, org_b, org_c):
        raw_token, token_record = Tier3Ingestor.generate_connector_token(
            organization_id=org_id,
            label=f"promote-{org_id}",
            created_by=USER_ID,
            expires_in_days=365,
            db=seeded_db,
        )
        token_record.federated_submissions_enabled = True
        seeded_db.commit()
        tokens.append(raw_token)

    # Submit same hostname from 3 orgs.
    for raw_token in tokens:
        resp = _submit(client, raw_token, hostname=HOSTNAME)
        assert resp.status_code == 200, resp.text

    observation = seeded_db.execute(
        select(FederatedHostnameObservation).where(
            FederatedHostnameObservation.hostname == HOSTNAME
        )
    ).scalar_one()

    resp = client.post(
        f"/api/v1/shadow-ai/federated/candidates/{observation.id}/promote",
        json={"provider_name": "Federated Example Tool", "category": "other"},
    )
    assert resp.status_code == 200, resp.text

    signature = seeded_db.execute(
        select(AISignatureRegistry).where(
            AISignatureRegistry.provider_name == "Federated Example Tool"
        )
    ).scalar_one_or_none()
    assert signature is not None


def test_metrics_includes_federated_stats(client, seeded_db):
    """GET /metrics includes federated_candidates_pending and federated_network_size."""
    raw_token, _ = _create_token_via_api(client, "metrics-fed", enabled=True)
    resp = _submit(client, raw_token, hostname="metrics.example.com")
    assert resp.status_code == 200, resp.text

    resp = client.get("/api/v1/shadow-ai/metrics")
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert "federated_candidates_pending" in data
    assert "federated_network_size" in data
