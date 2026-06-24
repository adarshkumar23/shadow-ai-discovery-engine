"""
Tests for the Metrics and Trust Document API endpoints.
"""

import json

from fastapi.testclient import TestClient

from app.core.database import get_db
from app.main import app
from app.models.detection import ShadowAIDetection
from app.services.tier1_scanner import Tier1Scanner
from tests.conftest import make_questionnaire_response


def test_metrics_returns_200(client, seeded_db, org_id):
    make_questionnaire_response(
        seeded_db, org_id,
        "We use ChatGPT for daily work.",
    )
    Tier1Scanner.scan_organization(org_id, None, seeded_db)

    response = client.get("/api/v1/shadow-ai/metrics")
    assert response.status_code == 200
    data = response.json()
    assert "total_active" in data
    assert "by_status" in data
    assert "by_confidence_band" in data
    assert "stale_count" in data
    assert "registry_version" in data
    assert "registry_total_tools" in data
    assert data["tier1_enabled"] is True
    assert data["tier2_enabled"] is False
    assert data["tier3_enabled"] is False


def test_trust_endpoint_no_auth_required(test_db):
    def override_get_db():
        yield test_db

    app.dependency_overrides[get_db] = override_get_db
    try:
        with TestClient(app) as c:
            response = c.get("/api/v1/shadow-ai/trust")
            assert response.status_code == 200
    finally:
        app.dependency_overrides.clear()


def test_trust_endpoint_contains_required_fields(client):
    response = client.get("/api/v1/shadow-ai/trust")
    assert response.status_code == 200
    data = response.json()
    assert data["document_version"] == "2.0.0"
    assert data["service"] == "Shadow AI Discovery Engine"
    assert "data_handling" in data
    assert "tier1" in data["data_handling"]
    assert "tier2" in data["data_handling"]
    assert "tier3" in data["data_handling"]
    assert "employee_privacy" in data
    assert "retention" in data
    assert "external_calls" in data["data_handling"]["tier1"]
    assert data["data_handling"]["tier1"]["external_calls"] == "None"
    assert "dark_ai_detection" in data
    assert data["dark_ai_detection"]["payload_inspection"] is False
    assert data["dark_ai_detection"]["tls_decryption"] is False
    assert "federated_network" in data
    assert data["federated_network"]["opt_in"] is True


def test_metrics_counts_match_actual_detections(client, seeded_db, org_id):
    make_questionnaire_response(
        seeded_db, org_id,
        "We use ChatGPT for daily work and Claude for document summarization.",
    )
    Tier1Scanner.scan_organization(org_id, None, seeded_db)

    response = client.get("/api/v1/shadow-ai/metrics")
    assert response.status_code == 200
    data = response.json()

    from sqlalchemy import select, func
    actual_active = seeded_db.execute(
        select(func.count()).select_from(ShadowAIDetection).where(
            ShadowAIDetection.organization_id == org_id,
            ShadowAIDetection.deleted_at.is_(None),
            ShadowAIDetection.status.notin_(["dismissed", "registered"]),
        )
    ).scalar() or 0

    assert data["total_active"] == actual_active
    assert data["total_active"] >= 1


def test_registry_tools_no_auth_required(test_db):
    from app.services.registry_service import RegistryService

    RegistryService.seed_signatures(test_db)

    def override_get_db():
        yield test_db

    app.dependency_overrides[get_db] = override_get_db
    try:
        with TestClient(app) as c:
            response = c.get("/api/v1/shadow-ai/registry/tools")
            assert response.status_code == 200
            data = response.json()
            assert data["total"] >= 50
            assert "version" in data
            assert "tools" in data
            assert len(data["tools"]) >= 50
    finally:
        app.dependency_overrides.clear()
