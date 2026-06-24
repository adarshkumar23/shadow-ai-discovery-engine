"""Tests for jurisdiction API endpoints."""

from datetime import datetime, timezone
from uuid import uuid4

import pytest

from app.models.detection import ShadowAIDetection
from app.models.signature import AISignatureRegistry
from app.services.jurisdiction_engine import JurisdictionEngine
from tests.conftest import GLOBEX_ORG_ID, make_signature


def _create_detection(db, org_id, signature=None):
    detection = ShadowAIDetection(
        id=uuid4(),
        organization_id=org_id,
        signature_id=signature.id if signature else None,
        provider_name="ChatGPT",
        confidence_score=0.85,
        confidence_band="high",
        detection_basis_json='{"tier1_signals": 1}',
        base_confidence_score=0.85,
        decay_lambda=0.023,
        status="new",
        first_detected_at=datetime.now(timezone.utc),
        last_observed_at=datetime.now(timezone.utc),
        intent_action="evaluating",
        intent_data_subject="job_candidates",
        intent_business_context="hr",
        inferred_use_case="Automated evaluation of job candidates",
        is_zero_day=False,
    )
    db.add(detection)
    db.commit()
    if signature:
        JurisdictionEngine.assess_detection(detection, signature, db)
    return detection


def test_get_jurisdiction_returns_200(client, test_db, org_id):
    sig = make_signature(test_db, category="llm", risk_level="high")
    detection = _create_detection(test_db, org_id, signature=sig)
    response = client.get(f"/api/v1/shadow-ai/detections/{detection.id}/jurisdiction")
    assert response.status_code == 200


def test_get_jurisdiction_structure(client, test_db, org_id):
    sig = make_signature(test_db, category="llm", risk_level="high")
    detection = _create_detection(test_db, org_id, signature=sig)
    response = client.get(f"/api/v1/shadow-ai/detections/{detection.id}/jurisdiction")
    data = response.json()
    assert "assessment" in data
    assessment = data["assessment"]
    assert "applicable_regulations" in assessment
    assert "applicable_articles" in assessment
    assert "missing_governance" in assessment
    assert "highest_risk" in assessment
    assert "EU_AI_ACT" in assessment["applicable_regulations"]


def test_refresh_jurisdiction_returns_200(client, test_db, org_id):
    sig = make_signature(test_db, category="llm", risk_level="high")
    detection = _create_detection(test_db, org_id, signature=sig)
    response = client.post(
        f"/api/v1/shadow-ai/detections/{detection.id}/jurisdiction/refresh"
    )
    assert response.status_code == 200
    data = response.json()
    assert data["assessment"]["graph_version"] == "1.0.0"


def test_regulations_endpoint_no_auth(client, test_db):
    JurisdictionEngine.seed_regulation_data(test_db)
    response = client.get("/api/v1/shadow-ai/registry/regulations")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 7


def test_articles_endpoint_no_auth(client, test_db):
    JurisdictionEngine.seed_regulation_data(test_db)
    response = client.get("/api/v1/shadow-ai/registry/regulations/EU_AI_ACT/articles")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 5
    assert any(article["article_number"] == "Article 6" for article in data)


def test_metrics_includes_jurisdiction_counts(client, test_db, org_id):
    sig = make_signature(test_db, category="llm", risk_level="high")
    _create_detection(test_db, org_id, signature=sig)
    response = client.get("/api/v1/shadow-ai/metrics")
    assert response.status_code == 200
    data = response.json()
    assert "jurisdiction_assessments_complete" in data
    assert "high_regulatory_risk_count" in data
    assert data["jurisdiction_assessments_complete"] >= 1
    assert data["high_regulatory_risk_count"] >= 1


def test_wrong_org_returns_404(client, test_db, org_id):
    sig = make_signature(test_db, category="llm", risk_level="high")
    detection = _create_detection(test_db, GLOBEX_ORG_ID, signature=sig)
    response = client.get(f"/api/v1/shadow-ai/detections/{detection.id}/jurisdiction")
    assert response.status_code == 404
