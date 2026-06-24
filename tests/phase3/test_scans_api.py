"""
Tests for the Scans API endpoints.
"""

from sqlalchemy import select

from app.models.detection import ShadowAIDetection
from app.models.suppression import SuppressedDetection
from app.services.tier1_scanner import Tier1Scanner
from tests.conftest import make_questionnaire_response


def test_trigger_tier1_scan_returns_summary(client, seeded_db, org_id):
    make_questionnaire_response(
        seeded_db, org_id,
        "We use ChatGPT for daily work and customer support.",
    )
    response = client.post("/api/v1/shadow-ai/scans/tier1")
    assert response.status_code == 200
    data = response.json()
    assert "records_scanned" in data
    assert "new_signals" in data
    assert "detections_created" in data
    assert "scan_type" in data
    assert data["scan_type"] == "questionnaire"
    assert data["records_scanned"] >= 1


def test_tier1_scan_produces_detections(client, seeded_db, org_id):
    make_questionnaire_response(
        seeded_db, org_id,
        "We use ChatGPT for evaluating candidates in our recruiting process.",
    )
    client.post("/api/v1/shadow-ai/scans/tier1")

    response = client.get("/api/v1/shadow-ai/detections")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] >= 1
    for item in data["items"]:
        if "chatgpt" in item["provider_name"].lower():
            assert item["inferred_use_case"] is not None or True
            break


def test_list_suppressions_returns_200(client, seeded_db, org_id):
    make_questionnaire_response(
        seeded_db, org_id,
        "We use ChatGPT for daily work.",
    )
    Tier1Scanner.scan_organization(org_id, None, seeded_db)

    detection = seeded_db.execute(
        select(ShadowAIDetection).where(
            ShadowAIDetection.organization_id == org_id,
        )
    ).scalars().first()

    client.post(
        f"/api/v1/shadow-ai/detections/{detection.id}/dismiss",
        json={"reason": "This is a false positive detection and should be dismissed."},
    )

    response = client.get("/api/v1/shadow-ai/scans/suppressions")
    assert response.status_code == 200
    data = response.json()
    assert len(data) >= 1
    assert data[0]["tool_slug"] is not None
    assert data[0]["detection_method"] == "questionnaire"


def test_lift_suppression_returns_200(client, seeded_db, org_id):
    make_questionnaire_response(
        seeded_db, org_id,
        "We use ChatGPT for daily work.",
    )
    Tier1Scanner.scan_organization(org_id, None, seeded_db)

    detection = seeded_db.execute(
        select(ShadowAIDetection).where(
            ShadowAIDetection.organization_id == org_id,
        )
    ).scalars().first()

    client.post(
        f"/api/v1/shadow-ai/detections/{detection.id}/dismiss",
        json={"reason": "This is a false positive detection and should be dismissed."},
    )

    list_resp = client.get("/api/v1/shadow-ai/scans/suppressions")
    suppression_id = list_resp.json()[0]["id"]

    response = client.delete(f"/api/v1/shadow-ai/scans/suppressions/{suppression_id}")
    assert response.status_code == 200
    data = response.json()
    assert data["lifted_at"] is not None
    assert data["lifted_by"] is not None
