"""
Tests for the Detections API endpoints.

Verifies Core Patent Claim 3: governance artifact generation
through human-validated promotion workflow.
"""

import json
from uuid import uuid4

from sqlalchemy import select

from app.models.ai_system import AISystem
from app.models.detection import ShadowAIDetection
from app.models.suppression import SuppressedDetection
from app.services.tier1_scanner import Tier1Scanner
from tests.conftest import make_questionnaire_response


def _setup_detections(db, org_id, count=3):
    texts = [
        "We use ChatGPT for evaluating candidates in our recruiting process.",
        "Claude is used for processing patient medical records in our clinic.",
        "Our engineering team uses GitHub Copilot for code generation.",
    ]
    for text in texts[:count]:
        make_questionnaire_response(db, org_id, text)
    Tier1Scanner.scan_organization(org_id, None, db)
    return list(db.execute(
        select(ShadowAIDetection).where(
            ShadowAIDetection.organization_id == org_id,
            ShadowAIDetection.deleted_at.is_(None),
        )
    ).scalars().all())


def test_list_detections_returns_200(client, seeded_db, org_id):
    _setup_detections(seeded_db, org_id, count=1)
    response = client.get("/api/v1/shadow-ai/detections")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] >= 1
    assert len(data["items"]) >= 1


def test_list_detections_pagination(client, seeded_db, org_id):
    _setup_detections(seeded_db, org_id, count=3)
    response = client.get("/api/v1/shadow-ai/detections?page=1&page_size=2")
    assert response.status_code == 200
    data = response.json()
    assert data["page"] == 1
    assert data["page_size"] == 2
    assert len(data["items"]) <= 2
    assert data["total"] >= 3
    assert data["has_next"] is True


def test_list_detections_filter_by_status(client, seeded_db, org_id):
    _setup_detections(seeded_db, org_id, count=1)
    response = client.get("/api/v1/shadow-ai/detections?status=new")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] >= 1
    for item in data["items"]:
        assert item["status"] == "new"


def test_list_detections_search(client, seeded_db, org_id):
    _setup_detections(seeded_db, org_id, count=1)
    response = client.get("/api/v1/shadow-ai/detections?search=chatgpt")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] >= 1
    for item in data["items"]:
        assert "chatgpt" in item["provider_name"].lower()


def test_get_detection_by_id_returns_200(client, seeded_db, org_id):
    detections = _setup_detections(seeded_db, org_id, count=1)
    det_id = detections[0].id
    response = client.get(f"/api/v1/shadow-ai/detections/{det_id}")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == str(det_id)
    assert "contributing_signals" in data


def test_get_detection_wrong_org_returns_404(client, seeded_db, org_id, globex_org_id):
    make_questionnaire_response(
        seeded_db, globex_org_id,
        "We use ChatGPT at Globex for everything.",
    )
    Tier1Scanner.scan_organization(globex_org_id, None, seeded_db)

    globex_detection = seeded_db.execute(
        select(ShadowAIDetection).where(
            ShadowAIDetection.organization_id == globex_org_id,
        )
    ).scalars().first()
    assert globex_detection is not None

    response = client.get(f"/api/v1/shadow-ai/detections/{globex_detection.id}")
    assert response.status_code == 404


def test_get_detection_not_found_returns_404(client, seeded_db):
    fake_id = uuid4()
    response = client.get(f"/api/v1/shadow-ai/detections/{fake_id}")
    assert response.status_code == 404


def test_dismiss_detection_returns_200(client, seeded_db, org_id):
    detections = _setup_detections(seeded_db, org_id, count=1)
    det_id = detections[0].id
    response = client.post(
        f"/api/v1/shadow-ai/detections/{det_id}/dismiss",
        json={"reason": "This is a false positive detection and should be dismissed."},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "dismissed"
    assert data["dismissed_at"] is not None
    assert data["deleted_at"] is None


def test_dismiss_creates_suppression(client, seeded_db, org_id):
    detections = _setup_detections(seeded_db, org_id, count=1)
    det_id = detections[0].id
    client.post(
        f"/api/v1/shadow-ai/detections/{det_id}/dismiss",
        json={"reason": "This is a false positive detection and should be dismissed."},
    )

    suppressions = seeded_db.execute(
        select(SuppressedDetection).where(
            SuppressedDetection.organization_id == org_id,
        )
    ).scalars().all()
    assert len(suppressions) >= 1


def test_dismiss_already_dismissed_returns_400(client, seeded_db, org_id):
    detections = _setup_detections(seeded_db, org_id, count=1)
    det_id = detections[0].id
    client.post(
        f"/api/v1/shadow-ai/detections/{det_id}/dismiss",
        json={"reason": "This is a false positive detection and should be dismissed."},
    )
    response = client.post(
        f"/api/v1/shadow-ai/detections/{det_id}/dismiss",
        json={"reason": "This is a false positive detection and should be dismissed again."},
    )
    assert response.status_code == 400


def test_escalate_creates_ai_system_record(client, seeded_db, org_id):
    detections = _setup_detections(seeded_db, org_id, count=1)
    det_id = detections[0].id
    response = client.post(
        f"/api/v1/shadow-ai/detections/{det_id}/escalate",
        json={"system_type": "application"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "ai_system" in data
    assert data["ai_system"]["source"] == "shadow_ai_discovery"
    assert data["ai_system"]["source_detection_id"] == str(det_id)

    ai_systems = seeded_db.execute(
        select(AISystem).where(AISystem.organization_id == org_id)
    ).scalars().all()
    assert len(ai_systems) >= 1


def test_escalate_sets_registered_status(client, seeded_db, org_id):
    detections = _setup_detections(seeded_db, org_id, count=1)
    det_id = detections[0].id
    response = client.post(
        f"/api/v1/shadow-ai/detections/{det_id}/escalate",
        json={"system_type": "model"},
    )
    assert response.status_code == 200
    assert response.json()["detection"]["status"] == "registered"


def test_escalate_already_registered_returns_400(client, seeded_db, org_id):
    detections = _setup_detections(seeded_db, org_id, count=1)
    det_id = detections[0].id
    client.post(
        f"/api/v1/shadow-ai/detections/{det_id}/escalate",
        json={"system_type": "application"},
    )
    response = client.post(
        f"/api/v1/shadow-ai/detections/{det_id}/escalate",
        json={"system_type": "application"},
    )
    assert response.status_code == 400


def test_escalate_response_contains_ai_system(client, seeded_db, org_id):
    detections = _setup_detections(seeded_db, org_id, count=1)
    det_id = detections[0].id
    response = client.post(
        f"/api/v1/shadow-ai/detections/{det_id}/escalate",
        json={"system_type": "agent", "owner_id": str(uuid4())},
    )
    assert response.status_code == 200
    data = response.json()
    assert "detection" in data
    assert "ai_system" in data
    assert "message" in data
    assert data["ai_system"]["system_type"] == "agent"


def test_bulk_dismiss_max_50_items(client, seeded_db, org_id):
    detections = _setup_detections(seeded_db, org_id, count=3)
    ids = [str(d.id) for d in detections] * 20
    response = client.post(
        "/api/v1/shadow-ai/detections/bulk/dismiss",
        json={"detection_ids": ids, "reason": "Bulk dismissing false positives."},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["total_succeeded"] + data["total_failed"] <= 50


def test_bulk_dismiss_partial_success(client, seeded_db, org_id):
    detections = _setup_detections(seeded_db, org_id, count=2)
    valid_id = str(detections[0].id)
    fake_id = str(uuid4())
    response = client.post(
        "/api/v1/shadow-ai/detections/bulk/dismiss",
        json={
            "detection_ids": [valid_id, fake_id],
            "reason": "Bulk dismissing false positives in this batch.",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["total_succeeded"] >= 1
    assert data["total_failed"] >= 1


def test_manual_report_creates_detection(client, seeded_db, org_id):
    response = client.post(
        "/api/v1/shadow-ai/detections/report",
        json={"tool_name": "Mystery AI Tool", "notes": "Saw someone using this."},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["provider_name"] == "Mystery AI Tool"
    assert data["status"] == "new"
    assert data["confidence_band"] == "medium"


def test_export_csv_returns_correct_headers(client, seeded_db, org_id):
    _setup_detections(seeded_db, org_id, count=1)
    response = client.get("/api/v1/shadow-ai/detections/export?format=csv")
    assert response.status_code == 200
    assert "text/csv" in response.headers.get("content-type", "")
    lines = response.text.strip().split("\n")
    header = lines[0]
    assert "tool_name" in header
    assert "confidence_score" in header
    assert "status" in header
    assert len(lines) >= 2


def test_export_json_returns_valid_json(client, seeded_db, org_id):
    _setup_detections(seeded_db, org_id, count=1)
    response = client.get("/api/v1/shadow-ai/detections/export?format=json")
    assert response.status_code == 200
    assert "application/json" in response.headers.get("content-type", "")
    data = json.loads(response.text)
    assert isinstance(data, list)
    assert len(data) >= 1
    assert "tool_name" in data[0]


def test_cross_org_isolation_comprehensive(client, seeded_db, org_id, globex_org_id):
    make_questionnaire_response(
        seeded_db, org_id,
        "We use ChatGPT for evaluating candidates in our HR process.",
    )
    Tier1Scanner.scan_organization(org_id, None, seeded_db)

    make_questionnaire_response(
        seeded_db, globex_org_id,
        "We use Claude for processing patient data at Globex.",
    )
    Tier1Scanner.scan_organization(globex_org_id, None, seeded_db)

    acme_detections = seeded_db.execute(
        select(ShadowAIDetection).where(
            ShadowAIDetection.organization_id == org_id,
        )
    ).scalars().all()
    globex_detections = seeded_db.execute(
        select(ShadowAIDetection).where(
            ShadowAIDetection.organization_id == globex_org_id,
        )
    ).scalars().all()
    assert len(acme_detections) >= 1
    assert len(globex_detections) >= 1

    response = client.get("/api/v1/shadow-ai/detections")
    assert response.status_code == 200
    data = response.json()
    acme_org_id = str(org_id)
    for item in data["items"]:
        assert item["organization_id"] == acme_org_id

    for g_det in globex_detections:
        resp = client.get(f"/api/v1/shadow-ai/detections/{g_det.id}")
        assert resp.status_code == 404

        resp = client.post(
            f"/api/v1/shadow-ai/detections/{g_det.id}/dismiss",
            json={"reason": "Trying to dismiss across orgs should fail."},
        )
        assert resp.status_code == 404

        resp = client.post(
            f"/api/v1/shadow-ai/detections/{g_det.id}/escalate",
            json={"system_type": "application"},
        )
        assert resp.status_code == 404
