"""
Tests for detection export functionality.
"""

import json
from io import StringIO
import csv

from sqlalchemy import select

from app.models.detection import AuditLog
from app.services.tier1_scanner import Tier1Scanner
from tests.conftest import make_questionnaire_response


EXPECTED_CSV_COLUMNS = [
    "tool_name", "vendor", "category", "confidence_score",
    "confidence_band", "status", "detection_method",
    "inferred_use_case", "risk_level", "is_stale",
    "first_detected_at", "last_observed_at",
    "reviewed_by", "intent_action", "intent_data_subject",
    "intent_business_context",
]


def _setup_detections(db, org_id):
    make_questionnaire_response(
        db, org_id,
        "We use ChatGPT for evaluating candidates in our recruiting process.",
    )
    make_questionnaire_response(
        db, org_id,
        "Claude is used for processing patient medical records in our clinic.",
    )
    Tier1Scanner.scan_organization(org_id, None, db)


def test_csv_export_all_columns_present(client, seeded_db, org_id):
    _setup_detections(seeded_db, org_id)
    response = client.get("/api/v1/shadow-ai/detections/export?format=csv")
    assert response.status_code == 200

    reader = csv.DictReader(StringIO(response.text))
    headers = reader.fieldnames
    for col in EXPECTED_CSV_COLUMNS:
        assert col in headers, f"Missing column: {col}"


def test_csv_export_correct_row_count(client, seeded_db, org_id):
    _setup_detections(seeded_db, org_id)
    response = client.get("/api/v1/shadow-ai/detections/export?format=csv")
    assert response.status_code == 200

    reader = csv.DictReader(StringIO(response.text))
    rows = list(reader)
    assert len(rows) >= 2

    from app.models.detection import ShadowAIDetection
    actual = seeded_db.execute(
        select(ShadowAIDetection).where(
            ShadowAIDetection.organization_id == org_id,
            ShadowAIDetection.deleted_at.is_(None),
        )
    ).scalars().all()
    assert len(rows) == len(actual)


def test_json_export_valid_structure(client, seeded_db, org_id):
    _setup_detections(seeded_db, org_id)
    response = client.get("/api/v1/shadow-ai/detections/export?format=json")
    assert response.status_code == 200

    data = json.loads(response.text)
    assert isinstance(data, list)
    assert len(data) >= 2
    for item in data:
        assert "tool_name" in item
        assert "confidence_score" in item
        assert "status" in item
        assert "detection_method" in item


def test_export_audit_log_created(client, seeded_db, org_id):
    _setup_detections(seeded_db, org_id)
    client.get("/api/v1/shadow-ai/detections/export?format=csv")

    logs = seeded_db.execute(
        select(AuditLog).where(
            AuditLog.organization_id == org_id,
            AuditLog.action == "shadow_ai.detections.exported",
        )
    ).scalars().all()
    assert len(logs) >= 1

    context = json.loads(logs[-1].context_json)
    assert context["format"] == "csv"
    assert context["count"] >= 2


def test_export_filters_by_status(client, seeded_db, org_id):
    _setup_detections(seeded_db, org_id)

    response = client.get("/api/v1/shadow-ai/detections/export?format=json&status=new")
    assert response.status_code == 200
    data = json.loads(response.text)
    assert len(data) >= 1
    for item in data:
        assert item["status"] == "new"

    response = client.get("/api/v1/shadow-ai/detections/export?format=json&status=registered")
    assert response.status_code == 200
    data = json.loads(response.text)
    assert len(data) == 0
