"""
Tests for the Detection Service.
"""

import json
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import select

from app.models.detection import AuditLog, ShadowAIDetection
from app.models.telemetry import TelemetryEvent
from app.services.detection_service import DetectionService
from app.services.decay_engine import DecayEngine
from tests.conftest import make_signature

ORG_ID = uuid4()


def _make_telemetry_event(db, signature_id, event_type="text_mention", raw_signal=None, source_label=None):
    if raw_signal is None:
        raw_signal = {"matched_keyword": "chatgpt"}
    if source_label is None:
        source_label = f"test:{uuid4()}"
    event = TelemetryEvent(
        id=uuid4(),
        organization_id=ORG_ID,
        tier=1,
        event_type=event_type,
        source_system_label=source_label,
        matched_signature_id=signature_id,
        raw_signal_json=json.dumps(raw_signal),
        signal_hash=source_label + "x" * (64 - len(source_label)),
        observed_at=datetime.now(timezone.utc),
    )
    db.add(event)
    db.commit()
    return event


def test_detection_created_from_telemetry(test_db):
    sig = make_signature(test_db, slug="detection-test-1")
    _make_telemetry_event(test_db, sig.id)

    result = DetectionService.run_detection(ORG_ID, test_db)
    assert result["detections_created"] >= 1

    detections = test_db.execute(
        select(ShadowAIDetection).where(
            ShadowAIDetection.organization_id == ORG_ID,
            ShadowAIDetection.signature_id == sig.id,
        )
    ).scalars().all()
    assert len(detections) == 1
    assert detections[0].provider_name == sig.provider_name


def test_duplicate_detection_not_created(test_db):
    sig = make_signature(test_db, slug="detection-test-2")
    _make_telemetry_event(test_db, sig.id, source_label="source-1")

    DetectionService.run_detection(ORG_ID, test_db)
    _make_telemetry_event(test_db, sig.id, source_label="source-2")
    result = DetectionService.run_detection(ORG_ID, test_db)

    assert result["detections_updated"] >= 1
    assert result["detections_created"] == 0

    detections = test_db.execute(
        select(ShadowAIDetection).where(
            ShadowAIDetection.organization_id == ORG_ID,
            ShadowAIDetection.signature_id == sig.id,
        )
    ).scalars().all()
    assert len(detections) == 1


def test_detection_has_correct_confidence_band(test_db):
    sig = make_signature(test_db, slug="detection-test-3")
    _make_telemetry_event(test_db, sig.id)

    DetectionService.run_detection(ORG_ID, test_db)
    detection = test_db.execute(
        select(ShadowAIDetection).where(
            ShadowAIDetection.organization_id == ORG_ID,
            ShadowAIDetection.signature_id == sig.id,
        )
    ).scalar_one()

    score = float(detection.confidence_score)
    if score >= 0.70:
        assert detection.confidence_band == "high"
    elif score >= 0.40:
        assert detection.confidence_band == "medium"
    else:
        assert False, "Detection should not have been stored below 0.40"


def test_detection_basis_json_structure(test_db):
    sig = make_signature(test_db, slug="detection-test-4")
    _make_telemetry_event(test_db, sig.id)

    DetectionService.run_detection(ORG_ID, test_db)
    detection = test_db.execute(
        select(ShadowAIDetection).where(
            ShadowAIDetection.organization_id == ORG_ID,
            ShadowAIDetection.signature_id == sig.id,
        )
    ).scalar_one()

    basis = json.loads(detection.detection_basis_json)
    assert "tier1_signals" in basis
    assert "tier2_signals" in basis
    assert "tier3_signals" in basis
    assert "signal_ids" in basis
    assert "score_breakdown" in basis
    assert isinstance(basis["signal_ids"], list)
    assert basis["tier1_signals"] >= 1


def test_audit_log_created_on_detection(test_db):
    sig = make_signature(test_db, slug="detection-test-5")
    _make_telemetry_event(test_db, sig.id)

    DetectionService.run_detection(ORG_ID, test_db)

    logs = test_db.execute(
        select(AuditLog).where(
            AuditLog.organization_id == ORG_ID,
            AuditLog.action == "shadow_ai.detection.created",
        )
    ).scalars().all()
    assert len(logs) >= 1


def test_detection_summary_returns_counts(test_db):
    sig = make_signature(test_db, slug="detection-test-6")
    _make_telemetry_event(test_db, sig.id)
    DetectionService.run_detection(ORG_ID, test_db)

    summary = DetectionService.get_detection_summary(ORG_ID, test_db)
    assert "total_active" in summary
    assert "by_status" in summary
    assert "by_confidence_band" in summary
    assert "stale_count" in summary
    assert "top_detected_tools" in summary
    assert summary["total_active"] >= 1
    assert "new" in summary["by_status"]


def test_rolling_average_on_update(test_db):
    weights = {
        "endpoint_match": 0.50,
        "identity_match": 0.0,
        "volume_match": 0.0,
        "keyword_match": 0.50,
    }
    sig = make_signature(test_db, slug="detection-test-7", confidence_weights=weights)

    _make_telemetry_event(
        test_db, sig.id,
        event_type="text_mention",
        raw_signal={"matched_keyword": "test tool"},
        source_label="source-1",
    )
    DetectionService.run_detection(ORG_ID, test_db)

    detection = test_db.execute(
        select(ShadowAIDetection).where(
            ShadowAIDetection.organization_id == ORG_ID,
            ShadowAIDetection.signature_id == sig.id,
        )
    ).scalar_one()
    first_score = float(detection.confidence_score)
    assert first_score == 1.0

    _make_telemetry_event(
        test_db, sig.id,
        event_type="endpoint_match",
        raw_signal={"endpoint_matched": "nonexistent.example.com"},
        source_label="source-2",
    )
    DetectionService.run_detection(ORG_ID, test_db)

    test_db.refresh(detection)
    updated_score = float(detection.confidence_score)
    assert updated_score != first_score
    assert 0.0 < updated_score < 1.0


def test_decay_lambda_set_from_category(test_db):
    sig = make_signature(test_db, slug="detection-test-8", category="image_gen")
    _make_telemetry_event(test_db, sig.id)

    DetectionService.run_detection(ORG_ID, test_db)
    detection = test_db.execute(
        select(ShadowAIDetection).where(
            ShadowAIDetection.organization_id == ORG_ID,
            ShadowAIDetection.signature_id == sig.id,
        )
    ).scalar_one()

    expected_lambda = DecayEngine.get_lambda_for_category("image_gen")
    assert float(detection.decay_lambda) == expected_lambda
    assert float(detection.base_confidence_score) == float(detection.confidence_score)
