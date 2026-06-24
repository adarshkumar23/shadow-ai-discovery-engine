"""
Tests for the dark AI side channel classifier.

Patent Dependent Claim 10: Dark AI Detection via Side Channels.
These tests verify that the classifier:
  - Uses only network flow metadata
  - Computes six patent-specified features
  - Respects DARK_AI_THRESHOLD = 0.60
  - Detects proxy patterns
  - Never accesses payload contents
  - Degrades gracefully when timing data is absent
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.schemas.telemetry import ConnectorSignalPayload
from app.services.dark_ai_classifier import (
    DARK_AI_THRESHOLD,
    DARK_AI_WEIGHTS,
    CLASSIFIER_VERSION,
    DarkAIClassifier,
    DarkAIFeatures,
)


def _make_payload(
    hostname: str = "proxy.company.internal",
    avg_response_time_ms: int | None = 800,
    response_time_variance_ms: int | None = 1200,
    avg_request_bytes: int | None = 100,
    avg_response_bytes: int | None = 8000,
    connection_reuse_ratio: float | None = 0.9,
    inter_request_gap_ms: int | None = 12000,
    call_count_24h: int = 250,
    matched_tool: str = "UnknownAI",
) -> ConnectorSignalPayload:
    now = datetime.now(timezone.utc)
    return ConnectorSignalPayload(
        org_id="11111111-1111-1111-1111-111111111111",
        signal_type="network_match",
        matched_tool=matched_tool,
        hostname_pattern=hostname,
        call_count_24h=call_count_24h,
        source_system_label="test-vpc-flow",
        first_seen=now,
        last_seen=now,
        connector_version="1.0.0",
        avg_response_time_ms=avg_response_time_ms,
        response_time_variance_ms=response_time_variance_ms,
        avg_request_bytes=avg_request_bytes,
        avg_response_bytes=avg_response_bytes,
        connection_reuse_ratio=connection_reuse_ratio,
        inter_request_gap_ms=inter_request_gap_ms,
    )


def test_high_variance_scores_ai_like():
    payload = _make_payload(response_time_variance_ms=1200)
    features = DarkAIClassifier.extract_features(payload)
    assert features.response_time_variance_score >= 0.7


def test_low_variance_scores_cdn_like():
    payload = _make_payload(response_time_variance_ms=50)
    features = DarkAIClassifier.extract_features(payload)
    assert features.response_time_variance_score <= 0.2


def test_asymmetric_payload_scores_high():
    payload = _make_payload(avg_request_bytes=100, avg_response_bytes=8000)
    features = DarkAIClassifier.extract_features(payload)
    assert features.payload_asymmetry_score >= 0.7


def test_symmetric_payload_scores_low():
    payload = _make_payload(avg_request_bytes=5000, avg_response_bytes=5000)
    features = DarkAIClassifier.extract_features(payload)
    assert features.payload_asymmetry_score <= 0.2


def test_human_paced_timing_scores_high():
    payload = _make_payload(inter_request_gap_ms=15000)
    features = DarkAIClassifier.extract_features(payload)
    assert features.inter_request_timing_score >= 0.8


def test_polling_timing_scores_low():
    payload = _make_payload(inter_request_gap_ms=50)
    features = DarkAIClassifier.extract_features(payload)
    assert features.inter_request_timing_score <= 0.2


def test_high_connection_reuse_scores_high():
    payload = _make_payload(connection_reuse_ratio=0.9)
    features = DarkAIClassifier.extract_features(payload)
    assert features.connection_efficiency_score >= 0.8


def test_no_timing_data_uses_neutral():
    payload = _make_payload(
        avg_response_time_ms=None,
        response_time_variance_ms=None,
        avg_request_bytes=None,
        avg_response_bytes=None,
        connection_reuse_ratio=None,
        inter_request_gap_ms=None,
    )
    features = DarkAIClassifier.extract_features(payload)
    assert features.has_timing_data is False
    assert features.response_time_variance_score == 0.5
    assert features.payload_asymmetry_score == 0.5
    assert features.inter_request_timing_score == 0.5
    assert features.connection_efficiency_score == 0.5
    assert features.response_latency_profile_score == 0.5


def test_composite_score_range():
    payload = _make_payload()
    features = DarkAIClassifier.extract_features(payload)
    assert 0.0 <= features.composite_score <= 1.0


def test_weights_sum_to_one():
    total = sum(DARK_AI_WEIGHTS.values())
    assert total == 1.0


def test_dark_ai_threshold_is_0_60():
    assert DARK_AI_THRESHOLD == 0.60


def test_proxy_hostname_detected():
    payload = _make_payload(hostname="proxy.company.internal")
    assert DarkAIClassifier._is_proxy_pattern(payload) is True


def test_no_payload_inspection():
    """The classifier never references raw content or identity fields."""
    import inspect

    source = inspect.getsource(DarkAIClassifier)
    forbidden = {
        "request_body",
        "response_body",
        "payload_content",
        "raw_log",
        "packet_data",
        "full_url",
        "query_string",
        "http_headers",
    }
    found = {field for field in forbidden if field in source}
    assert not found, f"Classifier references forbidden content fields: {found}"

    # Also verify the payload schema rejects a forbidden field before the
    # classifier can ever see it.
    now = datetime.now(timezone.utc)
    with pytest.raises(ValueError):
        ConnectorSignalPayload(
            org_id="11111111-1111-1111-1111-111111111111",
            signal_type="network_match",
            matched_tool="Test",
            hostname_pattern="test.example.com",
            call_count_24h=10,
            source_system_label="test",
            first_seen=now,
            last_seen=now,
            connector_version="1.0.0",
            request_body="should-not-be-here",
        )


def test_classifier_is_deterministic():
    payload = _make_payload()
    a = DarkAIClassifier.extract_features(payload)
    b = DarkAIClassifier.extract_features(payload)
    assert a == b


def test_dark_ai_detection_created_above_threshold(test_db):
    payload = _make_payload()
    from uuid import uuid4

    event_id = uuid4()
    org_id = uuid4()
    created = DarkAIClassifier.classify(
        payload, org_id, matched_signature_id=None,
        telemetry_event_id=event_id, db=test_db,
    )
    assert created is True

    from app.models.detection import ShadowAIDetection
    from sqlalchemy import select

    detection = test_db.execute(
        select(ShadowAIDetection).where(
            ShadowAIDetection.organization_id == org_id,
            ShadowAIDetection.is_dark_ai.is_(True),
        )
    ).scalar_one()
    assert detection.detection_method == "dark_ai_side_channel"
    assert detection.is_dark_ai is True
    assert float(detection.dark_ai_score) >= DARK_AI_THRESHOLD


def test_dark_ai_detection_method_string(test_db):
    payload = _make_payload()
    from uuid import uuid4

    event_id = uuid4()
    org_id = uuid4()
    DarkAIClassifier.classify(
        payload, org_id, matched_signature_id=None,
        telemetry_event_id=event_id, db=test_db,
    )

    from app.models.detection import ShadowAIDetection
    from sqlalchemy import select

    detection = test_db.execute(
        select(ShadowAIDetection).where(
            ShadowAIDetection.organization_id == org_id,
            ShadowAIDetection.is_dark_ai.is_(True),
        )
    ).scalar_one()
    assert detection.detection_method == "dark_ai_side_channel"


def test_below_threshold_no_detection(test_db):
    payload = _make_payload(
        avg_response_time_ms=10,
        response_time_variance_ms=50,
        avg_request_bytes=5000,
        avg_response_bytes=5000,
        connection_reuse_ratio=0.1,
        inter_request_gap_ms=50,
        call_count_24h=2,
    )
    from uuid import uuid4

    event_id = uuid4()
    org_id = uuid4()
    created = DarkAIClassifier.classify(
        payload, org_id, matched_signature_id=None,
        telemetry_event_id=event_id, db=test_db,
    )
    assert created is False
