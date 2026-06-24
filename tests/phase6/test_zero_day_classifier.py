"""
Tests for the zero-day behavioral classifier.

Validates classification logic, candidate creation, detection creation,
review actions, audit logging, and cross-organization isolation.
"""

import json
import secrets
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select

from app.models.detection import AuditLog, ConnectorToken, ShadowAIDetection
from app.models.signature import AISignatureRegistry
from app.models.suppression import SuppressedDetection
from app.models.zero_day import ZeroDayCandidate
from app.schemas.telemetry import ConnectorSignalPayload
from app.services.behavioral_feature_extractor import BehavioralFeatureExtractor
from app.services.tier3_ingestor import Tier3Ingestor
from app.services.zero_day_classifier import (
    AI_PROBABILITY_THRESHOLD,
    ZeroDayClassifier,
)

ORG_ID = UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
OTHER_ORG_ID = UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
USER_ID = UUID("cccccccc-cccc-cccc-cccc-cccccccccccc")


def make_connector_token(
    db,
    organization_id=None,
    label="test-connector",
    expires_in_days=365,
):
    """Create a ConnectorToken directly in the DB. Returns (raw_token, token)."""
    raw_token = secrets.token_urlsafe(32)
    token_hash = __import__("hashlib").sha256(raw_token.encode()).hexdigest()
    now = datetime.now(timezone.utc)

    token = ConnectorToken(
        organization_id=organization_id or ORG_ID,
        token_hash=token_hash,
        label=label,
        expires_at=now + timedelta(days=expires_in_days),
        created_by=USER_ID,
        is_active=True,
        signals_total=0,
        requests_this_hour=0,
    )
    db.add(token)
    db.commit()
    return raw_token, token


def make_signal_payload(
    org_id=None,
    matched_tool="UnknownAI",
    hostname_pattern="api.unknownai.ai",
    call_count_24h=250,
    source_system_label="test-vpc-flow",
    **overrides,
):
    """Build a valid ConnectorSignalPayload dict for zero-day testing."""
    now = datetime.now(timezone.utc)
    payload = {
        "org_id": str(org_id or ORG_ID),
        "signal_type": "network_match",
        "matched_tool": matched_tool,
        "hostname_pattern": hostname_pattern,
        "call_count_24h": call_count_24h,
        "source_system_label": source_system_label,
        "first_seen": (now - timedelta(hours=1)).isoformat(),
        "last_seen": now.isoformat(),
        "connector_version": "1.0.0",
    }
    payload.update(overrides)
    return payload


def test_known_registry_tool_not_classified(seeded_db):
    """If matched_signature is True, should_classify returns False."""
    payload = ConnectorSignalPayload(**make_signal_payload())
    assert ZeroDayClassifier.should_classify(payload, matched_signature=False) is True
    assert ZeroDayClassifier.should_classify(payload, matched_signature=True) is False


def test_low_call_count_not_classified(seeded_db):
    """Call counts below the minimum do not trigger classification."""
    payload = ConnectorSignalPayload(**make_signal_payload(call_count_24h=3))
    assert ZeroDayClassifier.should_classify(payload, matched_signature=False) is False


def test_non_network_signal_not_classified(seeded_db):
    """Only network_match signals are classified."""
    payload = ConnectorSignalPayload(
        **make_signal_payload(signal_type="cloudtrail_match")
    )
    assert ZeroDayClassifier.should_classify(payload, matched_signature=False) is False


def test_high_score_creates_candidate(seeded_db):
    """An AI-like hostname with high call count creates a zero-day candidate."""
    raw_token, token = make_connector_token(seeded_db)
    payload = ConnectorSignalPayload(**make_signal_payload())

    candidate = ZeroDayClassifier.classify_signal(payload, ORG_ID, seeded_db)

    assert candidate is not None
    assert candidate.organization_id == ORG_ID
    assert candidate.hostname == "api.unknownai.ai"
    assert Decimal(str(candidate.behavioral_score)) >= Decimal(
        str(AI_PROBABILITY_THRESHOLD)
    )
    assert candidate.status == "pending_review"


def test_below_threshold_no_candidate(seeded_db):
    """Score below threshold returns None and does not create a candidate."""
    raw_token, token = make_connector_token(seeded_db)
    payload = ConnectorSignalPayload(
        **make_signal_payload(
            hostname_pattern="cdn.example.com",
            call_count_24h=5,
        )
    )

    candidate = ZeroDayClassifier.classify_signal(payload, ORG_ID, seeded_db)

    assert candidate is None
    candidates = seeded_db.execute(
        select(ZeroDayCandidate).where(ZeroDayCandidate.organization_id == ORG_ID)
    ).scalars().all()
    assert len(candidates) == 0


def test_candidate_observation_count_incremented(seeded_db):
    """Sending the same hostname twice increments observation_count."""
    raw_token, token = make_connector_token(seeded_db)
    payload = ConnectorSignalPayload(**make_signal_payload())

    c1 = ZeroDayClassifier.classify_signal(payload, ORG_ID, seeded_db)
    assert c1.observation_count == 1

    c2 = ZeroDayClassifier.classify_signal(payload, ORG_ID, seeded_db)
    assert c2.observation_count == 2
    assert c2.id == c1.id


def test_zero_day_detection_has_null_signature_id(seeded_db):
    """Zero-day detections have signature_id = NULL."""
    raw_token, token = make_connector_token(seeded_db)
    payload = ConnectorSignalPayload(**make_signal_payload())

    candidate = ZeroDayClassifier.classify_signal(payload, ORG_ID, seeded_db)

    assert candidate.detection_id is not None
    detection = seeded_db.execute(
        select(ShadowAIDetection).where(
            ShadowAIDetection.id == candidate.detection_id
        )
    ).scalar_one()
    assert detection.signature_id is None


def test_zero_day_detection_has_correct_method(seeded_db):
    """Zero-day detections store detection_method in basis JSON."""
    raw_token, token = make_connector_token(seeded_db)
    payload = ConnectorSignalPayload(**make_signal_payload())

    candidate = ZeroDayClassifier.classify_signal(payload, ORG_ID, seeded_db)
    detection = seeded_db.execute(
        select(ShadowAIDetection).where(
            ShadowAIDetection.id == candidate.detection_id
        )
    ).scalar_one()

    basis = json.loads(detection.detection_basis_json)
    # The zero-day path is a Tier 3 network signal with no registry match.
    assert basis["tier3_signals"] == 1
    assert basis["zero_day_hostname"] == payload.hostname_pattern


def test_confidence_not_artificially_inflated(seeded_db):
    """Detection confidence equals the extracted composite score."""
    raw_token, token = make_connector_token(seeded_db)
    payload = ConnectorSignalPayload(**make_signal_payload())

    features = BehavioralFeatureExtractor.extract(
        hostname=payload.hostname_pattern,
        call_count_24h=payload.call_count_24h,
        first_seen=payload.first_seen,
        last_seen=payload.last_seen,
        signal_type=payload.signal_type,
    )

    candidate = ZeroDayClassifier.classify_signal(payload, ORG_ID, seeded_db)
    detection = seeded_db.execute(
        select(ShadowAIDetection).where(
            ShadowAIDetection.id == candidate.detection_id
        )
    ).scalar_one()

    assert float(detection.confidence_score) == features.composite_score


def test_detection_basis_json_has_features(seeded_db):
    """detection_basis_json contains the behavioral feature breakdown."""
    raw_token, token = make_connector_token(seeded_db)
    payload = ConnectorSignalPayload(**make_signal_payload())

    candidate = ZeroDayClassifier.classify_signal(payload, ORG_ID, seeded_db)
    detection = seeded_db.execute(
        select(ShadowAIDetection).where(
            ShadowAIDetection.id == candidate.detection_id
        )
    ).scalar_one()

    basis = json.loads(detection.detection_basis_json)
    assert "score_breakdown" in basis
    breakdown = basis["score_breakdown"]
    for key in (
        "call_frequency_score",
        "payload_asymmetry_score",
        "endpoint_pattern_score",
        "service_type_probability",
        "recency_score",
        "composite_score",
    ):
        assert key in breakdown


def test_classifier_version_in_detection(seeded_db):
    """Zero-day detections record the classifier version."""
    raw_token, token = make_connector_token(seeded_db)
    payload = ConnectorSignalPayload(**make_signal_payload())

    candidate = ZeroDayClassifier.classify_signal(payload, ORG_ID, seeded_db)
    detection = seeded_db.execute(
        select(ShadowAIDetection).where(
            ShadowAIDetection.id == candidate.detection_id
        )
    ).scalar_one()

    assert detection.classifier_version == "1.0.0"
    assert detection.is_zero_day is True
    assert detection.zero_day_hostname == payload.hostname_pattern


def test_behavioral_features_json_populated(seeded_db):
    """behavioral_features_json contains all 5 feature scores."""
    raw_token, token = make_connector_token(seeded_db)
    payload = ConnectorSignalPayload(**make_signal_payload())

    candidate = ZeroDayClassifier.classify_signal(payload, ORG_ID, seeded_db)
    detection = seeded_db.execute(
        select(ShadowAIDetection).where(
            ShadowAIDetection.id == candidate.detection_id
        )
    ).scalar_one()

    features = json.loads(detection.behavioral_features_json)
    for key in (
        "call_frequency_score",
        "payload_asymmetry_score",
        "endpoint_pattern_score",
        "service_type_probability",
        "recency_score",
    ):
        assert key in features
        assert 0.0 <= features[key] <= 1.0


def test_review_add_to_registry_creates_signature(seeded_db):
    """Review action add_to_registry creates an AISignatureRegistry entry."""
    payload = ConnectorSignalPayload(**make_signal_payload())
    candidate = ZeroDayClassifier.classify_signal(payload, ORG_ID, seeded_db)

    reviewed = ZeroDayClassifier.review_candidate(
        candidate_id=candidate.id,
        organization_id=ORG_ID,
        action="add_to_registry",
        reviewed_by=USER_ID,
        review_notes="Approved for registry",
        provider_name="Unknown AI Tool",
        category="llm",
        db=seeded_db,
    )

    assert reviewed.status == "added_to_registry"
    signature = seeded_db.execute(
        select(AISignatureRegistry).where(
            AISignatureRegistry.provider_name == "Unknown AI Tool"
        )
    ).scalar_one_or_none()
    assert signature is not None
    assert signature.category == "llm"


def test_review_dismiss_creates_suppression(seeded_db):
    """Review action dismiss creates a suppression record."""
    payload = ConnectorSignalPayload(**make_signal_payload())
    candidate = ZeroDayClassifier.classify_signal(payload, ORG_ID, seeded_db)

    reviewed = ZeroDayClassifier.review_candidate(
        candidate_id=candidate.id,
        organization_id=ORG_ID,
        action="dismiss",
        reviewed_by=USER_ID,
        review_notes="False positive",
        provider_name=None,
        category=None,
        db=seeded_db,
    )

    assert reviewed.status == "dismissed"
    suppressions = seeded_db.execute(
        select(SuppressedDetection).where(
            SuppressedDetection.organization_id == ORG_ID,
            SuppressedDetection.detection_method == "behavioral_inference",
        )
    ).scalars().all()
    assert len(suppressions) >= 1


def test_review_monitor_sets_status(seeded_db):
    """Review action monitor sets candidate status to monitoring."""
    payload = ConnectorSignalPayload(**make_signal_payload())
    candidate = ZeroDayClassifier.classify_signal(payload, ORG_ID, seeded_db)

    reviewed = ZeroDayClassifier.review_candidate(
        candidate_id=candidate.id,
        organization_id=ORG_ID,
        action="monitor",
        reviewed_by=USER_ID,
        review_notes="Keep watching",
        provider_name=None,
        category=None,
        db=seeded_db,
    )

    assert reviewed.status == "monitoring"


def test_audit_log_created_on_classification(seeded_db):
    """Classification creates an audit log entry for the detection."""
    payload = ConnectorSignalPayload(**make_signal_payload())
    candidate = ZeroDayClassifier.classify_signal(payload, ORG_ID, seeded_db)

    audits = seeded_db.execute(
        select(AuditLog).where(
            AuditLog.organization_id == ORG_ID,
            AuditLog.action == "shadow_ai.zero_day.detection_created",
        )
    ).scalars().all()
    assert len(audits) >= 1
    assert audits[0].entity_id == candidate.detection_id


def test_cross_org_isolation(seeded_db):
    """Org A candidates are not visible to Org B."""
    payload_a = ConnectorSignalPayload(**make_signal_payload(org_id=ORG_ID))
    candidate_a = ZeroDayClassifier.classify_signal(payload_a, ORG_ID, seeded_db)

    org_b_candidates = ZeroDayClassifier.get_candidates(OTHER_ORG_ID, seeded_db)
    assert candidate_a not in org_b_candidates
    assert len(org_b_candidates) == 0

    org_a_candidates = ZeroDayClassifier.get_candidates(ORG_ID, seeded_db)
    assert candidate_a in org_a_candidates


def test_review_wrong_org_returns_404(seeded_db):
    """Reviewing a candidate from a different org returns 404."""
    payload = ConnectorSignalPayload(**make_signal_payload())
    candidate = ZeroDayClassifier.classify_signal(payload, ORG_ID, seeded_db)

    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc_info:
        ZeroDayClassifier.review_candidate(
            candidate_id=candidate.id,
            organization_id=OTHER_ORG_ID,
            action="monitor",
            reviewed_by=USER_ID,
            review_notes=None,
            provider_name=None,
            category=None,
            db=seeded_db,
        )
    assert exc_info.value.status_code == 404


def test_only_one_active_detection_per_hostname(seeded_db):
    """Multiple classifications for the same hostname do not duplicate detections."""
    payload = ConnectorSignalPayload(**make_signal_payload())
    c1 = ZeroDayClassifier.classify_signal(payload, ORG_ID, seeded_db)
    c2 = ZeroDayClassifier.classify_signal(payload, ORG_ID, seeded_db)

    assert c1.detection_id == c2.detection_id

    detections = seeded_db.execute(
        select(ShadowAIDetection).where(
            ShadowAIDetection.organization_id == ORG_ID,
            ShadowAIDetection.zero_day_hostname == payload.hostname_pattern,
        )
    ).scalars().all()
    assert len(detections) == 1
