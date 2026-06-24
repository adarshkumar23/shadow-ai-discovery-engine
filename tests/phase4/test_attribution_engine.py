"""
Tests for the attribution engine.

Tests the 60% concentration threshold algorithm.
"""

import hashlib
import json
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest

from app.core.security import encrypt_value
from app.models.detection import ShadowAIDetection
from app.models.idp import IdpConnection
from app.models.signature import AISignatureRegistry
from app.models.telemetry import TelemetryEvent
from app.services.attribution_engine import (
    ATTRIBUTION_LOOKBACK_DAYS,
    ATTRIBUTION_THRESHOLD,
    AttributionEngine,
)
from app.services.decay_engine import DecayEngine
from tests.conftest import make_signature

ORG_ID = UUID("11111111-1111-1111-1111-111111111111")
USER_ID = UUID("11111111-1111-1111-1111-111111111101")


def _hash_actor(raw: str) -> str:
    """Hash an actor identifier (simulating connector behavior)."""
    return hashlib.sha256(raw.encode()).hexdigest()


def make_tier2_event(db, signature_id, actor_id_hash, observed_at=None):
    """Create a Tier 2 telemetry event with an actor_id."""
    if observed_at is None:
        observed_at = datetime.now(timezone.utc)
    event = TelemetryEvent(
        organization_id=ORG_ID,
        tier=2,
        event_type="identity_match",
        source_system_label="idp:okta",
        matched_signature_id=signature_id,
        raw_signal_json=json.dumps({
            "idp_provider": "okta",
            "app_name": "OpenAI ChatGPT",
            "app_id": "app_123",
            "oauth_scopes": [],
            "event_type": "grant",
            "actor_id": actor_id_hash,
        }),
        signal_hash=uuid4().hex,
        observed_at=observed_at,
    )
    db.add(event)
    db.commit()
    return event


def make_detection(db, signature_id):
    """Create an active detection for the signature."""
    now = datetime.now(timezone.utc)
    det = ShadowAIDetection(
        organization_id=ORG_ID,
        signature_id=signature_id,
        provider_name="OpenAI ChatGPT",
        confidence_score=0.8000,
        confidence_band="high",
        detection_basis_json=json.dumps({
            "tier1_signals": 0,
            "tier2_signals": 1,
            "tier3_signals": 0,
            "signal_ids": [],
            "score_breakdown": {},
        }),
        base_confidence_score=0.8000,
        decay_lambda=DecayEngine.get_lambda_for_category("llm"),
        status="new",
        first_detected_at=now,
        last_observed_at=now,
        is_stale=False,
    )
    db.add(det)
    db.commit()
    return det


def test_attribution_at_60_percent_threshold(test_db, seeded_db):
    """Actor A: 6/10 events → attributed."""
    sig = make_signature(seeded_db, slug="attr-test-60", provider_name="AttrTest60")
    actor_a = _hash_actor("user_a@company.com")
    actor_b = _hash_actor("user_b@company.com")

    for _ in range(6):
        make_tier2_event(seeded_db, sig.id, actor_a)
    for _ in range(4):
        make_tier2_event(seeded_db, sig.id, actor_b)

    result = AttributionEngine.compute_attribution(ORG_ID, sig.id, seeded_db)
    assert result[0] is not None
    assert result[0] == actor_a
    assert result[1] == 0.6


def test_no_attribution_below_threshold(test_db, seeded_db):
    """Actor A: 5/10 events → not attributed."""
    sig = make_signature(seeded_db, slug="attr-test-below", provider_name="AttrTestBelow")
    actor_a = _hash_actor("user_a@company.com")
    actor_b = _hash_actor("user_b@company.com")

    for _ in range(5):
        make_tier2_event(seeded_db, sig.id, actor_a)
    for _ in range(5):
        make_tier2_event(seeded_db, sig.id, actor_b)

    result = AttributionEngine.compute_attribution(ORG_ID, sig.id, seeded_db)
    assert result[0] is None
    assert result[1] is None


def test_attribution_confidence_is_correct_ratio(test_db, seeded_db):
    """7/10 events → confidence = 0.7000."""
    sig = make_signature(seeded_db, slug="attr-test-ratio", provider_name="AttrTestRatio")
    actor_a = _hash_actor("user_a@company.com")
    actor_b = _hash_actor("user_b@company.com")

    for _ in range(7):
        make_tier2_event(seeded_db, sig.id, actor_a)
    for _ in range(3):
        make_tier2_event(seeded_db, sig.id, actor_b)

    result = AttributionEngine.compute_attribution(ORG_ID, sig.id, seeded_db)
    assert result[0] == actor_a
    assert result[1] == 0.7


def test_no_tier2_events_returns_none(test_db, seeded_db):
    """No Tier 2 events → (None, None)."""
    sig = make_signature(seeded_db, slug="attr-test-empty", provider_name="AttrTestEmpty")
    result = AttributionEngine.compute_attribution(ORG_ID, sig.id, seeded_db)
    assert result == (None, None)


def test_attribution_uses_only_30_day_window(test_db, seeded_db):
    """Events older than 30 days → not counted."""
    sig = make_signature(seeded_db, slug="attr-test-window", provider_name="AttrTestWindow")
    actor_a = _hash_actor("user_a@company.com")

    old_date = datetime.now(timezone.utc) - timedelta(days=40)
    for _ in range(10):
        make_tier2_event(seeded_db, sig.id, actor_a, observed_at=old_date)

    result = AttributionEngine.compute_attribution(ORG_ID, sig.id, seeded_db)
    assert result == (None, None)


def test_attribution_never_stores_raw_email(test_db, seeded_db):
    """actor_id values are hashes only — no raw email addresses."""
    sig = make_signature(seeded_db, slug="attr-test-hash", provider_name="AttrTestHash")
    raw_email = "user_a@company.com"
    actor_hash = _hash_actor(raw_email)

    for _ in range(7):
        make_tier2_event(seeded_db, sig.id, actor_hash)
    for _ in range(2):
        make_tier2_event(seeded_db, sig.id, _hash_actor("other@company.com"))

    result = AttributionEngine.compute_attribution(ORG_ID, sig.id, seeded_db)
    assert result[0] is not None
    assert "@" not in result[0]
    assert result[0] == actor_hash
    assert result[0] != raw_email


def test_attribution_is_advisory(test_db, seeded_db):
    """Attribution sets attributed_owner_id but creates no permissions."""
    sig = make_signature(seeded_db, slug="attr-test-advisory", provider_name="AttrTestAdvisory")
    actor_a = _hash_actor("user_a@company.com")

    for _ in range(7):
        make_tier2_event(seeded_db, sig.id, actor_a)
    for _ in range(3):
        make_tier2_event(seeded_db, sig.id, _hash_actor("other@company.com"))

    det = make_detection(seeded_db, sig.id)
    assert det.attributed_owner_id is None

    result = AttributionEngine.run_attribution_pass(ORG_ID, seeded_db)

    assert result["detections_attributed"] >= 1

    from sqlalchemy import select
    det_refresh = seeded_db.execute(
        select(ShadowAIDetection).where(ShadowAIDetection.id == det.id)
    ).scalar_one()
    assert det_refresh.attributed_owner_id is not None
    assert float(det_refresh.attribution_confidence) == 0.7

    # No permissions table exists in this system. Attribution is advisory only.
    # The only effect is setting attributed_owner_id and attribution_confidence.
