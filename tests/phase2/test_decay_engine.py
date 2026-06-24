"""
Tests for the Decay Engine — Dependent Patent Claim 6.
"""

import math
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from app.models.detection import ShadowAIDetection
from app.services.decay_engine import DecayEngine

ORG_ID = uuid4()


def _make_detection(
    db,
    base_confidence=0.8,
    decay_lambda=0.023,
    days_ago=0,
    status="new",
    is_stale=False,
    category="llm",
):
    now = datetime.now(timezone.utc)
    detection = ShadowAIDetection(
        id=uuid4(),
        organization_id=ORG_ID,
        signature_id=uuid4(),
        provider_name="Test Tool",
        confidence_score=base_confidence,
        confidence_band="high" if base_confidence >= 0.70 else "medium",
        detection_basis_json='{"tier1_signals": 1, "tier2_signals": 0, "tier3_signals": 0, "signal_ids": [], "score_breakdown": {}}',
        status=status,
        first_detected_at=now - timedelta(days=days_ago + 1),
        last_observed_at=now - timedelta(days=days_ago),
        base_confidence_score=base_confidence,
        decay_lambda=decay_lambda,
        is_stale=is_stale,
    )
    db.add(detection)
    db.commit()
    return detection


# ── Formula tests ────────────────────────────

def test_decay_formula_exact_output():
    base = 1.0
    lam = 0.023
    days = 30
    expected = round(base * math.exp(-lam * days), 4)
    result = DecayEngine.compute_decayed_confidence(base, lam, days)
    assert result == expected
    assert result == 0.5016


def test_decay_never_goes_below_zero():
    result = DecayEngine.compute_decayed_confidence(0.5, 0.5, 365)
    assert result >= 0.0


def test_decay_returns_4_decimal_places():
    result = DecayEngine.compute_decayed_confidence(1.0, 0.023, 30)
    decimal_str = str(result)
    if "." in decimal_str:
        decimals = decimal_str.split(".")[1]
        assert len(decimals) <= 4


# ── Lambda lookup tests ──────────────────────

def test_lambda_values_by_category():
    assert DecayEngine.get_lambda_for_category("llm") == 0.023
    assert DecayEngine.get_lambda_for_category("code_assistant") == 0.023
    assert DecayEngine.get_lambda_for_category("agent") == 0.023
    assert DecayEngine.get_lambda_for_category("embedding") == 0.035
    assert DecayEngine.get_lambda_for_category("data_ai") == 0.035
    assert DecayEngine.get_lambda_for_category("image_gen") == 0.046
    assert DecayEngine.get_lambda_for_category("voice_ai") == 0.046
    assert DecayEngine.get_lambda_for_category("other") == 0.069


def test_unknown_category_returns_default():
    assert DecayEngine.get_lambda_for_category("nonexistent") == 0.046


# ── Decay pass tests ─────────────────────────

def test_detection_goes_stale_below_threshold(test_db):
    detection = _make_detection(
        test_db,
        base_confidence=0.5,
        decay_lambda=0.069,
        days_ago=20,
    )
    result = DecayEngine.run_decay_pass(ORG_ID, test_db)
    assert result["processed"] >= 1
    assert detection.is_stale is True


def test_stale_detection_triggers_needs_review(test_db):
    detection = _make_detection(
        test_db,
        base_confidence=0.5,
        decay_lambda=0.069,
        days_ago=20,
    )
    DecayEngine.run_decay_pass(ORG_ID, test_db)
    assert detection.status == "needs_review"
    assert detection.is_stale is True


def test_reactivation_clears_stale_flag(test_db):
    detection = _make_detection(
        test_db,
        base_confidence=0.3,
        decay_lambda=0.069,
        days_ago=20,
        status="needs_review",
        is_stale=True,
    )
    from uuid import UUID
    DecayEngine.reactivate_detection(
        detection=detection,
        new_confidence=0.85,
        db=test_db,
        triggered_by=uuid4(),
    )
    assert detection.is_stale is False
    assert detection.status == "new"
    assert float(detection.confidence_score) == 0.85
    assert float(detection.base_confidence_score) == 0.85


def test_zero_days_no_decay_applied(test_db):
    detection = _make_detection(
        test_db,
        base_confidence=0.8,
        days_ago=0,
    )
    result = DecayEngine.run_decay_pass(ORG_ID, test_db)
    assert result["skipped_same_day"] >= 1
    assert result["processed"] == 0
    assert float(detection.confidence_score) == 0.8


def test_decay_pass_skips_dismissed(test_db):
    _make_detection(
        test_db,
        base_confidence=0.8,
        days_ago=30,
        status="dismissed",
    )
    result = DecayEngine.run_decay_pass(ORG_ID, test_db)
    assert result["processed"] == 0


def test_decay_pass_skips_registered(test_db):
    _make_detection(
        test_db,
        base_confidence=0.8,
        days_ago=30,
        status="registered",
    )
    result = DecayEngine.run_decay_pass(ORG_ID, test_db)
    assert result["processed"] == 0
