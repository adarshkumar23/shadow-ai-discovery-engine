"""
Tests for the Confidence Engine — Core Patent Claim 1.
"""

import json
import math
from datetime import date, datetime, timezone
from uuid import UUID, uuid4

from app.models.signature import AISignatureRegistry
from app.models.telemetry import TelemetryEvent
from app.services.confidence_engine import ConfidenceEngine

ORG_ID = UUID("11111111-1111-1111-1111-111111111111")
SIG_ID = UUID("22222222-2222-2222-2222-222222222222")


def _make_signature(
    weights=None,
    keyword_patterns=None,
    endpoint_patterns=None,
    oauth_app_patterns=None,
    data_egress=None,
    category="llm",
):
    if weights is None:
        weights = {
            "endpoint_match": 0.25,
            "identity_match": 0.25,
            "volume_match": 0.20,
            "keyword_match": 0.30,
        }
    if keyword_patterns is None:
        keyword_patterns = ["chatgpt", "chat gpt", "chat-gpt", "openai chat"]
    if endpoint_patterns is None:
        endpoint_patterns = ["api.openai.com", "chatgpt.com"]
    if oauth_app_patterns is None:
        oauth_app_patterns = ["ChatGPT", "OpenAI ChatGPT"]
    if data_egress is None:
        data_egress = {"min_bytes": 1000, "max_bytes": 100000, "typical_latency_ms": 500}

    return AISignatureRegistry(
        id=SIG_ID,
        slug="openai-chatgpt",
        provider_name="ChatGPT",
        category=category,
        endpoint_patterns=json.dumps(endpoint_patterns),
        keyword_patterns=json.dumps(keyword_patterns),
        oauth_app_patterns=json.dumps(oauth_app_patterns),
        data_egress_indicators=json.dumps(data_egress),
        confidence_weights=json.dumps(weights),
        risk_level="high",
        is_active=True,
    )


def _make_event(event_type="text_mention", raw_signal=None):
    if raw_signal is None:
        raw_signal = {"matched_keyword": "chatgpt"}
    return TelemetryEvent(
        id=uuid4(),
        organization_id=ORG_ID,
        tier=1,
        event_type=event_type,
        source_system_label="test",
        matched_signature_id=SIG_ID,
        raw_signal_json=json.dumps(raw_signal),
        signal_hash="x" * 64,
        observed_at=datetime.now(timezone.utc),
    )


# ── Signal hash tests ───────────────────────

def test_signal_hash_is_deterministic():
    org = UUID("11111111-1111-1111-1111-111111111111")
    sig = UUID("22222222-2222-2222-2222-222222222222")
    d = date(2026, 6, 23)
    h1 = ConfidenceEngine.compute_signal_hash(org, sig, "source", d)
    h2 = ConfidenceEngine.compute_signal_hash(org, sig, "source", d)
    assert h1 == h2


def test_signal_hash_is_64_chars():
    org = UUID("11111111-1111-1111-1111-111111111111")
    sig = UUID("22222222-2222-2222-2222-222222222222")
    d = date(2026, 6, 23)
    h = ConfidenceEngine.compute_signal_hash(org, sig, "source", d)
    assert len(h) == 64
    int(h, 16)


# ── Confidence band tests ───────────────────

def test_discard_below_threshold():
    assert ConfidenceEngine.classify_confidence_band(0.3999) == "discard"
    assert ConfidenceEngine.classify_confidence_band(0.0) == "discard"


def test_medium_band_correct_range():
    assert ConfidenceEngine.classify_confidence_band(0.40) == "medium"
    assert ConfidenceEngine.classify_confidence_band(0.6999) == "medium"


def test_high_band_correct_range():
    assert ConfidenceEngine.classify_confidence_band(0.70) == "high"
    assert ConfidenceEngine.classify_confidence_band(1.0) == "high"


# ── Rolling average tests ───────────────────

def test_rolling_average_formula():
    existing_score = 0.5
    event_count = 5
    new_signal_score = 1.0
    expected = round(
        (0.5 * min(4, 9) + 1.0) / min(5, 10), 4
    )
    result = ConfidenceEngine.compute_rolling_average(
        existing_score, event_count, new_signal_score
    )
    assert result == expected
    assert result == 0.6


# ── Compute score tests ─────────────────────

def test_confidence_score_range():
    sig = _make_signature()
    events = [_make_event()]
    score, _ = ConfidenceEngine.compute_score(sig, events)
    assert 0.0 <= score <= 1.0

    events_empty = []
    score_empty, _ = ConfidenceEngine.compute_score(sig, events_empty)
    assert 0.0 <= score_empty <= 1.0


def test_confidence_score_precision():
    sig = _make_signature()
    events = [_make_event()]
    score, _ = ConfidenceEngine.compute_score(sig, events)
    decimal_str = str(score)
    if "." in decimal_str:
        decimals = decimal_str.split(".")[1]
        assert len(decimals) <= 4


def test_single_signal_type_uses_only_its_weight():
    weights = {
        "endpoint_match": 0.25,
        "identity_match": 0.25,
        "volume_match": 0.20,
        "keyword_match": 0.30,
    }
    sig = _make_signature(weights=weights)
    events = [_make_event(event_type="text_mention")]
    score, breakdown = ConfidenceEngine.compute_score(sig, events)
    assert score == 1.0
    assert breakdown["keyword_match"]["weight"] > 0
    assert breakdown["keyword_match"]["score"] == 1.0
    assert breakdown["endpoint_match"]["weight"] == 0.0
    assert breakdown["identity_match"]["weight"] == 0.0
    assert breakdown["volume_match"]["weight"] == 0.0


def test_weights_from_signature_respected():
    weights = {
        "endpoint_match": 0.25,
        "identity_match": 0.25,
        "volume_match": 0.20,
        "keyword_match": 0.30,
    }
    sig = _make_signature(weights=weights)

    kw_event = _make_event(event_type="text_mention", raw_signal={"matched_keyword": "chatgpt"})
    ep_event = _make_event(
        event_type="endpoint_match",
        raw_signal={"endpoint_matched": "nonexistent.example.com"},
    )
    events = [kw_event, ep_event]
    score, breakdown = ConfidenceEngine.compute_score(sig, events)

    kw_w = weights["keyword_match"]
    ep_w = weights["endpoint_match"]
    kw_s = 1.0
    ep_s = 0.0
    expected = round((kw_w * kw_s + ep_w * ep_s) / (kw_w + ep_w), 4)

    assert score == expected
    assert breakdown["keyword_match"]["weight"] == round(kw_w, 4)
    assert breakdown["endpoint_match"]["weight"] == round(ep_w, 4)


# ── Keyword match score tests ───────────────

def test_keyword_match_score_exact_match():
    patterns = ["chatgpt", "chat gpt", "chat-gpt", "openai chat"]
    text = "We use ChatGPT for drafting responses."
    score, matched = ConfidenceEngine.compute_keyword_match_score(text, patterns)
    assert score == 1.0
    assert matched is not None
    assert matched.lower() in text.lower()


def test_keyword_match_score_no_match():
    patterns = ["chatgpt", "chat gpt", "chat-gpt", "openai chat"]
    text = "We use a proprietary internal tool for everything."
    score, matched = ConfidenceEngine.compute_keyword_match_score(text, patterns)
    assert score == 0.0
    assert matched is None
