"""
Tests for the behavioral feature extractor.

Validates that the patent-specified feature set is computed correctly
from network envelope metadata and that the extractor is fully
deterministic, never inspects payloads, and makes no external calls.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from app.services.behavioral_feature_extractor import (
    AI_SERVICE_CALL_RANGES,
    BehavioralFeatureExtractor,
)


NOW = datetime(2026, 6, 24, 12, 0, 0, tzinfo=timezone.utc)


def extract(hostname, call_count, first_seen=None, last_seen=None):
    """Helper to call extract with sensible defaults."""
    first = first_seen or NOW - timedelta(hours=1)
    last = last_seen or NOW
    return BehavioralFeatureExtractor.extract(
        hostname=hostname,
        call_count_24h=call_count,
        first_seen=first,
        last_seen=last,
        signal_type="network_match",
    )


def test_high_call_count_scores_well():
    """Call count in the AI sweet spot gets a high frequency score."""
    features = extract("api.unknownai.ai", 500)
    assert features.call_frequency_score >= 0.7


def test_very_low_call_count_scores_poorly():
    """Very low call counts score poorly on frequency."""
    features = extract("api.unknownai.ai", 2)
    assert features.call_frequency_score <= 0.2


def test_api_hostname_scores_well():
    """API-style hostnames get a high endpoint pattern score."""
    features = extract("api.unknowntool.ai", 50)
    assert features.endpoint_pattern_score >= 0.6


def test_cdn_hostname_scores_poorly():
    """CDN-style hostnames score poorly on endpoint pattern."""
    features = extract("cdn.example.com", 50)
    assert features.endpoint_pattern_score <= 0.3


def test_composite_score_in_range():
    """Composite score is always bounded in [0.0, 1.0]."""
    hostnames = [
        "api.openai.com",
        "cdn.example.com",
        "static.assets.io",
        "inference.unknown.ai",
        "example.com",
    ]
    for hostname in hostnames:
        for call_count in (0, 5, 10, 100, 500, 50000, 100000):
            features = extract(hostname, call_count)
            assert 0.0 <= features.composite_score <= 1.0


def test_composite_score_precision():
    """Composite score is always rounded to 4 decimal places."""
    features = extract("api.unknownai.ai", 250)
    composite = features.composite_score
    assert round(composite, 4) == composite
    assert len(str(composite).split(".")[-1]) <= 4


def test_weights_sum_to_one():
    """FEATURE_WEIGHTS values must sum to exactly 1.0."""
    total = sum(BehavioralFeatureExtractor.FEATURE_WEIGHTS.values())
    assert abs(total - 1.0) < 1e-9


def test_recency_same_day_neutral():
    """first_seen == last_seen yields a neutral recency score."""
    same_moment = NOW
    features = extract("api.unknownai.ai", 50, same_moment, same_moment)
    assert features.recency_score == 0.5


def test_recency_week_apart_scores_high():
    """Signals observed consistently over a week score high on recency."""
    first = NOW - timedelta(days=7)
    features = extract("api.unknownai.ai", 50, first, NOW)
    assert features.recency_score >= 0.7


def test_feature_extraction_is_deterministic():
    """Same inputs must always produce identical outputs."""
    args = {
        "hostname": "api.unknownai.ai",
        "call_count_24h": 250,
        "first_seen": NOW - timedelta(days=3),
        "last_seen": NOW,
        "signal_type": "network_match",
    }
    first = BehavioralFeatureExtractor.extract(**args)
    second = BehavioralFeatureExtractor.extract(**args)
    assert first.to_dict() == second.to_dict()
    assert first.composite_score == second.composite_score


def test_no_external_calls():
    """The extractor never makes external network or filesystem calls."""
    with patch("requests.get") as mock_get, patch(
        "requests.post"
    ) as mock_post, patch("urllib.request.urlopen") as mock_urlopen:
        extract("api.unknownai.ai", 250)
        mock_get.assert_not_called()
        mock_post.assert_not_called()
        mock_urlopen.assert_not_called()


def test_call_frequency_suspiciously_high_penalized():
    """Extremely high call counts are penalized as likely CDN/monitoring."""
    features = extract("api.unknownai.ai", AI_SERVICE_CALL_RANGES["high_threshold"] + 1)
    assert features.call_frequency_score == 0.3


def test_payload_asymmetry_api_indicator():
    """API-style hostnames get an above-neutral payload asymmetry score."""
    features = extract("api.unknownai.ai", 50)
    assert features.payload_asymmetry_score == 0.7


def test_payload_asymmetry_cdn_indicator():
    """CDN-style hostnames get a below-neutral payload asymmetry score."""
    features = extract("cdn.example.com", 50)
    assert features.payload_asymmetry_score == 0.2


def test_service_type_probability_known_vendor():
    """Hostnames containing known AI vendor names return probability 1.0."""
    features = extract("api.openai.example.com", 50)
    assert features.service_type_probability == 1.0


def test_stale_signal_reduces_recency():
    """Signals older than 30 days get a low recency score."""
    first = NOW - timedelta(days=45)
    last = NOW - timedelta(days=35)
    features = extract("api.unknownai.ai", 50, first, last)
    assert features.recency_score == 0.3
