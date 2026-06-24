"""
Tests for the AI Signature Registry.
"""

import json

from app.registry.signature_registry import (
    KNOWN_AI_SIGNATURES,
    REGISTRY_LAST_UPDATED,
    REGISTRY_VERSION,
    TOTAL_SIGNATURES,
    get_registry_stats,
)
from app.services.confidence_engine import ConfidenceEngine
from app.services.registry_service import RegistryService


REQUIRED_FIELDS = {
    "slug", "provider_name", "category", "keyword_patterns",
    "endpoint_patterns", "oauth_app_patterns", "confidence_weights",
    "risk_level", "decay_lambda", "data_egress_indicators",
}

VALID_CATEGORIES = {
    "llm", "image_gen", "code_assistant", "voice_ai",
    "data_ai", "agent", "embedding", "other",
}

VALID_RISK_LEVELS = {"low", "medium", "high", "critical"}


def test_registry_has_minimum_50_tools():
    assert TOTAL_SIGNATURES >= 50
    assert len(KNOWN_AI_SIGNATURES) >= 50


def test_all_tools_have_required_fields():
    for sig in KNOWN_AI_SIGNATURES:
        missing = REQUIRED_FIELDS - set(sig.keys())
        assert not missing, f"{sig['slug']} missing fields: {missing}"
        assert isinstance(sig["slug"], str) and sig["slug"]
        assert isinstance(sig["provider_name"], str) and sig["provider_name"]
        assert sig["category"] in VALID_CATEGORIES
        assert sig["risk_level"] in VALID_RISK_LEVELS
        assert isinstance(sig["keyword_patterns"], list)
        assert len(sig["keyword_patterns"]) >= 4
        assert isinstance(sig["endpoint_patterns"], list)
        assert isinstance(sig["oauth_app_patterns"], list)
        assert isinstance(sig["confidence_weights"], dict)
        assert isinstance(sig["decay_lambda"], float)
        assert isinstance(sig["data_egress_indicators"], dict)
        assert "min_bytes" in sig["data_egress_indicators"]
        assert "max_bytes" in sig["data_egress_indicators"]
        assert "typical_latency_ms" in sig["data_egress_indicators"]


def test_all_confidence_weights_sum_to_one():
    for sig in KNOWN_AI_SIGNATURES:
        w = sig["confidence_weights"]
        assert "endpoint_match" in w
        assert "identity_match" in w
        assert "volume_match" in w
        assert "keyword_match" in w
        total = sum(float(v) for v in w.values())
        assert abs(total - 1.0) < 1e-9, f"{sig['slug']} weights sum to {total}"


def test_keyword_matching_case_insensitive():
    patterns = ["chatgpt", "chat gpt", "chat-gpt", "openai chat"]
    text = "We use ChatGPT for drafting customer support responses."
    score, matched = ConfidenceEngine.compute_keyword_match_score(text, patterns)
    assert score == 1.0
    assert matched is not None


def test_keyword_matching_word_boundary():
    patterns = ["openai"]
    score_match, _ = ConfidenceEngine.compute_keyword_match_score(
        "we use openai for projects", patterns
    )
    assert score_match == 1.0

    score_no_match, _ = ConfidenceEngine.compute_keyword_match_score(
        "we use nonopenai for projects", patterns
    )
    assert score_no_match == 0.0


def test_tool_not_in_registry_returns_no_match():
    patterns = ["chatgpt", "claude", "gemini"]
    text = "We use a proprietary internal tool for content generation."
    score, matched = ConfidenceEngine.compute_keyword_match_score(text, patterns)
    assert score == 0.0
    assert matched is None


def test_registry_version_constant_exists():
    assert isinstance(REGISTRY_VERSION, str)
    assert REGISTRY_VERSION
    assert isinstance(REGISTRY_LAST_UPDATED, str)
    assert REGISTRY_LAST_UPDATED


def test_get_registry_stats_returns_correct_counts():
    stats = get_registry_stats()
    assert stats["version"] == REGISTRY_VERSION
    assert stats["last_updated"] == REGISTRY_LAST_UPDATED
    assert stats["total_signatures"] == TOTAL_SIGNATURES
    assert isinstance(stats["by_category"], dict)
    assert isinstance(stats["by_risk_level"], dict)
    assert sum(stats["by_category"].values()) == TOTAL_SIGNATURES
    assert sum(stats["by_risk_level"].values()) == TOTAL_SIGNATURES


def test_registry_seed_is_idempotent(seeded_db):
    count1 = RegistryService.seed_signatures(seeded_db)
    count2 = RegistryService.seed_signatures(seeded_db)
    assert count1 == count2
    assert count1 >= 50

    from sqlalchemy import select
    from app.models.signature import AISignatureRegistry

    total = seeded_db.execute(
        select(AISignatureRegistry).where(AISignatureRegistry.is_active.is_(True))
    ).scalars().all()
    assert len(total) == TOTAL_SIGNATURES
