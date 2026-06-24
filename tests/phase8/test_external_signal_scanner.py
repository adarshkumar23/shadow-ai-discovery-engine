"""Tests for the external public signal scanner."""

from unittest.mock import MagicMock, patch

import pytest

from app.services.external_signal_scanner import (
    AI_JOB_KEYWORDS,
    ExternalSignalScanner,
)


def test_disabled_returns_neutral():
    result = ExternalSignalScanner.scan_vendor("SomeVendor", enabled=False)
    assert result["enabled"] is False
    assert result["skipped"] is True
    score = ExternalSignalScanner.compute_external_score(result)
    assert score == 0.5


def test_no_mentions_returns_low_score():
    result = {
        "enabled": True,
        "skipped": False,
        "vendor_name": "SafeVendor",
        "github_mentions": [],
        "signal_count": 0,
        "scanned_at": "2026-06-24T00:00:00Z",
    }
    score = ExternalSignalScanner.compute_external_score(result)
    assert score == 0.1


def test_few_mentions_returns_medium_score():
    result = {
        "enabled": True,
        "skipped": False,
        "vendor_name": "AICorp",
        "github_mentions": ["langchain", "openai"],
        "signal_count": 2,
        "scanned_at": "2026-06-24T00:00:00Z",
    }
    score = ExternalSignalScanner.compute_external_score(result)
    assert score == 0.6


def test_many_mentions_returns_high_score():
    result = {
        "enabled": True,
        "skipped": False,
        "vendor_name": "AICorp",
        "github_mentions": ["openai", "chatgpt", "claude", "langchain", "llamaindex"],
        "signal_count": 5,
        "scanned_at": "2026-06-24T00:00:00Z",
    }
    score = ExternalSignalScanner.compute_external_score(result)
    assert score == 0.9


def test_network_error_returns_empty():
    with patch("httpx.Client.get") as mock_get:
        mock_get.side_effect = Exception("network failure")
        result = ExternalSignalScanner.scan_vendor("AICorp", enabled=True)
    assert result["enabled"] is True
    assert result["signal_count"] == 0
    assert result["github_mentions"] == []


def test_never_calls_when_disabled():
    with patch("httpx.Client.get") as mock_get:
        result = ExternalSignalScanner.scan_vendor("AICorp", enabled=False)
    mock_get.assert_not_called()
    assert result["enabled"] is False


def test_ai_job_keywords_defined():
    assert len(AI_JOB_KEYWORDS) > 0
    assert "openai" in AI_JOB_KEYWORDS
    assert "llm" in AI_JOB_KEYWORDS
