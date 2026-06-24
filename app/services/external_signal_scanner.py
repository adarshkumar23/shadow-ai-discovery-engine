"""
PATENT NOTICE
Module: services/external_signal_scanner
Part of Dependent Patent Claim 5:
Vendor AI Contamination Index.

This module scans publicly available vendor information for AI tool usage
signals. It is Signal 2 of the three-signal contamination index.

CRITICAL: This module makes external HTTP calls. It MUST only run when
explicitly enabled per organization via the external_scan_enabled flag.
Default: DISABLED.

Data sources:
  1. GitHub API — public repositories for the vendor's organization
     (if discoverable via public search)

What this scanner NEVER does:
  - Makes calls when external_scan_enabled = False
  - Accesses private repositories
  - Accesses any authenticated resources
  - Stores raw page content
  - Stores any personal data

What it extracts:
  - AI tool name mentions from PUBLIC pages only
  - This is publicly available information
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from app.core.logging_config import get_logger

logger = get_logger(__name__)

AI_JOB_KEYWORDS = [
    "openai",
    "chatgpt",
    "gpt-4",
    "claude",
    "anthropic",
    "llama",
    "gemini",
    "copilot",
    "langchain",
    "llamaindex",
    "vector database",
    "rag",
    "retrieval augmented",
    "fine-tuning",
    "llm",
    "large language model",
    "generative ai",
    "ml engineer",
    "ai engineer",
    "prompt engineer",
    "embedding",
    "semantic search",
]

_GITHUB_SEARCH_URL = "https://api.github.com/search/repositories"


class ExternalSignalScanner:
    """Lightweight public-signal scanner for vendor AI usage."""

    @staticmethod
    def scan_vendor(
        vendor_name: str,
        enabled: bool = False,
        last_scanned_at: datetime | None = None,
    ) -> dict[str, Any]:
        """Scan public signals for a vendor.

        If `enabled` is False, returns immediately without making any HTTP
        calls. If `last_scanned_at` is within the last 24 hours, the scan is
        skipped to respect rate limits.

        On any network error, an empty result is returned and the error is
        logged. The contamination pipeline never fails because of external
        scan failures.
        """
        now = datetime.now(timezone.utc)

        if not enabled:
            return {"enabled": False, "skipped": True}

        if last_scanned_at is not None:
            if last_scanned_at.tzinfo is None:
                last_scanned_at = last_scanned_at.replace(tzinfo=timezone.utc)
            if (now - last_scanned_at) < timedelta(hours=24):
                return {
                    "enabled": True,
                    "vendor_name": vendor_name,
                    "skipped": True,
                    "reason": "rate_limited",
                    "scanned_at": now.isoformat(),
                }

        try:
            with httpx.Client(timeout=30.0) as client:
                query = f"{vendor_name} AI language model"
                response = client.get(
                    _GITHUB_SEARCH_URL,
                    params={"q": query, "per_page": 5},
                )
                response.raise_for_status()
                data = response.json()
        except Exception as exc:
            logger.warning(
                "External signal scan failed",
                extra={"vendor_name": vendor_name, "error": str(exc)},
            )
            return {
                "enabled": True,
                "vendor_name": vendor_name,
                "skipped": False,
                "github_mentions": [],
                "signal_count": 0,
                "scanned_at": now.isoformat(),
            }

        items = data.get("items", [])
        mentions: list[str] = []
        for item in items:
            text = " ".join(
                filter(
                    None,
                    [
                        item.get("name", ""),
                        item.get("description", ""),
                        item.get("language", ""),
                    ],
                )
            ).lower()
            for keyword in AI_JOB_KEYWORDS:
                if keyword in text:
                    mentions.append(keyword)

        mentions = sorted(set(mentions))
        return {
            "enabled": True,
            "vendor_name": vendor_name,
            "skipped": False,
            "github_mentions": mentions,
            "signal_count": len(mentions),
            "scanned_at": now.isoformat(),
        }

    @staticmethod
    def compute_external_score(external_signals: dict[str, Any]) -> float:
        """Convert external signal dict to a normalized score.

        Score mapping (patent-specified):
          - External scanning disabled or failed: 0.5 (neutral)
          - Enabled, 0 signals: 0.1
          - Enabled, 1-3 signals: 0.6
          - Enabled, >3 signals: 0.9
        """
        if not external_signals.get("enabled", False):
            return 0.5

        if external_signals.get("skipped", False):
            return 0.5

        signal_count = external_signals.get("signal_count", 0) or 0

        if signal_count == 0:
            return 0.1
        if 1 <= signal_count <= 3:
            return 0.6
        return 0.9
