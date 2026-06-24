"""
PATENT NOTICE
Module: services/confidence_engine
Implements the weighted signal aggregation
algorithm described in Core Patent Claim 1.
This is the primary novel technical method:
computing a unified confidence score from
heterogeneous signals across three data tiers.

Algorithm:
  ConfidenceScore = Σ(weight[i] × score[i])
                    / Σ(weight[i])

Where weight[i] comes from
signature.confidence_weights and score[i]
is computed per signal type as defined below.

This algorithm is non-negotiable. The exact
formula, the weight source, and the per-signal
score computation are patent claims and must
not be modified.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import date
from uuid import UUID

from sqlalchemy.orm import Session

from app.core.logging_config import get_logger
from app.models.signature import AISignatureRegistry
from app.models.telemetry import TelemetryEvent

logger = get_logger(__name__)

SIGNAL_SCORE_DEFINITIONS: dict[str, dict[str, float]] = {
    "endpoint_match": {
        "exact": 1.0,
        "subdomain": 0.7,
        "no_match": 0.0,
    },
    "identity_match": {
        "exact_app_name": 1.0,
        "app_id_match": 0.7,
        "scope_indicates_ai": 0.5,
        "no_match": 0.0,
    },
    "volume_match": {
        "within_range": 1.0,
        "within_2x_tolerance": 0.6,
        "outside_range": 0.0,
    },
    "keyword_match": {
        "exact": 1.0,
        "no_match": 0.0,
    },
}

EVENT_TYPE_TO_SIGNAL: dict[str, str] = {
    "text_mention": "keyword_match",
    "endpoint_match": "endpoint_match",
    "identity_match": "identity_match",
    "volume_match": "volume_match",
    "network_match": "endpoint_match",
}


class ConfidenceEngine:
    """Weighted signal aggregation algorithm — Core Patent Claim 1."""

    @staticmethod
    def compute_score(
        signature: AISignatureRegistry,
        events: list[TelemetryEvent],
    ) -> tuple[float, dict]:
        """Compute unified confidence score from heterogeneous signals.

        Implements Core Patent Claim 1 confidence scoring algorithm.

        Returns:
            (confidence_score: float 0.0000–1.0000,
             score_breakdown: dict with per-signal contribution)

        Never returns a value outside [0.0, 1.0].
        Rounds to 4 decimal places.

        This method must never be simplified or approximated.
        The exact weighted average formula is a patent invariant.
        """
        weights = json.loads(signature.confidence_weights)
        keyword_patterns = json.loads(signature.keyword_patterns)
        endpoint_patterns = json.loads(signature.endpoint_patterns)
        egress_indicators = None
        if signature.data_egress_indicators:
            egress_indicators = json.loads(signature.data_egress_indicators)

        events_by_signal: dict[str, list[TelemetryEvent]] = {}
        for event in events:
            signal_type = EVENT_TYPE_TO_SIGNAL.get(event.event_type)
            if signal_type is None:
                logger.debug(
                    "Unknown event_type in compute_score",
                    extra={"event_type": event.event_type},
                )
                continue
            events_by_signal.setdefault(signal_type, []).append(event)

        breakdown: dict[str, dict] = {}
        numerator = 0.0
        denominator = 0.0

        for signal_type in ("endpoint_match", "identity_match", "volume_match", "keyword_match"):
            weight = float(weights.get(signal_type, 0.0))
            signal_events = events_by_signal.get(signal_type, [])

            if not signal_events:
                breakdown[signal_type] = {
                    "weight": 0.0,
                    "score": 0.0,
                    "contribution": 0.0,
                }
                continue

            if signal_type == "keyword_match":
                score = ConfidenceEngine._compute_keyword_signal_score(
                    signal_events, keyword_patterns
                )
            elif signal_type == "endpoint_match":
                score = ConfidenceEngine._compute_endpoint_signal_score(
                    signal_events, endpoint_patterns
                )
            elif signal_type == "identity_match":
                oauth_patterns = json.loads(signature.oauth_app_patterns) if signature.oauth_app_patterns else []
                score = ConfidenceEngine._compute_identity_signal_score(
                    signal_events, oauth_patterns
                )
            elif signal_type == "volume_match":
                score = ConfidenceEngine._compute_volume_signal_score(
                    signal_events, egress_indicators
                )
            else:
                score = 0.0

            contribution = weight * score
            numerator += contribution
            denominator += weight

            breakdown[signal_type] = {
                "weight": round(weight, 4),
                "score": round(score, 4),
                "contribution": round(contribution, 4),
            }

        if denominator == 0.0:
            final_score = 0.0
        else:
            final_score = numerator / denominator

        final_score = max(0.0, min(1.0, final_score))
        final_score = round(final_score, 4)
        breakdown["final_score"] = final_score

        return final_score, breakdown

    @staticmethod
    def _compute_keyword_signal_score(
        events: list[TelemetryEvent],
        keyword_patterns: list[str],
    ) -> float:
        """Score for keyword_match signal — 1.0 if any event has a confirmed match."""
        for event in events:
            raw = json.loads(event.raw_signal_json)
            if raw.get("matched_keyword"):
                return SIGNAL_SCORE_DEFINITIONS["keyword_match"]["exact"]
        return SIGNAL_SCORE_DEFINITIONS["keyword_match"]["no_match"]

    @staticmethod
    def _compute_endpoint_signal_score(
        events: list[TelemetryEvent],
        endpoint_patterns: list[str],
    ) -> float:
        """Score for endpoint_match signal based on pattern matching quality."""
        best_score = 0.0
        for event in events:
            raw = json.loads(event.raw_signal_json)
            endpoint = raw.get("endpoint_matched", "")
            if not endpoint:
                continue
            for pattern in endpoint_patterns:
                cleaned = pattern.lstrip("*.")
                if endpoint == pattern or endpoint == cleaned:
                    best_score = max(best_score, SIGNAL_SCORE_DEFINITIONS["endpoint_match"]["exact"])
                elif cleaned and cleaned in endpoint:
                    best_score = max(best_score, SIGNAL_SCORE_DEFINITIONS["endpoint_match"]["subdomain"])
        return best_score

    @staticmethod
    def _compute_identity_signal_score(
        events: list[TelemetryEvent],
        oauth_patterns: list[str],
    ) -> float:
        """Score for identity_match signal based on OAuth app matching."""
        best_score = 0.0
        for event in events:
            raw = json.loads(event.raw_signal_json)
            app_name = raw.get("app_name", "")
            app_id = raw.get("app_id", "")
            scopes = raw.get("scopes", "")

            for pattern in oauth_patterns:
                if app_name and pattern.lower() == app_name.lower():
                    best_score = max(best_score, SIGNAL_SCORE_DEFINITIONS["identity_match"]["exact_app_name"])
                elif app_id and pattern.lower() == app_id.lower():
                    best_score = max(best_score, SIGNAL_SCORE_DEFINITIONS["identity_match"]["app_id_match"])
                elif scopes and any(kw in scopes.lower() for kw in ("ai", "openai", "claude", "gpt")):
                    best_score = max(best_score, SIGNAL_SCORE_DEFINITIONS["identity_match"]["scope_indicates_ai"])
        return best_score

    @staticmethod
    def _compute_volume_signal_score(
        events: list[TelemetryEvent],
        egress_indicators: dict | None,
    ) -> float:
        """Score for volume_match signal based on data egress range."""
        if not egress_indicators:
            return 0.0
        min_bytes = egress_indicators.get("min_bytes", 0)
        max_bytes = egress_indicators.get("max_bytes", 0)
        best_score = 0.0
        for event in events:
            raw = json.loads(event.raw_signal_json)
            volume = raw.get("volume_bytes", 0)
            if volume == 0:
                continue
            if min_bytes <= volume <= max_bytes:
                best_score = max(best_score, SIGNAL_SCORE_DEFINITIONS["volume_match"]["within_range"])
            elif min_bytes > 0 and (min_bytes * 0.5) <= volume <= (max_bytes * 2):
                best_score = max(best_score, SIGNAL_SCORE_DEFINITIONS["volume_match"]["within_2x_tolerance"])
        return best_score

    @staticmethod
    def compute_rolling_average(
        existing_score: float,
        existing_event_count: int,
        new_signal_score: float,
    ) -> float:
        """Rolling average of last 10 computations.

        Patent-specified formula:

          new_score = (
              (existing_score × min(event_count-1, 9))
              + new_signal_score
          ) / min(event_count, 10)

        Returns float rounded to 4 decimal places.
        """
        window = min(existing_event_count, 10)
        if window == 0:
            return round(new_signal_score, 4)
        prev_window = min(existing_event_count - 1, 9)
        new_score = (
            (existing_score * prev_window) + new_signal_score
        ) / window
        return round(max(0.0, min(1.0, new_score)), 4)

    @staticmethod
    def compute_signal_hash(
        organization_id: UUID,
        signature_id: UUID,
        source_system_label: str,
        event_date: date,
    ) -> str:
        """Compute SHA256 signal hash for deduplication.

        PATENT INVARIANT: This exact computation must never change.
        The signal_hash is how the system deduplicates signals
        across scans.

        SHA256 of concatenated string:
          f"{organization_id}:{signature_id}:
            {source_system_label}:{event_date.isoformat()}"

        Returns hex digest (64 characters).
        """
        raw = (
            f"{organization_id}:{signature_id}:"
            f"{source_system_label}:{event_date.isoformat()}"
        )
        return hashlib.sha256(raw.encode()).hexdigest()

    @staticmethod
    def classify_confidence_band(score: float) -> str:
        """Classify confidence score into a band.

        HIGH:    score >= 0.70
        MEDIUM:  score >= 0.40
        DISCARD: score <  0.40 (caller must not store)

        Returns: "high" | "medium" | "discard"
        DISCARD means the caller must not create a detection record.
        This is a patent invariant.
        """
        if score >= 0.70:
            return "high"
        if score >= 0.40:
            return "medium"
        return "discard"

    @staticmethod
    def compute_keyword_match_score(
        text: str,
        keyword_patterns: list[str],
    ) -> tuple[float, str | None]:
        """Case-insensitive whole-phrase matching with word boundaries.

        Returns (score, matched_keyword | None).

        Score = 1.0 if any pattern found in text.
        Score = 0.0 if no pattern found.

        Uses word boundary awareness:
        "openai" matches "we use openai for..."
        "openai" must NOT match "nonopenai" (prefix)

        Returns the first matched pattern for evidence trail purposes.
        """
        lower_text = text.lower()
        for pattern in keyword_patterns:
            lower_pattern = pattern.lower()
            regex = r"\b" + re.escape(lower_pattern) + r"\b"
            match = re.search(regex, lower_text)
            if match:
                return (SIGNAL_SCORE_DEFINITIONS["keyword_match"]["exact"], pattern)
        return (SIGNAL_SCORE_DEFINITIONS["keyword_match"]["no_match"], None)
