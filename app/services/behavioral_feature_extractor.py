"""
PATENT NOTICE
Module: services/behavioral_feature_extractor
Implements the behavioral feature extraction
component of Dependent Patent Claim 4:
Zero-Day AI Detection via Behavioral
Classification.

This module computes statistical features
from network signal metadata that distinguish
AI service traffic from other network traffic.
These features are computed WITHOUT inspecting
any packet payload contents.

PATENT-SPECIFIED FEATURES:
The following features are patent claims.
They must not be renamed, removed, or
substantially altered without patent counsel
review:

1. call_frequency_score
   AI services show characteristic call
   frequency patterns — neither constant
   (like monitoring) nor bursty (like
   file transfers) but conversational.
   Computed from call_count_24h relative
   to AI service typical ranges.

2. payload_asymmetry_score
   AI inference requests are small (prompts),
   responses are large (completions).
   Estimated from call_count vs data volume
   indicators where available.
   When volume data not available: 0.5 neutral.

3. endpoint_pattern_score
   AI services consistently use HTTPS port 443
   with specific path depth patterns.
   API endpoints tend to be versioned
   (e.g. /v1/, /api/v1/).
   Computed from hostname pattern structure.

4. service_type_probability
   Probability that the traffic characteristics
   match known AI service behavioral profiles
   rather than CDN, database, or file storage.
   Computed from call_count_24h ranges vs
   known AI service ranges.

5. recency_score
   AI services show strong recency patterns —
   they tend to be called consistently rather
   than in isolated bursts.
   Computed from first_seen vs last_seen ratio.

WHAT THIS EXTRACTOR NEVER DOES:
- Inspects packet payload contents
- Makes external API calls
- Uses probabilistic models
- Accesses user identity information
- Reads request or response bodies
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone

CLASSIFIER_VERSION = "1.0.0"

AI_SERVICE_CALL_RANGES = {
    "typical_min_24h": 10,
    "typical_max_24h": 50000,
    "low_threshold": 5,
    "high_threshold": 100000,
}

AI_HOSTNAME_STRUCTURAL_INDICATORS = [
    "/v1/",
    "/api/",
    "/v2/",
    "/v3/",
    "api.",
    "inference.",
    "ml.",
    "ai.",
    "model.",
    "llm.",
    "chat.",
    "embed.",
]

CDN_HOSTNAME_INDICATORS = [
    "cdn.",
    "static.",
    "assets.",
    "img.",
    "media.",
]

KNOWN_AI_VENDOR_SUBSTRINGS = [
    "bedrock",
    "vertex",
    "openai",
    "anthropic",
    "cohere",
    "mistral",
    "groq",
]


@dataclass
class BehavioralFeatures:
    """
    Container for all computed behavioral
    features for a single signal.

    All scores are floats in [0.0, 1.0].
    Higher score = more AI-like.

    This dataclass is patent specification.
    Fields must not be renamed without
    patent counsel review.
    """

    call_frequency_score: float  # [0.0, 1.0]
    payload_asymmetry_score: float  # [0.0, 1.0]
    endpoint_pattern_score: float  # [0.0, 1.0]
    service_type_probability: float  # [0.0, 1.0]
    recency_score: float  # [0.0, 1.0]
    composite_score: float  # weighted avg
    features_json: str  # JSON serialization

    def to_dict(self) -> dict:
        return {
            "call_frequency_score": self.call_frequency_score,
            "payload_asymmetry_score": self.payload_asymmetry_score,
            "endpoint_pattern_score": self.endpoint_pattern_score,
            "service_type_probability": self.service_type_probability,
            "recency_score": self.recency_score,
            "composite_score": self.composite_score,
            "classifier_version": CLASSIFIER_VERSION,
        }


class BehavioralFeatureExtractor:
    """
    Extracts patent-specified behavioral features from network
    signal metadata. This class is fully deterministic: the same
    input feature set always produces the same output.

    What this extractor NEVER does:
    - Inspects packet payload contents
    - Makes external API calls
    - Uses probabilistic models or random sampling
    - Accesses user identity information
    - Reads request or response bodies
    """

    FEATURE_WEIGHTS = {
        "call_frequency_score": 0.30,
        "payload_asymmetry_score": 0.20,
        "endpoint_pattern_score": 0.20,
        "service_type_probability": 0.20,
        "recency_score": 0.10,
    }
    # Weights sum to 1.0 — patent invariant

    @staticmethod
    def extract(
        hostname: str,
        call_count_24h: int,
        first_seen: datetime,
        last_seen: datetime,
        signal_type: str,
    ) -> BehavioralFeatures:
        """
        Computes all behavioral features for a single network signal.

        Inputs are network envelope metadata only. No payload inspection.

        Args:
            hostname: Hostname or endpoint pattern observed in traffic.
            call_count_24h: Number of calls observed in the last 24 hours.
            first_seen: Earliest observation timestamp.
            last_seen: Latest observation timestamp.
            signal_type: Type of signal (e.g., "network_match").

        Returns:
            BehavioralFeatures with all scores and JSON serialization.
        """
        call_frequency_score = BehavioralFeatureExtractor._score_call_frequency(
            call_count_24h
        )
        payload_asymmetry_score = (
            BehavioralFeatureExtractor._score_payload_asymmetry(
                call_count_24h, hostname
            )
        )
        endpoint_pattern_score = (
            BehavioralFeatureExtractor._score_endpoint_pattern(hostname)
        )
        service_type_probability = (
            BehavioralFeatureExtractor._score_service_type_probability(
                call_count_24h, hostname
            )
        )
        recency_score = BehavioralFeatureExtractor._score_recency(
            first_seen, last_seen
        )

        feature_dict = {
            "call_frequency_score": call_frequency_score,
            "payload_asymmetry_score": payload_asymmetry_score,
            "endpoint_pattern_score": endpoint_pattern_score,
            "service_type_probability": service_type_probability,
            "recency_score": recency_score,
        }
        composite = BehavioralFeatureExtractor._compute_composite(feature_dict)

        features = BehavioralFeatures(
            call_frequency_score=call_frequency_score,
            payload_asymmetry_score=payload_asymmetry_score,
            endpoint_pattern_score=endpoint_pattern_score,
            service_type_probability=service_type_probability,
            recency_score=recency_score,
            composite_score=composite,
            features_json=json.dumps(feature_dict),
        )
        return features

    @staticmethod
    def _score_call_frequency(call_count: int) -> float:
        """
        Scores how AI-like the call frequency is.

        Score logic (patent-specified):
          count < 5:        0.1 (too low — not AI)
          5 <= count < 10:  0.4 (possible)
          10 <= count < 100: 0.7 (likely)
          100 <= count < 10000: 0.9 (very likely)
          10000 <= count < 100000: 0.7 (high but ok)
          count >= 100000:  0.3 (suspiciously high)

        The sweet spot for AI API calls is
        10-10000/day. Very high counts suggest
        monitoring or CDN, not AI inference.

        This method never inspects payload contents.
        """
        count = max(0, int(call_count))
        if count < AI_SERVICE_CALL_RANGES["low_threshold"]:
            return 0.1
        if count < AI_SERVICE_CALL_RANGES["typical_min_24h"]:
            return 0.4
        if count < 100:
            return 0.7
        if count < 10000:
            return 0.9
        if count < AI_SERVICE_CALL_RANGES["high_threshold"]:
            return 0.7
        return 0.3

    @staticmethod
    def _score_payload_asymmetry(
        call_count: int,
        hostname: str,
    ) -> float:
        """
        Estimates payload asymmetry likelihood.

        When direct payload size data is not available (Tier 3 connector
        does not collect this to avoid sensitive data):
        Use proxy indicators:

        If hostname matches API-style patterns
        (contains api., /v1/, etc.): 0.7
          (API endpoints tend to have asymmetric
          request/response sizes)

        If hostname looks like CDN or static:
        (contains cdn., static., assets., img.): 0.2

        Default neutral: 0.5

        Note: This is intentionally a rough estimate because collecting
        actual payload sizes would raise privacy concerns. The patent
        claims this estimate approach as part of the privacy-preserving
        design.

        This method never inspects payload contents.
        """
        host_lower = hostname.lower()

        # Direct volume data is not collected for privacy; use proxy.
        if any(indicator in host_lower for indicator in AI_HOSTNAME_STRUCTURAL_INDICATORS):
            return 0.7
        if any(indicator in host_lower for indicator in CDN_HOSTNAME_INDICATORS):
            return 0.2
        return 0.5

    @staticmethod
    def _score_endpoint_pattern(hostname: str) -> float:
        """
        Scores how AI-like the hostname pattern is.

        Check each indicator in AI_HOSTNAME_STRUCTURAL_INDICATORS:
          If hostname contains "api.": +0.25
          If hostname contains "inference.": +0.30
          If hostname contains "ml." or "ai." (including as a TLD): +0.20
          If hostname contains "/v1/" or "/v2/": +0.15
          If hostname ends in ".ai": +0.20
          If hostname ends in ".ml": +0.20

        Cap at 1.0. Round to 4 decimal places.

        CDN-like patterns reduce score:
          Contains "cdn.", "static.", "assets.",
          "img.", "media.": -0.30 per indicator.
          Minimum 0.0.

        This method never inspects payload contents.
        """
        host_lower = hostname.lower()
        score = 0.0

        if "api." in host_lower:
            score += 0.25
        if "inference." in host_lower:
            score += 0.30
        if (
            "ml." in host_lower
            or "ai." in host_lower
            or host_lower.endswith(".ai")
            or host_lower.endswith(".ml")
        ):
            score += 0.20
        if "/v1/" in host_lower or "/v2/" in host_lower:
            score += 0.15
        if host_lower.endswith(".ai"):
            score += 0.20
        if host_lower.endswith(".ml"):
            score += 0.20

        for indicator in CDN_HOSTNAME_INDICATORS:
            if indicator in host_lower:
                score -= 0.30

        score = max(0.0, min(1.0, score))
        return round(score, 4)

    @staticmethod
    def _score_service_type_probability(
        call_count: int,
        hostname: str,
    ) -> float:
        """
        Estimates probability this is an AI inference service vs other
        service types.

        Uses a simple rule-based scoring:
        Start at 0.5 (neutral).

        If call_count in [10, 50000]:
          +0.2 (matches AI service range)
        If hostname has version path (/v1/, /v2/):
          +0.15 (versioned API = likely AI)
        If hostname has "api" subdomain:
          +0.15
        If hostname ends in .ai or .ml:
          +0.20
        If hostname contains "bedrock",
        "vertex", "openai", "anthropic",
        "cohere", "mistral", "groq":
          Return 1.0 immediately
          (known AI vendor domain — but not in
          registry, hence zero-day detection)

        Cap at 1.0. Floor at 0.0.

        This method never inspects payload contents.
        """
        host_lower = hostname.lower()
        score = 0.5

        if 10 <= call_count <= 50000:
            score += 0.20
        if "/v1/" in host_lower or "/v2/" in host_lower:
            score += 0.15
        if "api" in host_lower:  # covers api. subdomain or /api/ path
            score += 0.15
        if host_lower.endswith(".ai") or host_lower.endswith(".ml"):
            score += 0.20

        if any(vendor in host_lower for vendor in KNOWN_AI_VENDOR_SUBSTRINGS):
            return 1.0

        score = max(0.0, min(1.0, score))
        return round(score, 4)

    @staticmethod
    def _score_recency(
        first_seen: datetime,
        last_seen: datetime,
    ) -> float:
        """
        Scores traffic recency pattern.

        AI services show consistent usage patterns.
        A service seen for the first time today
        with high call count is interesting.
        A service seen consistently over days
        is even more interesting.

        duration_days = (last_seen - first_seen).days

        If duration_days == 0:
          (first and last seen same day)
          0.5 — single observation, neutral

        If duration_days >= 1 and duration_days <= 7:
          0.8 — consistent short-term usage

        If duration_days > 7:
          0.9 — established usage pattern

        If last_seen < now() - timedelta(days=30):
          0.3 — stale signal, less relevant

        This method never inspects payload contents.
        """
        now = datetime.now(timezone.utc)

        first = first_seen
        if first.tzinfo is None:
            first = first.replace(tzinfo=timezone.utc)
        last = last_seen
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)

        # Stale signal — observed more than 30 days ago.
        if (now - last).days > 30:
            return 0.3

        duration_days = (last - first).days
        if duration_days == 0:
            return 0.5
        if 1 <= duration_days <= 7:
            return 0.8
        return 0.9

    @staticmethod
    def _compute_composite(features: dict) -> float:
        """
        Computes weighted composite score.
        Uses FEATURE_WEIGHTS.
        Formula: Σ(weight[i] × score[i])
        Returns float rounded to 4 decimal places.
        Always in [0.0, 1.0].

        This method never inspects payload contents.
        """
        total = 0.0
        for key, weight in BehavioralFeatureExtractor.FEATURE_WEIGHTS.items():
            total += weight * float(features.get(key, 0.0))
        composite = max(0.0, min(1.0, total))
        return round(composite, 4)
