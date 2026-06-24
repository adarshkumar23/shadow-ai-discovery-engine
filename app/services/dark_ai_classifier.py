"""
PATENT NOTICE
Module: services/dark_ai_classifier
Implements Dependent Patent Claim 10:
Dark AI Detection via Side Channels.

This classifier identifies probable AI service usage from network flow
metadata when direct hostname identification is unavailable — for example
when traffic is routed through a proxy, VPN, or embedded within calls to
another service.

NOVEL TECHNICAL METHOD (patent claim):
  The classifier extracts a feature vector from six flow-level metadata
  signals: timing, variance, payload size distribution, connection
  patterns, and session behavior. These signals are measured from the
  network layer and are observable without payload decryption or TLS
  inspection.

PATENT-SPECIFIED FEATURES:

1. response_time_variance_score
   LLM inference has a characteristic response time variance pattern.
   Unlike static file servers (low variance) or database queries
   (medium variance), LLM generation time varies significantly based on
   response length. This produces a distinctive variance signature.

   Computed from response_time_variance_ms:
     variance < 100ms:   0.1 (static/CDN)
     100-500ms:          0.5 (database-like)
     500-2000ms:         0.8 (LLM-like)
     > 2000ms:           0.6 (too variable)

2. payload_asymmetry_score
   AI inference: small request, large response. Unlike file downloads
   (large both), CDN (large response, small request but low latency),
   databases (small both).

   Computed from avg_request_bytes and avg_response_bytes ratio:
     If both None: 0.5 (neutral)
     ratio = avg_response_bytes / max(avg_request_bytes, 1)
     ratio < 1:    0.1 (symmetric)
     1-5:          0.5 (slight asymmetry)
     5-50:         0.8 (AI-like asymmetry)
     > 50:         0.9 (strongly asymmetric)

3. inter_request_timing_score
   Human-AI conversation pattern produces gaps between requests (human
   reads, thinks, types next prompt). This is different from API polling
   (regular intervals) or streaming (continuous).

   Computed from inter_request_gap_ms:
     gap < 100ms:      0.1 (polling/streaming)
     100ms-2s:         0.4 (API integration)
     2s-60s:           0.9 (human-paced AI)
     > 60s:            0.5 (infrequent use)

4. connection_efficiency_score
   AI services are typically called via persistent connections (high
   reuse ratio) because establishing new TLS connections is expensive
   relative to inference time.

   Computed from connection_reuse_ratio:
     If None: 0.5 (neutral)
     ratio < 0.3:  0.2 (low reuse)
     0.3-0.7:      0.6 (moderate)
     > 0.7:        0.9 (high — AI-like)

5. call_volume_pattern_score
   Reuses Phase 6's call frequency scoring. AI services in production
   environments show consistent moderate call volumes.

6. response_latency_profile_score
   AI inference latency is distinctively higher than CDN or database
   queries.

   Computed from avg_response_time_ms:
     If None: 0.5 (neutral)
     < 50ms:       0.1 (CDN/static)
     50-200ms:     0.3 (fast API)
     200-2000ms:   0.8 (inference-like)
     > 2000ms:     0.6 (slow but possible)

CLASSIFIER FEATURE WEIGHTS (patent invariant):
  DARK_AI_WEIGHTS = {
    "response_time_variance_score": 0.25,
    "payload_asymmetry_score":      0.20,
    "inter_request_timing_score":   0.20,
    "connection_efficiency_score":  0.15,
    "call_volume_pattern_score":    0.10,
    "response_latency_profile_score": 0.10,
  }
  # Sum = 1.0 — patent invariant

DARK_AI_THRESHOLD = 0.60
  (Higher than zero-day threshold of 0.55 because dark AI detection
  requires stronger evidence due to less context)

WHAT THIS CLASSIFIER NEVER DOES:
  - Inspects packet payload contents
  - Decrypts TLS traffic
  - Reads HTTP headers or URLs
  - Identifies the specific AI service (only that traffic appears AI-like)
  - Makes external API calls
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.logging_config import get_logger
from app.models.detection import ShadowAIDetection
from app.schemas.telemetry import ConnectorSignalPayload
from app.services.audit_service import AuditService
from app.services.behavioral_feature_extractor import BehavioralFeatureExtractor
from app.services.confidence_engine import ConfidenceEngine
from app.services.jurisdiction_engine import JurisdictionEngine

logger = get_logger(__name__)

DARK_AI_THRESHOLD = 0.60
DARK_AI_WEIGHTS = {
    "response_time_variance_score": 0.25,
    "payload_asymmetry_score": 0.20,
    "inter_request_timing_score": 0.20,
    "connection_efficiency_score": 0.15,
    "call_volume_pattern_score": 0.10,
    "response_latency_profile_score": 0.10,
}
CLASSIFIER_VERSION = "1.0.0"
_DARK_AI_DECAY_LAMBDA = Decimal("0.046")

# Basic IPv4 pattern — sufficient to flag IP-address hostnames as proxies.
_IPV4_RE = re.compile(
    r"^(?:\d{1,3}\.){3}\d{1,3}$"
)

_TIMING_FIELDS = {
    "avg_response_time_ms",
    "response_time_variance_ms",
    "inter_request_gap_ms",
    "avg_response_bytes",
}


@dataclass
class DarkAIFeatures:
    response_time_variance_score: float
    payload_asymmetry_score: float
    inter_request_timing_score: float
    connection_efficiency_score: float
    call_volume_pattern_score: float
    response_latency_profile_score: float
    composite_score: float
    has_timing_data: bool

    def to_dict(self) -> dict:
        return {
            "response_time_variance_score": self.response_time_variance_score,
            "payload_asymmetry_score": self.payload_asymmetry_score,
            "inter_request_timing_score": self.inter_request_timing_score,
            "connection_efficiency_score": self.connection_efficiency_score,
            "call_volume_pattern_score": self.call_volume_pattern_score,
            "response_latency_profile_score": self.response_latency_profile_score,
            "composite_score": self.composite_score,
            "has_timing_data": self.has_timing_data,
            "classifier_version": CLASSIFIER_VERSION,
        }


class DarkAIClassifier:
    """
    Detects probable AI service usage from network flow metadata when the
    hostname is hidden or unknown.

    Fully deterministic. Operates only on metadata fields defined in
    ConnectorSignalPayload. Never inspects payload contents.
    """

    @staticmethod
    def should_classify(
        payload: ConnectorSignalPayload,
        matched_signature: bool,
    ) -> bool:
        """
        Dark AI classification runs when:
          1. A signature matched but the hostname pattern looks like a
             proxy, gateway, CDN, or IP address (direct identity hidden).
          2. No signature matched AND at least two timing/payload metadata
             fields are present, allowing traffic-shape analysis alone.
        """
        if matched_signature:
            return DarkAIClassifier._is_proxy_pattern(payload)

        present = sum(
            1
            for field in _TIMING_FIELDS
            if getattr(payload, field, None) is not None
        )
        return present >= 2

    @staticmethod
    def extract_features(payload: ConnectorSignalPayload) -> DarkAIFeatures:
        """
        Computes all six dark AI feature scores from flow metadata.

        Missing optional fields receive a neutral score of 0.5 and signal
        that dark AI analysis is operating with degraded timing data.
        """
        has_timing_data = any(
            getattr(payload, field, None) is not None for field in _TIMING_FIELDS
        )

        variance = DarkAIClassifier._score_response_time_variance(
            payload.response_time_variance_ms
        )
        asymmetry = DarkAIClassifier._score_payload_asymmetry(
            payload.avg_request_bytes,
            payload.avg_response_bytes,
        )
        timing = DarkAIClassifier._score_inter_request_timing(
            payload.inter_request_gap_ms
        )
        connection = DarkAIClassifier._score_connection_efficiency(
            payload.connection_reuse_ratio
        )
        volume = BehavioralFeatureExtractor._score_call_frequency(
            payload.call_count_24h
        )
        latency = DarkAIClassifier._score_response_latency_profile(
            payload.avg_response_time_ms
        )

        feature_values = {
            "response_time_variance_score": variance,
            "payload_asymmetry_score": asymmetry,
            "inter_request_timing_score": timing,
            "connection_efficiency_score": connection,
            "call_volume_pattern_score": volume,
            "response_latency_profile_score": latency,
        }

        composite = DarkAIClassifier._compute_composite(feature_values)

        return DarkAIFeatures(
            response_time_variance_score=variance,
            payload_asymmetry_score=asymmetry,
            inter_request_timing_score=timing,
            connection_efficiency_score=connection,
            call_volume_pattern_score=volume,
            response_latency_profile_score=latency,
            composite_score=composite,
            has_timing_data=has_timing_data,
        )

    @staticmethod
    def classify(
        payload: ConnectorSignalPayload,
        organization_id: UUID,
        matched_signature_id: UUID | None,
        telemetry_event_id: UUID,
        db: Session,
    ) -> bool:
        """
        Main classification entry point.

        Returns True if a new dark AI side channel detection was created.
        """
        hostname = payload.hostname_pattern

        features = DarkAIClassifier.extract_features(payload)
        score = features.composite_score

        if score < DARK_AI_THRESHOLD:
            return False

        proxy_detected = DarkAIClassifier._is_proxy_pattern(payload)

        existing = db.execute(
            select(ShadowAIDetection).where(
                ShadowAIDetection.organization_id == organization_id,
                ShadowAIDetection.zero_day_hostname == hostname,
                ShadowAIDetection.is_dark_ai.is_(True),
                ShadowAIDetection.status.notin_(["dismissed", "registered"]),
                ShadowAIDetection.deleted_at.is_(None),
            )
        ).scalar_one_or_none()

        if existing is not None:
            logger.debug(
                "Active dark AI detection already exists for hostname: %s",
                hostname,
                extra={"hostname": hostname},
            )
            return False

        band = ConfidenceEngine.classify_confidence_band(score)
        now = datetime.now(timezone.utc)

        basis = {
            "tier1_signals": 0,
            "tier2_signals": 0,
            "tier3_signals": 1,
            "signal_ids": [str(telemetry_event_id)],
            "dark_ai_features": features.to_dict(),
            "proxy_detected": proxy_detected,
            "detection_method": "dark_ai_side_channel",
        }

        detection = ShadowAIDetection(
            organization_id=organization_id,
            signature_id=matched_signature_id,
            provider_name=f"Dark AI Traffic ({hostname})",
            confidence_score=Decimal(str(score)).quantize(Decimal("0.0001")),
            confidence_band=band,
            detection_basis_json=json.dumps(basis),
            detection_method="dark_ai_side_channel",
            is_dark_ai=True,
            dark_ai_features_json=json.dumps(features.to_dict()),
            dark_ai_score=Decimal(str(score)).quantize(Decimal("0.0001")),
            dark_ai_proxy_detected=proxy_detected,
            zero_day_hostname=hostname,
            base_confidence_score=Decimal(str(score)).quantize(Decimal("0.0001")),
            decay_lambda=_DARK_AI_DECAY_LAMBDA,
            status="new",
            first_detected_at=now,
            last_observed_at=now,
            is_stale=False,
        )
        db.add(detection)
        db.flush()

        AuditService.log(
            db=db,
            organization_id=organization_id,
            user_id=None,
            action="shadow_ai.dark_ai.detection_created",
            entity_type="shadow_ai_detection",
            entity_id=detection.id,
            context_json={
                "hostname": hostname,
                "dark_ai_score": score,
                "proxy_detected": proxy_detected,
                "has_timing_data": features.has_timing_data,
                "classifier_version": CLASSIFIER_VERSION,
            },
        )

        # Dependent Patent Claim 9: regulatory assessment runs on every
        # new detection, including dark AI detections.
        JurisdictionEngine.assess_detection(detection, None, db)

        logger.info(
            "Dark AI detection created: %s score=%s proxy=%s timing=%s",
            hostname,
            score,
            proxy_detected,
            features.has_timing_data,
            extra={
                "hostname": hostname,
                "dark_ai_score": score,
                "proxy_detected": proxy_detected,
            },
        )

        return True

    # ── Feature scoring helpers ─────────────────────

    @staticmethod
    def _score_response_time_variance(variance_ms: int | None) -> float:
        if variance_ms is None:
            return 0.5
        if variance_ms < 100:
            return 0.1
        if variance_ms < 500:
            return 0.5
        if variance_ms <= 2000:
            return 0.8
        return 0.6

    @staticmethod
    def _score_payload_asymmetry(
        request_bytes: int | None,
        response_bytes: int | None,
    ) -> float:
        if request_bytes is None and response_bytes is None:
            return 0.5
        if response_bytes is None or request_bytes is None:
            return 0.5
        ratio = response_bytes / max(request_bytes, 1)
        if ratio <= 1:
            return 0.1
        if ratio < 5:
            return 0.5
        if ratio < 50:
            return 0.8
        return 0.9

    @staticmethod
    def _score_inter_request_timing(gap_ms: int | None) -> float:
        if gap_ms is None:
            return 0.5
        if gap_ms < 100:
            return 0.1
        if gap_ms <= 2000:
            return 0.4
        if gap_ms <= 60000:
            return 0.9
        return 0.5

    @staticmethod
    def _score_connection_efficiency(ratio: float | None) -> float:
        if ratio is None:
            return 0.5
        if ratio < 0.3:
            return 0.2
        if ratio <= 0.7:
            return 0.6
        return 0.9

    @staticmethod
    def _score_response_latency_profile(latency_ms: int | None) -> float:
        if latency_ms is None:
            return 0.5
        if latency_ms < 50:
            return 0.1
        if latency_ms <= 200:
            return 0.3
        if latency_ms <= 2000:
            return 0.8
        return 0.6

    @staticmethod
    def _compute_composite(features: dict[str, float]) -> float:
        total = sum(
            DARK_AI_WEIGHTS[key] * features[key]
            for key in DARK_AI_WEIGHTS
        )
        return round(max(0.0, min(1.0, total)), 4)

    @staticmethod
    def run_nightly_review(db: Session) -> dict:
        """
        Nightly review pass for active dark AI detections.

        Returns a summary dict. This is the sixth scheduler job and
        provides observability into how many dark AI detections are
        currently active across all organizations.
        """
        active_count = db.execute(
            select(func.count())
            .select_from(ShadowAIDetection)
            .where(
                ShadowAIDetection.is_dark_ai.is_(True),
                ShadowAIDetection.status.notin_(["dismissed", "registered"]),
                ShadowAIDetection.deleted_at.is_(None),
            )
        ).scalar() or 0

        proxy_count = db.execute(
            select(func.count())
            .select_from(ShadowAIDetection)
            .where(
                ShadowAIDetection.is_dark_ai.is_(True),
                ShadowAIDetection.dark_ai_proxy_detected.is_(True),
                ShadowAIDetection.status.notin_(["dismissed", "registered"]),
                ShadowAIDetection.deleted_at.is_(None),
            )
        ).scalar() or 0

        return {
            "dark_ai_detections_active": active_count,
            "dark_ai_proxy_detected_count": proxy_count,
            "classifier_version": CLASSIFIER_VERSION,
        }

    @staticmethod
    def _is_proxy_pattern(payload: ConnectorSignalPayload) -> bool:
        """
        Detect whether the traffic appears to be routed through a proxy,
        gateway, or anonymizing intermediate.
        """
        hostname = (payload.hostname_pattern or "").lower()

        proxy_keywords = ["proxy", "gateway", "relay", "forward", "cdn"]
        if any(kw in hostname for kw in proxy_keywords):
            return True

        if _IPV4_RE.match(payload.hostname_pattern or ""):
            return True

        port = getattr(payload, "port", None)
        if port is not None and port != 443:
            return True

        return False
