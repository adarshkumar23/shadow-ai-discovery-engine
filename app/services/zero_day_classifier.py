"""
PATENT NOTICE
Module: services/zero_day_classifier
Implements Dependent Patent Claim 4:
Zero-Day AI Detection via Behavioral
Classification.

This classifier detects AI services that
are NOT in the signature registry by
analyzing the statistical behavioral
properties of network signal metadata.

Novel technical method:
  The classifier extracts a feature vector
  from network envelope metadata (call count,
  hostname pattern, timing signals) and
  computes a composite behavioral score.
  When the score exceeds the AI_PROBABILITY_THRESHOLD,
  the unknown hostname is classified as a
  probable AI service and a zero-day detection
  is created.

What makes this patentable:
  The specific feature set (call_frequency,
  payload_asymmetry_estimate, endpoint_pattern,
  service_type_probability, recency) applied
  to the specific domain of AI service
  identification — without payload inspection
  and without prior knowledge of the service
  identity — is a novel technical method.

INVARIANTS (never change without patent counsel):
  AI_PROBABILITY_THRESHOLD = 0.55
  CLASSIFIER_VERSION = "1.0.0"
  Feature weights in BehavioralFeatureExtractor
  The zero-day detection method string:
    "behavioral_inference"
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from decimal import Decimal
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.logging_config import get_logger
from app.models.detection import ShadowAIDetection
from app.models.signature import AISignatureRegistry
from app.models.zero_day import ZeroDayCandidate
from app.schemas.telemetry import ConnectorSignalPayload
from app.services.audit_service import AuditService
from app.services.behavioral_feature_extractor import (
    BehavioralFeatureExtractor,
    CLASSIFIER_VERSION as EXTRACTOR_VERSION,
)
from app.services.confidence_engine import ConfidenceEngine
from app.services.suppression_service import SuppressionService

logger = get_logger(__name__)

AI_PROBABILITY_THRESHOLD = 0.55
CLASSIFIER_VERSION = "1.0.0"
MIN_DETECTION_SCORE = 0.40
MIN_CALLS_24H = 5
UNKNOWN_TOOL_DECAY_LAMBDA = Decimal("0.046")

# Candidate status values — must match DB check constraint intent.
CANDIDATE_STATUS_PENDING = "pending_review"
CANDIDATE_STATUS_ADDED = "added_to_registry"
CANDIDATE_STATUS_DISMISSED = "dismissed"
CANDIDATE_STATUS_MONITORING = "monitoring"

_NIL_UUID = UUID("00000000-0000-0000-0000-000000000000")


def _hostname_to_slug(hostname: str) -> str:
    """Derive a registry slug from a hostname.

    Replaces dots and slashes with underscores and truncates to 100
    characters. If the resulting slug collides with an existing
    signature, a short UUID suffix is appended.
    """
    base = re.sub(r"[^a-z0-9_-]", "_", hostname.lower()).strip("_")[:100]
    return base or "unknown"


class ZeroDayClassifier:
    """
    Zero-day behavioral classifier for unknown AI services.

    This classifier is fully deterministic and operates only on the
    network envelope metadata fields present in ConnectorSignalPayload:
    hostname_pattern, call_count_24h, first_seen, last_seen, signal_type.

    What this classifier NEVER does:
    - Inspects packet payload contents
    - Makes external API calls
    - Uses probabilistic models or random sampling
    - Reads request or response bodies
    """

    @staticmethod
    def should_classify(
        payload: ConnectorSignalPayload,
        matched_signature: bool,
    ) -> bool:
        """
        Returns True if zero-day classification should run on this payload.

        Classification runs when:
          matched_signature is False
          (no registry match found by ingestor)
          AND payload.signal_type == "network_match"
          (only network signals have behavioral data)
          AND payload.call_count_24h >= 5
          (minimum meaningful signal)

        Classification does NOT run for:
          Known registry matches (false = matched)
          Non-network signals (text/IdP signals)
          Very low call counts (< 5)

        This method never inspects payload contents.
        """
        if matched_signature:
            return False
        if payload.signal_type != "network_match":
            return False
        if payload.call_count_24h < MIN_CALLS_24H:
            return False
        return True

    @staticmethod
    def classify_signal(
        payload: ConnectorSignalPayload,
        organization_id: UUID,
        db: Session,
        telemetry_event_id: UUID | None = None,
    ) -> ZeroDayCandidate | None:
        """
        PATENT NOTICE: This method implements the zero-day classification
        algorithm of Dependent Patent Claim 4.

        Steps:
        1. Extract behavioral features from network envelope metadata.
        2. Check threshold.
        3. Upsert zero_day_candidates record.
        4. Optionally create shadow_ai_detections record.
        5. Link detection to candidate.

        This method never inspects packet payload contents.
        """
        hostname = payload.hostname_pattern

        features = BehavioralFeatureExtractor.extract(
            hostname=hostname,
            call_count_24h=payload.call_count_24h,
            first_seen=payload.first_seen,
            last_seen=payload.last_seen,
            signal_type=payload.signal_type,
        )

        score = features.composite_score

        if score < AI_PROBABILITY_THRESHOLD:
            logger.debug(
                "Signal below zero-day threshold: %s score=%s",
                hostname,
                score,
                extra={"hostname": hostname, "behavioral_score": score},
            )
            return None

        logger.info(
            "Zero-day AI candidate detected: %s score=%s",
            hostname,
            score,
            extra={"hostname": hostname, "behavioral_score": score},
        )

        now = datetime.now(timezone.utc)

        # 4. Upsert zero_day_candidates.
        candidate = ZeroDayClassifier._upsert_candidate(
            organization_id=organization_id,
            hostname=hostname,
            features=features,
            telemetry_event_id=telemetry_event_id,
            db=db,
        )

        # 5. Create detection if warranted.
        detection = None
        if score >= MIN_DETECTION_SCORE:
            detection = ZeroDayClassifier._maybe_create_detection(
                organization_id=organization_id,
                payload=payload,
                features=features,
                candidate=candidate,
                db=db,
            )

        if detection is not None:
            candidate.detection_id = detection.id
            db.flush()

        db.commit()
        return candidate

    @staticmethod
    def _upsert_candidate(
        organization_id: UUID,
        hostname: str,
        features,
        telemetry_event_id: UUID | None,
        db: Session,
    ) -> ZeroDayCandidate:
        """
        Insert a new zero-day candidate or update an existing pending one.

        Existing pending candidates have their observation_count
        incremented and score updated if the new score is higher.
        """
        score_decimal = Decimal(str(features.composite_score)).quantize(
            Decimal("0.0001")
        )
        now = datetime.now(timezone.utc)

        existing = db.execute(
            select(ZeroDayCandidate).where(
                ZeroDayCandidate.organization_id == organization_id,
                ZeroDayCandidate.hostname == hostname,
                ZeroDayCandidate.status == CANDIDATE_STATUS_PENDING,
            )
        ).scalar_one_or_none()

        feature_summary = {
            "call_frequency_score": features.call_frequency_score,
            "payload_asymmetry_score": features.payload_asymmetry_score,
            "endpoint_pattern_score": features.endpoint_pattern_score,
            "service_type_probability": features.service_type_probability,
            "recency_score": features.recency_score,
            "composite_score": features.composite_score,
        }

        if existing is not None:
            existing.last_observed_at = now
            existing.observation_count = (existing.observation_count or 0) + 1
            existing_signal_ids = []
            if existing.signal_ids:
                try:
                    existing_signal_ids = json.loads(existing.signal_ids)
                except (json.JSONDecodeError, TypeError):
                    existing_signal_ids = []
            if telemetry_event_id is not None:
                existing_signal_ids.append(str(telemetry_event_id))
                existing.signal_ids = json.dumps(existing_signal_ids)

            if score_decimal > Decimal(str(existing.behavioral_score)):
                existing.behavioral_score = score_decimal
                existing.feature_summary = json.dumps(feature_summary)
            existing.updated_at = now
            db.flush()
            return existing

        signal_ids_json = None
        if telemetry_event_id is not None:
            signal_ids_json = json.dumps([str(telemetry_event_id)])

        candidate = ZeroDayCandidate(
            organization_id=organization_id,
            hostname=hostname,
            first_observed_at=now,
            last_observed_at=now,
            observation_count=1,
            signal_ids=signal_ids_json,
            behavioral_score=score_decimal,
            feature_summary=json.dumps(feature_summary),
            status=CANDIDATE_STATUS_PENDING,
        )
        db.add(candidate)
        db.flush()

        return candidate

    @staticmethod
    def _maybe_create_detection(
        organization_id: UUID,
        payload: ConnectorSignalPayload,
        features,
        candidate: ZeroDayCandidate,
        db: Session,
    ) -> ShadowAIDetection | None:
        """
        Create a zero-day shadow_ai_detections record when the score
        supports it and no active detection already exists for this
        hostname.

        The detection confidence is exactly the composite score — never
        artificially inflated.
        """
        score = features.composite_score
        hostname = payload.hostname_pattern

        existing_detection = db.execute(
            select(ShadowAIDetection).where(
                ShadowAIDetection.organization_id == organization_id,
                ShadowAIDetection.zero_day_hostname == hostname,
                ShadowAIDetection.status.notin_(["dismissed", "registered"]),
                ShadowAIDetection.deleted_at.is_(None),
            )
        ).scalar_one_or_none()

        if existing_detection is not None:
            logger.debug(
                "Active zero-day detection already exists for hostname: %s",
                hostname,
                extra={"hostname": hostname},
            )
            return None

        band = ConfidenceEngine.classify_confidence_band(score)
        now = datetime.now(timezone.utc)

        basis = {
            "tier1_signals": 0,
            "tier2_signals": 0,
            "tier3_signals": 1,
            "signal_ids": [],
            "score_breakdown": features.to_dict(),
            "zero_day_hostname": hostname,
        }

        detection = ShadowAIDetection(
            organization_id=organization_id,
            signature_id=None,
            provider_name=f"Unknown AI Service ({hostname})",
            confidence_score=Decimal(str(score)).quantize(Decimal("0.0001")),
            confidence_band=band,
            detection_basis_json=json.dumps(basis),
            is_zero_day=True,
            zero_day_hostname=hostname,
            behavioral_features_json=json.dumps(features.to_dict()),
            classifier_version=CLASSIFIER_VERSION,
            base_confidence_score=Decimal(str(score)).quantize(Decimal("0.0001")),
            decay_lambda=UNKNOWN_TOOL_DECAY_LAMBDA,
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
            action="shadow_ai.zero_day.detection_created",
            entity_type="shadow_ai_detection",
            entity_id=detection.id,
            context_json={
                "hostname": hostname,
                "behavioral_score": score,
                "classifier_version": CLASSIFIER_VERSION,
                "observation_count": candidate.observation_count,
            },
        )

        return detection

    @staticmethod
    def get_candidates(
        organization_id: UUID,
        db: Session,
        status: str | None = None,
    ) -> list[ZeroDayCandidate]:
        """
        Returns zero-day candidates for the org.
        Ordered by behavioral_score DESC.
        Optionally filtered by status.
        """
        query = select(ZeroDayCandidate).where(
            ZeroDayCandidate.organization_id == organization_id
        )
        if status is not None:
            query = query.where(ZeroDayCandidate.status == status)
        query = query.order_by(ZeroDayCandidate.behavioral_score.desc())
        return list(db.execute(query).scalars().all())

    @staticmethod
    def review_candidate(
        candidate_id: UUID,
        organization_id: UUID,
        action: str,
        reviewed_by: UUID,
        review_notes: str | None,
        provider_name: str | None,
        category: str | None,
        db: Session,
    ) -> ZeroDayCandidate:
        """
        Reviews a zero-day candidate.

        action = "add_to_registry":
          Creates a new AISignatureRegistry entry
          with the candidate's hostname and
          the provided provider_name and category.
          Sets candidate status = "added_to_registry".
          From this point forward, the hostname
          will match the registry and produce
          standard (non-zero-day) detections.

        action = "dismiss":
          Sets candidate status = "dismissed".
          Creates suppression for this hostname.

        action = "monitor":
          Sets candidate status = "monitoring".
          No registry addition yet. System continues
          observing this hostname.

        This method never inspects payload contents.
        """
        candidate = db.execute(
            select(ZeroDayCandidate).where(
                ZeroDayCandidate.id == candidate_id,
                ZeroDayCandidate.organization_id == organization_id,
            )
        ).scalar_one_or_none()

        if candidate is None:
            from fastapi import HTTPException

            raise HTTPException(status_code=404, detail="Candidate not found")

        now = datetime.now(timezone.utc)
        candidate.reviewed_by = reviewed_by
        candidate.reviewed_at = now
        candidate.review_notes = review_notes
        candidate.updated_at = now

        if action == "add_to_registry":
            candidate.status = CANDIDATE_STATUS_ADDED
            slug = _hostname_to_slug(candidate.hostname)

            # Ensure slug uniqueness.
            collision = db.execute(
                select(AISignatureRegistry).where(AISignatureRegistry.slug == slug)
            ).scalar_one_or_none()
            if collision is not None:
                suffix = str(uuid4())[:8]
                slug = f"{slug[:91]}_{suffix}"

            registry_entry = AISignatureRegistry(
                slug=slug,
                provider_name=provider_name or candidate.hostname,
                category=category or "other",
                endpoint_patterns=json.dumps([candidate.hostname]),
                keyword_patterns=json.dumps([candidate.hostname]),
                oauth_app_patterns=json.dumps([]),
                data_egress_indicators=None,
                confidence_weights=json.dumps(
                    {
                        "endpoint_match": 0.25,
                        "identity_match": 0.25,
                        "volume_match": 0.20,
                        "keyword_match": 0.30,
                    }
                ),
                risk_level="medium",
                is_active=True,
            )
            db.add(registry_entry)
            db.flush()

            AuditService.log(
                db=db,
                organization_id=organization_id,
                user_id=reviewed_by,
                action="shadow_ai.zero_day.added_to_registry",
                entity_type="zero_day_candidate",
                entity_id=candidate.id,
                context_json={
                    "hostname": candidate.hostname,
                    "registry_slug": slug,
                    "provider_name": provider_name or candidate.hostname,
                    "category": category or "other",
                },
            )

        elif action == "dismiss":
            candidate.status = CANDIDATE_STATUS_DISMISSED
            source_id = candidate.detection_id or candidate.id
            SuppressionService.create_suppression(
                organization_id=organization_id,
                tool_slug=_hostname_to_slug(candidate.hostname),
                detection_method="behavioral_inference",
                suppressed_by=reviewed_by,
                reason=(
                    "Zero-day candidate dismissed by reviewer"
                    + (f". Notes: {review_notes}" if review_notes else "")
                ),
                source_detection_id=source_id,
                db=db,
            )
            AuditService.log(
                db=db,
                organization_id=organization_id,
                user_id=reviewed_by,
                action="shadow_ai.zero_day.dismissed",
                entity_type="zero_day_candidate",
                entity_id=candidate.id,
                context_json={
                    "hostname": candidate.hostname,
                    "review_notes": review_notes,
                },
            )

        elif action == "monitor":
            candidate.status = CANDIDATE_STATUS_MONITORING
            AuditService.log(
                db=db,
                organization_id=organization_id,
                user_id=reviewed_by,
                action="shadow_ai.zero_day.set_to_monitoring",
                entity_type="zero_day_candidate",
                entity_id=candidate.id,
                context_json={
                    "hostname": candidate.hostname,
                    "review_notes": review_notes,
                },
            )

        else:
            from fastapi import HTTPException

            raise HTTPException(
                status_code=400,
                detail=f"Invalid review action: {action}",
            )

        db.commit()
        return candidate
