"""
PATENT NOTICE
Module: services/decay_engine
Implements Dependent Patent Claim 6:
Temporal Confidence Decay with Category-
Calibrated Decay Coefficients.

Decay Formula (patent-invariant):
  current_confidence = base_confidence
    × e^(-λ × days_since_last_observation)

Where:
  base_confidence = detection.base_confidence_score
    (stored at creation, never changes)
  λ = detection.decay_lambda
    (category-specific, set at creation)
  days_since_last_observation =
    (now - detection.last_observed_at).days

Threshold Behaviour (patent-invariant):
  If current_confidence drops below 0.40:
    is_stale = True
    status → 'needs_review'
    Governance task created automatically

When a new signal arrives for a stale detection:
  is_stale → False
  base_confidence_score updated to current score
  status → 'new' (reactivated)
  AuditLog entry: "shadow_ai.detection.reactivated"
  This reactivation behaviour is patent-specified.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.logging_config import get_logger
from app.models.detection import ShadowAIDetection
from app.services.audit_service import AuditService

logger = get_logger(__name__)

# Patent-invariant decay coefficients by category
_LAMBDA_VALUES: dict[str, float] = {
    "llm": 0.023,
    "code_assistant": 0.023,
    "agent": 0.023,
    "embedding": 0.035,
    "data_ai": 0.035,
    "image_gen": 0.046,
    "voice_ai": 0.046,
    "other": 0.069,
}

_DEFAULT_LAMBDA = 0.046

_NIL_UUID = UUID("00000000-0000-0000-0000-000000000000")


class DecayEngine:
    """Temporal confidence decay with category-calibrated coefficients."""

    @staticmethod
    def compute_decayed_confidence(
        base_confidence: float,
        decay_lambda: float,
        days_since_observed: int,
    ) -> float:
        """Implement patent formula exactly.

        result = base_confidence × e^(-λ × days)
        Returns float rounded to 4 decimal places.
        Never returns value below 0.0 or above 1.0.
        """
        result = base_confidence * math.exp(-decay_lambda * days_since_observed)
        return round(max(0.0, min(1.0, result)), 4)

    @staticmethod
    def run_decay_pass(
        organization_id: UUID | None,
        db: Session,
    ) -> dict:
        """Run decay computation on all active detections.

        If organization_id is provided: only that org.
        If organization_id is None: all organizations.
        (None is used by the nightly scheduler.)

        Skips detections with status 'dismissed' or 'registered'.
        Skips detections that are already stale.
        Skips detections observed today (days == 0).

        Returns summary dict with processed/went_stale/skipped counts.
        """
        now = datetime.now(timezone.utc)

        query = select(ShadowAIDetection).where(
            ShadowAIDetection.status.notin_(["dismissed", "registered"]),
            ShadowAIDetection.deleted_at.is_(None),
            ShadowAIDetection.is_stale.is_(False),
        )
        if organization_id is not None:
            query = query.where(ShadowAIDetection.organization_id == organization_id)

        detections = db.execute(query).scalars().all()

        processed = 0
        went_stale = 0
        skipped_same_day = 0

        for detection in detections:
            last_observed = detection.last_observed_at
            if last_observed.tzinfo is None:
                last_observed = last_observed.replace(tzinfo=timezone.utc)

            days = (now - last_observed).days

            if days == 0:
                skipped_same_day += 1
                continue

            base = float(detection.base_confidence_score) if detection.base_confidence_score is not None else float(detection.confidence_score)
            lam = float(detection.decay_lambda) if detection.decay_lambda is not None else _DEFAULT_LAMBDA

            current = DecayEngine.compute_decayed_confidence(base, lam, days)

            detection.confidence_score = current
            detection.decayed_at = now
            detection.updated_at = now
            processed += 1

            if current < 0.40 and not detection.is_stale:
                detection.is_stale = True
                detection.status = "needs_review"
                went_stale += 1

                AuditService.log(
                    db=db,
                    organization_id=detection.organization_id,
                    user_id=None,
                    action="shadow_ai.detection.went_stale",
                    entity_type="shadow_ai_detection",
                    entity_id=detection.id,
                    context_json={
                        "provider_name": detection.provider_name,
                        "base_confidence": base,
                        "current_confidence": current,
                        "days_since_observed": days,
                        "decay_lambda": lam,
                    },
                )

        db.commit()

        return {
            "processed": processed,
            "went_stale": went_stale,
            "skipped_same_day": skipped_same_day,
            "organization_id": str(organization_id) if organization_id else "all",
        }

    @staticmethod
    def reactivate_detection(
        detection: ShadowAIDetection,
        new_confidence: float,
        db: Session,
        triggered_by: UUID,
    ) -> None:
        """Reactivate a stale detection when a new signal arrives.

        Sets:
          is_stale = False
          base_confidence_score = new_confidence
          confidence_score = new_confidence
          status = 'new'
          last_observed_at = now()

        Logs reactivation via AuditService.
        """
        previous_confidence = float(detection.confidence_score)

        detection.is_stale = False
        detection.base_confidence_score = new_confidence
        detection.confidence_score = new_confidence
        detection.status = "new"
        detection.last_observed_at = datetime.now(timezone.utc)
        detection.updated_at = datetime.now(timezone.utc)
        detection.decayed_at = None

        AuditService.log(
            db=db,
            organization_id=detection.organization_id,
            user_id=triggered_by,
            action="shadow_ai.detection.reactivated",
            entity_type="shadow_ai_detection",
            entity_id=detection.id,
            context_json={
                "provider_name": detection.provider_name,
                "previous_stale_confidence": previous_confidence,
                "new_confidence": new_confidence,
            },
        )

    @staticmethod
    def get_lambda_for_category(category: str) -> float:
        """Return the patent-specified decay coefficient for the category.

        llm → 0.023
        code_assistant → 0.023
        agent → 0.023
        embedding → 0.035
        data_ai → 0.035
        image_gen → 0.046
        voice_ai → 0.046
        other → 0.069

        Default for unknown category: 0.046
        These values are patent-invariant.
        """
        return _LAMBDA_VALUES.get(category, _DEFAULT_LAMBDA)
