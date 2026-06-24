"""
PATENT NOTICE
Module: services/attribution_engine
Implements the owner attribution algorithm
described in Core Patent Claim 1.

Attribution Algorithm (patent-specified):
  1. Collect all Tier 2 (IdP) telemetry events
     for a given (organization_id, signature_id)
     within the past 30 days.
  2. Extract actor_id from raw_signal_json
     of each event.
  3. Count events per unique actor_id.
  4. If the top actor accounts for > 60% of
     total events:
     attributed_owner_id = that actor
     attribution_confidence = their_count /
                              total_count
  5. If < 60% concentration: no attribution.
     Leave attributed_owner_id as NULL.

This algorithm is advisory only.
Attribution never grants access or creates
permissions. It is a governance suggestion
for human review.

The 60% threshold is patent-specified.
Do not change it.

PATENT INVARIANT 14: Attribution is advisory only.
The attributed_owner_id field on a detection is a
suggestion — it never automatically grants access
or creates permissions.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import datetime, timedelta, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.logging_config import get_logger
from app.models.detection import ShadowAIDetection
from app.models.telemetry import TelemetryEvent
from app.services.audit_service import AuditService

logger = get_logger(__name__)

ATTRIBUTION_THRESHOLD = 0.60  # patent invariant
ATTRIBUTION_LOOKBACK_DAYS = 30  # patent invariant

_NIL_UUID = UUID("00000000-0000-0000-0000-000000000000")


def _actor_id_to_uuid(actor_id: str) -> UUID:
    """Convert an actor_id string to a UUID for storage.

    Actor IDs from IdP connectors are either:
    - SHA256 hashes (64 hex chars) from Azure/Google connectors
    - Raw IdP user IDs (e.g. Okta actor IDs)

    Both are converted to a deterministic UUID for storage in the
    attributed_owner_id column (UUID type). This never handles raw
    PII — actor_ids are already hashed by connectors where needed.
    """
    if len(actor_id) == 64:
        try:
            return UUID(actor_id[:32])
        except ValueError:
            pass
    hash_hex = hashlib.sha256(actor_id.encode()).hexdigest()
    return UUID(hash_hex[:32])


class AttributionEngine:
    """Owner attribution algorithm — Core Patent Claim 1.

    PATENT INVARIANT 14: Attribution is advisory only. The
    attributed_owner_id field on a detection is a suggestion —
    it never automatically grants access or creates permissions.
    """

    @staticmethod
    def compute_attribution(
        organization_id: UUID,
        signature_id: UUID,
        db: Session,
    ) -> tuple[str | None, float | None]:
        """Returns (actor_id_hash | None, confidence | None).

        Queries telemetry_events WHERE:
          organization_id = org_id
          matched_signature_id = sig_id
          tier = 2
          observed_at >= now() - 30 days

        Extracts actor_id from each event's
        raw_signal_json["actor_id"].

        Applies 60% concentration threshold.

        Returns (actor_id_hash, confidence) if threshold met,
        else (None, None).

        Note: actor_id values are already SHA256 hashes (applied
        by connectors before storage). This method never handles
        raw PII.

        PATENT INVARIANT 14: This method is advisory only.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(
            days=ATTRIBUTION_LOOKBACK_DAYS
        )

        events = db.execute(
            select(TelemetryEvent).where(
                TelemetryEvent.organization_id == organization_id,
                TelemetryEvent.matched_signature_id == signature_id,
                TelemetryEvent.tier == 2,
                TelemetryEvent.observed_at >= cutoff,
            )
        ).scalars().all()

        if not events:
            return (None, None)

        actor_counts: Counter[str] = Counter()
        for event in events:
            try:
                raw = json.loads(event.raw_signal_json)
            except (json.JSONDecodeError, TypeError):
                continue
            actor_id = raw.get("actor_id")
            if actor_id is not None:
                actor_counts[actor_id] += 1

        if not actor_counts:
            return (None, None)

        total_count = sum(actor_counts.values())
        top_actor, top_count = actor_counts.most_common(1)[0]
        ratio = top_count / total_count

        if ratio >= ATTRIBUTION_THRESHOLD:
            return (top_actor, round(ratio, 4))

        return (None, None)

    @staticmethod
    def run_attribution_pass(
        organization_id: UUID,
        db: Session,
    ) -> dict:
        """Runs attribution for all active detections with Tier 2 signals.

        For each detection with Tier 2 telemetry:
          result = compute_attribution(org, sig, db)
          If result[0] is not None:
            Update detection.attributed_owner_id
            Update detection.attribution_confidence
            AuditService.log(
              action: "shadow_ai.detection.attributed")

        PATENT INVARIANT 14: Attribution is advisory only.
        Setting attributed_owner_id never grants access or
        creates permissions. It is a governance suggestion.

        Returns:
        {
            "detections_evaluated": int,
            "detections_attributed": int,
            "detections_no_attribution": int
        }
        """
        detections = db.execute(
            select(ShadowAIDetection).where(
                ShadowAIDetection.organization_id == organization_id,
                ShadowAIDetection.status.notin_(
                    ["dismissed", "registered"]
                ),
                ShadowAIDetection.deleted_at.is_(None),
                ShadowAIDetection.signature_id.is_not(None),
            )
        ).scalars().all()

        evaluated = 0
        attributed = 0
        no_attribution = 0

        for detection in detections:
            evaluated += 1
            actor_id_hash, confidence = AttributionEngine.compute_attribution(
                organization_id=organization_id,
                signature_id=detection.signature_id,
                db=db,
            )

            if actor_id_hash is not None:
                detection.attributed_owner_id = _actor_id_to_uuid(actor_id_hash)
                detection.attribution_confidence = confidence
                detection.updated_at = datetime.now(timezone.utc)
                attributed += 1

                AuditService.log(
                    db=db,
                    organization_id=organization_id,
                    user_id=None,
                    action="shadow_ai.detection.attributed",
                    entity_type="shadow_ai_detection",
                    entity_id=detection.id,
                    context_json={
                        "provider_name": detection.provider_name,
                        "attribution_confidence": confidence,
                        "advisory_only": True,
                    },
                )
            else:
                no_attribution += 1

        db.commit()

        return {
            "detections_evaluated": evaluated,
            "detections_attributed": attributed,
            "detections_no_attribution": no_attribution,
        }
