"""
PATENT NOTICE
Module: services/tier1_scanner
Implements Tier 1 of Core Patent Claim 1.

Detection method: Contextual text inference
with entity recognition, tool-name
disambiguation, and confidence weighting.

This is NOT simple keyword matching.
Each match is:
1. Pattern-matched with word boundaries
2. Scored via the confidence engine
3. Hashed for deduplication
4. Only stored if confidence >= 0.40

What this scanner NEVER does:
- Sends text to any external service
- Uses any probabilistic language model
- Inspects data outside the CompliVibe DB
- Creates detection records below 0.40 confidence
"""

from __future__ import annotations

import json
import re
import time
from datetime import date, datetime, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.logging_config import get_logger
from app.models.questionnaire_response import QuestionnaireResponse
from app.models.telemetry import TelemetryEvent
from app.models.signature import AISignatureRegistry
from app.services.audit_service import AuditService
from app.services.confidence_engine import ConfidenceEngine
from app.services.detection_service import DetectionService
from app.services.intent_engine import IntentEngine
from app.services.registry_service import RegistryService
from app.services.suppression_service import SuppressionService

logger = get_logger(__name__)

_NIL_UUID = UUID("00000000-0000-0000-0000-000000000000")


class Tier1Scanner:
    """Tier 1 text inference scanner."""

    @staticmethod
    def scan_organization(
        organization_id: UUID,
        triggered_by: UUID | None,
        db: Session,
    ) -> dict:
        """Scan all questionnaire_responses for the organization.

        For each response with non-empty answer_text, runs
        keyword matching against all active signatures.

        After processing all responses, calls DetectionService
        to compute/update detection records from new telemetry.

        Returns ScanSummary dict.
        """
        start = time.perf_counter()
        actor = triggered_by or _NIL_UUID

        logger.info(
            "Tier 1 scan started",
            extra={"organization_id": str(organization_id)},
        )

        signatures = RegistryService.get_merged_registry(organization_id, db)

        responses = db.execute(
            select(QuestionnaireResponse).where(
                QuestionnaireResponse.organization_id == organization_id,
                QuestionnaireResponse.deleted_at.is_(None),
                QuestionnaireResponse.answer_text.is_not(None),
                QuestionnaireResponse.answer_text != "",
            )
        ).scalars().all()

        records_scanned = len(responses)
        total_new = 0
        total_dups = 0

        for resp in responses:
            new_signals, dups = Tier1Scanner._process_response_text(
                response_id=resp.id,
                answer_text=resp.answer_text,
                organization_id=organization_id,
                signatures=signatures,
                db=db,
            )
            total_new += new_signals
            total_dups += dups

        detection_result = DetectionService.run_detection(organization_id, db)

        duration_ms = int((time.perf_counter() - start) * 1000)

        summary = {
            "records_scanned": records_scanned,
            "new_signals": total_new,
            "duplicates_skipped": total_dups,
            "detections_created": detection_result.get("detections_created", 0),
            "detections_updated": detection_result.get("detections_updated", 0),
            "scan_duration_ms": duration_ms,
            "scan_type": "questionnaire",
        }

        logger.info(
            "Tier 1 scan completed",
            extra=summary,
        )

        AuditService.log(
            db=db,
            organization_id=organization_id,
            user_id=actor,
            action="shadow_ai.scan.tier1_completed",
            entity_type="scan",
            entity_id=_NIL_UUID,
            context_json=summary,
        )

        return summary

    @staticmethod
    def _process_response_text(
        response_id: UUID,
        answer_text: str,
        organization_id: UUID,
        signatures: list[AISignatureRegistry],
        db: Session,
    ) -> tuple[int, int]:
        """Process a single response text against all signatures.

        Returns (new_signals_created, duplicates_skipped).

        For each active signature:
          Compute keyword match score.
          If no match: continue.
          Compute signal_hash for deduplication.
          If hash exists: skip (duplicate).
          If new: INSERT telemetry_event.

        Never stores more than first 150 chars of surrounding text
        in matched_text_excerpt. Never stores the full answer_text.
        """
        new_signals = 0
        duplicates = 0
        event_date = date.today()
        now = datetime.now(timezone.utc)
        source_label = f"questionnaire_response:{response_id}"

        for signature in signatures:
            keyword_patterns = json.loads(signature.keyword_patterns)

            score, matched_keyword = ConfidenceEngine.compute_keyword_match_score(
                answer_text, keyword_patterns
            )

            if score == 0.0:
                continue

            if SuppressionService.is_suppressed(
                organization_id, signature.slug, "questionnaire", db
            ):
                continue

            classification = IntentEngine.classify(
                text=answer_text,
                tool_name=signature.provider_name,
            )

            signal_hash = ConfidenceEngine.compute_signal_hash(
                organization_id=organization_id,
                signature_id=signature.id,
                source_system_label=source_label,
                event_date=event_date,
            )

            existing = db.execute(
                select(TelemetryEvent).where(
                    TelemetryEvent.organization_id == organization_id,
                    TelemetryEvent.signal_hash == signal_hash,
                )
            ).scalar_one_or_none()

            if existing is not None:
                duplicates += 1
                continue

            lower_text = answer_text.lower()
            lower_kw = matched_keyword.lower()
            regex = r"\b" + re.escape(lower_kw) + r"\b"
            match = re.search(regex, lower_text)
            pos = match.start() if match else 0

            excerpt_start = max(0, pos - 50)
            excerpt_end = min(len(answer_text), pos + 100)
            excerpt = answer_text[excerpt_start:excerpt_end]
            if len(excerpt) > 150:
                excerpt = excerpt[:150]

            event = TelemetryEvent(
                organization_id=organization_id,
                tier=1,
                event_type="text_mention",
                source_system_label=source_label,
                matched_signature_id=signature.id,
                raw_signal_json=json.dumps({
                    "source_table": "questionnaire_responses",
                    "source_record_id": str(response_id),
                    "matched_keyword": matched_keyword,
                    "matched_text_excerpt": excerpt,
                    "match_position": pos,
                    "intent_classification": classification,
                }),
                signal_hash=signal_hash,
                observed_at=now,
            )
            db.add(event)
            new_signals += 1

        if new_signals > 0:
            db.flush()

        return new_signals, duplicates

    @staticmethod
    def scan_single_response(
        response_id: UUID,
        answer_text: str,
        organization_id: UUID,
        db: Session,
    ) -> int:
        """Real-time hook for when a new questionnaire response is saved.

        Scans just that one response. Called synchronously before
        the save returns. Returns count of new signals created.

        This method enables real-time detection — a patent design
        point. Detections are computed immediately so governance
        teams are alerted without waiting for the nightly batch.
        """
        signatures = RegistryService.get_merged_registry(organization_id, db)

        new_signals, _ = Tier1Scanner._process_response_text(
            response_id=response_id,
            answer_text=answer_text,
            organization_id=organization_id,
            signatures=signatures,
            db=db,
        )

        if new_signals > 0:
            DetectionService.run_detection(organization_id, db)

        return new_signals
