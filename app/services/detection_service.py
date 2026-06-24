"""
PATENT NOTICE
Module: services/detection_service
Part of: Shadow AI Discovery Engine
Patent: System and Method for Inferring Undeclared
Artificial Intelligence Systems and Generating AI
Governance Artifacts from Enterprise Telemetry
Status: Provisional filing in preparation

Core detection algorithm. Converts telemetry events
into detection records using the confidence engine
and manages the detection lifecycle.
"""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from typing import Literal
from uuid import UUID

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.logging_config import get_logger
from app.models.ai_system import AISystem
from app.models.detection import ShadowAIDetection
from app.models.signature import AISignatureRegistry
from app.models.telemetry import TelemetryEvent
from app.registry.signature_registry import REGISTRY_VERSION
from app.services.audit_service import AuditService
from app.services.confidence_engine import ConfidenceEngine
from app.services.decay_engine import DecayEngine
from app.services.jurisdiction_engine import JurisdictionEngine
from app.services.suppression_service import SuppressionService
from app.schemas.detection import BulkActionResponse, EscalateRequest

logger = get_logger(__name__)

_NIL_UUID = UUID("00000000-0000-0000-0000-000000000000")


class DetectionService:
    """Detection CRUD and lifecycle management."""

    @staticmethod
    def run_detection(
        organization_id: UUID,
        db: Session,
    ) -> dict:
        """Core detection algorithm.

        Called after every scan to convert new telemetry events
        into detection records. Groups telemetry_events by
        (organization_id, matched_signature_id) and computes
        confidence scores.

        Returns summary dict with created/updated/discarded counts.
        """
        events_q = (
            select(TelemetryEvent)
            .where(
                TelemetryEvent.organization_id == organization_id,
                TelemetryEvent.matched_signature_id.is_not(None),
            )
            .order_by(TelemetryEvent.ingested_at)
        )
        all_events = db.execute(events_q).scalars().all()

        groups: dict[UUID, list[TelemetryEvent]] = {}
        for event in all_events:
            groups.setdefault(event.matched_signature_id, []).append(event)

        detections_created = 0
        detections_updated = 0
        discarded_low_confidence = 0

        for signature_id, events in groups.items():
            signature = db.execute(
                select(AISignatureRegistry).where(
                    AISignatureRegistry.id == signature_id
                )
            ).scalar_one_or_none()

            if signature is None:
                continue

            score, breakdown = ConfidenceEngine.compute_score(signature, events)
            band = ConfidenceEngine.classify_confidence_band(score)

            if band == "discard":
                logger.debug(
                    "Detection discarded below threshold",
                    extra={
                        "signature_slug": signature.slug,
                        "confidence_score": score,
                    },
                )
                discarded_low_confidence += 1
                continue

            existing = db.execute(
                select(ShadowAIDetection).where(
                    ShadowAIDetection.organization_id == organization_id,
                    ShadowAIDetection.signature_id == signature.id,
                    ShadowAIDetection.status.notin_(["dismissed", "registered"]),
                    ShadowAIDetection.deleted_at.is_(None),
                )
            ).scalar_one_or_none()

            tier1_count = sum(1 for e in events if e.tier == 1)
            tier2_count = sum(1 for e in events if e.tier == 2)
            tier3_count = sum(1 for e in events if e.tier == 3)

            basis = {
                "tier1_signals": tier1_count,
                "tier2_signals": tier2_count,
                "tier3_signals": tier3_count,
                "signal_ids": [str(e.id) for e in events],
                "score_breakdown": breakdown,
            }

            now = datetime.now(timezone.utc)

            if existing is not None:
                new_score = ConfidenceEngine.compute_rolling_average(
                    float(existing.confidence_score),
                    len(events),
                    score,
                )
                new_band = ConfidenceEngine.classify_confidence_band(new_score)

                if existing.is_stale:
                    DecayEngine.reactivate_detection(
                        detection=existing,
                        new_confidence=new_score,
                        db=db,
                        triggered_by=_NIL_UUID,
                    )
                else:
                    existing.confidence_score = new_score
                    existing.confidence_band = new_band
                    existing.last_observed_at = now
                    existing.updated_at = now

                existing.detection_basis_json = json.dumps(basis)
                detections_updated += 1

                JurisdictionEngine.assess_detection(existing, signature, db)

                AuditService.log(
                    db=db,
                    organization_id=organization_id,
                    user_id=None,
                    action="shadow_ai.detection.updated",
                    entity_type="shadow_ai_detection",
                    entity_id=existing.id,
                    context_json={
                        "provider_name": signature.provider_name,
                        "confidence_score": float(new_score),
                        "confidence_band": new_band,
                        "tier1_signals": tier1_count,
                    },
                )
            else:
                if SuppressionService.is_suppressed(
                    organization_id, signature.slug, "questionnaire", db
                ):
                    continue

                decay_lambda = DecayEngine.get_lambda_for_category(
                    signature.category
                )

                detection = ShadowAIDetection(
                    organization_id=organization_id,
                    signature_id=signature.id,
                    provider_name=signature.provider_name,
                    confidence_score=score,
                    confidence_band=band,
                    detection_basis_json=json.dumps(basis),
                    base_confidence_score=score,
                    decay_lambda=decay_lambda,
                    status="new",
                    first_detected_at=now,
                    last_observed_at=now,
                    is_stale=False,
                )
                db.add(detection)
                db.flush()
                detections_created += 1

                best_classification = DetectionService._extract_best_intent(events)
                if best_classification is not None:
                    detection.intent_action = best_classification["intent_tuple"]["action"]
                    detection.intent_data_subject = best_classification["intent_tuple"]["data_subject"]
                    detection.intent_business_context = best_classification["intent_tuple"]["business_context"]
                    detection.inferred_use_case = best_classification["use_case"]
                    detection.use_case_risk_json = json.dumps(best_classification)
                    detection.intent_classified_at = now

                    AuditService.log(
                        db=db,
                        organization_id=organization_id,
                        user_id=None,
                        action="shadow_ai.detection.intent_classified",
                        entity_type="shadow_ai_detection",
                        entity_id=detection.id,
                        context_json={
                            "use_case": best_classification["use_case"],
                            "risk_level": best_classification["risk_level"],
                            "confidence": best_classification["classification_confidence"],
                            "regulations_count": len(best_classification["applicable_regulations"]),
                        },
                    )

                JurisdictionEngine.assess_detection(detection, signature, db)

                AuditService.log(
                    db=db,
                    organization_id=organization_id,
                    user_id=None,
                    action="shadow_ai.detection.created",
                    entity_type="shadow_ai_detection",
                    entity_id=detection.id,
                    context_json={
                        "provider_name": signature.provider_name,
                        "confidence_score": float(score),
                        "confidence_band": band,
                        "tier1_signals": tier1_count,
                        "registry_version": REGISTRY_VERSION,
                    },
                )

        db.commit()

        return {
            "detections_created": detections_created,
            "detections_updated": detections_updated,
            "discarded_low_confidence": discarded_low_confidence,
            "organization_id": str(organization_id),
        }

    @staticmethod
    def get_detection_summary(
        organization_id: UUID,
        db: Session,
    ) -> dict:
        """Return dashboard metric payload."""
        active_filter = (
            ShadowAIDetection.organization_id == organization_id,
            ShadowAIDetection.deleted_at.is_(None),
            ShadowAIDetection.status.notin_(["dismissed", "registered"]),
        )

        total_active = db.execute(
            select(func.count()).select_from(ShadowAIDetection).where(*active_filter)
        ).scalar() or 0

        status_counts: dict[str, int] = {}
        for status_val in ("new", "reviewed", "needs_review", "escalated"):
            count = db.execute(
                select(func.count())
                .select_from(ShadowAIDetection)
                .where(
                    ShadowAIDetection.organization_id == organization_id,
                    ShadowAIDetection.deleted_at.is_(None),
                    ShadowAIDetection.status == status_val,
                )
            ).scalar() or 0
            status_counts[status_val] = count

        band_counts: dict[str, int] = {}
        for band_val in ("high", "medium"):
            count = db.execute(
                select(func.count())
                .select_from(ShadowAIDetection)
                .where(
                    ShadowAIDetection.organization_id == organization_id,
                    ShadowAIDetection.deleted_at.is_(None),
                    ShadowAIDetection.status.notin_(["dismissed", "registered"]),
                    ShadowAIDetection.confidence_band == band_val,
                )
            ).scalar() or 0
            band_counts[band_val] = count

        stale_count = db.execute(
            select(func.count())
            .select_from(ShadowAIDetection)
            .where(
                ShadowAIDetection.organization_id == organization_id,
                ShadowAIDetection.deleted_at.is_(None),
                ShadowAIDetection.is_stale.is_(True),
            )
        ).scalar() or 0

        top_q = (
            select(ShadowAIDetection)
            .where(
                ShadowAIDetection.organization_id == organization_id,
                ShadowAIDetection.deleted_at.is_(None),
                ShadowAIDetection.status.notin_(["dismissed", "registered"]),
            )
            .order_by(ShadowAIDetection.confidence_score.desc())
            .limit(10)
        )
        top_detections = db.execute(top_q).scalars().all()
        top_tools = [
            {
                "provider_name": d.provider_name,
                "confidence_score": float(d.confidence_score),
                "confidence_band": d.confidence_band,
                "first_detected_at": d.first_detected_at,
                "is_stale": d.is_stale,
            }
            for d in top_detections
        ]

        return {
            "total_active": total_active,
            "by_status": status_counts,
            "by_confidence_band": band_counts,
            "stale_count": stale_count,
            "top_detected_tools": top_tools,
        }

    @staticmethod
    def _extract_best_intent(
        events: list[TelemetryEvent],
    ) -> dict | None:
        """Find the highest-confidence intent classification from telemetry events."""
        confidence_order = {"high": 3, "medium": 2, "low": 1}
        best: dict | None = None
        best_score = 0

        for event in events:
            try:
                raw = json.loads(event.raw_signal_json)
            except (json.JSONDecodeError, TypeError):
                continue
            classification = raw.get("intent_classification")
            if classification is None:
                continue
            score = confidence_order.get(classification.get("classification_confidence", "low"), 0)
            if score > best_score:
                best = classification
                best_score = score

        return best

    @staticmethod
    def get_detection_by_id(
        detection_id: UUID,
        organization_id: UUID,
        db: Session,
    ) -> ShadowAIDetection | None:
        """Fetches single detection.
        MUST filter by both detection_id AND organization_id —
        never trust detection_id alone. This enforces tenant isolation.
        Returns None if not found or wrong org.
        """
        return db.execute(
            select(ShadowAIDetection).where(
                ShadowAIDetection.id == detection_id,
                ShadowAIDetection.organization_id == organization_id,
                ShadowAIDetection.deleted_at.is_(None),
            )
        ).scalar_one_or_none()

    @staticmethod
    def list_detections(
        organization_id: UUID,
        db: Session,
        status: str | None = None,
        confidence_band: str | None = None,
        is_stale: bool | None = None,
        search: str | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[list[ShadowAIDetection], int]:
        """Paginated detection list.
        search param filters on provider_name and inferred_use_case
        (case-insensitive).
        Returns (items, total_count).
        """
        query = select(ShadowAIDetection).where(
            ShadowAIDetection.organization_id == organization_id,
            ShadowAIDetection.deleted_at.is_(None),
        )

        if status is not None:
            query = query.where(ShadowAIDetection.status == status)
        if confidence_band is not None:
            query = query.where(ShadowAIDetection.confidence_band == confidence_band)
        if is_stale is not None:
            query = query.where(ShadowAIDetection.is_stale.is_(is_stale))
        if search is not None:
            pattern = f"%{search.lower()}%"
            query = query.where(
                or_(
                    func.lower(ShadowAIDetection.provider_name).like(pattern),
                    func.lower(ShadowAIDetection.inferred_use_case).like(pattern),
                )
            )

        count_q = select(func.count()).select_from(query.subquery())
        total = db.execute(count_q).scalar() or 0

        offset = (page - 1) * page_size
        query = query.order_by(ShadowAIDetection.confidence_score.desc())
        query = query.offset(offset).limit(page_size)
        items = list(db.execute(query).scalars().all())

        return items, total

    @staticmethod
    def dismiss_detection(
        detection_id: UUID,
        organization_id: UUID,
        dismissed_by: UUID,
        reason: str,
        notes: str | None,
        db: Session,
    ) -> ShadowAIDetection:
        """Dismiss a detection.

        PATENT INVARIANT: Detection is NEVER hard deleted.
        deleted_at remains NULL. Only dismissed_at and
        dismissal_reason are set. The record is retained
        permanently for audit trail purposes.

        After setting dismissed status, creates a suppression
        record to prevent future re-detection via the same method.

        Raises ValueError if detection is already dismissed or registered.
        """
        detection = DetectionService.get_detection_by_id(
            detection_id, organization_id, db
        )
        if detection is None:
            raise ValueError("Detection not found")

        if detection.status == "dismissed":
            raise ValueError("Detection is already dismissed")
        if detection.status == "registered":
            raise ValueError("Cannot dismiss a registered detection")

        now = datetime.now(timezone.utc)
        detection.status = "dismissed"
        detection.dismissed_at = now
        detection.dismissed_by_user_id = dismissed_by
        detection.dismissal_reason = reason
        detection.updated_at = now

        db.flush()

        signature = None
        if detection.signature_id is not None:
            signature = db.execute(
                select(AISignatureRegistry).where(
                    AISignatureRegistry.id == detection.signature_id
                )
            ).scalar_one_or_none()

        tool_slug = signature.slug if signature else "unknown"
        detection_method = "questionnaire"

        SuppressionService.create_suppression(
            organization_id=organization_id,
            tool_slug=tool_slug,
            detection_method=detection_method,
            suppressed_by=dismissed_by,
            reason=reason,
            source_detection_id=detection.id,
            db=db,
        )

        AuditService.log(
            db=db,
            organization_id=organization_id,
            user_id=dismissed_by,
            action="shadow_ai.detection.dismissed",
            entity_type="shadow_ai_detection",
            entity_id=detection.id,
            context_json={
                "provider_name": detection.provider_name,
                "reason": reason,
                "suppression_created": True,
            },
        )

        db.commit()
        return detection

    @staticmethod
    def escalate_to_inventory(
        detection_id: UUID,
        organization_id: UUID,
        escalated_by: UUID,
        escalate_request: EscalateRequest,
        db: Session,
    ) -> tuple[ShadowAIDetection, AISystem]:
        """Promote a confirmed detection to a formal AI System governance record.

        PATENT NOTICE: This method implements Core Patent Claim 3:
        Latent AI System Entity conversion to governance artifact.
        No governance record becomes authoritative until this method is
        called with explicit human authorization. The system never
        auto-promotes detections. Human action is required every time.
        """
        detection = DetectionService.get_detection_by_id(
            detection_id, organization_id, db
        )
        if detection is None:
            raise ValueError("Detection not found")

        if detection.status == "dismissed":
            raise ValueError("Cannot escalate a dismissed detection")
        if detection.status == "registered":
            raise ValueError("Detection already promoted to inventory")

        if detection.registered_ai_system_id is not None:
            raise ValueError("Detection already promoted to inventory")

        signature = None
        if detection.signature_id is not None:
            signature = db.execute(
                select(AISignatureRegistry).where(
                    AISignatureRegistry.id == detection.signature_id
                )
            ).scalar_one_or_none()

        regulatory_flags_list: list[str] = []
        if detection.jurisdiction_assessment_json:
            try:
                assessment = json.loads(detection.jurisdiction_assessment_json)
                for article in assessment.get("applicable_articles", []):
                    regulatory_flags_list.append(article.get("article_id", ""))
            except (json.JSONDecodeError, TypeError):
                pass
        elif detection.use_case_risk_json:
            try:
                risk_json = json.loads(detection.use_case_risk_json)
                for reg in risk_json.get("applicable_regulations", []):
                    regulatory_flags_list.append(reg.get("code", ""))
            except (json.JSONDecodeError, TypeError):
                pass

        owner_id = escalate_request.owner_id or detection.attributed_owner_id

        ai_system = AISystem(
            organization_id=organization_id,
            name=detection.provider_name,
            vendor=signature.provider_name if signature else detection.provider_name,
            category=signature.category if signature else "other",
            system_type=escalate_request.system_type,
            deployment_status="unknown",
            risk_level=signature.risk_level if signature else None,
            source="shadow_ai_discovery",
            source_detection_id=detection.id,
            inferred_use_case=detection.inferred_use_case,
            regulatory_flags=json.dumps(regulatory_flags_list) if regulatory_flags_list else None,
            owner_id=owner_id,
            created_by=escalated_by,
        )
        db.add(ai_system)
        db.flush()

        now = datetime.now(timezone.utc)
        detection.status = "registered"
        detection.registered_ai_system_id = ai_system.id
        detection.escalated_at = now
        detection.escalated_by_user_id = escalated_by
        detection.escalation_notes = escalate_request.notes
        detection.updated_at = now

        db.flush()

        AuditService.log(
            db=db,
            organization_id=organization_id,
            user_id=escalated_by,
            action="shadow_ai.detection.escalated",
            entity_type="shadow_ai_detection",
            entity_id=detection.id,
            context_json={
                "provider_name": detection.provider_name,
                "ai_system_id": str(ai_system.id),
                "system_type": escalate_request.system_type,
                "inferred_use_case": detection.inferred_use_case,
                "regulatory_flags": regulatory_flags_list or None,
                "source": "shadow_ai_discovery",
            },
        )

        AuditService.log(
            db=db,
            organization_id=organization_id,
            user_id=escalated_by,
            action="shadow_ai.ai_system.created",
            entity_type="ai_system",
            entity_id=ai_system.id,
            context_json={
                "source_detection_id": str(detection.id),
                "source": "shadow_ai_discovery",
            },
        )

        db.commit()
        return detection, ai_system

    @staticmethod
    def bulk_dismiss(
        detection_ids: list[UUID],
        organization_id: UUID,
        dismissed_by: UUID,
        reason: str,
        db: Session,
    ) -> BulkActionResponse:
        """Dismisses multiple detections at once. Max 50 IDs per call.
        For each ID: try dismiss_detection(). On success: add to succeeded.
        On ValueError: add to failed list with reason.
        Never raises — always returns summary.
        """
        succeeded: list[UUID] = []
        failed: list[dict] = []

        for det_id in detection_ids[:50]:
            try:
                DetectionService.dismiss_detection(
                    detection_id=det_id,
                    organization_id=organization_id,
                    dismissed_by=dismissed_by,
                    reason=reason,
                    notes=None,
                    db=db,
                )
                succeeded.append(det_id)
            except ValueError as exc:
                failed.append({"id": str(det_id), "reason": str(exc)})

        return BulkActionResponse(
            succeeded=succeeded,
            failed=failed,
            total_succeeded=len(succeeded),
            total_failed=len(failed),
        )

    @staticmethod
    def bulk_review(
        detection_ids: list[UUID],
        organization_id: UUID,
        reviewed_by: UUID,
        db: Session,
    ) -> BulkActionResponse:
        """Sets multiple detections to 'reviewed' status.
        Same pattern as bulk_dismiss. Never raises.
        """
        succeeded: list[UUID] = []
        failed: list[dict] = []

        for det_id in detection_ids[:50]:
            detection = DetectionService.get_detection_by_id(
                det_id, organization_id, db
            )
            if detection is None:
                failed.append({"id": str(det_id), "reason": "Detection not found"})
                continue
            if detection.status in ("dismissed", "registered"):
                failed.append({
                    "id": str(det_id),
                    "reason": f"Cannot review a {detection.status} detection",
                })
                continue

            now = datetime.now(timezone.utc)
            detection.status = "reviewed"
            detection.reviewed_by_user_id = reviewed_by
            detection.reviewed_at = now
            detection.updated_at = now

            AuditService.log(
                db=db,
                organization_id=organization_id,
                user_id=reviewed_by,
                action="shadow_ai.detection.reviewed",
                entity_type="shadow_ai_detection",
                entity_id=detection.id,
                context_json={"provider_name": detection.provider_name},
            )
            succeeded.append(det_id)

        db.commit()

        return BulkActionResponse(
            succeeded=succeeded,
            failed=failed,
            total_succeeded=len(succeeded),
            total_failed=len(failed),
        )

    @staticmethod
    def export_detections(
        organization_id: UUID,
        db: Session,
        format: Literal["csv", "json"],
        status: str | None = None,
    ) -> str:
        """Returns detection data as CSV or JSON string.

        CSV columns (in order):
          tool_name, vendor, category, confidence_score,
          confidence_band, status, detection_method,
          inferred_use_case, risk_level, is_stale,
          first_detected_at, last_observed_at,
          reviewed_by, intent_action, intent_data_subject,
          intent_business_context
        """
        query = select(ShadowAIDetection).where(
            ShadowAIDetection.organization_id == organization_id,
            ShadowAIDetection.deleted_at.is_(None),
        )
        if status is not None:
            query = query.where(ShadowAIDetection.status == status)
        query = query.order_by(ShadowAIDetection.confidence_score.desc())

        detections = db.execute(query).scalars().all()

        sig_map: dict[UUID, AISignatureRegistry] = {}
        for d in detections:
            if d.signature_id and d.signature_id not in sig_map:
                sig = db.execute(
                    select(AISignatureRegistry).where(
                        AISignatureRegistry.id == d.signature_id
                    )
                ).scalar_one_or_none()
                if sig:
                    sig_map[d.signature_id] = sig

        rows: list[dict] = []
        for d in detections:
            sig = sig_map.get(d.signature_id) if d.signature_id else None
            try:
                basis = json.loads(d.detection_basis_json) if d.detection_basis_json else {}
            except (json.JSONDecodeError, TypeError):
                basis = {}

            if d.detection_method:
                method = d.detection_method
            elif basis.get("tier1_signals", 0) > 0:
                method = "questionnaire"
            elif basis.get("tier2_signals", 0) > 0:
                method = "idp_log"
            elif basis.get("tier3_signals", 0) > 0:
                method = "network_scan"
            else:
                method = "unknown"

            rows.append({
                "tool_name": d.provider_name,
                "vendor": sig.provider_name if sig else d.provider_name,
                "category": sig.category if sig else "other",
                "confidence_score": float(d.confidence_score),
                "confidence_band": d.confidence_band,
                "status": d.status,
                "detection_method": method,
                "inferred_use_case": d.inferred_use_case or "",
                "risk_level": sig.risk_level if sig else "",
                "is_stale": d.is_stale,
                "first_detected_at": d.first_detected_at.isoformat() if d.first_detected_at else "",
                "last_observed_at": d.last_observed_at.isoformat() if d.last_observed_at else "",
                "reviewed_by": str(d.reviewed_by_user_id) if d.reviewed_by_user_id else "",
                "intent_action": d.intent_action or "",
                "intent_data_subject": d.intent_data_subject or "",
                "intent_business_context": d.intent_business_context or "",
            })

        AuditService.log(
            db=db,
            organization_id=organization_id,
            user_id=None,
            action="shadow_ai.detections.exported",
            entity_type="shadow_ai_detection",
            entity_id=_NIL_UUID,
            context_json={"format": format, "count": len(rows)},
        )

        if format == "csv":
            output = io.StringIO()
            fieldnames = [
                "tool_name", "vendor", "category", "confidence_score",
                "confidence_band", "status", "detection_method",
                "inferred_use_case", "risk_level", "is_stale",
                "first_detected_at", "last_observed_at",
                "reviewed_by", "intent_action", "intent_data_subject",
                "intent_business_context",
            ]
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
            return output.getvalue()
        else:
            return json.dumps(rows, indent=2, default=str)
