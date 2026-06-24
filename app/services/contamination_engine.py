"""
PATENT NOTICE
Module: services/contamination_engine
Implements Dependent Patent Claim 5:
Vendor AI Contamination Index.

This engine computes a numeric Vendor AI Contamination Score by combining
three independent signal inputs:

CONTAMINATION SCORE FORMULA (patent invariant):
  ContaminationScore = (
    WEIGHT_INTERNAL × internal_signal_score +
    WEIGHT_EXTERNAL × external_signal_score +
    WEIGHT_CONTRACTUAL × contractual_gap_score
  )

SIGNAL WEIGHTS (patent-specified constants):
  WEIGHT_INTERNAL    = 0.30
  WEIGHT_EXTERNAL    = 0.30
  WEIGHT_CONTRACTUAL = 0.40

These weights are non-negotiable patent invariants. Do not change them.

SIGNAL DEFINITIONS:
  Signal 1 — Internal (w=0.30):
    Scans shadow_ai_detections / telemetry_events for questionnaire
    responses associated with the vendor name. Produces a score based on
    the number and confidence of AI tool detections.

  Signal 2 — External (w=0.30):
    Optional public signal scan via ExternalSignalScanner. Default 0.5 when
    disabled (neutral — no information).

  Signal 3 — Contractual (w=0.40):
    Checks vendor_dpa_records:
      No DPA: 1.0 (maximum gap)
      DPA exists, no AI coverage: 0.5
      DPA exists, covers AI: 0.0

CONTAMINATION BANDS:
  critical: >= 0.80
  high:     >= 0.60
  medium:   >= 0.40
  low:      <  0.40
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from decimal import Decimal
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.logging_config import get_logger
from app.models.contamination import VendorAIContamination, VendorDPARecord
from app.models.detection import ShadowAIDetection
from app.models.questionnaire_response import QuestionnaireResponse
from app.models.signature import AISignatureRegistry
from app.models.telemetry import TelemetryEvent
from app.models.vendor import Vendor
from app.schemas.contamination import VendorContaminationRead, VendorContaminationSummary
from app.services.audit_service import AuditService
from app.services.external_signal_scanner import (
    ExternalSignalScanner,
)

logger = get_logger(__name__)

WEIGHT_INTERNAL = 0.30
WEIGHT_EXTERNAL = 0.30
WEIGHT_CONTRACTUAL = 0.40
ASSESSMENT_VERSION = "1.0.0"


def _classify_band(score: float) -> str:
    if score >= 0.80:
        return "critical"
    if score >= 0.60:
        return "high"
    if score >= 0.40:
        return "medium"
    return "low"


class ContaminationEngine:
    """Computes Vendor AI Contamination Index scores."""

    @staticmethod
    def compute_internal_score(
        vendor_id: UUID,
        vendor_name: str,
        organization_id: UUID,
        db: Session,
    ) -> tuple[float, list[str]]:
        """Signal 1: Internal assessment text mining.

        Locates questionnaire_responses associated with the vendor by name,
        finds telemetry events linked to those responses, and returns a score
        based on how many distinct AI tools were detected and whether any
        active detection has high confidence.
        """
        response_ids = db.execute(
            select(QuestionnaireResponse.id).where(
                QuestionnaireResponse.organization_id == organization_id,
                QuestionnaireResponse.vendor_name == vendor_name,
                QuestionnaireResponse.deleted_at.is_(None),
            )
        ).scalars().all()

        if not response_ids:
            return 0.0, []

        source_labels = [f"questionnaire_response:{rid}" for rid in response_ids]

        events = db.execute(
            select(TelemetryEvent).where(
                TelemetryEvent.organization_id == organization_id,
                TelemetryEvent.tier == 1,
                TelemetryEvent.source_system_label.in_(source_labels),
            )
        ).scalars().all()

        signature_ids = {e.matched_signature_id for e in events if e.matched_signature_id}
        if not signature_ids:
            return 0.0, []

        signatures = db.execute(
            select(AISignatureRegistry).where(
                AISignatureRegistry.id.in_(list(signature_ids))
            )
        ).scalars().all()

        tool_names = sorted({sig.provider_name for sig in signatures})
        signature_id_to_name = {sig.id: sig.provider_name for sig in signatures}

        detections = db.execute(
            select(ShadowAIDetection).where(
                ShadowAIDetection.organization_id == organization_id,
                ShadowAIDetection.signature_id.in_(list(signature_ids)),
                ShadowAIDetection.status.notin_(["dismissed", "registered"]),
                ShadowAIDetection.deleted_at.is_(None),
            )
        ).scalars().all()

        has_high_confidence = any(
            d.confidence_band == "high" for d in detections
        )

        distinct_count = len(tool_names)
        if distinct_count >= 3:
            score = 0.9 if has_high_confidence else 0.7
        elif 1 <= distinct_count <= 2:
            score = 0.6 if has_high_confidence else 0.4
        else:
            score = 0.0

        return score, tool_names

    @staticmethod
    def compute_contractual_score(
        vendor_id: UUID,
        organization_id: UUID,
        db: Session,
    ) -> tuple[float, bool, bool]:
        """Signal 3: Contractual gap detection.

        Queries vendor_dpa_records for this vendor.

        Returns (score, dpa_exists, dpa_covers_ai):
          No record:                 (1.0, False, False)
          Record, covers_ai=False:   (0.5, True, False)
          Record, covers_ai=True:    (0.0, True, True)
        """
        record = db.execute(
            select(VendorDPARecord).where(
                VendorDPARecord.organization_id == organization_id,
                VendorDPARecord.vendor_id == vendor_id,
                VendorDPARecord.deleted_at.is_(None),
            )
        ).scalar_one_or_none()

        if record is None:
            return 1.0, False, False
        if record.covers_ai_processing:
            return 0.0, True, True
        return 0.5, True, False

    @staticmethod
    def compute_contamination_score(
        vendor_id: UUID,
        vendor_name: str,
        organization_id: UUID,
        enable_external_scan: bool,
        db: Session,
        user_id: UUID | None = None,
    ) -> VendorAIContamination:
        """Main computation method. Combines all three signals.

        Steps:
          1. internal_score, tools = compute_internal_score()
          2. external_signals = ExternalSignalScanner.scan_vendor(...)
             external_score = compute_external_score(external_signals)
          3. contractual_score, dpa_exists, dpa_covers_ai = compute_contractual_score()
          4. contamination_score = round(
               WEIGHT_INTERNAL*internal_score +
               WEIGHT_EXTERNAL*external_score +
               WEIGHT_CONTRACTUAL*contractual_score, 4)
          5. Determine contamination_band.
          6. Upsert vendor_ai_contamination record.
          7. Write audit log.
        """
        internal_score, tools = ContaminationEngine.compute_internal_score(
            vendor_id, vendor_name, organization_id, db
        )

        existing = db.execute(
            select(VendorAIContamination).where(
                VendorAIContamination.organization_id == organization_id,
                VendorAIContamination.vendor_id == vendor_id,
            )
        ).scalar_one_or_none()

        last_scanned_at = None
        if existing is not None:
            last_scanned_at = existing.assessed_at

        external_signals = ExternalSignalScanner.scan_vendor(
            vendor_name=vendor_name,
            enabled=enable_external_scan,
            last_scanned_at=last_scanned_at,
        )
        external_score = ExternalSignalScanner.compute_external_score(external_signals)

        contractual_score, dpa_exists, dpa_covers_ai = (
            ContaminationEngine.compute_contractual_score(
                vendor_id, organization_id, db
            )
        )

        contamination_score = round(
            WEIGHT_INTERNAL * internal_score
            + WEIGHT_EXTERNAL * external_score
            + WEIGHT_CONTRACTUAL * contractual_score,
            4,
        )
        band = _classify_band(contamination_score)
        now = datetime.now(timezone.utc)

        if existing is not None:
            existing.vendor_name = vendor_name
            existing.contamination_score = contamination_score
            existing.contamination_band = band
            existing.internal_signal_score = internal_score
            existing.external_signal_score = external_score
            existing.contractual_gap_score = contractual_score
            existing.ai_tools_detected = json.dumps(tools)
            existing.external_signals = json.dumps(external_signals)
            existing.dpa_exists = dpa_exists
            existing.dpa_covers_ai = dpa_covers_ai
            existing.assessed_at = now
            existing.assessment_version = ASSESSMENT_VERSION
            existing.external_scan_enabled = enable_external_scan
            existing.updated_at = now
            record = existing
        else:
            record = VendorAIContamination(
                organization_id=organization_id,
                vendor_id=vendor_id,
                vendor_name=vendor_name,
                contamination_score=contamination_score,
                contamination_band=band,
                internal_signal_score=internal_score,
                external_signal_score=external_score,
                contractual_gap_score=contractual_score,
                ai_tools_detected=json.dumps(tools),
                external_signals=json.dumps(external_signals),
                dpa_exists=dpa_exists,
                dpa_covers_ai=dpa_covers_ai,
                assessed_at=now,
                assessment_version=ASSESSMENT_VERSION,
                external_scan_enabled=enable_external_scan,
            )
            db.add(record)

        db.flush()

        try:
            AuditService.log(
                db=db,
                organization_id=organization_id,
                user_id=user_id,
                action="shadow_ai.vendor.contamination_assessed",
                entity_type="vendor_ai_contamination",
                entity_id=record.id,
                context_json={
                    "vendor_id": str(vendor_id),
                    "vendor_name": vendor_name,
                    "contamination_score": float(contamination_score),
                    "contamination_band": band,
                    "internal_signal_score": internal_score,
                    "external_signal_score": external_score,
                    "contractual_gap_score": contractual_score,
                    "ai_tools_detected": tools,
                    "dpa_exists": dpa_exists,
                    "external_scan_enabled": enable_external_scan,
                },
            )
        except Exception:
            logger.error(
                "Audit logging failed for contamination assessment",
                extra={"vendor_id": str(vendor_id)},
            )

        return record

    @staticmethod
    def run_assessment_pass(
        organization_id: UUID,
        enable_external_scan: bool,
        db: Session,
        user_id: UUID | None = None,
        vendor_ids: list[UUID] | None = None,
    ) -> dict:
        """Run contamination assessment for all or selected vendors.

        Returns dict with assessed count and band counts.
        """
        query = select(Vendor).where(
            Vendor.organization_id == organization_id,
        )
        if vendor_ids is not None:
            query = query.where(Vendor.id.in_(vendor_ids))

        vendors = db.execute(query).scalars().all()

        bands = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        for vendor in vendors:
            record = ContaminationEngine.compute_contamination_score(
                vendor_id=vendor.id,
                vendor_name=vendor.name,
                organization_id=organization_id,
                enable_external_scan=enable_external_scan,
                db=db,
                user_id=user_id,
            )
            bands[record.contamination_band] += 1

        return {
            "assessed": len(vendors),
            **bands,
        }

    @staticmethod
    def get_summary(
        organization_id: UUID,
        db: Session,
    ) -> VendorContaminationSummary:
        """Return aggregated contamination summary for the organization."""
        records = db.execute(
            select(VendorAIContamination).where(
                VendorAIContamination.organization_id == organization_id,
            ).order_by(VendorAIContamination.contamination_score.desc())
        ).scalars().all()

        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        vendors_without_dpa = 0
        vendors_with_dpa_no_ai = 0

        for record in records:
            counts[record.contamination_band] += 1
            if not record.dpa_exists:
                vendors_without_dpa += 1
            elif record.dpa_exists and not record.dpa_covers_ai:
                vendors_with_dpa_no_ai += 1

        top_five = [VendorContaminationRead.model_validate(r) for r in records[:5]]

        return VendorContaminationSummary(
            total_vendors_assessed=len(records),
            critical_count=counts["critical"],
            high_count=counts["high"],
            medium_count=counts["medium"],
            low_count=counts["low"],
            vendors_without_dpa=vendors_without_dpa,
            vendors_with_dpa_no_ai_coverage=vendors_with_dpa_no_ai,
            top_contaminated=top_five,
        )
