"""
PATENT NOTICE
Module: routers/detections
Part of: Shadow AI Discovery Engine
Patent: System and Method for Inferring Undeclared
Artificial Intelligence Systems and Generating AI
Governance Artifacts from Enterprise Telemetry
Status: Provisional filing in preparation

Detection CRUD and lifecycle endpoints.
Implements Core Patent Claim 3: governance artifact
generation through human-validated promotion workflow.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import get_current_user, get_organization_id, require_permission
from app.models.detection import ShadowAIDetection
from app.models.signature import AISignatureRegistry
from app.models.telemetry import TelemetryEvent
from app.models.zero_day import ZeroDayCandidate
from app.schemas.ai_system import AISystemRead, EscalationResponse
from app.schemas.common import PaginatedResponse
from app.schemas.detection import (
    BulkActionRequest,
    BulkActionResponse,
    DetectionSummaryResponse,
    DismissRequest,
    EscalateRequest,
    ShadowAIDetectionDetail,
    ShadowAIDetectionRead,
)
from app.schemas.suppression import SuppressionRead
from app.schemas.zero_day import ZeroDayCandidateRead, ZeroDayCandidateReview
from app.schemas.jurisdiction import JurisdictionAssessmentResponse
from app.services.audit_service import AuditService
from app.services.capability_service import require_shadow_ai_enabled
from app.services.decay_engine import DecayEngine
from app.services.detection_service import DetectionService
from app.services.jurisdiction_engine import JurisdictionEngine
from app.services.suppression_service import SuppressionService
from app.services.zero_day_classifier import ZeroDayClassifier

router = APIRouter()


class ManualReportRequest(BaseModel):
    tool_name: str
    notes: str | None = None


@router.get(
    "/detections",
    summary="List Shadow AI Detections",
    description=(
        "Returns paginated list of all ungoverned AI system detections "
        "for the organization. Supports filtering by status, confidence "
        "band, staleness, and text search."
    ),
    response_model=PaginatedResponse[ShadowAIDetectionRead],
)
def list_detections(
    status_filter: str | None = Query(None, alias="status"),
    confidence_band: str | None = Query(None),
    is_stale: bool | None = Query(None),
    search: str | None = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    organization_id: UUID = Depends(get_organization_id),
    user_id: UUID = Depends(get_current_user),
    _: None = Depends(require_shadow_ai_enabled),
    __: None = Depends(require_permission("shadow_ai:read")),
):
    items, total = DetectionService.list_detections(
        organization_id=organization_id,
        db=db,
        status=status_filter,
        confidence_band=confidence_band,
        is_stale=is_stale,
        search=search,
        page=page,
        page_size=page_size,
    )
    return PaginatedResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        has_next=(page * page_size) < total,
    )


@router.get(
    "/detections/export",
    summary="Export Detections",
    description=(
        "Export all detection records as CSV or JSON for "
        "audit and reporting purposes."
    ),
)
def export_detections(
    format: str = Query("csv", pattern="^(csv|json)$"),
    status_filter: str | None = Query(None, alias="status"),
    db: Session = Depends(get_db),
    organization_id: UUID = Depends(get_organization_id),
    user_id: UUID = Depends(get_current_user),
    _: None = Depends(require_shadow_ai_enabled),
    __: None = Depends(require_permission("shadow_ai:read")),
):
    data = DetectionService.export_detections(
        organization_id=organization_id,
        db=db,
        format=format,
        status=status_filter,
    )
    if format == "csv":
        return Response(
            content=data,
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=detections.csv"},
        )
    return Response(
        content=data,
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=detections.json"},
    )


@router.get(
    "/detections/summary",
    summary="Detection Summary Metrics",
    description=(
        "Returns aggregated detection counts by status, confidence "
        "band, and staleness. Used for dashboard display."
    ),
    response_model=DetectionSummaryResponse,
)
def detection_summary(
    db: Session = Depends(get_db),
    organization_id: UUID = Depends(get_organization_id),
    user_id: UUID = Depends(get_current_user),
    _: None = Depends(require_shadow_ai_enabled),
    __: None = Depends(require_permission("shadow_ai:read")),
):
    return DetectionService.get_detection_summary(organization_id, db)


@router.post(
    "/detections/bulk/dismiss",
    summary="Bulk Dismiss Detections",
    description=(
        "Dismisses multiple detections in a single operation. "
        "Maximum 50 records per request."
    ),
    response_model=BulkActionResponse,
)
def bulk_dismiss(
    body: BulkActionRequest,
    db: Session = Depends(get_db),
    organization_id: UUID = Depends(get_organization_id),
    user_id: UUID = Depends(get_current_user),
    _: None = Depends(require_shadow_ai_enabled),
    __: None = Depends(require_permission("shadow_ai:write")),
):
    if body.reason is None or len(body.reason) < 10:
        raise HTTPException(
            status_code=422,
            detail="reason is required for dismiss and must be at least 10 characters",
        )
    return DetectionService.bulk_dismiss(
        detection_ids=body.detection_ids,
        organization_id=organization_id,
        dismissed_by=user_id,
        reason=body.reason,
        db=db,
    )


@router.post(
    "/detections/bulk/review",
    summary="Bulk Mark as Reviewed",
    description="Marks multiple detections as reviewed in a single operation.",
    response_model=BulkActionResponse,
)
def bulk_review(
    body: BulkActionRequest,
    db: Session = Depends(get_db),
    organization_id: UUID = Depends(get_organization_id),
    user_id: UUID = Depends(get_current_user),
    _: None = Depends(require_shadow_ai_enabled),
    __: None = Depends(require_permission("shadow_ai:write")),
):
    return DetectionService.bulk_review(
        detection_ids=body.detection_ids,
        organization_id=organization_id,
        reviewed_by=user_id,
        db=db,
    )


@router.post(
    "/detections/report",
    summary="Submit Manual Detection Report",
    description=(
        "Allows any org member to flag a suspected ungoverned AI tool "
        "for review. Creates a detection with method=manual_report and "
        "confidence=medium."
    ),
    response_model=ShadowAIDetectionRead,
)
def manual_report(
    body: ManualReportRequest,
    db: Session = Depends(get_db),
    organization_id: UUID = Depends(get_organization_id),
    user_id: UUID = Depends(get_current_user),
    _: None = Depends(require_shadow_ai_enabled),
    __: None = Depends(require_permission("shadow_ai:read")),
):
    now = datetime.now(timezone.utc)
    detection = ShadowAIDetection(
        organization_id=organization_id,
        signature_id=None,
        provider_name=body.tool_name,
        confidence_score=0.50,
        confidence_band="medium",
        detection_basis_json=json.dumps({
            "tier1_signals": 0,
            "tier2_signals": 0,
            "tier3_signals": 0,
            "signal_ids": [],
            "score_breakdown": {},
            "detection_method": "manual_report",
            "notes": body.notes,
        }),
        base_confidence_score=0.50,
        decay_lambda=DecayEngine.get_lambda_for_category("other"),
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
        user_id=user_id,
        action="shadow_ai.detection.manual_report",
        entity_type="shadow_ai_detection",
        entity_id=detection.id,
        context_json={
            "tool_name": body.tool_name,
            "reported_by": str(user_id),
        },
    )

    db.commit()
    return detection


# ═══════════════════════════════════════════════
# ZERO-DAY AI CANDIDATE ENDPOINTS
# (Dependent Patent Claim 4)
# Registered BEFORE /detections/{id} to avoid route conflict.
# ═══════════════════════════════════════════════


@router.get(
    "/detections/zero-day/candidates",
    summary="List Zero-Day AI Candidates",
    description=(
        "Returns hostnames observed in network traffic that exhibit AI service "
        "behavioral characteristics but are not in the detection registry. These are "
        "unknown AI services potentially in use in the environment. Human review required "
        "before registry addition."
    ),
    response_model=list[ZeroDayCandidateRead],
)
def list_zero_day_candidates(
    status: str | None = Query(None),
    db: Session = Depends(get_db),
    organization_id: UUID = Depends(get_organization_id),
    user_id: UUID = Depends(get_current_user),
    _: None = Depends(require_shadow_ai_enabled),
    __: None = Depends(require_permission("shadow_ai:read")),
):
    return ZeroDayClassifier.get_candidates(
        organization_id=organization_id,
        db=db,
        status=status,
    )


@router.get(
    "/detections/zero-day/candidates/{candidate_id}",
    summary="Get Zero-Day Candidate Detail",
    response_model=ZeroDayCandidateRead,
)
def get_zero_day_candidate(
    candidate_id: UUID,
    db: Session = Depends(get_db),
    organization_id: UUID = Depends(get_organization_id),
    user_id: UUID = Depends(get_current_user),
    _: None = Depends(require_shadow_ai_enabled),
    __: None = Depends(require_permission("shadow_ai:read")),
):
    candidate = db.execute(
        select(ZeroDayCandidate).where(
            ZeroDayCandidate.id == candidate_id,
            ZeroDayCandidate.organization_id == organization_id,
        )
    ).scalar_one_or_none()
    if candidate is None:
        raise HTTPException(status_code=404, detail="Candidate not found")
    return candidate


@router.post(
    "/detections/zero-day/candidates/{candidate_id}/review",
    summary="Review Zero-Day Candidate",
    description=(
        "Reviews a zero-day AI candidate. Actions: add_to_registry (creates new "
        "signature and enables standard detection), dismiss (suppresses future detections "
        "for this hostname), monitor (continues observation without action)."
    ),
    response_model=ZeroDayCandidateRead,
)
def review_zero_day_candidate(
    candidate_id: UUID,
    body: ZeroDayCandidateReview,
    db: Session = Depends(get_db),
    organization_id: UUID = Depends(get_organization_id),
    user_id: UUID = Depends(get_current_user),
    _: None = Depends(require_shadow_ai_enabled),
    __: None = Depends(require_permission("shadow_ai:write")),
):
    candidate = ZeroDayClassifier.review_candidate(
        candidate_id=candidate_id,
        organization_id=organization_id,
        action=body.action,
        reviewed_by=user_id,
        review_notes=body.review_notes,
        provider_name=body.provider_name,
        category=body.category,
        db=db,
    )
    return candidate


@router.get(
    "/detections/{detection_id}/jurisdiction",
    summary="Get Regulatory Jurisdiction Assessment",
    description=(
        "Returns the complete regulatory jurisdiction graph traversal result for a "
        "detection. Shows which regulations apply, which specific articles are "
        "triggered, and what governance actions are missing. This assessment is "
        "computed automatically at detection creation time using the Regulatory "
        "Jurisdiction Graph (Patent Claim 9)."
    ),
    response_model=JurisdictionAssessmentResponse,
)
def get_jurisdiction_assessment(
    detection_id: UUID,
    db: Session = Depends(get_db),
    organization_id: UUID = Depends(get_organization_id),
    user_id: UUID = Depends(get_current_user),
    _: None = Depends(require_shadow_ai_enabled),
    __: None = Depends(require_permission("shadow_ai:read")),
):
    detection = DetectionService.get_detection_by_id(detection_id, organization_id, db)
    if detection is None:
        raise HTTPException(status_code=404, detail="Detection not found")

    if detection.jurisdiction_assessment_json is None:
        signature = None
        if detection.signature_id is not None:
            signature = db.execute(
                select(AISignatureRegistry).where(
                    AISignatureRegistry.id == detection.signature_id
                )
            ).scalar_one_or_none()
        JurisdictionEngine.assess_detection(detection, signature, db)
        db.commit()

    try:
        parsed = json.loads(detection.jurisdiction_assessment_json or "{}")
    except (json.JSONDecodeError, TypeError):
        parsed = {}

    return {
        "detection_id": detection.id,
        "provider_name": detection.provider_name,
        "assessment": parsed,
        "assessed_at": detection.jurisdiction_assessed_at or datetime.now(timezone.utc),
    }


@router.post(
    "/detections/{detection_id}/jurisdiction/refresh",
    summary="Refresh Jurisdiction Assessment",
    description=(
        "Re-runs the regulatory jurisdiction graph traversal for a detection using "
        "the current graph version. Use when detection attributes have been updated "
        "or when the regulatory graph has been updated."
    ),
    response_model=JurisdictionAssessmentResponse,
)
def refresh_jurisdiction_assessment(
    detection_id: UUID,
    db: Session = Depends(get_db),
    organization_id: UUID = Depends(get_organization_id),
    user_id: UUID = Depends(get_current_user),
    _: None = Depends(require_shadow_ai_enabled),
    __: None = Depends(require_permission("shadow_ai:write")),
):
    detection = DetectionService.get_detection_by_id(detection_id, organization_id, db)
    if detection is None:
        raise HTTPException(status_code=404, detail="Detection not found")

    signature = None
    if detection.signature_id is not None:
        signature = db.execute(
            select(AISignatureRegistry).where(
                AISignatureRegistry.id == detection.signature_id
            )
        ).scalar_one_or_none()
    JurisdictionEngine.assess_detection(detection, signature, db)
    db.commit()

    try:
        parsed = json.loads(detection.jurisdiction_assessment_json or "{}")
    except (json.JSONDecodeError, TypeError):
        parsed = {}

    return {
        "detection_id": detection.id,
        "provider_name": detection.provider_name,
        "assessment": parsed,
        "assessed_at": detection.jurisdiction_assessed_at or datetime.now(timezone.utc),
    }


@router.get(
    "/detections/{detection_id}",
    summary="Get Detection Detail",
    description=(
        "Returns full detection record including contributing signals, "
        "intent classification, and regulatory risk assessment."
    ),
    response_model=ShadowAIDetectionDetail,
)
def get_detection(
    detection_id: UUID,
    db: Session = Depends(get_db),
    organization_id: UUID = Depends(get_organization_id),
    user_id: UUID = Depends(get_current_user),
    _: None = Depends(require_shadow_ai_enabled),
    __: None = Depends(require_permission("shadow_ai:read")),
):
    detection = DetectionService.get_detection_by_id(detection_id, organization_id, db)
    if detection is None:
        raise HTTPException(status_code=404, detail="Detection not found")

    contributing_signals: list[dict] = []
    try:
        basis = json.loads(detection.detection_basis_json)
        signal_ids = basis.get("signal_ids", [])
        for sid in signal_ids:
            try:
                event_uuid = UUID(sid)
            except (ValueError, AttributeError):
                continue
            event = db.execute(
                select(TelemetryEvent).where(TelemetryEvent.id == event_uuid)
            ).scalar_one_or_none()
            if event:
                raw = json.loads(event.raw_signal_json) if event.raw_signal_json else {}
                contributing_signals.append({
                    "event_id": str(event.id),
                    "tier": event.tier,
                    "event_type": event.event_type,
                    "source_system_label": event.source_system_label,
                    "matched_keyword": raw.get("matched_keyword"),
                    "observed_at": event.observed_at.isoformat() if event.observed_at else None,
                })
    except (json.JSONDecodeError, TypeError):
        pass

    detail = ShadowAIDetectionDetail.model_validate(detection)
    detail.contributing_signals = contributing_signals
    return detail


@router.patch(
    "/detections/{detection_id}/review",
    summary="Mark Detection as Under Review",
    description=(
        "Transitions detection to reviewed status. Required before "
        "dismissal or escalation in formal workflows."
    ),
    response_model=ShadowAIDetectionRead,
)
def review_detection(
    detection_id: UUID,
    db: Session = Depends(get_db),
    organization_id: UUID = Depends(get_organization_id),
    user_id: UUID = Depends(get_current_user),
    _: None = Depends(require_shadow_ai_enabled),
    __: None = Depends(require_permission("shadow_ai:write")),
):
    detection = DetectionService.get_detection_by_id(detection_id, organization_id, db)
    if detection is None:
        raise HTTPException(status_code=404, detail="Detection not found")
    if detection.status in ("dismissed", "registered"):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot review a {detection.status} detection",
        )

    now = datetime.now(timezone.utc)
    detection.status = "reviewed"
    detection.reviewed_by_user_id = user_id
    detection.reviewed_at = now
    detection.updated_at = now

    AuditService.log(
        db=db,
        organization_id=organization_id,
        user_id=user_id,
        action="shadow_ai.detection.reviewed",
        entity_type="shadow_ai_detection",
        entity_id=detection.id,
        context_json={"provider_name": detection.provider_name},
    )

    db.commit()
    return detection


@router.post(
    "/detections/{detection_id}/dismiss",
    summary="Dismiss Detection",
    description=(
        "Dismisses a detection as a false positive or known/acceptable "
        "tool. Creates a suppression record to prevent re-detection. "
        "Record is permanently retained for audit purposes — not deleted."
    ),
    response_model=ShadowAIDetectionRead,
)
def dismiss_detection(
    detection_id: UUID,
    body: DismissRequest,
    db: Session = Depends(get_db),
    organization_id: UUID = Depends(get_organization_id),
    user_id: UUID = Depends(get_current_user),
    _: None = Depends(require_shadow_ai_enabled),
    __: None = Depends(require_permission("shadow_ai:write")),
):
    try:
        detection = DetectionService.dismiss_detection(
            detection_id=detection_id,
            organization_id=organization_id,
            dismissed_by=user_id,
            reason=body.reason,
            notes=body.notes,
            db=db,
        )
        return detection
    except ValueError as exc:
        if "not found" in str(exc).lower():
            raise HTTPException(status_code=404, detail=str(exc))
        raise HTTPException(status_code=400, detail=str(exc))


@router.post(
    "/detections/{detection_id}/escalate",
    summary="Escalate to AI System Inventory",
    description=(
        "Promotes a confirmed detection to a formal AI System governance "
        "record. This is the governance artifact generation step described "
        "in Core Patent Claim 3. Requires explicit human authorization. "
        "No detection is auto-promoted."
    ),
    response_model=EscalationResponse,
)
def escalate_detection(
    detection_id: UUID,
    body: EscalateRequest,
    db: Session = Depends(get_db),
    organization_id: UUID = Depends(get_organization_id),
    user_id: UUID = Depends(get_current_user),
    _: None = Depends(require_shadow_ai_enabled),
    __: None = Depends(require_permission("shadow_ai:write")),
):
    try:
        detection, ai_system = DetectionService.escalate_to_inventory(
            detection_id=detection_id,
            organization_id=organization_id,
            escalated_by=user_id,
            escalate_request=body,
            db=db,
        )
        return EscalationResponse(
            detection=ShadowAIDetectionRead.model_validate(detection),
            ai_system=AISystemRead.model_validate(ai_system),
            message="Detection escalated to AI System inventory successfully.",
        )
    except ValueError as exc:
        if "not found" in str(exc).lower():
            raise HTTPException(status_code=404, detail=str(exc))
        raise HTTPException(status_code=400, detail=str(exc))
