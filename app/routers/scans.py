"""
PATENT NOTICE
Module: routers/scans
Part of: Shadow AI Discovery Engine
Patent: System and Method for Inferring Undeclared
Artificial Intelligence Systems and Generating AI
Governance Artifacts from Enterprise Telemetry
Status: Provisional filing in preparation

Scan trigger and suppression management endpoints.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import get_current_user, get_organization_id, require_permission
from app.models.suppression import SuppressedDetection
from app.schemas.detection import ScanSummaryResponse
from app.schemas.suppression import SuppressionRead
from app.services.capability_service import require_shadow_ai_enabled
from app.services.suppression_service import SuppressionService
from app.services.tier1_scanner import Tier1Scanner

router = APIRouter()


@router.post(
    "/scans/tier1",
    summary="Trigger Tier 1 Questionnaire Scan",
    description=(
        "Initiates a synchronous Tier 1 contextual text inference scan "
        "across all questionnaire responses for the organization. "
        "Returns scan summary on completion."
    ),
    response_model=ScanSummaryResponse,
)
def trigger_tier1_scan(
    db: Session = Depends(get_db),
    organization_id: UUID = Depends(get_organization_id),
    user_id: UUID = Depends(get_current_user),
    _: None = Depends(require_shadow_ai_enabled),
    __: None = Depends(require_permission("shadow_ai:write")),
):
    summary = Tier1Scanner.scan_organization(
        organization_id=organization_id,
        triggered_by=user_id,
        db=db,
    )
    return summary


@router.get(
    "/scans/suppressions",
    summary="List Active Suppressions",
    description=(
        "Returns all active detection suppressions for the organization."
    ),
    response_model=list[SuppressionRead],
)
def list_suppressions(
    db: Session = Depends(get_db),
    organization_id: UUID = Depends(get_organization_id),
    user_id: UUID = Depends(get_current_user),
    _: None = Depends(require_shadow_ai_enabled),
    __: None = Depends(require_permission("shadow_ai:read")),
):
    return SuppressionService.list_suppressions(organization_id, db)


@router.delete(
    "/scans/suppressions/{suppression_id}",
    summary="Lift Suppression",
    description=(
        "Re-enables detection for a previously suppressed tool+method "
        "combination. The tool will be detected again on next scan."
    ),
    response_model=SuppressionRead,
)
def lift_suppression(
    suppression_id: UUID,
    db: Session = Depends(get_db),
    organization_id: UUID = Depends(get_organization_id),
    user_id: UUID = Depends(get_current_user),
    _: None = Depends(require_shadow_ai_enabled),
    __: None = Depends(require_permission("shadow_ai:write")),
):
    suppression = db.execute(
        select(SuppressedDetection).where(
            SuppressedDetection.id == suppression_id,
            SuppressedDetection.organization_id == organization_id,
        )
    ).scalar_one_or_none()

    if suppression is None:
        raise HTTPException(status_code=404, detail="Suppression not found")

    if suppression.lifted_at is not None:
        raise HTTPException(status_code=400, detail="Suppression already lifted")

    lifted = SuppressionService.lift_suppression(
        organization_id=organization_id,
        tool_slug=suppression.tool_slug,
        detection_method=suppression.detection_method,
        lifted_by=user_id,
        db=db,
    )

    if not lifted:
        raise HTTPException(status_code=404, detail="Suppression not found")

    db.commit()
    return suppression
