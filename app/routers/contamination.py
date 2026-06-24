"""
PATENT NOTICE
Module: routers/contamination
Part of: Shadow AI Discovery Engine
Patent: System and Method for Inferring Undeclared
Artificial Intelligence Systems and Generating AI
Governance Artifacts from Enterprise Telemetry
Status: Provisional filing in preparation

Vendor AI Contamination Index endpoints.
Implements Dependent Patent Claim 5.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import get_current_user, get_organization_id, require_permission
from app.models.contamination import VendorAIContamination, VendorDPARecord
from app.models.vendor import Vendor
from app.schemas.common import PaginatedResponse
from app.schemas.contamination import (
    ContaminationAssessmentRequest,
    VendorContaminationRead,
    VendorContaminationSummary,
    VendorDPAUpdate,
)
from app.services.capability_service import require_shadow_ai_enabled
from app.services.contamination_engine import ContaminationEngine

router = APIRouter()


@router.post(
    "/vendors/assess",
    summary="Run Vendor AI Contamination Assessment",
    description=(
        "Computes the Vendor AI Contamination Index for all or specified vendors. "
        "Combines internal assessment signals, optional external public signals, "
        "and contractual coverage gap detection into a numeric contamination score. "
        "Patent Claim 5."
    ),
)
def assess_vendors(
    body: ContaminationAssessmentRequest,
    db: Session = Depends(get_db),
    organization_id: UUID = Depends(get_organization_id),
    user_id: UUID = Depends(get_current_user),
    _: None = Depends(require_shadow_ai_enabled),
    __: None = Depends(require_permission("shadow_ai:write")),
):
    result = ContaminationEngine.run_assessment_pass(
        organization_id=organization_id,
        enable_external_scan=body.enable_external_scan,
        db=db,
        user_id=user_id,
        vendor_ids=body.vendor_ids,
    )
    summary = ContaminationEngine.get_summary(organization_id, db)
    db.commit()
    return {
        "assessed": result["assessed"],
        "summary": summary,
    }


@router.get(
    "/vendors/contamination",
    summary="List Vendor Contamination Scores",
    description=(
        "Returns contamination scores for all assessed vendors ordered by score "
        "descending. Supports band filtering and pagination."
    ),
    response_model=PaginatedResponse[VendorContaminationRead],
)
def list_contamination(
    band: str | None = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    organization_id: UUID = Depends(get_organization_id),
    user_id: UUID = Depends(get_current_user),
    _: None = Depends(require_shadow_ai_enabled),
    __: None = Depends(require_permission("shadow_ai:read")),
):
    query = select(VendorAIContamination).where(
        VendorAIContamination.organization_id == organization_id,
    ).order_by(VendorAIContamination.contamination_score.desc())

    if band is not None:
        query = query.where(VendorAIContamination.contamination_band == band)

    total = db.execute(
        select(func.count()).select_from(query.subquery())
    ).scalar() or 0

    offset = (page - 1) * page_size
    query = query.offset(offset).limit(page_size)
    items = list(db.execute(query).scalars().all())

    return PaginatedResponse(
        items=[VendorContaminationRead.model_validate(r) for r in items],
        total=total,
        page=page,
        page_size=page_size,
        has_next=(page * page_size) < total,
    )


@router.get(
    "/vendors/contamination/summary",
    summary="Vendor Contamination Summary",
    description=(
        "Returns aggregated contamination counts and top 5 most contaminated "
        "vendors for the organization."
    ),
    response_model=VendorContaminationSummary,
)
def get_contamination_summary(
    db: Session = Depends(get_db),
    organization_id: UUID = Depends(get_organization_id),
    user_id: UUID = Depends(get_current_user),
    _: None = Depends(require_shadow_ai_enabled),
    __: None = Depends(require_permission("shadow_ai:read")),
):
    return ContaminationEngine.get_summary(organization_id, db)


@router.get(
    "/vendors/{vendor_id}/contamination",
    summary="Get Vendor Contamination Detail",
    response_model=VendorContaminationRead,
)
def get_vendor_contamination(
    vendor_id: UUID,
    db: Session = Depends(get_db),
    organization_id: UUID = Depends(get_organization_id),
    user_id: UUID = Depends(get_current_user),
    _: None = Depends(require_shadow_ai_enabled),
    __: None = Depends(require_permission("shadow_ai:read")),
):
    record = db.execute(
        select(VendorAIContamination).where(
            VendorAIContamination.organization_id == organization_id,
            VendorAIContamination.vendor_id == vendor_id,
        )
    ).scalar_one_or_none()
    if record is None:
        raise HTTPException(status_code=404, detail="Vendor contamination record not found")
    return VendorContaminationRead.model_validate(record)


@router.post(
    "/vendors/{vendor_id}/dpa",
    summary="Update Vendor DPA Record",
    description=(
        "Records whether a vendor has a Data Processing Agreement and whether it "
        "covers AI processing. This data feeds the contractual gap detection "
        "signal of the Contamination Index. Re-runs contamination assessment for "
        "the vendor after the DPA update."
    ),
    response_model=VendorContaminationRead,
)
def update_vendor_dpa(
    vendor_id: UUID,
    body: VendorDPAUpdate,
    db: Session = Depends(get_db),
    organization_id: UUID = Depends(get_organization_id),
    user_id: UUID = Depends(get_current_user),
    _: None = Depends(require_shadow_ai_enabled),
    __: None = Depends(require_permission("shadow_ai:write")),
):
    if body.vendor_id != vendor_id:
        raise HTTPException(status_code=400, detail="vendor_id in path and body must match")

    vendor = db.execute(
        select(Vendor).where(
            Vendor.id == vendor_id,
            Vendor.organization_id == organization_id,
        )
    ).scalar_one_or_none()
    if vendor is None:
        raise HTTPException(status_code=404, detail="Vendor not found")

    record = db.execute(
        select(VendorDPARecord).where(
            VendorDPARecord.organization_id == organization_id,
            VendorDPARecord.vendor_id == vendor_id,
            VendorDPARecord.deleted_at.is_(None),
        )
    ).scalar_one_or_none()

    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    if record is None:
        record = VendorDPARecord(
            organization_id=organization_id,
            vendor_id=vendor_id,
            vendor_name=body.vendor_name,
            dpa_exists=body.dpa_exists,
            covers_ai_processing=body.covers_ai_processing,
            notes=body.notes,
            created_by=user_id,
            dpa_reviewed_at=now,
        )
        db.add(record)
    else:
        record.vendor_name = body.vendor_name
        record.dpa_exists = body.dpa_exists
        record.covers_ai_processing = body.covers_ai_processing
        record.notes = body.notes
        record.dpa_reviewed_at = now
        record.updated_at = now

    db.flush()

    contamination = ContaminationEngine.compute_contamination_score(
        vendor_id=vendor_id,
        vendor_name=vendor.name,
        organization_id=organization_id,
        enable_external_scan=False,
        db=db,
        user_id=user_id,
    )
    db.commit()
    return VendorContaminationRead.model_validate(contamination)
