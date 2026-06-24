"""
PATENT NOTICE
Module: routers/metrics
Part of: Shadow AI Discovery Engine
Patent: System and Method for Inferring Undeclared
Artificial Intelligence Systems and Generating AI
Governance Artifacts from Enterprise Telemetry
Status: Provisional filing in preparation

Dashboard metrics and data trust document endpoints.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends
from sqlalchemy import select, func
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import get_current_user, get_organization_id, require_permission
from app.models.contamination import VendorAIContamination
from app.models.detection import ConnectorToken, ShadowAIDetection
from app.models.federated import FederatedHostnameObservation
from app.models.idp import IdpConnection
from app.models.zero_day import ZeroDayCandidate
from app.registry.signature_registry import REGISTRY_VERSION, TOTAL_SIGNATURES
from app.services.capability_service import require_shadow_ai_enabled
from app.services.detection_service import DetectionService

router = APIRouter()


@router.get(
    "/metrics",
    summary="Shadow AI Dashboard Metrics",
    description=(
        "Returns aggregated metrics for the Shadow AI Discovery dashboard "
        "panel. Includes detection counts, top tools, and registry coverage "
        "for this organization."
    ),
)
def get_metrics(
    db: Session = Depends(get_db),
    organization_id: UUID = Depends(get_organization_id),
    user_id: UUID = Depends(get_current_user),
    _: None = Depends(require_shadow_ai_enabled),
    __: None = Depends(require_permission("shadow_ai:read")),
):
    summary = DetectionService.get_detection_summary(organization_id, db)
    summary["registry_version"] = REGISTRY_VERSION
    summary["registry_total_tools"] = TOTAL_SIGNATURES
    summary["tier1_enabled"] = True

    active_idp_count = db.execute(
        select(func.count()).select_from(IdpConnection).where(
            IdpConnection.organization_id == organization_id,
            IdpConnection.sync_status == "active",
            IdpConnection.deleted_at.is_(None),
        )
    ).scalar() or 0
    summary["tier2_enabled"] = active_idp_count > 0

    from datetime import datetime, timedelta, timezone

    now = datetime.now(timezone.utc)
    active_token = db.execute(
        select(ConnectorToken).where(
            ConnectorToken.organization_id == organization_id,
            ConnectorToken.is_active.is_(True),
            ConnectorToken.revoked_at.is_(None),
        )
    ).scalars().all()
    tier3_enabled = any(
        t.last_ingest_at is not None
        and (
            t.last_ingest_at.replace(tzinfo=timezone.utc)
            if t.last_ingest_at.tzinfo is None
            else t.last_ingest_at
        )
        > now - timedelta(hours=48)
        for t in active_token
    )
    summary["tier3_enabled"] = tier3_enabled

    pending_zero_day_count = db.execute(
        select(func.count()).select_from(ZeroDayCandidate).where(
            ZeroDayCandidate.organization_id == organization_id,
            ZeroDayCandidate.status == "pending_review",
        )
    ).scalar() or 0
    summary["zero_day_candidates_pending"] = pending_zero_day_count

    jurisdiction_assessments_complete = db.execute(
        select(func.count()).select_from(ShadowAIDetection).where(
            ShadowAIDetection.organization_id == organization_id,
            ShadowAIDetection.deleted_at.is_(None),
            ShadowAIDetection.status.notin_(["dismissed", "registered"]),
            ShadowAIDetection.jurisdiction_assessed_at.is_not(None),
        )
    ).scalar() or 0
    summary["jurisdiction_assessments_complete"] = jurisdiction_assessments_complete

    contamination_critical = db.execute(
        select(func.count()).select_from(VendorAIContamination).where(
            VendorAIContamination.organization_id == organization_id,
            VendorAIContamination.contamination_band == "critical",
        )
    ).scalar() or 0
    contamination_high = db.execute(
        select(func.count()).select_from(VendorAIContamination).where(
            VendorAIContamination.organization_id == organization_id,
            VendorAIContamination.contamination_band == "high",
        )
    ).scalar() or 0
    vendors_without_dpa = db.execute(
        select(func.count()).select_from(VendorAIContamination).where(
            VendorAIContamination.organization_id == organization_id,
            VendorAIContamination.dpa_exists.is_(False),
        )
    ).scalar() or 0
    summary["vendor_contamination_critical"] = contamination_critical
    summary["vendor_contamination_high"] = contamination_high
    summary["vendors_without_dpa"] = vendors_without_dpa

    high_regulatory_risk_count = db.execute(
        select(func.count()).select_from(ShadowAIDetection).where(
            ShadowAIDetection.organization_id == organization_id,
            ShadowAIDetection.deleted_at.is_(None),
            ShadowAIDetection.status.notin_(["dismissed", "registered"]),
            ShadowAIDetection.highest_regulatory_risk.in_(["high", "critical"]),
        )
    ).scalar() or 0
    summary["high_regulatory_risk_count"] = high_regulatory_risk_count

    # Federated network counts (global, non-identifying aggregates).
    from app.models.federated import FederatedSubmissionLog

    federated_candidates_pending = db.execute(
        select(func.count())
        .select_from(FederatedHostnameObservation)
        .where(FederatedHostnameObservation.status == "candidate")
    ).scalar() or 0
    summary["federated_candidates_pending"] = federated_candidates_pending

    federated_network_size = db.execute(
        select(func.count(func.distinct(FederatedSubmissionLog.organization_id)))
        .select_from(FederatedSubmissionLog)
        .where(FederatedSubmissionLog.was_duplicate.is_(False))
    ).scalar() or 0
    summary["federated_network_size"] = federated_network_size

    return summary


@router.get(
    "/trust",
    summary="Data Trust Document",
    description=(
        "Machine-readable document describing exactly what data this service "
        "collects per tier, what it never collects, and the OAuth scopes "
        "requested for Tier 2. This endpoint requires no authentication. "
        "It is CompliVibe's data trust declaration for the Shadow AI "
        "Discovery feature."
    ),
)
def get_trust_document():
    return {
        "document_version": "2.0.0",
        "effective_date": "2026-06-24",
        "service": "Shadow AI Discovery Engine",
        "patent_status": "Provisional filing in preparation",
        "connector_schema_endpoint": (
            "/api/v1/shadow-ai/connector/schema"
        ),
        "data_handling": {
            "tier1": {
                "name": "Platform Discovery",
                "data_received": [
                    "Text already submitted into CompliVibe by the customer",
                ],
                "data_never_received": [
                    "Any data not already stored in CompliVibe",
                ],
                "external_calls": "None",
            },
            "tier2": {
                "name": "Connected Discovery",
                "data_received": [
                    "OAuth app names from IdP audit logs",
                    "OAuth scopes granted",
                    "Event timestamps",
                ],
                "data_never_received": [
                    "Passwords or MFA codes",
                    "Session tokens",
                    "User directory contents",
                    "Request or response contents",
                ],
                "oauth_scopes": {
                    "okta": "okta.logs.read",
                    "azure_ad": "AuditLog.Read.All",
                    "google_ws": "admin.reports.audit.readonly",
                },
            },
            "tier3": {
                "name": "Deep Discovery",
                "data_received": [
                    "Matched tool name (pre-processed by connector)",
                    "Hostname pattern (pre-processed)",
                    "Call count (pre-processed)",
                    "Source system label (customer-assigned)",
                ],
                "data_never_received": [
                    "Raw log lines",
                    "Internal IP addresses",
                    "Request or response contents",
                    "Prompts or completions",
                    "User identities",
                ],
                "architecture": (
                    "Edge-processing — raw telemetry never leaves "
                    "customer environment"
                ),
                "connector_open_source": True,
                "connector_repo": "complivibe-connector-shadow-ai",
                "offline_queue": (
                    "Signals buffered locally when API unreachable"
                ),
                "token_expiry": "365 days (configurable)",
                "payload_enforcement": (
                    "Forbidden fields rejected at HTTP 400 before "
                    "any DB write"
                ),
            },
        },
        "employee_privacy": (
            "This system detects organisational AI system usage, not "
            "individual employee content. It processes metadata and "
            "governance-relevant signals only."
        ),
        "retention": (
            "Detection records are retained permanently for audit purposes. "
            "Dismissed records are never deleted."
        ),
        "dark_ai_detection": {
            "method": "network flow metadata analysis",
            "payload_inspection": False,
            "tls_decryption": False,
            "features": [
                "response_time_variance_score",
                "payload_asymmetry_score",
                "inter_request_timing_score",
                "connection_efficiency_score",
                "call_volume_pattern_score",
                "response_latency_profile_score",
            ],
        },
        "federated_network": {
            "opt_in": True,
            "anonymization": "SHA256 hash only",
            "promotion_threshold": 3,
            "org_identity_stored": False,
        },
    }
