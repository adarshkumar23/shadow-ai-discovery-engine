"""
PATENT NOTICE
Module: routers/federated
Implements Dependent Patent Claim 8:
Federated Registry Intelligence Network.

REST API for the privacy-preserving federated hostname aggregation system.

Authentication model:
  * POST /federated/submit uses X-Connector-Token only (no JWT, no
    X-Organization-ID). Organization identity comes from the token and is
    stripped before aggregation storage.
  * Admin/read endpoints use the standard CompliVibe header auth.
  * GET /federated/stats requires no authentication — it returns only
    aggregate counts as a public trust signal.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import get_current_user, get_organization_id, require_permission
from app.models.detection import ConnectorToken
from app.models.federated import FederatedHostnameObservation
from app.schemas.federated import (
    FederatedCandidateRead,
    FederatedNetworkStats,
    FederatedPromoteRequest,
    FederatedSignalSubmission,
    FederatedSubmissionResponse,
)
from app.schemas.telemetry import ConnectorTokenRead
from app.services.federated_aggregator import FederatedAggregator
from app.services.tier3_ingestor import Tier3Ingestor

router = APIRouter()


def _token_read(token: ConnectorToken) -> ConnectorTokenRead:
    """Build ConnectorTokenRead from ORM."""
    return ConnectorTokenRead(
        id=token.id,
        organization_id=token.organization_id,
        label=token.label,
        created_by=token.created_by,
        created_at=token.created_at,
        expires_at=token.expires_at,
        last_used_at=token.last_used_at,
        last_ingest_at=token.last_ingest_at,
        connector_version=token.connector_version,
        signals_total=token.signals_total or 0,
        is_active=token.is_active,
        revoked_at=token.revoked_at,
        federated_submissions_enabled=token.federated_submissions_enabled or False,
        federated_submissions_count=token.federated_submissions_count or 0,
    )


@router.post(
    "/federated/submit",
    summary="Submit Federated Hostname Signal",
    description=(
        "Submits an unknown hostname to the global federated registry network "
        "for cross-organization observation counting. Organization identity is "
        "stripped before storage. Only enabled for tokens with "
        "federated_submissions_enabled=True. Patent Claim 8 — Federated Registry "
        "Intelligence Network."
    ),
    response_model=FederatedSubmissionResponse,
)
def submit_signal(
    body: FederatedSignalSubmission,
    x_connector_token: str | None = Header(default=None, alias="X-Connector-Token"),
    db: Session = Depends(get_db),
):
    """
    Token-authenticated endpoint for connectors to submit unknown hostnames.
    No JWT. No X-Organization-ID. org_id comes from the token and is stripped.
    """
    if not x_connector_token:
        raise HTTPException(
            status_code=401,
            detail="X-Connector-Token header required",
        )

    connector_token = Tier3Ingestor.validate_connector_token(
        x_connector_token, None, db
    )

    return FederatedAggregator.submit_hostname(
        organization_id=connector_token.organization_id,
        hostname=body.hostname,
        behavioral_score=body.behavioral_score,
        connector_token=connector_token,
        db=db,
    )


@router.get(
    "/federated/candidates",
    summary="List Federated Candidates",
    description=(
        "Returns hostnames observed by 3+ independent organizations that are "
        "pending registry addition. These are AI services discovered through "
        "collective intelligence across the customer network."
    ),
    response_model=list[FederatedCandidateRead],
)
def list_candidates(
    status: str | None = None,
    db: Session = Depends(get_db),
    organization_id: UUID = Depends(get_organization_id),
    user_id: UUID = Depends(get_current_user),
    _: None = Depends(require_permission("shadow_ai:read")),
):
    """
    Returns global federated candidates. Intentionally not filtered by
    organization_id — the value of the network is shared.
    """
    del organization_id, user_id  # used by dependency layer only
    candidates = FederatedAggregator.get_candidates(db, status=status)
    return [FederatedCandidateRead.model_validate(c) for c in candidates]


@router.get(
    "/federated/candidates/{candidate_id}",
    summary="Get Federated Candidate",
    response_model=FederatedCandidateRead,
)
def get_candidate(
    candidate_id: UUID,
    db: Session = Depends(get_db),
    organization_id: UUID = Depends(get_organization_id),
    user_id: UUID = Depends(get_current_user),
    _: None = Depends(require_permission("shadow_ai:read")),
):
    """Return a single federated candidate by ID."""
    del organization_id, user_id  # used by dependency layer only

    candidate = db.execute(
        select(FederatedHostnameObservation).where(
            FederatedHostnameObservation.id == candidate_id
        )
    ).scalar_one_or_none()

    if candidate is None:
        raise HTTPException(status_code=404, detail="Federated candidate not found")

    return FederatedCandidateRead.model_validate(candidate)


@router.post(
    "/federated/candidates/{candidate_id}/promote",
    summary="Promote to Registry",
    description=(
        "Adds a federated candidate to the global AI signature registry. After "
        "promotion, this hostname will be detected as a standard known tool for "
        "ALL organizations in the network."
    ),
    response_model=FederatedCandidateRead,
)
def promote_candidate(
    candidate_id: UUID,
    body: FederatedPromoteRequest,
    db: Session = Depends(get_db),
    organization_id: UUID = Depends(get_organization_id),
    user_id: UUID = Depends(get_current_user),
    _: None = Depends(require_permission("shadow_ai:admin")),
):
    """Admin endpoint to promote a federated candidate to the registry."""
    FederatedAggregator.promote_to_registry(
        observation_id=candidate_id,
        provider_name=body.provider_name,
        category=body.category,
        reviewed_by=user_id,
        db=db,
    )
    return get_candidate(
        candidate_id,
        db=db,
        organization_id=organization_id,
        user_id=user_id,
    )


@router.post(
    "/federated/candidates/{candidate_id}/dismiss",
    summary="Dismiss Federated Candidate",
    response_model=FederatedCandidateRead,
)
def dismiss_candidate(
    candidate_id: UUID,
    db: Session = Depends(get_db),
    organization_id: UUID = Depends(get_organization_id),
    user_id: UUID = Depends(get_current_user),
    _: None = Depends(require_permission("shadow_ai:admin")),
):
    """Admin endpoint to dismiss a federated candidate."""
    FederatedAggregator.dismiss_candidate(
        observation_id=candidate_id,
        reviewed_by=user_id,
        db=db,
    )
    return get_candidate(
        candidate_id,
        db=db,
        organization_id=organization_id,
        user_id=user_id,
    )


@router.get(
    "/federated/stats",
    summary="Federated Network Statistics",
    description=(
        "Returns aggregate statistics about the federated intelligence network. "
        "No organization-identifying data is returned. Only counts."
    ),
    response_model=FederatedNetworkStats,
)
def get_stats(db: Session = Depends(get_db)):
    """
    Public trust signal endpoint. Requires no authentication.
    Demonstrates network value without exposing any customer data.
    """
    stats = FederatedAggregator.get_network_stats(db)
    return FederatedNetworkStats(**stats)


@router.post(
    "/federated/tokens/{token_id}/enable",
    summary="Enable Federated Submissions",
    description=(
        "Enables federated hostname submission for a specific connector token. "
        "This is an opt-in action. Requires explicit administrator approval per token."
    ),
    response_model=ConnectorTokenRead,
)
def enable_federated_for_token(
    token_id: UUID,
    db: Session = Depends(get_db),
    organization_id: UUID = Depends(get_organization_id),
    user_id: UUID = Depends(get_current_user),
    _: None = Depends(require_permission("shadow_ai:admin")),
):
    """Enable federated submissions for a connector token."""
    token = db.execute(
        select(ConnectorToken).where(
            ConnectorToken.id == token_id,
            ConnectorToken.organization_id == organization_id,
        )
    ).scalar_one_or_none()

    if token is None:
        raise HTTPException(status_code=404, detail="Connector token not found")

    token.federated_submissions_enabled = True
    db.commit()

    return _token_read(token)


@router.post(
    "/federated/tokens/{token_id}/disable",
    summary="Disable Federated Submissions",
    response_model=ConnectorTokenRead,
)
def disable_federated_for_token(
    token_id: UUID,
    db: Session = Depends(get_db),
    organization_id: UUID = Depends(get_organization_id),
    user_id: UUID = Depends(get_current_user),
    _: None = Depends(require_permission("shadow_ai:admin")),
):
    """Disable federated submissions for a connector token."""
    token = db.execute(
        select(ConnectorToken).where(
            ConnectorToken.id == token_id,
            ConnectorToken.organization_id == organization_id,
        )
    ).scalar_one_or_none()

    if token is None:
        raise HTTPException(status_code=404, detail="Connector token not found")

    token.federated_submissions_enabled = False
    db.commit()

    return _token_read(token)
