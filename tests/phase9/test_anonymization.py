"""
Tests for Federated Registry Intelligence Network anonymization invariants.

Dependent Patent Claim 8: privacy-preserving federated signal aggregation.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.detection import ConnectorToken
from app.models.federated import (
    FederatedHostnameObservation,
    FederatedSubmissionLog,
)
from app.services.audit_service import AuditService
from app.services.federated_aggregator import FederatedAggregator

ORG_A = UUID("11111111-1111-1111-1111-111111111111")
ORG_B = UUID("22222222-2222-2222-2222-222222222222")
ORG_C = UUID("33333333-3333-3333-3333-333333333333")
HOSTNAME = "api.unknownai.ai"


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _make_token(db: Session, org_id: UUID, enabled: bool = True) -> ConnectorToken:
    token = ConnectorToken(
        id=uuid4(),
        organization_id=org_id,
        token_hash="deadbeef",
        label="test-token",
        created_by=org_id,
        expires_at=datetime.now(timezone.utc) + timedelta(days=365),
        federated_submissions_enabled=enabled,
        federated_submissions_count=0,
    )
    db.add(token)
    db.commit()
    return token


def test_org_id_never_in_observations_table(test_db):
    """
    Patent Invariant 32: the aggregation table must never contain a column
    that can identify which organization submitted a hostname.
    """
    token = _make_token(test_db, ORG_A, enabled=True)

    FederatedAggregator.submit_hostname(
        organization_id=ORG_A,
        hostname=HOSTNAME,
        behavioral_score=0.75,
        connector_token=token,
        db=test_db,
    )

    observation = test_db.execute(
        select(FederatedHostnameObservation)
    ).scalar_one()
    assert observation.hostname == HOSTNAME

    columns = {c.name for c in FederatedHostnameObservation.__table__.columns}
    assert "organization_id" not in columns


def test_submission_token_is_deterministic(test_db):
    """Same org + hostname + date → same submission_token."""
    token = _make_token(test_db, ORG_A, enabled=True)

    FederatedAggregator.submit_hostname(
        organization_id=ORG_A,
        hostname=HOSTNAME,
        behavioral_score=0.75,
        connector_token=token,
        db=test_db,
    )

    log = test_db.execute(select(FederatedSubmissionLog)).scalar_one()
    today = __import__("datetime").date.today().isoformat()
    expected_token = _hash(f"{ORG_A}:{HOSTNAME}:{today}")
    assert log.submission_token == expected_token


def test_different_orgs_same_hostname_increments(test_db):
    """3 different orgs submitting the same hostname → observation_count = 3."""
    for org_id in (ORG_A, ORG_B, ORG_C):
        token = _make_token(test_db, org_id, enabled=True)
        FederatedAggregator.submit_hostname(
            organization_id=org_id,
            hostname=HOSTNAME,
            behavioral_score=0.75,
            connector_token=token,
            db=test_db,
        )

    observation = test_db.execute(
        select(FederatedHostnameObservation)
    ).scalar_one()
    assert observation.observation_count == 3
    assert observation.status == "candidate"


def test_same_org_same_hostname_is_duplicate(test_db):
    """Submit twice from same org same day → second is duplicate, count stays 1."""
    token = _make_token(test_db, ORG_A, enabled=True)

    result1 = FederatedAggregator.submit_hostname(
        organization_id=ORG_A,
        hostname=HOSTNAME,
        behavioral_score=0.75,
        connector_token=token,
        db=test_db,
    )
    result2 = FederatedAggregator.submit_hostname(
        organization_id=ORG_A,
        hostname=HOSTNAME,
        behavioral_score=0.80,
        connector_token=token,
        db=test_db,
    )

    assert result1.was_duplicate is False
    assert result2.was_duplicate is True

    observation = test_db.execute(
        select(FederatedHostnameObservation)
    ).scalar_one()
    assert observation.observation_count == 1


def test_hostname_normalized_before_hash(test_db):
    """Different URL forms of the same hostname produce the same hash."""
    variants = [
        "API.OpenAI.COM/v1/chat",
        "api.openai.com/v1/completions",
        "api.openai.com",
    ]

    tokens = []
    for org_id in (ORG_A, ORG_B, ORG_C):
        tokens.append(_make_token(test_db, org_id, enabled=True))

    for org_id, token, variant in zip((ORG_A, ORG_B, ORG_C), tokens, variants):
        FederatedAggregator.submit_hostname(
            organization_id=org_id,
            hostname=variant,
            behavioral_score=0.75,
            connector_token=token,
            db=test_db,
        )

    observations = test_db.execute(
        select(FederatedHostnameObservation)
    ).scalars().all()
    assert len(observations) == 1
    assert observations[0].hostname == "api.openai.com"


def test_path_stripped_from_hostname(test_db):
    """A hostname with a path is stored as the hostname only."""
    token = _make_token(test_db, ORG_A, enabled=True)

    FederatedAggregator.submit_hostname(
        organization_id=ORG_A,
        hostname="api.example.com/v1/chat",
        behavioral_score=0.75,
        connector_token=token,
        db=test_db,
    )

    observation = test_db.execute(
        select(FederatedHostnameObservation)
    ).scalar_one()
    assert observation.hostname == "api.example.com"


def test_hostname_not_in_audit_context_json(test_db, monkeypatch):
    """AuditService.log must be called with hostname_hash, not hostname."""
    token = _make_token(test_db, ORG_A, enabled=True)
    captured = {}

    def fake_log(*, db, organization_id, user_id, action, entity_type, entity_id, context_json):
        captured["action"] = action
        captured["context_json"] = context_json

    monkeypatch.setattr(AuditService, "log", fake_log)

    FederatedAggregator.submit_hostname(
        organization_id=ORG_A,
        hostname=HOSTNAME,
        behavioral_score=0.75,
        connector_token=token,
        db=test_db,
    )

    assert captured["action"] == "shadow_ai.federated.signal_submitted"
    assert "hostname" not in captured["context_json"]
    assert "hostname_hash" in captured["context_json"]
    assert captured["context_json"]["hostname_hash"] == _hash(HOSTNAME)
