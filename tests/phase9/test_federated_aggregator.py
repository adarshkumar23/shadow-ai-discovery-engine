"""
Tests for the FederatedAggregator service.

Dependent Patent Claim 8: Federated Registry Intelligence Network.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from sqlalchemy import select

from app.models.detection import ConnectorToken
from app.models.federated import FederatedHostnameObservation
from app.models.signature import AISignatureRegistry
from app.models.zero_day import ZeroDayCandidate
from app.services.federated_aggregator import (
    PROMOTION_THRESHOLD,
    FederatedAggregator,
)

ORG_A = UUID("11111111-1111-1111-1111-111111111111")
ORG_B = UUID("22222222-2222-2222-2222-222222222222")
ORG_C = UUID("33333333-3333-3333-3333-333333333333")
HOSTNAME = "aggregator-test.example.com"


def _make_token(test_db, org_id: UUID = ORG_A, enabled: bool = True) -> ConnectorToken:
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
    test_db.add(token)
    test_db.commit()
    return token


def test_submission_disabled_by_default(test_db):
    """Token with federated_submissions_enabled=False rejects submission."""
    token = _make_token(test_db, ORG_A, enabled=False)

    result = FederatedAggregator.submit_hostname(
        organization_id=ORG_A,
        hostname=HOSTNAME,
        behavioral_score=0.75,
        connector_token=token,
        db=test_db,
    )

    assert result.accepted is False
    assert "not enabled" in result.message


def test_submission_requires_opt_in(test_db):
    """Cannot submit without explicitly enabling the token."""
    token = ConnectorToken(
        id=uuid4(),
        organization_id=ORG_A,
        token_hash="deadbeef",
        label="test-token",
        created_by=ORG_A,
        expires_at=datetime.now(timezone.utc) + timedelta(days=365),
        federated_submissions_enabled=False,
        federated_submissions_count=0,
    )
    test_db.add(token)
    test_db.commit()

    result = FederatedAggregator.submit_hostname(
        organization_id=ORG_A,
        hostname=HOSTNAME,
        behavioral_score=0.75,
        connector_token=token,
        db=test_db,
    )
    assert result.accepted is False


def test_three_observations_promotes_candidate(test_db):
    """3 orgs submitting same hostname → status = 'candidate'."""
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
    assert observation.promoted_at is not None


def test_two_observations_stays_observing(test_db):
    """2 orgs submitting same hostname → status remains 'observing'."""
    for org_id in (ORG_A, ORG_B):
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
    assert observation.observation_count == 2
    assert observation.status == "observing"


def test_promotion_threshold_is_three():
    """PROMOTION_THRESHOLD is exactly 3. Patent Invariant 33."""
    assert PROMOTION_THRESHOLD == 3


def test_promote_to_registry_creates_signature(test_db):
    """Promote endpoint creates a new AISignatureRegistry entry."""
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

    admin_id = uuid4()
    signature = FederatedAggregator.promote_to_registry(
        observation_id=observation.id,
        provider_name="Unknown AI Service",
        category="other",
        reviewed_by=admin_id,
        db=test_db,
    )

    assert signature.provider_name == "Unknown AI Service"
    assert signature.category == "other"
    keyword_patterns = json.loads(signature.keyword_patterns)
    endpoint_patterns = json.loads(signature.endpoint_patterns)
    assert HOSTNAME in keyword_patterns
    assert HOSTNAME in endpoint_patterns

    test_db.refresh(observation)
    assert observation.status == "promoted"
    assert observation.signature_id == signature.slug
    assert observation.reviewed_by_admin is True


def test_after_promotion_hostname_matches_registry(test_db, seeded_db):
    """After promotion, a Tier 3 signal with that hostname matches registry."""
    from app.models.telemetry import TelemetryEvent
    from app.schemas.telemetry import ConnectorSignalPayload
    from app.services.tier3_ingestor import Tier3Ingestor

    for org_id in (ORG_A, ORG_B, ORG_C):
        token = _make_token(seeded_db, org_id, enabled=True)
        FederatedAggregator.submit_hostname(
            organization_id=org_id,
            hostname=HOSTNAME,
            behavioral_score=0.75,
            connector_token=token,
            db=seeded_db,
        )

    observation = seeded_db.execute(
        select(FederatedHostnameObservation)
    ).scalar_one()

    admin_id = uuid4()
    FederatedAggregator.promote_to_registry(
        observation_id=observation.id,
        provider_name="Aggregator Test Tool",
        category="other",
        reviewed_by=admin_id,
        db=seeded_db,
    )

    payload = ConnectorSignalPayload(
        org_id=str(ORG_A),
        signal_type="network_match",
        matched_tool="Aggregator Test Tool",
        hostname_pattern=HOSTNAME,
        call_count_24h=10,
        source_system_label="test",
        first_seen=datetime.now(timezone.utc) - timedelta(hours=1),
        last_seen=datetime.now(timezone.utc),
        connector_version="1.0.0",
    )

    token = seeded_db.execute(
        select(ConnectorToken).where(ConnectorToken.organization_id == ORG_A)
    ).scalars().first()
    signal_id, duplicate = Tier3Ingestor.ingest_signal(payload, token, seeded_db)

    event = seeded_db.execute(
        select(TelemetryEvent).where(TelemetryEvent.id == signal_id)
    ).scalar_one()
    assert event.matched_signature_id is not None


def test_dismiss_prevents_further_promotion(test_db):
    """Dismissed candidate stays dismissed even with more observations."""
    for org_id in (ORG_A, ORG_B):
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

    admin_id = uuid4()
    FederatedAggregator.dismiss_candidate(
        observation_id=observation.id,
        reviewed_by=admin_id,
        db=test_db,
    )

    token_c = _make_token(test_db, ORG_C, enabled=True)
    FederatedAggregator.submit_hostname(
        organization_id=ORG_C,
        hostname=HOSTNAME,
        behavioral_score=0.75,
        connector_token=token_c,
        db=test_db,
    )

    test_db.refresh(observation)
    assert observation.status == "dismissed"


def test_network_stats_never_reveals_org_identity(test_db):
    """Network stats return only counts; no org IDs anywhere."""
    for org_id in (ORG_A, ORG_B, ORG_C):
        token = _make_token(test_db, org_id, enabled=True)
        FederatedAggregator.submit_hostname(
            organization_id=org_id,
            hostname=HOSTNAME,
            behavioral_score=0.75,
            connector_token=token,
            db=test_db,
        )

    stats = FederatedAggregator.get_network_stats(test_db)

    assert set(stats.keys()) == {
        "total_hostnames_observed",
        "candidates_pending_review",
        "promoted_to_registry",
        "observation_threshold",
        "network_size_orgs",
    }
    assert stats["candidates_pending_review"] == 1
    assert stats["network_size_orgs"] == 3
    assert str(ORG_A) not in json.dumps(stats)


def test_stats_endpoint_no_auth(test_db):
    """GET /federated/stats returns 200 without headers."""
    from fastapi.testclient import TestClient

    from app.core.database import get_db
    from app.main import app

    def override_get_db():
        yield test_db

    app.dependency_overrides[get_db] = override_get_db
    try:
        with TestClient(app) as c:
            resp = c.get("/api/v1/shadow-ai/federated/stats")
            assert resp.status_code == 200
            data = resp.json()
            assert "observation_threshold" in data
            assert data["observation_threshold"] == PROMOTION_THRESHOLD
    finally:
        app.dependency_overrides.clear()


def test_submit_zero_day_candidates(test_db):
    """Nightly scheduler submits pending zero-day candidates >= 0.55."""
    now = datetime.now(timezone.utc)
    candidate = ZeroDayCandidate(
        id=uuid4(),
        organization_id=ORG_A,
        hostname=HOSTNAME,
        first_observed_at=now,
        last_observed_at=now,
        observation_count=1,
        behavioral_score=0.75,
        status="pending_review",
    )
    test_db.add(candidate)
    test_db.commit()

    token = _make_token(test_db, ORG_A, enabled=True)
    result = FederatedAggregator.submit_zero_day_candidates(
        organization_id=ORG_A,
        connector_token=token,
        db=test_db,
    )

    assert result["candidates_submitted"] == 1

    observation = test_db.execute(
        select(FederatedHostnameObservation)
    ).scalar_one_or_none()
    assert observation is not None
    assert observation.observation_count == 1
