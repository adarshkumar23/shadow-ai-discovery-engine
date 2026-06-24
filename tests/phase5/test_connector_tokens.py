"""
Tests for connector token lifecycle: generation, storage, revocation,
and validation on ingest.
"""

import hashlib
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select

from app.models.detection import ConnectorToken
from app.schemas.telemetry import ConnectorTokenCreate, ConnectorTokenRead
from app.services.tier3_ingestor import Tier3Ingestor
from tests.phase5.test_tier3_ingestor import ORG_ID, USER_ID, make_connector_token

ORG_ID = ORG_ID  # re-export for clarity


def test_generate_token_returns_raw_once(seeded_db):
    """generate_connector_token returns the raw token and a token record."""
    raw_token, token = Tier3Ingestor.generate_connector_token(
        organization_id=ORG_ID,
        label="prod-connector",
        created_by=USER_ID,
        expires_in_days=365,
        db=seeded_db,
    )

    assert raw_token is not None
    assert len(raw_token) > 20
    assert token.label == "prod-connector"
    assert token.organization_id == ORG_ID
    assert token.is_active is True
    assert token.revoked_at is None


def test_raw_token_not_in_db(seeded_db):
    """The token stored in DB is a SHA256 hash, not the raw token."""
    raw_token, token = Tier3Ingestor.generate_connector_token(
        organization_id=ORG_ID,
        label="test",
        created_by=USER_ID,
        expires_in_days=365,
        db=seeded_db,
    )

    expected_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    assert token.token_hash == expected_hash
    assert token.token_hash != raw_token

    db_token = seeded_db.execute(
        select(ConnectorToken).where(ConnectorToken.id == token.id)
    ).scalar_one()
    assert db_token.token_hash == expected_hash
    assert db_token.token_hash != raw_token


def test_revoke_sets_is_active_false(seeded_db):
    """Revoking a token sets is_active=False and revoked_at."""
    raw_token, token = Tier3Ingestor.generate_connector_token(
        organization_id=ORG_ID,
        label="to-revoke",
        created_by=USER_ID,
        expires_in_days=365,
        db=seeded_db,
    )

    revoked = Tier3Ingestor.revoke_token(
        token_id=token.id,
        organization_id=ORG_ID,
        revoked_by=USER_ID,
        db=seeded_db,
    )

    assert revoked.is_active is False
    assert revoked.revoked_at is not None


def test_revoked_token_rejected_on_ingest(seeded_db):
    """A revoked token is rejected when trying to ingest."""
    raw_token, token = make_connector_token(seeded_db, revoked=True)

    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc_info:
        Tier3Ingestor.validate_connector_token(raw_token, ORG_ID, seeded_db)

    assert exc_info.value.status_code == 401


def test_expired_token_rejected_on_ingest(seeded_db):
    """An expired token is rejected when trying to ingest."""
    raw_token, token = make_connector_token(seeded_db, expires_in_days=-1)
    token.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
    seeded_db.commit()

    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc_info:
        Tier3Ingestor.validate_connector_token(raw_token, ORG_ID, seeded_db)

    assert exc_info.value.status_code == 401
    assert "expired" in exc_info.value.detail.lower()


def test_list_tokens_excludes_hash(seeded_db):
    """list_tokens returns token records; the schema omits token_hash."""
    Tier3Ingestor.generate_connector_token(
        organization_id=ORG_ID, label="token-1", created_by=USER_ID,
        expires_in_days=365, db=seeded_db,
    )
    Tier3Ingestor.generate_connector_token(
        organization_id=ORG_ID, label="token-2", created_by=USER_ID,
        expires_in_days=365, db=seeded_db,
    )

    tokens = Tier3Ingestor.list_tokens(ORG_ID, seeded_db)
    assert len(tokens) == 2

    for t in tokens:
        read = ConnectorTokenRead.model_validate(t)
        dumped = read.model_dump()
        assert "token_hash" not in dumped or dumped.get("token_hash") is None


def test_token_label_required(seeded_db):
    """ConnectorTokenCreate requires a label with min_length=3."""
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        ConnectorTokenCreate(label="ab")

    with pytest.raises(ValidationError):
        ConnectorTokenCreate(label="")

    valid = ConnectorTokenCreate(label="prod-connector")
    assert valid.label == "prod-connector"
    assert valid.expires_in_days == 365
