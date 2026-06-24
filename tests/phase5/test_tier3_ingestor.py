"""
Tests for the Tier 3 Ingestor service.

Tests the core signal ingestion, token validation, forbidden field
enforcement, deduplication, and detection triggering logic.
"""

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError
from sqlalchemy import select

from app.models.detection import AuditLog, ConnectorToken, ShadowAIDetection
from app.models.telemetry import TelemetryEvent
from app.schemas.telemetry import ConnectorSignalPayload
from app.services.tier3_ingestor import Tier3Ingestor

ORG_ID = UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
USER_ID = UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")


def make_connector_token(
    db,
    organization_id=None,
    label="test-connector",
    expires_in_days=365,
    is_active=True,
    revoked=False,
):
    """Create a ConnectorToken directly in the DB. Returns (raw_token, token)."""
    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    now = datetime.now(timezone.utc)

    token = ConnectorToken(
        organization_id=organization_id or ORG_ID,
        token_hash=token_hash,
        label=label,
        expires_at=now + timedelta(days=expires_in_days),
        created_by=USER_ID,
        is_active=is_active,
        signals_total=0,
        requests_this_hour=0,
    )
    if revoked:
        token.revoked_at = now
        token.is_active = False

    db.add(token)
    db.commit()
    return raw_token, token


def make_signal_payload(
    org_id=None,
    matched_tool="OpenAI API",
    hostname_pattern="api.openai.com",
    source_system_label="test-vpc-flow",
    **overrides,
):
    """Build a valid ConnectorSignalPayload dict."""
    now = datetime.now(timezone.utc)
    payload = {
        "org_id": str(org_id or ORG_ID),
        "signal_type": "network_match",
        "matched_tool": matched_tool,
        "hostname_pattern": hostname_pattern,
        "call_count_24h": 5,
        "source_system_label": source_system_label,
        "first_seen": (now - timedelta(hours=1)).isoformat(),
        "last_seen": now.isoformat(),
        "connector_version": "1.0.0",
    }
    payload.update(overrides)
    return payload


# ═══════════════════════════════════════════════
# SIGNAL INGESTION TESTS
# ═══════════════════════════════════════════════


def test_valid_signal_creates_telemetry_event(seeded_db):
    """A valid signal matching a registry signature creates a telemetry event."""
    raw_token, token = make_connector_token(seeded_db)
    payload = ConnectorSignalPayload(**make_signal_payload())

    event_id, duplicate = Tier3Ingestor.ingest_signal(payload, token, seeded_db)

    assert duplicate is False
    assert event_id is not None

    event = seeded_db.execute(
        select(TelemetryEvent).where(TelemetryEvent.id == event_id)
    ).scalar_one()
    assert event.tier == 3
    assert event.event_type == "network_match"
    assert event.matched_signature_id is not None


def test_forbidden_field_rejected_at_400(seeded_db):
    """Payload with 'raw_log' field is rejected by the schema validator."""
    payload_dict = make_signal_payload()
    payload_dict["raw_log"] = "some raw log line"

    with pytest.raises(ValidationError) as exc_info:
        ConnectorSignalPayload(**payload_dict)

    assert "forbidden" in str(exc_info.value).lower() or "raw_log" in str(exc_info.value)


def test_forbidden_field_ip_address_rejected(seeded_db):
    """Payload with 'ip_address' field is rejected by the schema validator."""
    payload_dict = make_signal_payload()
    payload_dict["ip_address"] = "10.0.0.1"

    with pytest.raises(ValidationError) as exc_info:
        ConnectorSignalPayload(**payload_dict)

    assert "ip_address" in str(exc_info.value)


def test_duplicate_signal_returns_duplicate_true(seeded_db):
    """Sending the same signal twice returns duplicate=True the second time."""
    raw_token, token = make_connector_token(seeded_db)
    payload = ConnectorSignalPayload(**make_signal_payload())

    event_id1, dup1 = Tier3Ingestor.ingest_signal(payload, token, seeded_db)
    assert dup1 is False

    event_id2, dup2 = Tier3Ingestor.ingest_signal(payload, token, seeded_db)
    assert dup2 is True
    assert event_id2 is None


def test_unrecognized_tool_accepted_not_matched(seeded_db):
    """Signal with an unrecognized tool is accepted but signature_id is NULL."""
    raw_token, token = make_connector_token(seeded_db)
    payload = ConnectorSignalPayload(
        **make_signal_payload(matched_tool="UnknownAI", hostname_pattern="unknown.ai")
    )

    event_id, duplicate = Tier3Ingestor.ingest_signal(payload, token, seeded_db)

    assert duplicate is False
    assert event_id is not None

    event = seeded_db.execute(
        select(TelemetryEvent).where(TelemetryEvent.id == event_id)
    ).scalar_one()
    assert event.matched_signature_id is None


def test_confidence_score_updated_after_ingest(seeded_db):
    """run_detection is called after ingest, creating a detection."""
    raw_token, token = make_connector_token(seeded_db)
    payload = ConnectorSignalPayload(**make_signal_payload())

    Tier3Ingestor.ingest_signal(payload, token, seeded_db)

    detections = seeded_db.execute(
        select(ShadowAIDetection).where(
            ShadowAIDetection.organization_id == ORG_ID
        )
    ).scalars().all()
    assert len(detections) >= 1
    assert float(detections[0].confidence_score) > 0


def test_token_hash_not_stored_in_plaintext(seeded_db):
    """The token_hash in the DB is a SHA256 hash, not the raw token."""
    raw_token, token = make_connector_token(seeded_db)

    assert token.token_hash != raw_token
    assert token.token_hash == hashlib.sha256(raw_token.encode()).hexdigest()
    assert len(token.token_hash) == 64


# ═══════════════════════════════════════════════
# TOKEN VALIDATION TESTS
# ═══════════════════════════════════════════════


def test_expired_token_returns_401(seeded_db):
    """An expired token is rejected with HTTP 401."""
    raw_token, token = make_connector_token(seeded_db, expires_in_days=-1)
    token.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
    seeded_db.commit()

    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc_info:
        Tier3Ingestor.validate_connector_token(raw_token, ORG_ID, seeded_db)

    assert exc_info.value.status_code == 401
    assert "expired" in exc_info.value.detail.lower()


def test_revoked_token_returns_401(seeded_db):
    """A revoked token is rejected with HTTP 401."""
    raw_token, token = make_connector_token(seeded_db, revoked=True)

    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc_info:
        Tier3Ingestor.validate_connector_token(raw_token, ORG_ID, seeded_db)

    assert exc_info.value.status_code == 401


def test_wrong_org_token_returns_401(seeded_db):
    """A token from org A is rejected when validating against org B."""
    org_a = uuid4()
    org_b = uuid4()
    raw_token, token = make_connector_token(seeded_db, organization_id=org_a)

    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc_info:
        Tier3Ingestor.validate_connector_token(raw_token, org_b, seeded_db)

    assert exc_info.value.status_code == 401


def test_signals_total_incremented(seeded_db):
    """signals_total is incremented on each successful ingest."""
    raw_token, token = make_connector_token(seeded_db)

    assert token.signals_total == 0

    payload = ConnectorSignalPayload(**make_signal_payload())
    Tier3Ingestor.ingest_signal(payload, token, seeded_db)

    seeded_db.refresh(token)
    assert token.signals_total == 1


def test_audit_log_created_per_signal(seeded_db):
    """An audit log entry is created for each ingested signal."""
    raw_token, token = make_connector_token(seeded_db)
    payload = ConnectorSignalPayload(**make_signal_payload())

    Tier3Ingestor.ingest_signal(payload, token, seeded_db)

    audit_entries = seeded_db.execute(
        select(AuditLog).where(
            AuditLog.organization_id == ORG_ID,
            AuditLog.action == "shadow_ai.tier3.signal_ingested",
        )
    ).scalars().all()
    assert len(audit_entries) >= 1
    assert audit_entries[0].user_id is None
