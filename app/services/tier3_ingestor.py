"""
PATENT NOTICE
Module: services/tier3_ingestor
Implements Core Patent Claim 2:
The Edge Processing Architecture.

ARCHITECTURE INVARIANTS (patent-specified):
1. The connector sends signals only — never
   raw telemetry. CompliVibe never initiates
   connection into the customer environment.
   The customer's connector is always the
   initiator.

2. Signal extraction computation happens
   inside the customer environment. Only
   matched, pre-processed results cross the
   network boundary.

3. The ingest endpoint enforces payload
   exclusion at the HTTP layer. Forbidden
   fields (raw logs, IPs, user identities,
   payload contents) are rejected before
   any database write occurs.

4. This separation — edge computation,
   signal transmission, central governance
   artifact assembly — is the core technical
   method of Core Patent Claim 2.

What this module NEVER does:
- Accepts raw log lines
- Accepts internal IP addresses
- Accepts user identities
- Accepts request or response contents
- Initiates any connection to customer infra
- Receives anything beyond the ConnectorSignal
  schema fields
"""

from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone
from uuid import UUID

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.core.logging_config import get_logger
from app.models.detection import ConnectorHeartbeat, ConnectorToken
from app.models.signature import AISignatureRegistry
from app.models.telemetry import TelemetryEvent
from app.services.audit_service import AuditService
from app.services.confidence_engine import ConfidenceEngine
from app.services.detection_service import DetectionService
from app.services.registry_service import RegistryService
from app.services.zero_day_classifier import ZeroDayClassifier
from app.services.dark_ai_classifier import DarkAIClassifier
from app.schemas.telemetry import (
    ConnectorHeartbeatPayload,
    ConnectorSignalPayload,
)

logger = get_logger(__name__)

# Optional flow metadata fields added in Phase 10.
_FLOW_METADATA_FIELDS = [
    "avg_response_time_ms",
    "response_time_variance_ms",
    "avg_request_bytes",
    "avg_response_bytes",
    "connection_reuse_ratio",
    "inter_request_gap_ms",
    "port",
]

_NIL_UUID = UUID("00000000-0000-0000-0000-000000000000")


class Tier3Ingestor:
    """Central reception layer for Tier 3 edge-processed signals.

    Implements Core Patent Claim 2: the Edge Processing Architecture.
    Receives pre-processed signals from the open source connector
    running inside the customer's environment. Raw telemetry never
    crosses the network boundary.
    """

    @staticmethod
    def validate_connector_token(
        raw_token: str,
        organization_id: UUID | None,
        db: Session,
    ) -> ConnectorToken:
        """Validate a connector token for ingest and heartbeat endpoints.

        Steps:
        1. SHA256 hash the raw_token.
        2. Query connector_tokens WHERE:
             token_hash = computed_hash
             organization_id = organization_id (if provided)
             is_active = True
             revoked_at IS NULL
        3. If not found: raise HTTPException(401, "Invalid connector token")
        4. If found but expires_at <= now():
           raise HTTPException(401, "Connector token expired. Generate a
            new token via the API.")
        5. Return the ConnectorToken record.

        Never log the raw_token value.
        """
        from fastapi import HTTPException

        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

        query = select(ConnectorToken).where(
            ConnectorToken.token_hash == token_hash,
            ConnectorToken.is_active.is_(True),
            ConnectorToken.revoked_at.is_(None),
        )
        if organization_id is not None:
            query = query.where(ConnectorToken.organization_id == organization_id)

        token = db.execute(query).scalar_one_or_none()

        if token is None:
            raise HTTPException(
                status_code=401,
                detail="Invalid connector token",
            )

        now = datetime.now(timezone.utc)
        expires_at = token.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at <= now:
            raise HTTPException(
                status_code=401,
                detail="Connector token expired. Generate a new token via the API.",
            )

        return token

    @staticmethod
    def _find_matching_signature(
        matched_tool: str,
        hostname_pattern: str,
        signatures: list[AISignatureRegistry],
    ) -> AISignatureRegistry | None:
        """Find matching signature by provider_name or keyword/endpoint patterns."""
        tool_lower = matched_tool.lower()
        host_lower = hostname_pattern.lower() if hostname_pattern else ""

        for sig in signatures:
            if tool_lower == sig.provider_name.lower():
                return sig

            try:
                keyword_patterns = json.loads(sig.keyword_patterns)
            except (json.JSONDecodeError, TypeError):
                keyword_patterns = []
            for kw in keyword_patterns:
                kw_lower = kw.lower()
                if kw_lower == tool_lower or kw_lower in tool_lower:
                    return sig

            try:
                endpoint_patterns = json.loads(sig.endpoint_patterns)
            except (json.JSONDecodeError, TypeError):
                endpoint_patterns = []
            for ep in endpoint_patterns:
                cleaned = ep.lstrip("*.")
                if cleaned and (cleaned in host_lower or host_lower in cleaned):
                    return sig

        return None

    @staticmethod
    def _build_raw_signal(payload: ConnectorSignalPayload) -> dict:
        """Build the raw_signal_json dict stored on TelemetryEvent.

        Includes optional Phase 10 flow metadata fields when present.
        These are network envelope measurements only and contain no
        payload content.
        """
        raw_signal: dict = {
            "signal_type": payload.signal_type,
            "matched_tool": payload.matched_tool,
            "hostname_pattern": payload.hostname_pattern,
            "call_count_24h": payload.call_count_24h,
            "source_system_label": payload.source_system_label,
            "first_seen": payload.first_seen.isoformat(),
            "last_seen": payload.last_seen.isoformat(),
            "connector_version": payload.connector_version,
            "endpoint_matched": payload.hostname_pattern,
        }
        for field in _FLOW_METADATA_FIELDS:
            value = getattr(payload, field, None)
            if value is not None:
                raw_signal[field] = value
        return raw_signal

    @staticmethod
    def ingest_signal(
        payload: ConnectorSignalPayload,
        connector_token: ConnectorToken,
        db: Session,
    ) -> tuple[UUID | None, bool]:
        """Receive a pre-processed signal from the edge connector.

        PATENT NOTICE: This method implements the central reception
        layer of Core Patent Claim 2. It receives pre-processed signals
        from the edge connector and creates telemetry events for the
        detection engine.

        The payload has already been validated by Pydantic
        (FORBIDDEN_FIELDS check ran). This method performs additional
        validation and deduplication.

        Returns (event_id | None, is_duplicate).
        """
        org_id = UUID(payload.org_id)

        signatures = RegistryService.get_merged_registry(org_id, db)
        signature = Tier3Ingestor._find_matching_signature(
            payload.matched_tool,
            payload.hostname_pattern,
            signatures,
        )

        event_date = payload.last_seen.date()

        if signature is None:
            logger.warning(
                "Unrecognized tool in signal: %s. Signal accepted but "
                "cannot be matched to registry.",
                payload.matched_tool,
                extra={"matched_tool": payload.matched_tool},
            )

            raw_hash_input = (
                f"{org_id}:unmatched:{payload.matched_tool}:"
                f"{payload.source_system_label}:{event_date.isoformat()}"
            )
            signal_hash = hashlib.sha256(raw_hash_input.encode()).hexdigest()

            existing = db.execute(
                select(TelemetryEvent).where(
                    TelemetryEvent.organization_id == org_id,
                    TelemetryEvent.signal_hash == signal_hash,
                )
            ).scalar_one_or_none()
            if existing is not None:
                return (None, True)

            raw_signal = Tier3Ingestor._build_raw_signal(payload)

            event = TelemetryEvent(
                organization_id=org_id,
                tier=3,
                event_type="network_match",
                source_system_label=payload.source_system_label,
                matched_signature_id=None,
                raw_signal_json=json.dumps(raw_signal),
                signal_hash=signal_hash,
                observed_at=payload.last_seen,
            )
            db.add(event)
            db.flush()

            now = datetime.now(timezone.utc)
            connector_token.last_ingest_at = now
            connector_token.last_used_at = now
            connector_token.connector_version = payload.connector_version
            connector_token.signals_total = (connector_token.signals_total or 0) + 1

            AuditService.log(
                db=db,
                organization_id=org_id,
                user_id=None,
                action="shadow_ai.tier3.signal_ingested",
                entity_type="telemetry_event",
                entity_id=event.id,
                context_json={
                    "signal_type": payload.signal_type,
                    "matched_tool": payload.matched_tool,
                    "connector_version": payload.connector_version,
                    "matched_signature": None,
                },
            )

            # Zero-day behavioral classification for unrecognized hostnames.
            # Runs only on network envelope metadata; never inspects payload
            # contents. This is the integration point for Dependent Patent
            # Claim 4.
            candidate = None
            if ZeroDayClassifier.should_classify(payload, matched_signature=False):
                candidate = ZeroDayClassifier.classify_signal(
                    payload,
                    org_id,
                    db,
                    telemetry_event_id=event.id,
                )
            if candidate is not None:
                logger.info(
                    "Zero-day candidate created or updated: %s score=%s",
                    payload.hostname_pattern,
                    candidate.behavioral_score,
                    extra={
                        "hostname": payload.hostname_pattern,
                        "behavioral_score": float(candidate.behavioral_score),
                    },
                )

            # Phase 10: dark AI side channel classification for unknown
            # hostnames that provide enough timing/flow metadata.
            if DarkAIClassifier.should_classify(payload, matched_signature=False):
                DarkAIClassifier.classify(
                    payload,
                    org_id,
                    matched_signature_id=None,
                    telemetry_event_id=event.id,
                    db=db,
                )

            db.commit()
            return (event.id, False)

        # ── Signature matched ───────────────────
        signal_hash = ConfidenceEngine.compute_signal_hash(
            organization_id=org_id,
            signature_id=signature.id,
            source_system_label=payload.source_system_label,
            event_date=event_date,
        )

        existing = db.execute(
            select(TelemetryEvent).where(
                TelemetryEvent.organization_id == org_id,
                TelemetryEvent.signal_hash == signal_hash,
            )
        ).scalar_one_or_none()
        if existing is not None:
            return (None, True)

        raw_signal = Tier3Ingestor._build_raw_signal(payload)

        event = TelemetryEvent(
            organization_id=org_id,
            tier=3,
            event_type="network_match",
            source_system_label=payload.source_system_label,
            matched_signature_id=signature.id,
            raw_signal_json=json.dumps(raw_signal),
            signal_hash=signal_hash,
            observed_at=payload.last_seen,
        )
        db.add(event)
        db.flush()

        now = datetime.now(timezone.utc)
        connector_token.last_ingest_at = now
        connector_token.last_used_at = now
        connector_token.connector_version = payload.connector_version
        connector_token.signals_total = (connector_token.signals_total or 0) + 1

        DetectionService.run_detection(org_id, db)

        # Phase 10: dark AI side channel classification for proxied or
        # otherwise identity-obscured known AI traffic.
        if DarkAIClassifier.should_classify(payload, matched_signature=True):
            DarkAIClassifier.classify(
                payload,
                org_id,
                matched_signature_id=signature.id,
                telemetry_event_id=event.id,
                db=db,
            )

        AuditService.log(
            db=db,
            organization_id=org_id,
            user_id=None,
            action="shadow_ai.tier3.signal_ingested",
            entity_type="telemetry_event",
            entity_id=event.id,
            context_json={
                "signal_type": payload.signal_type,
                "matched_tool": payload.matched_tool,
                "connector_version": payload.connector_version,
                "matched_signature": signature.slug,
            },
        )

        db.commit()
        return (event.id, False)

    @staticmethod
    def process_heartbeat(
        payload: ConnectorHeartbeatPayload,
        connector_token: ConnectorToken,
        db: Session,
    ) -> ConnectorHeartbeat:
        """Process a connector heartbeat.

        Deletes previous heartbeat for this token.
        Inserts new ConnectorHeartbeat record.
        Updates connector_token.last_used_at.
        Returns the new heartbeat record.
        """
        db.execute(
            delete(ConnectorHeartbeat).where(
                ConnectorHeartbeat.token_id == connector_token.id
            )
        )

        heartbeat = ConnectorHeartbeat(
            organization_id=connector_token.organization_id,
            token_id=connector_token.id,
            connector_version=payload.connector_version,
            signals_last_hour=payload.signals_last_hour,
            sources_active=json.dumps(payload.sources_active),
            status=payload.status,
        )
        db.add(heartbeat)
        db.flush()

        connector_token.last_used_at = datetime.now(timezone.utc)
        db.commit()
        return heartbeat

    @staticmethod
    def generate_connector_token(
        organization_id: UUID,
        label: str,
        created_by: UUID,
        expires_in_days: int,
        db: Session,
    ) -> tuple[str, ConnectorToken]:
        """Generate a new connector token.

        1. Generate raw token: secrets.token_urlsafe(32)
           This is the ONLY time the raw token exists.
        2. Compute token_hash: SHA256(raw_token)
        3. INSERT connector_tokens
        4. AuditService.log()

        Returns (raw_token, connector_token_record).
        The raw_token is returned to the caller immediately
        and NEVER stored anywhere.
        """
        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        expires_at = datetime.now(timezone.utc) + timedelta(days=expires_in_days)

        token = ConnectorToken(
            organization_id=organization_id,
            token_hash=token_hash,
            label=label,
            expires_at=expires_at,
            created_by=created_by,
            is_active=True,
            signals_total=0,
            requests_this_hour=0,
        )
        db.add(token)
        db.flush()

        AuditService.log(
            db=db,
            organization_id=organization_id,
            user_id=created_by,
            action="shadow_ai.connector_token.created",
            entity_type="connector_token",
            entity_id=token.id,
            context_json={
                "label": label,
                "expires_at": str(expires_at),
                "expires_in_days": expires_in_days,
            },
        )

        db.commit()
        return (raw_token, token)

    @staticmethod
    def revoke_token(
        token_id: UUID,
        organization_id: UUID,
        revoked_by: UUID,
        db: Session,
    ) -> ConnectorToken:
        """Revoke a connector token.

        Sets revoked_at = now() and is_active = False.
        Subsequent ingest calls with this token will receive HTTP 401.
        """
        token = db.execute(
            select(ConnectorToken).where(
                ConnectorToken.id == token_id,
                ConnectorToken.organization_id == organization_id,
            )
        ).scalar_one_or_none()

        if token is None:
            from fastapi import HTTPException

            raise HTTPException(status_code=404, detail="Connector token not found")

        now = datetime.now(timezone.utc)
        token.revoked_at = now
        token.is_active = False

        AuditService.log(
            db=db,
            organization_id=organization_id,
            user_id=revoked_by,
            action="shadow_ai.connector_token.revoked",
            entity_type="connector_token",
            entity_id=token.id,
            context_json={"label": token.label},
        )

        db.commit()
        return token

    @staticmethod
    def list_tokens(
        organization_id: UUID,
        db: Session,
    ) -> list[ConnectorToken]:
        """List all connector tokens for the org.

        Includes revoked and expired tokens.
        token_hash is never included in API responses (the schema omits it).
        """
        return list(
            db.execute(
                select(ConnectorToken).where(
                    ConnectorToken.organization_id == organization_id
                ).order_by(ConnectorToken.created_at.desc())
            ).scalars().all()
        )

    @staticmethod
    def get_connector_status(
        organization_id: UUID,
        db: Session,
    ) -> dict:
        """Return aggregated connector status for the org's dashboard."""
        now = datetime.now(timezone.utc)

        tokens = db.execute(
            select(ConnectorToken).where(
                ConnectorToken.organization_id == organization_id
            )
        ).scalars().all()

        total_tokens = len(tokens)
        active_tokens = sum(
            1 for t in tokens
            if t.is_active
            and t.revoked_at is None
            and (
                t.expires_at.replace(tzinfo=timezone.utc)
                if t.expires_at.tzinfo is None
                else t.expires_at
            ) > now
        )

        heartbeats = db.execute(
            select(ConnectorHeartbeat).where(
                ConnectorHeartbeat.organization_id == organization_id
            )
        ).scalars().all()

        two_hours_ago = now - timedelta(hours=2)
        twenty_four_hours_ago = now - timedelta(hours=24)

        def _hb_time(hb: ConnectorHeartbeat) -> datetime:
            reported = hb.reported_at
            if reported.tzinfo is None:
                return reported.replace(tzinfo=timezone.utc)
            return reported

        connectors_online = sum(
            1 for hb in heartbeats if _hb_time(hb) >= two_hours_ago
        )
        connectors_stale = sum(
            1 for hb in heartbeats
            if two_hours_ago > _hb_time(hb) >= twenty_four_hours_ago
        )
        connectors_offline = sum(
            1 for hb in heartbeats if _hb_time(hb) < twenty_four_hours_ago
        )

        active_token_ids = {
            str(t.id) for t in tokens if t.is_active and t.revoked_at is None
        }
        tokens_without_hb = len(active_token_ids) - (
            connectors_online + connectors_stale
        )
        if tokens_without_hb < 0:
            tokens_without_hb = 0
        connectors_offline += tokens_without_hb

        total_signals_received = sum(t.signals_total or 0 for t in tokens)

        last_signal_times = [
            t.last_ingest_at for t in tokens if t.last_ingest_at is not None
        ]
        last_signal_at = max(last_signal_times) if last_signal_times else None

        return {
            "active_tokens": active_tokens,
            "total_tokens": total_tokens,
            "connectors_online": connectors_online,
            "connectors_stale": connectors_stale,
            "connectors_offline": connectors_offline,
            "total_signals_received": total_signals_received,
            "last_signal_at": last_signal_at,
        }
