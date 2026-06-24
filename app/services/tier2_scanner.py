"""
PATENT NOTICE
Module: services/tier2_scanner
Implements Tier 2 of Core Patent Claim 1.

Detection method: Identity Provider OAuth
log analysis via read-only token integration.

What this scanner reads:
  OAuth app names, app IDs, granted scopes,
  event timestamps from IdP audit logs.

What this scanner NEVER does:
  - Reads directory contents
  - Reads user passwords or credentials
  - Requests write scopes
  - Stores raw IdP API responses
  - Logs access tokens or refresh tokens
  - Stores raw actor email addresses
    (actor_ids are SHA256 hashes only)

PATENT INVARIANT 11: IdP credentials MUST be encrypted with
Fernet before any DB write. Plaintext credentials must NEVER
appear in any log, response body, or database column.
decrypt_value() from app/core/security.py is the only
decryption path.

PATENT INVARIANT 13: Only OAuthEvent fields are extracted from
IdP responses. All other fields are discarded immediately.

PATENT INVARIANT 14: Attribution is advisory only.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.logging_config import get_logger
from app.core.security import encrypt_value
from app.models.idp import IdpConnection, IdpSyncLog
from app.models.telemetry import TelemetryEvent
from app.services.attribution_engine import AttributionEngine
from app.services.audit_service import AuditService
from app.services.confidence_engine import ConfidenceEngine
from app.services.detection_service import DetectionService
from app.services.idp_connectors.azure_ad import AzureADConnector
from app.services.idp_connectors.base import BaseIdpConnector, OAuthEvent
from app.services.idp_connectors.google_ws import GoogleWSConnector
from app.services.idp_connectors.okta import OktaConnector
from app.services.registry_service import RegistryService

logger = get_logger(__name__)

_NIL_UUID = UUID("00000000-0000-0000-0000-000000000000")


class Tier2Scanner:
    """Tier 2 IdP OAuth log analysis scanner."""

    CONNECTOR_MAP: dict[str, type[BaseIdpConnector]] = {
        "okta": OktaConnector,
        "azure_ad": AzureADConnector,
        "google_ws": GoogleWSConnector,
    }

    @staticmethod
    def get_connector(
        connection: IdpConnection,
        settings,
    ) -> BaseIdpConnector:
        """Factory method returning the correct connector subclass.

        Raises ValueError for unknown provider.
        """
        connector_cls = Tier2Scanner.CONNECTOR_MAP.get(connection.idp_provider)
        if connector_cls is None:
            raise ValueError(
                f"Unknown IdP provider: {connection.idp_provider}"
            )
        return connector_cls(connection, settings)

    @staticmethod
    def sync_connection(
        connection_id: UUID,
        organization_id: UUID,
        triggered_by: UUID | None,
        db: Session,
    ) -> IdpSyncLog:
        """Full sync cycle for one IdP connection.

        Steps:
        1. Load IdpConnection, validate org
        2. Create IdpSyncLog (status='running')
        3. Compute sync window
        4. Get connector
        5. Fetch OAuth events
        6. Match against signatures
        7. Create telemetry events
        8. Run detection
        9. Run attribution
        10. Update connection
        11. Update sync_log
        12. Audit log

        Returns completed IdpSyncLog.
        """
        from app.core.config import settings

        # Step 1: Load connection, validate org
        connection = db.execute(
            select(IdpConnection).where(
                IdpConnection.id == connection_id,
                IdpConnection.deleted_at.is_(None),
            )
        ).scalar_one_or_none()

        if connection is None:
            raise ValueError("IdP connection not found")
        if connection.organization_id != organization_id:
            raise ValueError("IdP connection does not belong to this organization")

        # Step 2: Create sync log
        sync_log = IdpSyncLog(
            organization_id=organization_id,
            connection_id=connection_id,
            idp_provider=connection.idp_provider,
            status="running",
            triggered_by=triggered_by,
            started_at=datetime.now(timezone.utc),
        )
        db.add(sync_log)
        db.flush()

        # Step 3: Compute sync window
        now = datetime.now(timezone.utc)
        sync_window_hours = connection.sync_window_hours or 24
        since = connection.last_synced_at or (now - timedelta(hours=sync_window_hours))
        until = now

        sync_log.sync_from = since
        sync_log.sync_to = until

        # Step 4: Get connector
        try:
            connector = Tier2Scanner.get_connector(connection, settings)
        except ValueError as e:
            sync_log.status = "failed"
            sync_log.error_message = str(e)
            sync_log.completed_at = now
            connection.sync_status = "error"
            connection.sync_error = str(e)
            db.commit()
            AuditService.log(
                db=db,
                organization_id=organization_id,
                user_id=triggered_by,
                action="shadow_ai.idp.sync_failed",
                entity_type="idp_sync_log",
                entity_id=sync_log.id,
                context_json={"error": str(e)},
            )
            return sync_log

        # Step 5: Fetch OAuth events
        try:
            events = connector.fetch_oauth_events(since=since, until=until)
        except (ConnectionError, PermissionError) as e:
            error_msg = str(e)
            sync_log.status = "failed"
            sync_log.error_message = error_msg
            sync_log.completed_at = datetime.now(timezone.utc)
            connection.sync_status = "error"
            connection.sync_error = error_msg
            db.commit()
            AuditService.log(
                db=db,
                organization_id=organization_id,
                user_id=triggered_by,
                action="shadow_ai.idp.sync_failed",
                entity_type="idp_sync_log",
                entity_id=sync_log.id,
                context_json={
                    "provider": connection.idp_provider,
                    "error": error_msg,
                },
            )
            return sync_log

        # Step 6: Match events against signatures
        signatures = RegistryService.get_merged_registry(organization_id, db)

        events_fetched = len(events)
        events_matched = 0
        signals_created = 0
        signals_duplicate = 0

        source_label = f"idp:{connection.idp_provider}"

        for event in events:
            matched_sig = Tier2Scanner._match_event_to_signature(
                event, signatures
            )
            if matched_sig is None:
                continue

            events_matched += 1

            signal_hash = ConfidenceEngine.compute_signal_hash(
                organization_id=organization_id,
                signature_id=matched_sig.id,
                source_system_label=source_label,
                event_date=event.event_time.date(),
            )

            existing = db.execute(
                select(TelemetryEvent).where(
                    TelemetryEvent.organization_id == organization_id,
                    TelemetryEvent.signal_hash == signal_hash,
                )
            ).scalar_one_or_none()

            if existing is not None:
                signals_duplicate += 1
                continue

            raw_signal = {
                "idp_provider": connection.idp_provider,
                "app_name": event.app_name,
                "app_id": event.app_id,
                "oauth_scopes": event.oauth_scopes,
                "event_type": event.event_type,
                "actor_id": event.actor_id,
            }

            telemetry = TelemetryEvent(
                organization_id=organization_id,
                tier=2,
                event_type="identity_match",
                source_system_label=source_label,
                matched_signature_id=matched_sig.id,
                raw_signal_json=json.dumps(raw_signal),
                signal_hash=signal_hash,
                observed_at=event.event_time,
            )
            db.add(telemetry)
            signals_created += 1

        if signals_created > 0:
            db.flush()

        # Step 8: Run detection
        detection_result = DetectionService.run_detection(organization_id, db)
        detections_created = detection_result.get("detections_created", 0)
        detections_updated = detection_result.get("detections_updated", 0)

        # Step 9: Run attribution
        AttributionEngine.run_attribution_pass(organization_id, db)

        # Step 10: Update connection
        connection.last_synced_at = now
        connection.sync_status = "active"
        connection.sync_error = None
        connection.total_syncs = (connection.total_syncs or 0) + 1
        connection.total_signals = (connection.total_signals or 0) + signals_created

        # Step 11: Update sync log
        sync_log.status = "completed"
        sync_log.completed_at = datetime.now(timezone.utc)
        sync_log.events_fetched = events_fetched
        sync_log.events_matched = events_matched
        sync_log.signals_created = signals_created
        sync_log.signals_duplicate = signals_duplicate
        sync_log.detections_created = detections_created
        sync_log.detections_updated = detections_updated

        db.commit()

        # Step 12: Audit log
        AuditService.log(
            db=db,
            organization_id=organization_id,
            user_id=triggered_by,
            action="shadow_ai.idp.sync_completed",
            entity_type="idp_sync_log",
            entity_id=sync_log.id,
            context_json={
                "provider": connection.idp_provider,
                "events_fetched": events_fetched,
                "signals_created": signals_created,
                "detections_created": detections_created,
            },
        )

        return sync_log

    @staticmethod
    def _match_event_to_signature(
        event: OAuthEvent,
        signatures: list,
    ):
        """Match an OAuthEvent against all active signatures.

        Uses case-insensitive substring match of event.app_name
        against signature.oauth_app_patterns.

        Returns the first matching signature, or None.
        """
        if not event.app_name:
            return None
        app_name_lower = event.app_name.lower()
        for sig in signatures:
            try:
                patterns = json.loads(sig.oauth_app_patterns) if sig.oauth_app_patterns else []
            except (json.JSONDecodeError, TypeError):
                continue
            for pattern in patterns:
                if pattern and pattern.lower() in app_name_lower:
                    return sig
        return None

    @staticmethod
    def initiate_oauth_flow(
        organization_id: UUID,
        idp_provider: str,
        idp_domain: str | None,
        redirect_uri: str,
        connected_by_user_id: UUID,
        db: Session,
    ) -> dict:
        """Creates a pending IdpConnection record and returns the OAuth
        authorization URL.

        Returns: {
            "authorization_url": str,
            "connection_id": UUID,
            "provider": str
        }
        """
        from app.core.config import settings

        connection = IdpConnection(
            organization_id=organization_id,
            idp_provider=idp_provider,
            idp_domain=idp_domain,
            access_token_enc=encrypt_value("pending"),
            refresh_token_enc=None,
            sync_status="pending",
            connected_by_user_id=connected_by_user_id,
            sync_window_hours=24,
            total_syncs=0,
            total_signals=0,
        )
        db.add(connection)
        db.commit()

        connector = Tier2Scanner.get_connector(connection, settings)
        state = str(organization_id)
        auth_url = connector.get_authorization_url(
            state=state,
            redirect_uri=redirect_uri,
        )

        return {
            "authorization_url": auth_url,
            "connection_id": connection.id,
            "provider": idp_provider,
        }

    @staticmethod
    def handle_oauth_callback(
        code: str,
        state: str,
        idp_provider: str,
        redirect_uri: str,
        db: Session,
    ) -> IdpConnection:
        """Exchanges authorization code for tokens.

        Encrypts tokens with Fernet. Stores in IdpConnection.
        Triggers immediate sync_connection() call.

        The state parameter contains organization_id.

        Token encryption:
          access_token_enc = encrypt_value(token)
          refresh_token_enc = encrypt_value(refresh) if present

        Never logs token values.
        Returns updated IdpConnection.
        """
        from app.core.config import settings

        organization_id = UUID(state)

        connection = db.execute(
            select(IdpConnection).where(
                IdpConnection.organization_id == organization_id,
                IdpConnection.idp_provider == idp_provider,
                IdpConnection.sync_status == "pending",
                IdpConnection.deleted_at.is_(None),
            )
        ).scalar_one_or_none()

        if connection is None:
            raise ValueError(
                "No pending IdP connection found for this organization and provider"
            )

        connector = Tier2Scanner.get_connector(connection, settings)

        token_data = connector.exchange_code_for_tokens(
            code=code,
            redirect_uri=redirect_uri,
        )

        access_token = token_data["access_token"]
        refresh_token = token_data.get("refresh_token")
        expires_in = token_data.get("expires_in")

        connection.access_token_enc = encrypt_value(access_token)
        if refresh_token:
            connection.refresh_token_enc = encrypt_value(refresh_token)
        if expires_in:
            connection.token_expires_at = datetime.now(
                timezone.utc
            ) + timedelta(seconds=expires_in)

        scopes = token_data.get("scope", "")
        if scopes:
            connection.scopes_granted = scopes

        connection.sync_status = "active"
        db.commit()

        Tier2Scanner.sync_connection(
            connection_id=connection.id,
            organization_id=organization_id,
            triggered_by=connection.connected_by_user_id,
            db=db,
        )

        return connection
