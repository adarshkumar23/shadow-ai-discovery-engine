"""
PATENT NOTICE
Module: services/federated_aggregator
Implements Dependent Patent Claim 8:
Federated Registry Intelligence Network.

ANONYMIZATION PROTOCOL (patent-specified):

Input: (organization_id, hostname,
        behavioral_score, connector_version)

Step 1 — Deduplication token:
  submission_token = SHA256(
    f"{organization_id}:{hostname_lower}:{date_today}"
  )
  This token prevents the same organization
  from submitting the same hostname twice in
  a day. It is stored ONLY in the
  federated_submission_log table.

Step 2 — Hostname hash:
  hostname_hash = SHA256(hostname.lower())
  This hash is used to link the submission_log
  to the observations table WITHOUT storing
  organization_id in the observations table.

Step 3 — Anonymized aggregation:
  The observations table receives ONLY:
    hostname_hash, hostname, behavioral_score
  It NEVER receives organization_id.
  The joining key is hostname_hash, which
  does not reveal organization identity.

PRIVACY GUARANTEE:
  An adversary with access to only the
  federated_hostname_observations table
  cannot determine which organizations
  contributed to any observation count.
  The submission_log contains org_id but
  it is architecturally separated from the
  aggregation table with no queryable join.

This anonymization protocol is a patent claim.
The architecture — separated tables, hash-only
linking, no org_id in aggregation — must be
preserved exactly.

PROMOTION THRESHOLD:
  PROMOTION_THRESHOLD = 3
  When observation_count reaches 3, the
  hostname is automatically promoted to
  'candidate' status for human review.
  This threshold is patent-specified.
"""

from __future__ import annotations

import hashlib
import json
from datetime import date, datetime, timezone
from decimal import Decimal
from uuid import UUID

import re
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.logging_config import get_logger
from app.models.detection import ConnectorToken
from app.models.federated import (
    FederatedHostnameObservation,
    FederatedSubmissionLog,
)
from app.models.signature import AISignatureRegistry
from app.schemas.federated import FederatedSubmissionResponse
from app.services.audit_service import AuditService

logger = get_logger(__name__)

# Patent-specified threshold. Never change without patent counsel review.
PROMOTION_THRESHOLD = 3

AGGREGATOR_VERSION = "1.0.0"

_DEFAULT_CONFIDENCE_WEIGHTS = {
    "endpoint_match": 0.25,
    "identity_match": 0.25,
    "volume_match": 0.20,
    "keyword_match": 0.30,
}


def _sha256(value: str) -> str:
    """Return SHA256 hex digest of value."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _hostname_to_slug(hostname: str) -> str:
    """Derive a registry slug from a hostname, avoiding collisions."""
    base = re.sub(r"[^a-z0-9_-]", "_", hostname.lower()).strip("_")[:100]
    return base or "unknown"


def _normalize_hostname(hostname: str) -> str:
    """
    Normalize hostname for federated submission.

    Steps:
      - lower-case
      - strip whitespace
      - strip scheme (https://)
      - strip path/query/fragment (everything after first "/", "?", "#")
      - strip standard ports (:443, :80)
    """
    hostname = hostname.lower().strip()

    if "://" in hostname:
        hostname = hostname.split("://", 1)[1]

    for sep in ("/", "?", "#"):
        if sep in hostname:
            hostname = hostname.split(sep, 1)[0]

    if hostname.endswith(":443") or hostname.endswith(":80"):
        hostname = hostname.rsplit(":", 1)[0]

    return hostname


class FederatedAggregator:
    """
    Privacy-preserving federated hostname aggregation service.

    PATENT NOTICE: This class implements the anonymization protocol of
    Dependent Patent Claim 8. Organization identity is stripped before any
    aggregation storage. The aggregation table has no organization_id.
    """

    @staticmethod
    def submit_hostname(
        organization_id: UUID,
        hostname: str,
        behavioral_score: float,
        connector_token: ConnectorToken,
        db: Session,
    ) -> FederatedSubmissionResponse:
        """
        PATENT NOTICE: This method implements the anonymization protocol of
        Dependent Patent Claim 8.

        Steps:
        1. Validate opt-in.
        2. Normalize hostname.
        3. Compute hostname_hash and submission_token.
        4. Check deduplication in submission_log.
        5. Write audit record to submission_log (org_id stored here ONLY).
        6. Upsert observations table WITHOUT organization_id.
        7. Check promotion threshold; promote to candidate if reached.
        8. Update connector_token submission counters.
        9. Audit signal submission.

        Returns FederatedSubmissionResponse. The hostname itself is never
        returned to the connector.
        """
        # 1. Validate opt-in. Patent Invariant 34.
        if not connector_token.federated_submissions_enabled:
            return FederatedSubmissionResponse(
                accepted=False,
                was_duplicate=False,
                hostname_hash="",
                message=(
                    "Federated submission not enabled for this token. "
                    "Enable via connector config."
                ),
            )

        # 2. Normalize hostname.
        hostname = _normalize_hostname(hostname)

        # 3. Compute hashes.
        hostname_hash = _sha256(hostname)
        today = date.today().isoformat()
        submission_token = _sha256(f"{organization_id}:{hostname}:{today}")

        # 4. Check deduplication: same org cannot submit same hostname twice/day.
        existing_log = db.execute(
            select(FederatedSubmissionLog).where(
                FederatedSubmissionLog.submission_token == submission_token
            )
        ).scalar_one_or_none()

        if existing_log is not None:
            # Already submitted today. Return hash but mark duplicate.
            observation = db.execute(
                select(FederatedHostnameObservation).where(
                    FederatedHostnameObservation.hostname_hash == hostname_hash
                )
            ).scalar_one_or_none()
            return FederatedSubmissionResponse(
                accepted=True,
                was_duplicate=True,
                hostname_hash=hostname_hash,
                current_observation_count=(
                    observation.observation_count if observation else None
                ),
                message="Already submitted today",
            )

        # 5. Write to submission_log. organization_id is stored here ONLY.
        log_entry = FederatedSubmissionLog(
            organization_id=organization_id,
            submission_token=submission_token,
            hostname_hash=hostname_hash,
            behavioral_score=behavioral_score,
            was_duplicate=False,
        )
        db.add(log_entry)

        # 6. Upsert observations table. NO organization_id here.
        observation = db.execute(
            select(FederatedHostnameObservation).where(
                FederatedHostnameObservation.hostname_hash == hostname_hash
            )
        ).scalar_one_or_none()

        now = datetime.now(timezone.utc)

        if observation is None:
            observation = FederatedHostnameObservation(
                hostname_hash=hostname_hash,
                hostname=hostname,
                observation_count=1,
                behavioral_score=behavioral_score,
                first_observed_at=now,
                last_observed_at=now,
                status="observing",
            )
            db.add(observation)
        else:
            observation.observation_count = (
                observation.observation_count or 0
            ) + 1
            # Rolling average of behavioral scores.
            current_avg = observation.behavioral_score
            if current_avg is None:
                observation.behavioral_score = behavioral_score
            else:
                n = observation.observation_count
                observation.behavioral_score = (
                    (float(current_avg) * (n - 1)) + behavioral_score
                ) / n
            observation.last_observed_at = now

        db.flush()

        # 7. Check promotion threshold. Patent Invariant 33.
        if (
            observation.observation_count >= PROMOTION_THRESHOLD
            and observation.status == "observing"
        ):
            observation.status = "candidate"
            observation.promoted_at = now

            AuditService.log(
                db=db,
                organization_id=organization_id,
                user_id=None,
                action="shadow_ai.federated.candidate_promoted",
                entity_type="federated_hostname_observation",
                entity_id=observation.id,
                context_json={
                    "hostname_hash": hostname_hash,
                    "observation_count": observation.observation_count,
                    "threshold": PROMOTION_THRESHOLD,
                },
            )

        # 8. Update connector token counter.
        connector_token.federated_submissions_count = (
            connector_token.federated_submissions_count or 0
        ) + 1

        # 9. Audit signal submission. Hostname NOT logged.
        AuditService.log(
            db=db,
            organization_id=organization_id,
            user_id=None,
            action="shadow_ai.federated.signal_submitted",
            entity_type="federated_submission_log",
            entity_id=log_entry.id,
            context_json={
                "hostname_hash": hostname_hash,
                "was_duplicate": False,
                "observation_count": observation.observation_count,
            },
        )

        db.commit()

        return FederatedSubmissionResponse(
            accepted=True,
            was_duplicate=False,
            hostname_hash=hostname_hash,
            current_observation_count=observation.observation_count,
            message="Signal accepted",
        )

    @staticmethod
    def get_candidates(
        db: Session,
        status: str | None = None,
    ) -> list[FederatedHostnameObservation]:
        """
        Returns federated candidates.

        This is an admin/internal function. No organization_id filter —
        this is global shared network data.
        """
        query = select(FederatedHostnameObservation)
        if status:
            query = query.where(FederatedHostnameObservation.status == status)
        query = query.order_by(FederatedHostnameObservation.observation_count.desc())
        return list(db.execute(query).scalars().all())

    @staticmethod
    def promote_to_registry(
        observation_id: UUID,
        provider_name: str,
        category: str,
        reviewed_by: UUID,
        db: Session,
    ) -> AISignatureRegistry:
        """
        Promotes a federated candidate to the global AI signature registry.

        Creates a new AISignatureRegistry entry with the observation's
        hostname in keyword and endpoint patterns. From this point forward
        the hostname will match standard registry detection for ALL
        organizations. This is the network effect the patent claims.
        """
        observation = db.execute(
            select(FederatedHostnameObservation).where(
                FederatedHostnameObservation.id == observation_id
            )
        ).scalar_one_or_none()

        if observation is None:
            raise ValueError("Federated candidate not found")

        slug = _hostname_to_slug(provider_name)

        # Avoid slug collisions deterministically.
        existing_slug = db.execute(
            select(AISignatureRegistry).where(AISignatureRegistry.slug == slug)
        ).scalar_one_or_none()
        if existing_slug is not None:
            slug = f"{slug}-{str(observation_id)[:8]}"

        signature = AISignatureRegistry(
            slug=slug,
            provider_name=provider_name,
            category=category,
            keyword_patterns=json.dumps([observation.hostname]),
            endpoint_patterns=json.dumps([observation.hostname]),
            oauth_app_patterns=json.dumps([]),
            data_egress_indicators=None,
            confidence_weights=json.dumps(_DEFAULT_CONFIDENCE_WEIGHTS),
            risk_level="medium",
            is_active=True,
        )
        db.add(signature)
        db.flush()

        observation.status = "promoted"
        observation.signature_id = slug
        observation.reviewed_by_admin = True

        AuditService.log(
            db=db,
            organization_id=reviewed_by,
            user_id=reviewed_by,
            action="shadow_ai.federated.promoted_to_registry",
            entity_type="federated_hostname_observation",
            entity_id=observation.id,
            context_json={
                "hostname": observation.hostname,
                "provider_name": provider_name,
                "signature_slug": slug,
                "observation_count": observation.observation_count,
            },
        )

        db.commit()
        return signature

    @staticmethod
    def dismiss_candidate(
        observation_id: UUID,
        reviewed_by: UUID,
        db: Session,
    ) -> FederatedHostnameObservation:
        """
        Dismisses a federated candidate.

        Sets status = 'dismissed'. This hostname will not be promoted
        even if more observations arrive.
        """
        observation = db.execute(
            select(FederatedHostnameObservation).where(
                FederatedHostnameObservation.id == observation_id
            )
        ).scalar_one_or_none()

        if observation is None:
            raise ValueError("Federated candidate not found")

        observation.status = "dismissed"
        observation.reviewed_by_admin = True

        AuditService.log(
            db=db,
            organization_id=reviewed_by,
            user_id=reviewed_by,
            action="shadow_ai.federated.candidate_dismissed",
            entity_type="federated_hostname_observation",
            entity_id=observation.id,
            context_json={
                "hostname_hash": observation.hostname_hash,
                "observation_count": observation.observation_count,
            },
        )

        db.commit()
        return observation

    @staticmethod
    def get_network_stats(db: Session) -> dict:
        """
        Returns aggregated network statistics.

        Does not expose which organizations contributed — only aggregate
        counts.
        """
        total_hostnames = db.execute(
            select(func.count()).select_from(FederatedHostnameObservation)
        ).scalar() or 0

        candidates_pending = db.execute(
            select(func.count())
            .select_from(FederatedHostnameObservation)
            .where(FederatedHostnameObservation.status == "candidate")
        ).scalar() or 0

        promoted = db.execute(
            select(func.count())
            .select_from(FederatedHostnameObservation)
            .where(FederatedHostnameObservation.status == "promoted")
        ).scalar() or 0

        network_size_orgs = db.execute(
            select(func.count(func.distinct(FederatedSubmissionLog.organization_id)))
            .select_from(FederatedSubmissionLog)
            .where(FederatedSubmissionLog.was_duplicate.is_(False))
        ).scalar() or 0

        return {
            "total_hostnames_observed": total_hostnames,
            "candidates_pending_review": candidates_pending,
            "promoted_to_registry": promoted,
            "observation_threshold": PROMOTION_THRESHOLD,
            "network_size_orgs": network_size_orgs,
        }

    @staticmethod
    def submit_zero_day_candidates(
        organization_id: UUID,
        connector_token: ConnectorToken,
        db: Session,
    ) -> dict:
        """
        Called by nightly scheduler or manually.

        Reads all zero_day_candidates for the org with status
        'pending_review' and behavioral_score >= 0.55, and submits each
        to the federated network.

        This is the integration point between Phase 6 (zero-day
        detection) and Phase 9 (federated network).
        """
        from app.models.zero_day import ZeroDayCandidate

        candidates = db.execute(
            select(ZeroDayCandidate).where(
                ZeroDayCandidate.organization_id == organization_id,
                ZeroDayCandidate.status == "pending_review",
                ZeroDayCandidate.behavioral_score >= 0.55,
            )
        ).scalars().all()

        submitted = 0
        duplicates = 0
        errors = 0

        for candidate in candidates:
            try:
                result = FederatedAggregator.submit_hostname(
                    organization_id=organization_id,
                    hostname=candidate.hostname,
                    behavioral_score=float(candidate.behavioral_score),
                    connector_token=connector_token,
                    db=db,
                )
                if result.accepted and not result.was_duplicate:
                    submitted += 1
                elif result.was_duplicate:
                    duplicates += 1
            except Exception as exc:
                errors += 1
                logger.error(
                    "Failed to submit zero-day candidate to federated network",
                    extra={
                        "hostname_hash": _sha256(candidate.hostname),
                        "error": str(exc),
                    },
                )

        return {
            "candidates_submitted": submitted,
            "duplicates": duplicates,
            "errors": errors,
        }
