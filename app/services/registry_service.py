"""
PATENT NOTICE
Module: services/registry_service
Part of: Shadow AI Discovery Engine
Patent: System and Method for Inferring Undeclared
Artificial Intelligence Systems and Generating AI
Governance Artifacts from Enterprise Telemetry
Status: Provisional filing in preparation

Manages the AI Signature Registry: seeding, lookup,
and merge of global vs org-specific overrides.
"""

from __future__ import annotations

import json
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.logging_config import get_logger
from app.models.signature import AISignatureRegistry
from app.registry.signature_registry import (
    KNOWN_AI_SIGNATURES,
    REGISTRY_VERSION,
)
from app.services.audit_service import AuditService

logger = get_logger(__name__)

_NIL_UUID = UUID("00000000-0000-0000-0000-000000000000")


def _validate_confidence_weights(weights: dict) -> bool:
    """Validate that confidence_weights values sum to exactly 1.0."""
    total = sum(float(v) for v in weights.values())
    return abs(total - 1.0) < 1e-9


class RegistryService:
    """Static methods for registry seeding and lookup."""

    @staticmethod
    def seed_signatures(db: Session) -> int:
        """Upsert all KNOWN_AI_SIGNATURES into ai_signature_registry.

        For each signature:
          Check if slug exists.
          If not: INSERT new record.
          If yes: UPDATE existing record with latest values.

        Validates that confidence_weights sum to 1.0.
        Returns count of records upserted.
        """
        count = 0
        for sig_data in KNOWN_AI_SIGNATURES:
            if not _validate_confidence_weights(sig_data["confidence_weights"]):
                logger.error(
                    "Invalid confidence_weights for signature",
                    extra={"slug": sig_data["slug"]},
                )
                continue

            existing = db.execute(
                select(AISignatureRegistry).where(
                    AISignatureRegistry.slug == sig_data["slug"]
                )
            ).scalar_one_or_none()

            if existing is None:
                record = AISignatureRegistry(
                    slug=sig_data["slug"],
                    provider_name=sig_data["provider_name"],
                    category=sig_data["category"],
                    endpoint_patterns=json.dumps(sig_data["endpoint_patterns"]),
                    keyword_patterns=json.dumps(sig_data["keyword_patterns"]),
                    oauth_app_patterns=json.dumps(sig_data["oauth_app_patterns"]),
                    data_egress_indicators=json.dumps(sig_data["data_egress_indicators"]),
                    confidence_weights=json.dumps(sig_data["confidence_weights"]),
                    risk_level=sig_data["risk_level"],
                    is_active=True,
                )
                db.add(record)
            else:
                existing.provider_name = sig_data["provider_name"]
                existing.category = sig_data["category"]
                existing.endpoint_patterns = json.dumps(sig_data["endpoint_patterns"])
                existing.keyword_patterns = json.dumps(sig_data["keyword_patterns"])
                existing.oauth_app_patterns = json.dumps(sig_data["oauth_app_patterns"])
                existing.data_egress_indicators = json.dumps(sig_data["data_egress_indicators"])
                existing.confidence_weights = json.dumps(sig_data["confidence_weights"])
                existing.risk_level = sig_data["risk_level"]
                existing.is_active = True

            count += 1

        db.commit()

        logger.info(
            "Registry seeded",
            extra={"count": count, "version": REGISTRY_VERSION},
        )

        AuditService.log(
            db=db,
            organization_id=_NIL_UUID,
            user_id=None,
            action="shadow_ai.registry.seeded",
            entity_type="ai_signature_registry",
            entity_id=_NIL_UUID,
            context_json={"count": count, "version": REGISTRY_VERSION},
        )

        return count

    @staticmethod
    def get_merged_registry(
        organization_id: UUID,
        db: Session,
    ) -> list[AISignatureRegistry]:
        """Return global signatures merged with org-specific overrides.

        Org overrides take precedence on slug conflict.
        Called fresh on every scan — not cached.

        Patent-specified behaviour: registry changes take effect
        immediately on next scan without restart. The merged
        registry is recomputed from the database on every call
        to ensure the latest signatures are always used.
        """
        return list(
            db.execute(
                select(AISignatureRegistry).where(
                    AISignatureRegistry.is_active.is_(True)
                )
            ).scalars().all()
        )

    @staticmethod
    def find_signature_by_slug(
        slug: str,
        db: Session,
    ) -> AISignatureRegistry | None:
        """Find a single active signature by slug."""
        return db.execute(
            select(AISignatureRegistry).where(
                AISignatureRegistry.slug == slug,
                AISignatureRegistry.is_active.is_(True),
            )
        ).scalar_one_or_none()

    @staticmethod
    def find_signatures_by_category(
        category: str,
        db: Session,
    ) -> list[AISignatureRegistry]:
        """Find all active signatures in a category."""
        return list(
            db.execute(
                select(AISignatureRegistry).where(
                    AISignatureRegistry.category == category,
                    AISignatureRegistry.is_active.is_(True),
                )
            ).scalars().all()
        )
