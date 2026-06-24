"""
PATENT NOTICE
Module: services/suppression_service
Part of: Shadow AI Discovery Engine
Patent: System and Method for Inferring Undeclared
Artificial Intelligence Systems and Generating AI
Governance Artifacts from Enterprise Telemetry
Status: Provisional filing in preparation

PATENT INVARIANT 9: Dismissed detections must NEVER be hard
deleted. deleted_at must remain NULL on dismissed records.
dismissed_at is set. The record is retained permanently for
audit trail purposes.

PATENT INVARIANT 10: The suppression table prevents re-detection
of dismissed tools via the same method. Once dismissed, that
tool + method combination is suppressed for that org permanently
unless explicitly lifted.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.logging_config import get_logger
from app.models.suppression import SuppressedDetection
from app.services.audit_service import AuditService

logger = get_logger(__name__)

_NIL_UUID = UUID("00000000-0000-0000-0000-000000000000")


class SuppressionService:
    """Static methods for detection suppression management.

    PATENT INVARIANT 10: Once a detection is dismissed, the
    tool + method combination is suppressed for that org.
    The Tier1Scanner calls is_suppressed() before creating
    any new telemetry event to enforce this invariant.
    """

    @staticmethod
    def is_suppressed(
        organization_id: UUID,
        tool_slug: str,
        detection_method: str,
        db: Session,
    ) -> bool:
        """Returns True if this tool + method combination
        is actively suppressed for this org.
        Called by Tier1Scanner before creating any
        new telemetry event.
        """
        result = db.execute(
            select(SuppressedDetection).where(
                SuppressedDetection.organization_id == organization_id,
                SuppressedDetection.tool_slug == tool_slug,
                SuppressedDetection.detection_method == detection_method,
                SuppressedDetection.lifted_at.is_(None),
            )
        ).scalar_one_or_none()
        return result is not None

    @staticmethod
    def create_suppression(
        organization_id: UUID,
        tool_slug: str,
        detection_method: str,
        suppressed_by: UUID,
        reason: str,
        source_detection_id: UUID,
        db: Session,
    ) -> SuppressedDetection:
        """Called when a detection is dismissed.
        Creates suppression record.
        If an active suppression already exists for this
        tool+method+org, returns the existing record instead
        of creating a duplicate (patent invariant 10).
        """
        existing = db.execute(
            select(SuppressedDetection).where(
                SuppressedDetection.organization_id == organization_id,
                SuppressedDetection.tool_slug == tool_slug,
                SuppressedDetection.detection_method == detection_method,
                SuppressedDetection.lifted_at.is_(None),
            )
        ).scalar_one_or_none()

        if existing is not None:
            return existing

        suppression = SuppressedDetection(
            organization_id=organization_id,
            tool_slug=tool_slug,
            detection_method=detection_method,
            suppressed_by=suppressed_by,
            reason=reason,
            source_detection_id=source_detection_id,
        )
        db.add(suppression)
        db.flush()

        AuditService.log(
            db=db,
            organization_id=organization_id,
            user_id=suppressed_by,
            action="shadow_ai.suppression.created",
            entity_type="suppressed_detection",
            entity_id=suppression.id,
            context_json={
                "tool_slug": tool_slug,
                "detection_method": detection_method,
                "source_detection_id": str(source_detection_id),
            },
        )

        return suppression

    @staticmethod
    def lift_suppression(
        organization_id: UUID,
        tool_slug: str,
        detection_method: str,
        lifted_by: UUID,
        db: Session,
    ) -> bool:
        """Re-enables detection for this tool+method.
        Sets lifted_at = now(), lifted_by = user_id.
        Returns True if suppression was found and lifted.
        """
        suppression = db.execute(
            select(SuppressedDetection).where(
                SuppressedDetection.organization_id == organization_id,
                SuppressedDetection.tool_slug == tool_slug,
                SuppressedDetection.detection_method == detection_method,
                SuppressedDetection.lifted_at.is_(None),
            )
        ).scalar_one_or_none()

        if suppression is None:
            return False

        suppression.lifted_at = datetime.now(timezone.utc)
        suppression.lifted_by = lifted_by

        AuditService.log(
            db=db,
            organization_id=organization_id,
            user_id=lifted_by,
            action="shadow_ai.suppression.lifted",
            entity_type="suppressed_detection",
            entity_id=suppression.id,
            context_json={
                "tool_slug": tool_slug,
                "detection_method": detection_method,
            },
        )

        return True

    @staticmethod
    def list_suppressions(
        organization_id: UUID,
        db: Session,
    ) -> list[SuppressedDetection]:
        """Returns all active suppressions for the org.
        Used by the suppressions management endpoint.
        """
        return list(
            db.execute(
                select(SuppressedDetection).where(
                    SuppressedDetection.organization_id == organization_id,
                    SuppressedDetection.lifted_at.is_(None),
                ).order_by(SuppressedDetection.created_at.desc())
            ).scalars().all()
        )
