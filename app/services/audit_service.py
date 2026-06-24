"""
PATENT NOTICE
Module: services/audit_service
Part of: Shadow AI Discovery Engine
Patent: System and Method for Inferring Undeclared
Artificial Intelligence Systems and Generating AI
Governance Artifacts from Enterprise Telemetry
Status: Provisional filing in preparation
"""

import json
from uuid import UUID

from sqlalchemy.orm import Session

from app.core.logging_config import get_logger
from app.models.detection import AuditLog

logger = get_logger(__name__)


class AuditService:
    """Static methods for writing audit log entries.

    Integration seam 3: own table now, import AuditService later.
    At integration time, import and call CompliVibe's AuditService.log()
    with the identical signature. This file becomes a one-line import swap.
    """

    @staticmethod
    def log(
        db: Session,
        organization_id: UUID,
        user_id: UUID | None,
        action: str,
        entity_type: str,
        entity_id: UUID,
        context_json: dict,
    ) -> None:
        """Write an audit log entry.

        Action must follow convention: "shadow_ai.{entity}.{verb}"
        On DB error: logs ERROR but does not raise.
        Audit failures must never break the main flow.
        """
        try:
            entry = AuditLog(
                organization_id=organization_id,
                user_id=user_id,
                action=action,
                entity_type=entity_type,
                entity_id=entity_id,
                context_json=json.dumps(context_json),
            )
            db.add(entry)
            db.commit()
        except Exception as exc:
            db.rollback()
            logger.error(
                "Audit log write failed",
                extra={
                    "action": action,
                    "entity_type": entity_type,
                    "entity_id": str(entity_id),
                    "organization_id": str(organization_id),
                    "error": str(exc),
                },
            )
