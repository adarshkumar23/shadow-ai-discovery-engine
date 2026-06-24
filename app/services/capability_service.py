"""
Capability flag service.

Integration seam 4: env var check now, DB query later.
"""

from fastapi import HTTPException

from app.core.config import settings


def require_shadow_ai_enabled() -> None:
    """Check if the Shadow AI capability is enabled.

    If False: raises HTTPException(404, detail={"error": "not_found"}).
    Note: 404 not 403 — do not reveal feature existence if not enabled.

    At integration time, replace env var check with DB query against
    CompliVibe innovation_capabilities table for capability slug
    'shadow_ai_discovery'.
    """
    if not settings.shadow_ai_enabled:
        raise HTTPException(
            status_code=404,
            detail={"error": "not_found"},
        )
