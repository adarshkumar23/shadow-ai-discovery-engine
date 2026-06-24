"""
Auth middleware and dependency functions.

Integration seam 2 (organization ID) and seam 6 (permissions).
"""

from collections.abc import Callable
from uuid import UUID

from fastapi import Header, HTTPException

from app.core.logging_config import get_logger

logger = get_logger(__name__)


def get_organization_id(
    x_organization_id: str = Header(...),
) -> UUID:
    """Validate and return the organization ID from request header.

    At integration time, this maps to CompliVibe's get_current_org()
    dependency. No change to function signature.
    """
    try:
        return UUID(x_organization_id)
    except (ValueError, AttributeError):
        raise HTTPException(
            status_code=400,
            detail="X-Organization-ID must be a valid UUID",
        )


def get_current_user(
    x_user_id: str = Header(...),
) -> UUID:
    """Validate and return the user ID from request header.

    At integration time, replace with JWT-based get_current_user()
    from CompliVibe auth module.
    """
    try:
        return UUID(x_user_id)
    except (ValueError, AttributeError):
        raise HTTPException(
            status_code=400,
            detail="X-User-ID must be a valid UUID",
        )


def require_permission(permission_code: str) -> Callable:
    """Return a dependency that checks the given permission code.

    During standalone operation: always passes (returns None).
    Logs the permission code being checked at DEBUG.

    At integration time, swap body with:
    return require_permission(permission_code)
    from CompliVibe permission system.
    """

    def _check() -> None:
        logger.debug("Checking permission", extra={"permission_code": permission_code})
        return None

    return _check
