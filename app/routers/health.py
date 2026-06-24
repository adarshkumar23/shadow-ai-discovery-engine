"""
Health check endpoints — no auth, no capability flag.

GET /health/live  — Kubernetes liveness probe
GET /health/ready — Kubernetes readiness probe
GET /shadow-ai/status — Production Shadow AI system status
"""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request, Response, status
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.orm import Session
from fastapi.routing import APIRoute

from app.core.config import settings
from app.core.database import Base, get_db
from app.core.logging_config import get_logger
from app.registry.signature_registry import TOTAL_SIGNATURES
from app.schemas.common import HealthResponse

logger = get_logger(__name__)

router = APIRouter()


@router.get("/health/live")
def liveness():
    """Liveness probe — returns 200 if process is running."""
    return {"status": "ok"}


@router.get("/health/ready", response_model=HealthResponse)
def readiness(db: Session = Depends(get_db)):
    """Readiness probe — checks all dependencies before returning 200."""
    checks: dict[str, str] = {}
    all_ok = True

    # 1. DB connection
    try:
        db.execute(text("SELECT 1"))
        checks["database"] = "ok"
        logger.debug("Readiness check passed", extra={"check": "database", "result": "ok"})
    except Exception as exc:
        checks["database"] = f"failed: {exc}"
        all_ok = False
        logger.debug(
            "Readiness check failed",
            extra={"check": "database", "result": "failed", "error": str(exc)},
        )

    # 2. Fernet key
    if settings.shadow_ai_fernet_key:
        checks["fernet_key"] = "ok"
        logger.debug("Readiness check passed", extra={"check": "fernet_key", "result": "ok"})
    else:
        checks["fernet_key"] = "failed: SHADOW_AI_FERNET_KEY not set"
        all_ok = False
        logger.debug(
            "Readiness check failed",
            extra={"check": "fernet_key", "result": "failed"},
        )

    # 3. Capability flag
    if settings.shadow_ai_enabled:
        checks["capability_flag"] = "ok"
        logger.debug(
            "Readiness check passed", extra={"check": "capability_flag", "result": "ok"}
        )
    else:
        checks["capability_flag"] = "failed: SHADOW_AI_ENABLED is false"
        all_ok = False
        logger.debug(
            "Readiness check failed",
            extra={"check": "capability_flag", "result": "failed"},
        )

    response = HealthResponse(
        status="ok" if all_ok else "degraded",
        version=settings.app_version,
        environment=settings.app_env,
        checks=checks,
        timestamp=datetime.now(timezone.utc),
    )

    if not all_ok:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content=response.model_dump(mode="json"),
        )

    return response


def _count_api_routes(app) -> int:
    """Recursively count APIRoute endpoints across included routers."""
    count = 0
    for route in app.routes:
        if isinstance(route, APIRoute):
            count += 1
        elif hasattr(route, "original_router"):
            count += _count_api_routes(route.original_router)
        elif hasattr(route, "routes"):
            count += _count_api_routes(route)
    return count


@router.get(
    "/shadow-ai/status",
    summary="Shadow AI System Status",
    description=(
        "Returns comprehensive system status including all implemented "
        "patent claims, active detection methods, and service health. "
        "No authentication required."
    ),
)
def shadow_ai_status(request: Request):
    """Production readiness status for the Shadow AI Discovery Engine."""
    endpoint_count = _count_api_routes(request.app)

    scheduler = getattr(request.app.state, "scheduler", None)
    scheduler_job_count = len(scheduler.get_jobs()) if scheduler is not None else 0

    return {
        "service": "shadow-ai-discovery",
        "version": settings.app_version,
        "patent_claims_implemented": 10,
        "patent_status": "provisional_in_preparation",
        "patent_title": (
            "System and Method for Inferring Undeclared Artificial "
            "Intelligence Systems and Generating AI Governance Artifacts "
            "from Enterprise Telemetry"
        ),
        "build_phases_complete": 10,
        "detection_methods": [
            "questionnaire_text_inference",
            "idp_oauth_analysis",
            "network_signal_analysis",
            "behavioral_zero_day",
            "dark_ai_side_channel",
            "federated_registry",
        ],
        "database_tables": len(Base.metadata.tables),
        "api_endpoints": endpoint_count,
        "registry_tools": TOTAL_SIGNATURES,
        "scheduler_jobs": scheduler_job_count,
        "trust_document_version": "2.0.0",
        "timestamp": datetime.now(timezone.utc),
    }
