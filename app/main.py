"""
Shadow AI Discovery Engine — FastAPI application entry point.

Integration seam 7: own main.py now, one include_router() later.
"""

import time
import traceback
from contextlib import asynccontextmanager
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from urllib.parse import urlparse

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from sqlalchemy import text

from app.core.config import settings
from app.core.database import SessionLocal
from app.core.logging_config import get_logger, request_id_var
from app.routers.health import router as health_router
from app.routers.detections import router as detections_router
from app.routers.scans import router as scans_router
from app.routers.registry import router as registry_router
from app.routers.metrics import router as metrics_router
from app.routers.idp import router as idp_router
from app.routers.connector import router as connector_router
from app.routers.contamination import router as contamination_router
from app.routers.federated import router as federated_router
from app.schemas.common import ErrorResponse

logger = get_logger(__name__)


def nightly_tier1_scan() -> None:
    """Nightly Tier 1 scan for all organizations.

    Runs at 2 AM UTC. Scans questionnaire responses for every
    organization that has responses. An exception in one org's
    scan never stops scans for other orgs.
    """
    logger.info("Nightly Tier 1 scan job started")
    db = SessionLocal()
    try:
        orgs = db.execute(
            text(
                "SELECT DISTINCT organization_id "
                "FROM questionnaire_responses "
                "WHERE deleted_at IS NULL"
            )
        ).fetchall()
        for row in orgs:
            try:
                from app.services.tier1_scanner import Tier1Scanner

                Tier1Scanner.scan_organization(
                    organization_id=row[0],
                    triggered_by=None,
                    db=db,
                )
            except Exception:
                logger.error(
                    "Nightly Tier 1 scan failed for organization",
                    extra={
                        "organization_id": str(row[0]),
                        "traceback": traceback.format_exc(),
                    },
                )
    finally:
        db.close()
    logger.info("Nightly Tier 1 scan job completed")


def nightly_decay_pass() -> None:
    """Nightly decay pass for all organizations.

    Runs at 3 AM UTC. Applies temporal confidence decay to
    all active detections across all organizations.
    """
    logger.info("Nightly decay pass job started")
    db = SessionLocal()
    try:
        from app.services.decay_engine import DecayEngine

        result = DecayEngine.run_decay_pass(organization_id=None, db=db)
        db.commit()
        logger.info("Decay pass complete", extra=result)
    except Exception:
        logger.error(
            "Nightly decay pass failed",
            extra={"traceback": traceback.format_exc()},
        )
        db.rollback()
    finally:
        db.close()


def nightly_dark_ai_review() -> None:
    """Nightly dark AI detection review pass.

    Runs at 5 AM UTC. Reviews active dark AI detections, ensures
    jurisdiction assessments are current, and emits a telemetry count.
    """
    logger.info("Nightly dark AI review job started")
    db = SessionLocal()
    try:
        from app.services.dark_ai_classifier import DarkAIClassifier

        result = DarkAIClassifier.run_nightly_review(db=db)
        db.commit()
        logger.info("Nightly dark AI review complete", extra=result)
    except Exception:
        logger.error(
            "Nightly dark AI review failed",
            extra={"traceback": traceback.format_exc()},
        )
        db.rollback()
    finally:
        db.close()


def nightly_jurisdiction_pass() -> None:
    """Nightly jurisdiction assessment pass for all organizations.

    Runs at 4 AM UTC. Re-evaluates active detections against the current
    regulatory graph version for every organization with active detections.
    """
    logger.info("Nightly jurisdiction pass job started")
    db = SessionLocal()
    try:
        from app.services.jurisdiction_engine import JurisdictionEngine

        orgs = db.execute(
            text(
                "SELECT DISTINCT organization_id "
                "FROM shadow_ai_detections "
                "WHERE deleted_at IS NULL "
                "AND status NOT IN ('dismissed', 'registered')"
            )
        ).fetchall()
        for org in orgs:
            try:
                JurisdictionEngine.run_assessment_pass(
                    organization_id=org[0],
                    db=db,
                )
            except Exception:
                logger.error(
                    "Jurisdiction pass failed for organization",
                    extra={
                        "organization_id": str(org[0]),
                        "traceback": traceback.format_exc(),
                    },
                )
                continue
    except Exception:
        logger.error(
            "Nightly jurisdiction pass failed",
            extra={"traceback": traceback.format_exc()},
        )
        db.rollback()
    finally:
        db.close()
    logger.info("Nightly jurisdiction pass job completed")


def nightly_federated_submission() -> None:
    """Nightly federated submission of zero-day candidates.

    Runs at 12:30 AM UTC — before all other jobs so fresh federated
    candidates are available for nightly scans.

    Iterates over all connector tokens with federated_submissions_enabled
    and submits pending zero-day candidates with behavioral_score >= 0.55.
    Exceptions for one token never stop submissions for other tokens.
    """
    logger.info("Nightly federated submission job started")
    db = SessionLocal()
    try:
        from sqlalchemy import text

        tokens = db.execute(
            text(
                "SELECT * FROM connector_tokens WHERE "
                "federated_submissions_enabled = TRUE "
                "AND is_active = TRUE "
                "AND revoked_at IS NULL"
            )
        ).fetchall()

        for token in tokens:
            try:
                from app.services.federated_aggregator import FederatedAggregator

                FederatedAggregator.submit_zero_day_candidates(
                    token.organization_id,
                    token,
                    db,
                )
                db.commit()
            except Exception:
                logger.error(
                    "Federated submission failed",
                    extra={
                        "token_id": str(token.id),
                        "traceback": traceback.format_exc(),
                    },
                )
                db.rollback()
                continue
    finally:
        db.close()
    logger.info("Nightly federated submission job completed")


def nightly_tier2_sync() -> None:
    """Nightly Tier 2 IdP sync for all organizations.

    Runs at 1 AM UTC — before Tier 1 at 2 AM so combined
    signals are available for the detection engine.

    Fetches OAuth events from all active/pending IdP connections.
    An exception in one connection's sync never stops other
    connections from syncing.
    """
    logger.info("Nightly Tier 2 sync job started")
    db = SessionLocal()
    try:
        from app.services.tier2_scanner import Tier2Scanner

        connections = db.execute(
            text(
                "SELECT * FROM idp_connections WHERE "
                "sync_status IN ('active', 'pending') "
                "AND deleted_at IS NULL"
            )
        ).fetchall()

        for conn in connections:
            try:
                Tier2Scanner.sync_connection(
                    connection_id=conn[0],
                    organization_id=conn[1],
                    triggered_by=None,
                    db=db,
                )
            except Exception:
                logger.error(
                    "Tier2 sync failed for connection",
                    extra={
                        "connection_id": str(conn[0]),
                        "traceback": traceback.format_exc(),
                    },
                )
                continue
    finally:
        db.close()
    logger.info("Nightly Tier 2 sync job completed")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Log application startup information and start scheduler."""
    db_url = settings.database_url
    parsed = urlparse(db_url)
    if parsed.password:
        masked_url = db_url.replace(parsed.password, "***")
    else:
        masked_url = db_url

    logger.info(
        "Application starting",
        extra={
            "app_name": settings.app_name,
            "app_version": settings.app_version,
            "app_env": settings.app_env,
            "database_url": masked_url,
            "shadow_ai_enabled": settings.shadow_ai_enabled,
            "fernet_key_set": bool(settings.shadow_ai_fernet_key),
        },
    )

    scheduler = BackgroundScheduler()
    scheduler.add_job(
        nightly_federated_submission,
        trigger=CronTrigger(hour=0, minute=30, timezone="UTC"),
        id="nightly_federated_submission",
        replace_existing=True,
    )
    scheduler.add_job(
        nightly_tier2_sync,
        trigger=CronTrigger(hour=1, minute=0, timezone="UTC"),
        id="nightly_tier2_sync",
        replace_existing=True,
    )
    scheduler.add_job(
        nightly_tier1_scan,
        trigger=CronTrigger(hour=2, minute=0, timezone="UTC"),
        id="nightly_tier1_scan",
        replace_existing=True,
    )
    scheduler.add_job(
        nightly_decay_pass,
        trigger=CronTrigger(hour=3, minute=0, timezone="UTC"),
        id="nightly_decay_pass",
        replace_existing=True,
    )
    scheduler.add_job(
        nightly_jurisdiction_pass,
        trigger=CronTrigger(hour=4, minute=0, timezone="UTC"),
        id="nightly_jurisdiction_pass",
        replace_existing=True,
    )
    scheduler.add_job(
        nightly_dark_ai_review,
        trigger=CronTrigger(hour=5, minute=0, timezone="UTC"),
        id="nightly_dark_ai_review",
        replace_existing=True,
    )
    scheduler.start()
    # Expose scheduler on app state so the production status endpoint can
    # report the actual number of configured scheduler jobs.
    app.state.scheduler = scheduler
    logger.info(
        "APScheduler started with 6 jobs: "
        "nightly_federated_submission, nightly_tier2_sync, nightly_tier1_scan, "
        "nightly_decay_pass, nightly_jurisdiction_pass, nightly_dark_ai_review"
    )

    yield

    scheduler.shutdown(wait=False)
    logger.info("APScheduler shut down")


app = FastAPI(
    title="Shadow AI Discovery Engine",
    description="Patent P1 — CompliVibe AI Governance",
    version=settings.app_version,
    docs_url="/docs" if settings.app_env == "development" else None,
    redoc_url="/redoc" if settings.app_env == "development" else None,
    lifespan=lifespan,
)


# ── Middleware ──────────────────────────────

@app.middleware("http")
async def logging_middleware(request: Request, call_next):
    """Log every request: method, path, status, duration, org, request_id."""
    start_time = time.perf_counter()
    response = await call_next(request)
    duration_ms = int((time.perf_counter() - start_time) * 1000)
    logger.info(
        "Request processed",
        extra={
            "method": request.method,
            "path": request.url.path,
            "status_code": response.status_code,
            "duration_ms": duration_ms,
            "organization_id": request.headers.get("X-Organization-ID", ""),
        },
    )
    return response


@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    """Generate a UUID request_id for every request, set in contextvars."""
    request_id = str(uuid4())
    request_id_var.set(request_id)
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response


if settings.app_env == "development":
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
else:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[],
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["*"],
    )


# ── Exception Handlers ──────────────────────

@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    """Format HTTP exceptions as ErrorResponse JSON."""
    if isinstance(exc.detail, dict):
        error = exc.detail.get("error", "error")
        detail = str(exc.detail)
    else:
        error = "error"
        detail = str(exc.detail) if exc.detail else None
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(
            error=error,
            detail=detail,
            request_id=request_id_var.get() or None,
        ).model_dump(),
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Return 422 with field errors listed clearly."""
    return JSONResponse(
        status_code=422,
        content=ErrorResponse(
            error="validation_error",
            detail=str(exc.errors()),
            request_id=request_id_var.get() or None,
        ).model_dump(),
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """Catch all unhandled exceptions, return 500 with request_id."""
    logger.error(
        "Unhandled exception",
        extra={
            "error": str(exc),
            "traceback": traceback.format_exc(),
        },
    )
    return JSONResponse(
        status_code=500,
        content=ErrorResponse(
            error="internal_server_error",
            detail="An unexpected error occurred",
            request_id=request_id_var.get() or None,
        ).model_dump(),
    )


# ── Router Registration ─────────────────────

app.include_router(health_router, prefix="/api/v1", tags=["Health"])
app.include_router(detections_router, prefix="/api/v1/shadow-ai", tags=["Detections"])
app.include_router(scans_router, prefix="/api/v1/shadow-ai", tags=["Scans"])
app.include_router(registry_router, prefix="/api/v1/shadow-ai", tags=["Registry"])
app.include_router(metrics_router, prefix="/api/v1/shadow-ai", tags=["Metrics"])
app.include_router(idp_router, prefix="/api/v1/shadow-ai", tags=["IdP Integration"])
app.include_router(connector_router, prefix="/api/v1/shadow-ai", tags=["Connector"])
app.include_router(contamination_router, prefix="/api/v1/shadow-ai", tags=["Vendor Contamination"])
app.include_router(federated_router, prefix="/api/v1/shadow-ai", tags=["Federated Network"])
