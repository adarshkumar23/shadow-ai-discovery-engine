"""
Structured JSON logging configuration.

Every log record automatically includes:
  - timestamp (ISO 8601 UTC)
  - level
  - logger_name
  - message
  - app_name (from settings)
  - app_version (from settings)
  - app_env (from settings)

All modules import get_logger(__name__) and use that.
Never use print() anywhere in the application.
"""

import contextvars
import logging
import sys
from datetime import datetime, timezone

from pythonjsonlogger.json import JsonFormatter

from app.core.config import settings

request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "request_id", default=""
)


class RequestIdFilter(logging.Filter):
    """Inject request_id from contextvars into every log record."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id_var.get()
        return True


class StructuredJsonFormatter(JsonFormatter):
    """JSON formatter that injects app metadata into every log record."""

    def add_fields(self, log_record, record, message_dict):
        super().add_fields(log_record, record, message_dict)
        log_record["timestamp"] = datetime.now(timezone.utc).isoformat()
        log_record["level"] = record.levelname
        log_record["logger_name"] = record.name
        log_record["app_name"] = settings.app_name
        log_record["app_version"] = settings.app_version
        log_record["app_env"] = settings.app_env
        rid = getattr(record, "request_id", "")
        if rid:
            log_record["request_id"] = rid


def get_logger(name: str) -> logging.Logger:
    """Return a logger with the JSON formatter pre-attached."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(StructuredJsonFormatter())
        handler.addFilter(RequestIdFilter())
        logger.addHandler(handler)
        logger.setLevel(settings.log_level)
        logger.propagate = False
    return logger
