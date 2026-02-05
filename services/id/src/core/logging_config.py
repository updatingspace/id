"""
Structured JSON logging configuration for UpdSpace ID Service.

Provides:
- JSON-formatted logs for production (log aggregation ready)
- Correlation ID propagation across requests
- Contextual fields (user_id, tenant_id, request_id)
- Per-environment log level configuration
"""
from __future__ import annotations

import json
import logging
import sys
import threading
import time
import traceback
import uuid
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any

from django.conf import settings

# Context variables for request-scoped data
correlation_id_var: ContextVar[str | None] = ContextVar("correlation_id", default=None)
user_id_var: ContextVar[str | None] = ContextVar("user_id", default=None)
tenant_id_var: ContextVar[str | None] = ContextVar("tenant_id", default=None)
request_path_var: ContextVar[str | None] = ContextVar("request_path", default=None)


def get_correlation_id() -> str | None:
    """Get the current correlation ID."""
    return correlation_id_var.get()


def set_correlation_id(correlation_id: str | None) -> None:
    """Set the correlation ID for the current context."""
    correlation_id_var.set(correlation_id)


def generate_correlation_id() -> str:
    """Generate a new correlation ID."""
    return str(uuid.uuid4())


def set_user_context(user_id: str | None = None, tenant_id: str | None = None) -> None:
    """Set user context for logging."""
    if user_id is not None:
        user_id_var.set(user_id)
    if tenant_id is not None:
        tenant_id_var.set(tenant_id)


def clear_context() -> None:
    """Clear all context variables."""
    correlation_id_var.set(None)
    user_id_var.set(None)
    tenant_id_var.set(None)
    request_path_var.set(None)


class JsonFormatter(logging.Formatter):
    """
    JSON log formatter for structured logging.
    
    Output format compatible with common log aggregation systems
    (ELK, Loki, Datadog, etc.)
    """

    def __init__(
        self,
        *,
        include_timestamp: bool = True,
        include_hostname: bool = True,
        extra_fields: dict[str, Any] | None = None,
    ):
        super().__init__()
        self.include_timestamp = include_timestamp
        self.include_hostname = include_hostname
        self.extra_fields = extra_fields or {}
        self._hostname: str | None = None

    def _get_hostname(self) -> str:
        if self._hostname is None:
            import socket
            try:
                self._hostname = socket.gethostname()
            except Exception:
                self._hostname = "unknown"
        return self._hostname

    def format(self, record: logging.LogRecord) -> str:
        log_obj: dict[str, Any] = {
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Add timestamp
        if self.include_timestamp:
            log_obj["timestamp"] = datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).isoformat()

        # Add hostname
        if self.include_hostname:
            log_obj["hostname"] = self._get_hostname()

        # Add correlation ID and context
        correlation_id = correlation_id_var.get()
        if correlation_id:
            log_obj["correlation_id"] = correlation_id

        user_id = user_id_var.get()
        if user_id:
            log_obj["user_id"] = user_id

        tenant_id = tenant_id_var.get()
        if tenant_id:
            log_obj["tenant_id"] = tenant_id

        request_path = request_path_var.get()
        if request_path:
            log_obj["request_path"] = request_path

        # Add source location for errors
        if record.levelno >= logging.WARNING:
            log_obj["source"] = {
                "file": record.pathname,
                "line": record.lineno,
                "function": record.funcName,
            }

        # Add exception info
        if record.exc_info:
            log_obj["exception"] = {
                "type": record.exc_info[0].__name__ if record.exc_info[0] else None,
                "message": str(record.exc_info[1]) if record.exc_info[1] else None,
                "traceback": traceback.format_exception(*record.exc_info),
            }

        # Add thread info
        log_obj["thread"] = {
            "id": record.thread,
            "name": record.threadName,
        }

        # Add extra fields from record
        extra_keys = set(record.__dict__.keys()) - {
            "name", "msg", "args", "created", "filename", "funcName",
            "levelname", "levelno", "lineno", "module", "msecs",
            "pathname", "process", "processName", "relativeCreated",
            "stack_info", "exc_info", "exc_text", "thread", "threadName",
            "message", "asctime",
        }
        for key in extra_keys:
            value = getattr(record, key, None)
            if value is not None and key not in log_obj:
                log_obj[key] = value

        # Add configured extra fields
        log_obj.update(self.extra_fields)

        return json.dumps(log_obj, default=str, ensure_ascii=False)


class ConsoleFormatter(logging.Formatter):
    """
    Human-readable colored console formatter for development.
    """

    COLORS = {
        "DEBUG": "\033[36m",     # Cyan
        "INFO": "\033[32m",      # Green
        "WARNING": "\033[33m",   # Yellow
        "ERROR": "\033[31m",     # Red
        "CRITICAL": "\033[35m",  # Magenta
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, "")
        reset = self.RESET if color else ""

        # Build prefix with correlation ID if present
        correlation_id = correlation_id_var.get()
        prefix = f"[{correlation_id[:8]}]" if correlation_id else ""

        user_id = user_id_var.get()
        if user_id:
            prefix += f" user={user_id[:8]}"

        timestamp = datetime.fromtimestamp(record.created).strftime("%H:%M:%S.%f")[:-3]

        formatted = (
            f"{color}{timestamp} {record.levelname:8}{reset} "
            f"{prefix} {record.name}: {record.getMessage()}"
        )

        if record.exc_info:
            formatted += "\n" + "".join(traceback.format_exception(*record.exc_info))

        return formatted


def configure_logging(
    *,
    json_format: bool | None = None,
    log_level: str | None = None,
    service_name: str = "id-service",
) -> None:
    """
    Configure logging for the application.
    
    Args:
        json_format: Use JSON formatting. Default: True in production, False in DEBUG.
        log_level: Logging level. Default: from LOG_LEVEL env or INFO.
        service_name: Service name to include in logs.
    """
    import os

    if json_format is None:
        json_format = not getattr(settings, "DEBUG", False)

    if log_level is None:
        log_level = os.getenv("LOG_LEVEL", "INFO").upper()

    # Get numeric level
    numeric_level = getattr(logging, log_level, logging.INFO)

    # Create handler
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(numeric_level)

    # Set formatter
    if json_format:
        formatter = JsonFormatter(
            extra_fields={"service": service_name, "env": os.getenv("ENV", "development")}
        )
    else:
        formatter = ConsoleFormatter()

    handler.setFormatter(formatter)

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)
    
    # Remove existing handlers and add ours
    root_logger.handlers.clear()
    root_logger.addHandler(handler)

    # Reduce noise from third-party libraries
    logging.getLogger("django").setLevel(logging.WARNING)
    logging.getLogger("django.request").setLevel(logging.WARNING)
    logging.getLogger("django.db.backends").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)

    # Keep our loggers at configured level
    logging.getLogger("accounts").setLevel(numeric_level)
    logging.getLogger("idp").setLevel(numeric_level)
    logging.getLogger("updspaceid").setLevel(numeric_level)
    logging.getLogger("core").setLevel(numeric_level)


# ============================================================================
# Logging helpers
# ============================================================================

def log_auth_event(
    event: str,
    *,
    user_id: str | None = None,
    email: str | None = None,
    success: bool = True,
    reason: str | None = None,
    ip_address: str | None = None,
    extra: dict[str, Any] | None = None,
) -> None:
    """
    Log an authentication event with structured data.
    
    Args:
        event: Event type (login, logout, mfa_verify, etc.)
        user_id: User ID if known
        email: Email address (will be partially masked)
        success: Whether the event was successful
        reason: Failure reason if not successful
        ip_address: Client IP address
        extra: Additional fields to include
    """
    logger = logging.getLogger("accounts.auth")
    
    log_data = {
        "event": event,
        "success": success,
    }
    
    if user_id:
        log_data["user_id"] = user_id
    if email:
        # Mask email for privacy
        log_data["email_masked"] = _mask_email(email)
    if reason:
        log_data["reason"] = reason
    if ip_address:
        log_data["ip_address"] = ip_address
    if extra:
        log_data.update(extra)
    
    level = logging.INFO if success else logging.WARNING
    logger.log(level, f"Auth event: {event}", extra=log_data)


def log_oidc_event(
    event: str,
    *,
    client_id: str | None = None,
    user_id: str | None = None,
    grant_type: str | None = None,
    success: bool = True,
    error_code: str | None = None,
    extra: dict[str, Any] | None = None,
) -> None:
    """Log an OIDC event with structured data."""
    logger = logging.getLogger("idp.oidc")
    
    log_data = {
        "event": event,
        "success": success,
    }
    
    if client_id:
        log_data["client_id"] = client_id
    if user_id:
        log_data["user_id"] = user_id
    if grant_type:
        log_data["grant_type"] = grant_type
    if error_code:
        log_data["error_code"] = error_code
    if extra:
        log_data.update(extra)
    
    level = logging.INFO if success else logging.WARNING
    logger.log(level, f"OIDC event: {event}", extra=log_data)


def _mask_email(email: str) -> str:
    """Mask an email address for logging (privacy)."""
    if "@" not in email:
        return "***"
    local, domain = email.rsplit("@", 1)
    if len(local) <= 2:
        masked_local = "*" * len(local)
    else:
        masked_local = local[0] + "*" * (len(local) - 2) + local[-1]
    return f"{masked_local}@{domain}"
