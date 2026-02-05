from __future__ import annotations

import os
import uuid
from dataclasses import dataclass

from ninja.errors import HttpError

from updspaceid.errors import error_payload


@dataclass(frozen=True)
class RequestContext:
    request_id: str
    tenant_id: str
    tenant_slug: str


def _env_flag(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


DEV_AUTH_MODE = _env_flag("DEV_AUTH_MODE", False)


def require_request_id(request) -> str:
    request_id = request.headers.get("X-Request-Id")
    if not request_id:
        if DEV_AUTH_MODE:
            return str(uuid.uuid4())
        raise HttpError(
            400,
            error_payload(
                "MISSING_REQUEST_ID",
                "X-Request-Id is required",
            ),
        )
    return str(request_id)


def require_tenant_headers(request) -> tuple[str, str]:
    tenant_id = request.headers.get("X-Tenant-Id")
    tenant_slug = request.headers.get("X-Tenant-Slug")
    if not tenant_id or not tenant_slug:
        if DEV_AUTH_MODE:
            default_id = os.getenv(
                "DEFAULT_TENANT_ID",
                "00000000-0000-0000-0000-000000000001",
            )
            default_slug = os.getenv("DEFAULT_TENANT_SLUG", "aef")
            return str(default_id), str(default_slug)
        raise HttpError(
            400,
            error_payload(
                "MISSING_TENANT",
                "X-Tenant-Id and X-Tenant-Slug are required",
            ),
        )
    # Validate tenant_id is UUID-like (string form is enough for MVP)
    try:
        uuid.UUID(str(tenant_id))
    except Exception as exc:
        if DEV_AUTH_MODE:
            # When running with DEFAULT_TENANT_ID, keep UX smooth.
            return str(tenant_id), str(tenant_slug)
        raise HttpError(
            400,
            error_payload(
                "INVALID_TENANT_ID",
                "X-Tenant-Id must be a UUID",
            ),
        ) from exc
    return str(tenant_id), str(tenant_slug)


def require_context(request) -> RequestContext:
    request_id = require_request_id(request)
    tenant_id, tenant_slug = require_tenant_headers(request)
    return RequestContext(
        request_id=request_id,
        tenant_id=tenant_id,
        tenant_slug=tenant_slug,
    )
