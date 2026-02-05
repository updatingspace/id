from __future__ import annotations

from dataclasses import dataclass

from ninja.errors import HttpError

from core.errors import error_payload


@dataclass(frozen=True)
class RequestContext:
    request_id: str
    tenant_id: str
    tenant_slug: str


def require_request_id(request) -> str:
    request_id = request.headers.get("X-Request-Id")
    if not request_id:
        raise HttpError(
            400, error_payload("MISSING_REQUEST_ID", "X-Request-Id is required")
        )
    return request_id


def require_context(request) -> RequestContext:
    rid = require_request_id(request)
    tid = request.headers.get("X-Tenant-Id")
    tslug = request.headers.get("X-Tenant-Slug")

    if not tid or not tslug:
        # For MVP, assume error if context is explicitly required
        raise HttpError(
            400, error_payload("MISSING_TENANT_CONTEXT", "Tenant headers required")
        )

    return RequestContext(request_id=rid, tenant_id=tid, tenant_slug=tslug)
