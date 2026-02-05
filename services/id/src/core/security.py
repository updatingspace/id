from __future__ import annotations

import hashlib
import hmac
import time
from typing import Any, cast

from django.conf import settings
from ninja.errors import HttpError


def _body_sha256(body: bytes) -> str:
    return hashlib.sha256(body or b"").hexdigest()


def require_internal_signature(request) -> None:
    request_id = request.headers.get("X-Request-Id")
    ts = request.headers.get("X-Updspace-Timestamp")
    sig = request.headers.get("X-Updspace-Signature")

    if not request_id:
        raise HttpError(
            400,
            cast(Any, {"code": "MISSING_REQUEST_ID", "message": "X-Request-Id is required"}),
        )

    if not ts or not sig:
        raise HttpError(
            401,
            cast(Any, {"code": "UNAUTHORIZED", "message": "Missing internal signature"}),
        )

    try:
        ts_int = int(str(ts))
    except Exception as exc:
        raise HttpError(
            401,
            cast(Any, {"code": "UNAUTHORIZED", "message": "Invalid internal timestamp"}),
        ) from exc

    # Basic replay protection (5 min)
    now = int(time.time())
    if abs(now - ts_int) > 300:
        raise HttpError(
            401,
            cast(Any, {"code": "UNAUTHORIZED", "message": "Internal signature expired"}),
        )

    secret = getattr(settings, "BFF_INTERNAL_HMAC_SECRET", "")
    if not secret:
        raise HttpError(
            500,
            cast(Any, {"code": "SERVER_ERROR", "message": "Internal HMAC secret is not configured"}),
        )

    body = request.body or b""
    path = request.path
    msg = "\n".join([request.method.upper(), path, _body_sha256(body), str(request_id), str(ts_int)]).encode(
        "utf-8"
    )
    expected = hmac.new(secret.encode("utf-8"), msg, digestmod=hashlib.sha256).hexdigest()

    if not hmac.compare_digest(str(sig), expected):
        raise HttpError(
            401,
            cast(Any, {"code": "UNAUTHORIZED", "message": "Invalid internal signature"}),
        )
