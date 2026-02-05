import json
import logging

from ninja import NinjaAPI
from ninja.errors import HttpError

from accounts.transport.schemas import ErrorOut

logger = logging.getLogger(__name__)


def _error_envelope_response(api: NinjaAPI, request, status: int, raw_detail):
    if raw_detail is None:
        raw_detail = str(status)
    if not isinstance(raw_detail, dict):
        raw_detail = {"code": "HTTP_ERROR", "message": str(raw_detail)}

    request_id = request.headers.get("X-Request-Id") or ""
    payload = {
        "error": {
            "code": str(
                raw_detail.get("code")
                or ("SERVER_ERROR" if status >= 500 else "HTTP_ERROR")
            ),
            "message": str(raw_detail.get("message") or "Error"),
            "details": raw_detail.get("details"),
            "request_id": str(request_id),
        }
    }
    return api.create_response(request, payload, status=status)


def _normalize_form_errors(raw: str):
    try:
        data = json.loads(raw)
    except Exception:
        return None, None
    if not isinstance(data, dict):
        return None, None

    errors: dict[str, list[dict]] = {}
    fields: dict[str, str] = {}
    for field, entries in data.items():
        if not isinstance(entries, list):
            continue
        norm: list[dict] = []
        for e in entries:
            if isinstance(e, dict):
                msg = (e.get("message") or "").strip() or str(e)
                code = e.get("code")
            else:
                msg = str(e)
                code = None
            norm.append({"message": msg, "code": code})
        if norm:
            errors[field] = norm
            fields[field] = norm[0]["message"]
    return (errors or None), (fields or None)


def install_http_error_handler(api: NinjaAPI) -> None:
    @api.exception_handler(HttpError)
    def on_http_error(request, exc: HttpError):  # noqa: N802
        status = getattr(exc, "status_code", 500)
        raw_detail = getattr(exc, "message", None)
        if getattr(request, "_error_envelope", False):
            return _error_envelope_response(api, request, status, raw_detail)
        if raw_detail is None:
            raw_detail = str(exc)
        user = getattr(request, "user", None)
        if status >= 500:
            level = logging.CRITICAL
        elif status in (400, 401, 403, 404, 409, 429):
            level = logging.INFO
        else:
            level = logging.WARNING
        logger.log(
            level,
            "HTTP error handled",
            extra={
                "status": status,
                "detail": str(raw_detail),
                "path": getattr(request, "path", None),
                "method": getattr(request, "method", None),
                "user_id": getattr(user, "id", None),
            },
        )
        errors, fields = _normalize_form_errors(str(raw_detail))
        payload_detail = raw_detail
        payload_code = None
        payload_message = None
        payload_details = None
        if isinstance(raw_detail, dict):
            payload_code = raw_detail.get("code") or None
            payload_message = raw_detail.get("message") or None
            payload_details = raw_detail.get("details") or None
        if errors:
            payload_code = payload_code or "VALIDATION_ERROR"
            payload_message = payload_message or "Проверьте введённые данные"
            payload_details = payload_details or {
                "errors": errors,
                "fields": fields,
            }
            return api.create_response(
                request,
                ErrorOut(
                    code=payload_code,
                    message=payload_message,
                    details=payload_details,
                    errors=errors,
                    fields=fields,
                    status=status,
                    detail=str(payload_detail),
                ),
                status=status,
            )
        if isinstance(raw_detail, str):
            payload_message = payload_message or raw_detail
        if not payload_code:
            payload_code = "HTTP_ERROR" if status < 500 else "SERVER_ERROR"
        if not payload_message:
            payload_message = "Произошла ошибка"
        return api.create_response(
            request,
            ErrorOut(
                code=str(payload_code),
                message=str(payload_message),
                details=payload_details,
                status=status,
                detail=str(payload_detail),
            ),
            status=status,
        )
