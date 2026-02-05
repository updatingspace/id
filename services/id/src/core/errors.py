from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ErrorEnvelope:
    code: str
    message: str
    details: dict | None = None


def error_payload(code: str, message: str, details: dict | None = None) -> dict:
    payload: dict = {"code": code, "message": message}
    if details is not None:
        payload["details"] = details
    return payload
