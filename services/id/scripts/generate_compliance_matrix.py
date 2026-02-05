#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path


def _normalize_status(value: str) -> str:
    normalized = (value or "").strip().lower()
    if normalized == "success":
        return "PASS"
    if normalized in {"failure", "cancelled", "timed_out"}:
        return "FAIL"
    if normalized in {"skipped", "neutral"}:
        return "N/A"
    return "UNKNOWN"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate GDPR/152-FZ technical control matrix markdown."
    )
    parser.add_argument("--output", required=True)
    parser.add_argument("--backend-status", default="unknown")
    parser.add_argument("--postgres-status", default="unknown")
    parser.add_argument("--frontend-status", default="unknown")
    parser.add_argument("--e2e-status", default="unknown")
    args = parser.parse_args()

    backend = _normalize_status(args.backend_status)
    postgres = _normalize_status(args.postgres_status)
    frontend = _normalize_status(args.frontend_status)
    e2e = _normalize_status(args.e2e_status)

    generated_at = datetime.now(timezone.utc).isoformat()
    markdown = f"""# Compliance Control Matrix (GDPR / 152-FZ Technical Scope)

Generated at: `{generated_at}`

Scope note:
- Includes technical controls for secure processing, minimization, protocol security, and traceability.
- Excludes data residency/storage-location policy decisions for this iteration.

| Requirement | Control | Evidence (Tests/Checks) | Status |
|---|---|---|---|
| Data minimization (GDPR Art.5(1)(c), 152-FZ minimization) | Safe API error envelopes for `/api/v1` and `/oauth`, no raw internal diagnostics in external responses | `src/accounts/tests/test_exception_handlers.py`, `src/idp/tests/test_oidc.py::test_oidc_errors_use_safe_envelope` | {backend} |
| Secure processing (GDPR Art.32, 152-FZ security obligations) | Redaction of tokens/passwords/secrets/emails in logs and middleware extras | `src/core/tests/test_logging_config.py`, `src/core/tests/test_middleware.py` | {backend} |
| Protocol correctness (OAuth2/OIDC PKCE) | PKCE S256-only, deny `plain`, strict code lifecycle/reuse checks | `src/idp/tests/test_oidc.py::OidcProtocolComplianceTests` | {backend} |
| Session and token protection | Token refresh rotation, revoke behavior, no-store headers for token-sensitive responses | `src/idp/tests/test_oidc.py::OidcTokenLifecycleTests`, `src/accounts/tests/test_api.py` | {backend} |
| Internal API integrity | HMAC internal signature verification, timestamp drift/replay rejection, request-id requirement | `src/core/tests/test_internal_signature.py` | {backend} |
| Abuse resistance | Auth/OIDC rate limiting with 429 + retry semantics | `src/accounts/tests/test_rate_limit.py`, `src/idp/tests/test_oidc.py::test_check_rate_limit_raises_429_when_blocked` | {backend} |
| Contract integrity between FE/BE | API method/path/payload contract tests for auth/account/authorize flows | `web/id-frontend/src/lib/api.contract.test.ts`, `web/id-frontend/src/pages/authorize/Authorize.protocol.test.tsx` | {frontend} |
| End-to-end critical user paths | Smoke E2E for login, authorize approve/deny, account update path | `web/id-frontend/e2e/auth-smoke.spec.ts`, `web/id-frontend/e2e/authorize-smoke.spec.ts`, `web/id-frontend/e2e/account-smoke.spec.ts` | {e2e} |
| Cross-DB execution confidence | Full backend test suite on SQLite + Postgres | CI jobs `backend-sqlite` and `backend-postgres` | SQLite: {backend}, Postgres: {postgres} |

## Gate Summary

- Backend coverage profile gate: `line >= 85%`, `branch >= 80%` with critical security modules at `100%`.
- Frontend quality gate: lint + typecheck + unit tests with coverage thresholds.
- Smoke E2E gate: blocking Playwright run in CI.
"""

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(markdown, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
