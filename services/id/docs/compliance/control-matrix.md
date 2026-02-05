# Compliance Control Matrix (GDPR / 152-FZ Technical Scope)

Generated at: `2026-02-05T23:25:36.683158+00:00`

Scope note:
- Includes technical controls for secure processing, minimization, protocol security, and traceability.
- Excludes data residency/storage-location policy decisions for this iteration.

| Requirement | Control | Evidence (Tests/Checks) | Status |
|---|---|---|---|
| Data minimization (GDPR Art.5(1)(c), 152-FZ minimization) | Safe API error envelopes for `/api/v1` and `/oauth`, no raw internal diagnostics in external responses | `src/accounts/tests/test_exception_handlers.py`, `src/idp/tests/test_oidc.py::test_oidc_errors_use_safe_envelope` | PASS |
| Secure processing (GDPR Art.32, 152-FZ security obligations) | Redaction of tokens/passwords/secrets/emails in logs and middleware extras | `src/core/tests/test_logging_config.py`, `src/core/tests/test_middleware.py` | PASS |
| Protocol correctness (OAuth2/OIDC PKCE) | PKCE S256-only, deny `plain`, strict code lifecycle/reuse checks | `src/idp/tests/test_oidc.py::OidcProtocolComplianceTests` | PASS |
| Session and token protection | Token refresh rotation, revoke behavior, no-store headers for token-sensitive responses | `src/idp/tests/test_oidc.py::OidcTokenLifecycleTests`, `src/accounts/tests/test_api.py` | PASS |
| Internal API integrity | HMAC internal signature verification, timestamp drift/replay rejection, request-id requirement | `src/core/tests/test_internal_signature.py` | PASS |
| Abuse resistance | Auth/OIDC rate limiting with 429 + retry semantics | `src/accounts/tests/test_rate_limit.py`, `src/idp/tests/test_oidc.py::test_check_rate_limit_raises_429_when_blocked` | PASS |
| Contract integrity between FE/BE | API method/path/payload contract tests for auth/account/authorize flows | `web/id-frontend/src/lib/api.contract.test.ts`, `web/id-frontend/src/pages/authorize/Authorize.protocol.test.tsx` | PASS |
| End-to-end critical user paths | Smoke E2E for login, authorize approve/deny, account update path | `web/id-frontend/e2e/auth-smoke.spec.ts`, `web/id-frontend/e2e/authorize-smoke.spec.ts`, `web/id-frontend/e2e/account-smoke.spec.ts` | PASS |
| Cross-DB execution confidence | Full backend test suite on SQLite + Postgres | CI jobs `backend-sqlite` and `backend-postgres` | SQLite: PASS, Postgres: PASS |

## Gate Summary

- Backend coverage profile gate: `line >= 85%`, `branch >= 80%` with critical security modules at `100%`.
- Frontend quality gate: lint + typecheck + unit tests with coverage thresholds.
- Smoke E2E gate: blocking Playwright run in CI.
