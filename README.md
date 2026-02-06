# UpdSpace ID

[![CI/CD](https://github.com/updatingspace/id/actions/workflows/ci-cd.yml/badge.svg)](https://github.com/updatingspace/id/actions/workflows/ci-cd.yml)
[![Backend Coverage Gate](https://img.shields.io/badge/backend%20coverage-line%20%E2%89%A5%2085%25%20%7C%20branch%20%E2%89%A5%2080%25-blue)](./.github/workflows/ci-cd.yml)
[![E2E Smoke](https://img.shields.io/badge/e2e-smoke%20artifact-green)](https://github.com/updatingspace/id/actions/workflows/ci-cd.yml?query=branch%3Amain)
[![Compliance Matrix](https://img.shields.io/badge/compliance-matrix%20artifact-green)](https://github.com/updatingspace/id/actions/workflows/ci-cd.yml?query=branch%3Amain)
[![GDPR/152-FZ Controls](https://img.shields.io/badge/GDPR%2F152--FZ-controls-success)](https://github.com/updatingspace/id/actions/workflows/ci-cd.yml?query=branch%3Amain)

Identity-сервис UpdSpace: единая аутентификация, управление сессиями и OAuth2/OIDC контур.

## Что в проекте

- `services/id` — backend на Django + Ninja (IdP, auth, MFA, OIDC, security controls)
- `web/id-frontend` — frontend на React + Vite (login/signup/authorize/account flows)

## Ключевые возможности

- Headless auth (email/password + session token), signup и logout
- MFA: TOTP, recovery codes, passkeys (WebAuthn)
- OAuth2/OIDC provider: authorize/token/userinfo/revoke + PKCE(S256)
- Privacy и account controls: consents, sessions, data export/delete, security event flow

## Документация

- Backend overview: [`services/id/README.md`](./services/id/README.md)
- Frontend overview: [`web/id-frontend/README.md`](./web/id-frontend/README.md)
- Operations: [`services/id/RUNBOOK.md`](./services/id/RUNBOOK.md)
- Troubleshooting: [`services/id/TROUBLESHOOTING.md`](./services/id/TROUBLESHOOTING.md)
- Compliance controls matrix: [`services/id/docs/compliance/control-matrix.md`](./services/id/docs/compliance/control-matrix.md)

## CI/CD

Workflow: [`.github/workflows/ci-cd.yml`](./.github/workflows/ci-cd.yml)

- CI (PR/push): backend lint + tests + coverage gates, frontend lint + typecheck + unit tests, smoke E2E
- Reports (`playwright-report`, `test-results`, compliance matrix) are published as GitHub Actions artifacts per run
- CD (push в `main`/`master`): публикация образов в GHCR
  - `ghcr.io/updatingspace/id-service`
  - `ghcr.io/updatingspace/id-frontend`
