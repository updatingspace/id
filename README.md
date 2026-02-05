# UpdSpace ID

Отдельный репозиторий Identity-компонентов UpdSpace.

## Структура

- `services/id` - Django/Ninja backend (IdP)
- `web/id-frontend` - React/Vite frontend для Identity UI

## CI/CD

Workflow: `.github/workflows/ci-cd.yml`

- CI (PR/push): backend lint+tests, frontend lint+typecheck+tests
- CD (push в `main`/`master`): обязательная публикация Docker images в `ghcr.io`
  - `ghcr.io/<owner>/id-service`
  - `ghcr.io/<owner>/id-frontend`
