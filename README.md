# UpdSpace ID

UpdSpace ID — единый вход, управление доступом приложений и данными аккаунта.

## Проект

- [Документация по задачам](docs/README.md): устройство сервиса, разработка, проверки и операторские процедуры.
- [Rust workspace](services/id-rust/README.md): API на Axum, Topcoat SSR, фоновые задания и операторский CLI `idctl`.
- [Интерфейс](services/id-rust/crates/id-web/README.md): публичные страницы, вход и личный кабинет.
- [Эксплуатация и релизы](docs/operations.md): домашний k3s, проверки и откат.
- [Данные и письма](docs/data-and-mail.md): действующие потоки и ограничения.
- [План развития](docs/development/id-development-plan-2026-10-13.md): оставшиеся этапы.

Манифесты рабочего сервера находятся в отдельном [репозитории infra](https://github.com/updatingspace/infra). Исторические Django/React, облачный deploy и отчёты миграции доступны в Git. Совместимость существующих аккаунтов, паролей, MFA и сессий остаётся частью Rust runtime.

## Проверки

Из `services/id-rust`, с toolchain из `rust-toolchain.toml`, `libssl-dev` и `pkg-config`:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo build --locked --workspace --bins
```

Интеграционные тесты требуют отдельную локальную YDB; команды описаны в [руководстве по локальной разработке](docs/development/rust-local.md). Для браузера выполните `npm ci` в `services/id-rust/browser-tests`. [Основной CI](.github/workflows/ci-cd.yml) и [расширенный набор](.github/workflows/rust-pilot.yml) проверяют аутентификацию, данные и интерфейс. Тестовые базы и SMTP не являются проверкой реальных аккаунтов и доставки production-писем.
