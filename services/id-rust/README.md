# Rust-реализация UpdSpace ID

Здесь находятся API, веб-страницы, фоновые задания и операторские утилиты ID. Этот README — точка входа. Устройство сервиса, тесты и рабочие процедуры вынесены в [документацию](../../docs/README.md).

## Куда перейти

| Задача | Документ |
| --- | --- |
| Понять компоненты и потоки данных | [Устройство Rust-сервиса](../../docs/architecture/rust-service.md) |
| Настроить локальную YDB и запустить тесты | [Локальная разработка](../../docs/development/rust-local.md) |
| Разобраться с Bash, Chromium и Playwright | [Карта проверок](../../docs/development/testing.md) |
| Выпустить или откатить ID | [Эксплуатация](../../docs/operations.md) |
| Управлять OIDC-клиентом через `idctl` | [Операторская инструкция](../../docs/operations/oidc-clients.md) |
| Посмотреть оставшиеся задачи | [План развития](../../docs/development/id-development-plan-2026-10-13.md) |

## Исходники

- [`crates/id-runtime`](crates/id-runtime) — API, доступ к YDB, фоновые операции и `idctl`.
- [`crates/id-web`](crates/id-web/README.md) — страницы входа, кабинета и публичная информация. Web читает данные через API, не из YDB.
- [`crates/id-compat`](crates/id-compat) — совместимость существующих паролей, сессий и MFA.
- [`browser-tests`](browser-tests) и [`scripts`](scripts) — браузерные сценарии и запуск их локального окружения.
- [`certs`](certs) — публичный CA Yandex Cloud для проверки TLS, не приватные ключи. [Зачем он нужен](../../docs/architecture/rust-service.md#сертификат-yandex-cloud).

## Быстрая проверка

Из этой директории, с toolchain из `rust-toolchain.toml`:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo build --locked --workspace --bins
```

Тесты с реальной YDB и Chromium требуют отдельной подготовки. Команды и границы безопасности — в [локальной разработке](../../docs/development/rust-local.md) и [CI](../../.github/workflows/ci-cd.yml). Старые заметки о пилотах остались в истории Git; они не описывают текущую готовность рабочего сервиса.
