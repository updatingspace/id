# UpdSpace ID

UpdSpace ID — единый вход, управление доступом к приложениям и данными аккаунта.

## Состав проекта

- [`services/id-rust`](services/id-rust/README.md) — Rust workspace: Axum API, отдельно развёртываемый Topcoat SSR-интерфейс, jobs и операторский CLI `idctl`.
- [`infra/terraform/yandex-cloud`](infra/terraform/yandex-cloud/README.md) — Yandex Cloud, YDB, API Gateway, Object Storage и очереди.
- [`services/id-rust/browser-tests`](services/id-rust/browser-tests/package.json) — небольшой Playwright runner для проверки Topcoat в браузере.

Django и React больше не входят в актуальные исходники или проектные GitHub workflows. Историческая реализация и её контракты доступны в Git. Rust сохраняет чтение действующих форматов credentials и sessions, пока они нужны пользователям.

## Локальная проверка

Для Rust нужны toolchain из [`rust-toolchain.toml`](services/id-rust/rust-toolchain.toml), `libssl-dev` и `pkg-config`. Из `services/id-rust`:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo build --locked --workspace --bins
```

Интеграционные тесты работают с локальной YDB. После её запуска выполните `idctl legacy-schema --apply` и `idctl cache-schema`; детали и команды находятся в [Rust README](services/id-rust/README.md). Тесты Topcoat используют `npm ci` в `services/id-rust/browser-tests` и настоящий браузер с Rust API.

Основной [CI workflow](.github/workflows/ci-cd.yml) проверяет Rust, локальную YDB, browser-сценарии и инфраструктуру. [Расширенная проверка](.github/workflows/rust-pilot.yml) покрывает дополнительные сценарии аутентификации. [Deploy workflow](.github/workflows/deploy-yandex-cloud.yml) строит и выкладывает отдельные образы API, web и jobs.

Миграция ещё не завершена: операторский web-интерфейс, включение задержанной выгрузки данных в production и итоговая приёмка всех пользовательских сценариев остаются открытыми. Удаление старых исходников не означает, что эти функции проверены или доступны пользователям.
