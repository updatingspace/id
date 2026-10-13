# Локальная разработка Rust ID

Команды выполняются из `services/id-rust`. Нужны Rust из `rust-toolchain.toml`, `libssl-dev` и `pkg-config`. CI остаётся точным списком проверок для выпуска: [основной workflow](../../.github/workflows/ci-cd.yml) и [расширенные интеграционные тесты](../../.github/workflows/rust-pilot.yml).

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo build --locked --workspace --bins
```

Интеграционные сценарии используют отдельную локальную YDB. Не направляйте тесты с `--ignored`, меняющие схему или записи, на рабочую базу. Образ и подготовка из CI:

```sh
docker run -d --rm --name id-rust-ydb --hostname localhost \
  -p 127.0.0.1:2136:2136 -p 127.0.0.1:8765:8765 \
  ydbplatform/local-ydb@sha256:9e46fd45875551a75bcf34d0bb9ca0baa1d8763a4ccf2070af45f4467c4b7402
export YDB_ENDPOINT=grpc://localhost:2136
export YDB_DATABASE=/local
export YDB_CREDENTIALS_MODE=anonymous
scripts/wait-for-ydb-local.sh
cargo run --locked --bin idctl -- legacy-schema --apply
cargo run --locked --bin idctl -- cache-schema
cargo test --locked -p id-runtime --test ydb_pilot -- --ignored
```

Этот `wait` проверяет возможность операции со схемой, потому что открытый порт ещё не означает готовность YDB принимать тестовые транзакции. Он относится только к локальным интеграционным тестам.

Для разработки страниц `id-web` нужны API того же origin и разрешённые локальные флаги. Отдельный `id-web` не заменяет API. Браузерные проверки и назначение тестовых оболочек описаны в [карте проверок](testing.md).

Для защищённой YDB используйте `grpcs://`, явный режим credentials и при необходимости `YDB_CA_FILE`. Анонимный режим разрешён только на loopback. [Назначение CA](../architecture/rust-service.md#сертификат-yandex-cloud) не связано с секретами аутентификации.
