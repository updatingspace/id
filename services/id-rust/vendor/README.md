# YDB SDK dependency patch

`ydb/` is the published Apache-2.0 `ydb` **0.18.2** crate from
<https://crates.io/crates/ydb/0.18.2>. Its Rust source is unchanged. The original
manifest is retained as `Cargo.toml.orig`, and the upstream license is
`ydb/LICENSE.txt`.

Published crate SHA-256:
`d9c60f3dc2ca2def7f84a40f2c49a65969f69874cc4328c3a6176daf5740e23d`.
Upstream source revision: `cd1d20b15f5a149f8090c7f8149dbe5c87cd2b51`
(`ydb` subdirectory).

The normalized published manifest has two dependency changes:

- `reqwest`: 0.11 is replaced with exact 0.12.28, preserving blocking, JSON,
  Rustls, HTTP/2 and charset support. Both the latest published SDK and upstream
  master still use reqwest 0.11 as of 2026-10-08. That branch pulls in dependencies
  affected by RUSTSEC-2026-0258 (h2) and RUSTSEC-2026-0098, RUSTSEC-2026-0099,
  RUSTSEC-2026-0104 (rustls-webpki). There are no compatible fixed releases in
  their old minor-version lines.
- `jsonwebtoken`: 9.3 is replaced with exact 10.3.0 and the explicit
  `aws_lc_rs` crypto provider. This removes the version affected by
  [GHSA-h395-gr6q-cpjc](https://github.com/Keats/jsonwebtoken/security/advisories/GHSA-h395-gr6q-cpjc)
  from the whole graph. The SDK only signs IAM JWTs with PS256; it does not
  validate caller-supplied JWTs. The new provider preserves that signing API.
  `rust_crypto` was considered but resolves `rsa` 0.9.10, affected by unpatched
  [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071).
  The runtime JWT regression suite checks RS256 and PS256 signatures against
  OpenSSL as well as HS256 compatibility and malformed time-claim rejection.

The workspace uses `[patch.crates-io]` and a committed `Cargo.lock`, so local
checks, CI and container builds resolve the same source and dependency graph.
This is a temporary source patch, not a new SDK implementation. Replace it with
the official published SDK once that release uses fixed HTTP/TLS and JWT
dependencies; then remove the patch, vendor directory and Dockerfile copy steps
together.
