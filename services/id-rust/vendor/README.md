# YDB SDK dependency patch

`ydb/` is the published Apache-2.0 `ydb` **0.18.2** crate from
<https://crates.io/crates/ydb/0.18.2>. Its Rust source is unchanged. The original
manifest is retained as `Cargo.toml.orig`, and the upstream license is
`ydb/LICENSE.txt`.

Published crate SHA-256:
`d9c60f3dc2ca2def7f84a40f2c49a65969f69874cc4328c3a6176daf5740e23d`.
Upstream source revision: `cd1d20b15f5a149f8090c7f8149dbe5c87cd2b51`
(`ydb` subdirectory).

The only change to the normalized published manifest is its `reqwest`
dependency: 0.11 is replaced with exact 0.12.28, preserving blocking, JSON,
Rustls, HTTP/2 and charset support. Both the latest published SDK and upstream
master still use reqwest 0.11 as of 2026-10-08. That branch pulls in dependencies
affected by RUSTSEC-2026-0258 (h2) and RUSTSEC-2026-0098, RUSTSEC-2026-0099,
RUSTSEC-2026-0104 (rustls-webpki). There are no compatible fixed releases in
their old minor-version lines.

The workspace uses `[patch.crates-io]` and a committed `Cargo.lock`, so local
checks, CI and container builds resolve the same source and dependency graph.
This is a temporary source patch, not a new SDK implementation. Replace it with
the official published SDK once that release uses fixed HTTP/TLS dependencies;
then remove the patch, vendor directory and Dockerfile copy steps together.
