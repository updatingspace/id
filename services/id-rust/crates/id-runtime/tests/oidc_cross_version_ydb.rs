//! Synthetic Python -> Rust -> Python OIDC refresh hand-off on local YDB.

use anyhow::{Context, Result, ensure};
use id_runtime::{
    oidc_code_exchange::ExchangeFailure,
    oidc_keys::OidcKeyRing,
    oidc_refresh::{RefreshRequest, rotate},
    oidc_userinfo::userinfo,
};
use serde_json::{Value, json};
use std::{env, fs, sync::Arc, time::SystemTime};

#[tokio::test]
#[ignore = "requires a synthetic fixture and migrated local /local YDB"]
async fn rotate_python_refresh_and_emit_rust_result() -> Result<()> {
    ensure!(
        matches!(
            env::var("YDB_ENDPOINT")?.as_str(),
            "grpc://localhost:2136" | "grpc://127.0.0.1:2136"
        ) && env::var("YDB_DATABASE")? == "/local",
        "cross-version check requires local YDB"
    );
    let input = env::var("ID_OIDC_ROUNDTRIP_INPUT")?;
    let output = env::var("ID_OIDC_ROUNDTRIP_OUTPUT")?;
    let fixture: Value = serde_json::from_slice(&fs::read(input)?)?;
    ensure!(
        fixture["synthetic"] == true && fixture["format_version"] == 1,
        "only synthetic version 1 fixtures are accepted"
    );
    let field = |name| -> Result<&str> {
        fixture[name]
            .as_str()
            .with_context(|| format!("missing {name}"))
    };
    let keys = Arc::new(OidcKeyRing::from_json(&fixture["keyset"].to_string())?);
    let issuer = field("issuer")?;
    let subject = field("subject")?;
    let now = SystemTime::now();
    let client = id_runtime::connect_ydb().await?;
    let result = rotate(
        &client,
        keys.clone(),
        issuer,
        field("refresh_salt")?,
        RefreshRequest {
            client_id: field("client_id")?.to_owned(),
            client_secret: None,
            refresh_token: field("refresh_token")?.to_owned(),
            scope: None,
        },
        now,
    )
    .await?;
    if fixture["expect_revoked"] == true {
        ensure!(
            matches!(result, Err(ExchangeFailure::InvalidGrant)),
            "cross-version revoked refresh was accepted"
        );
        ensure!(
            userinfo(&client, &keys, issuer, field("access_token")?, None, now)
                .await?
                .is_none(),
            "cross-version revoked access remained valid"
        );
        fs::write(output, serde_json::to_vec(&json!({"revoked": true}))?)?;
        return Ok(());
    }
    let result =
        result.map_err(|failure| anyhow::anyhow!("cross-version refresh rejected: {failure:?}"))?;
    ensure!(result.refresh_token.is_some(), "refresh family ended early");
    let claims = userinfo(&client, &keys, issuer, &result.access_token, None, now)
        .await?
        .context("Rust access did not pass UserInfo")?;
    ensure!(claims["sub"] == subject, "cross-version subject changed");
    fs::write(output, serde_json::to_vec(&result)?)?;
    Ok(())
}
