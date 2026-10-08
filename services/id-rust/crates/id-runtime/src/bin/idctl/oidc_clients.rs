//! CLI inputs never accept an operator password, session or client secret as arguments.

use anyhow::{Result, anyhow, ensure};
use clap::Args;
use id_runtime::oidc_client_operator::{self, ClientSpec, Creation, Rotation};
use std::{fs::File, io::Read, path::PathBuf};

#[derive(Args)]
pub struct OperatorFiles {
    /// Private regular file containing the exact session token (no trailing newline).
    #[arg(long)]
    operator_session_file: PathBuf,
    /// Private regular file containing the exact current password (no trimming).
    #[arg(long)]
    operator_password_file: PathBuf,
}

impl OperatorFiles {
    fn read(&self) -> Result<(String, String)> {
        Ok((
            oidc_client_operator::read_private_input(&self.operator_session_file)?,
            oidc_client_operator::read_private_input(&self.operator_password_file)?,
        ))
    }
}

pub async fn create(
    config: PathBuf,
    expected_config_digest: Option<String>,
    operator: OperatorFiles,
    output: Option<PathBuf>,
    apply: bool,
) -> Result<()> {
    let mut contents = Vec::new();
    File::open(config)
        .map_err(|_| anyhow!("cannot open client configuration"))?
        .take(32 * 1024 + 1)
        .read_to_end(&mut contents)
        .map_err(|_| anyhow!("cannot read client configuration"))?;
    ensure!(
        contents.len() <= 32 * 1024,
        "client configuration exceeds 32 KiB"
    );
    let spec: ClientSpec = serde_json::from_slice(&contents)
        .map_err(|_| anyhow!("invalid client configuration JSON"))?;
    spec.validate()?;
    let (session, password) = operator.read()?;
    let codec = id_runtime::session_store::session_codec_from_env()
        .map_err(|_| anyhow!("operator session verification configuration unavailable"))?;
    let client = id_runtime::connect_ydb()
        .await
        .map_err(|_| anyhow!("YDB connection unavailable"))?;
    let report = oidc_client_operator::create(
        &client,
        codec,
        session,
        password,
        Creation {
            spec,
            expected_config_digest,
            apply,
            secret_output: output.as_deref(),
        },
    )
    .await?;
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}

pub async fn show(client_id: String, operator: OperatorFiles) -> Result<()> {
    let (session, password) = operator.read()?;
    let codec = id_runtime::session_store::session_codec_from_env()
        .map_err(|_| anyhow!("operator session verification configuration unavailable"))?;
    let client = id_runtime::connect_ydb()
        .await
        .map_err(|_| anyhow!("YDB connection unavailable"))?;
    let report = oidc_client_operator::show(&client, codec, session, password, client_id).await?;
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}

pub async fn rotate(
    client_id: String,
    expected_revision: Option<String>,
    operator: OperatorFiles,
    output: Option<PathBuf>,
    apply: bool,
) -> Result<()> {
    let (session, password) = operator.read()?;
    let codec = id_runtime::session_store::session_codec_from_env()
        .map_err(|_| anyhow!("operator session verification configuration unavailable"))?;
    let client = id_runtime::connect_ydb()
        .await
        .map_err(|_| anyhow!("YDB connection unavailable"))?;
    let report = oidc_client_operator::rotate_secret(
        &client,
        codec,
        session,
        password,
        Rotation {
            client_id,
            expected_revision,
            apply,
            secret_output: output.as_deref(),
        },
    )
    .await?;
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}
