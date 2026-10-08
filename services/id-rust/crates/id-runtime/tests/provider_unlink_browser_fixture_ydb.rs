//! Disposable owner held while Chromium disconnects providers through the real API.
use anyhow::{Context, Result, bail, ensure};
use id_compat::session::SessionCodec;
use serde_json::json;
use std::{
    env, fs,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;
use ydb::{Transaction, TxMode, closure};

#[tokio::test]
#[ignore = "requires local YDB and external Chromium driver"]
async fn hold_owner_for_provider_unlink() -> Result<()> {
    ensure!(
        matches!(
            env::var("YDB_ENDPOINT")?.as_str(),
            "grpc://localhost:2136" | "grpc://127.0.0.1:2136"
        ) && env::var("YDB_DATABASE")? == "/local"
            && env::var("DJANGO_DEBUG")? == "true",
        "local debug YDB required"
    );
    let output = env::var("ID_PROVIDER_BROWSER_FIXTURE_OUTPUT")?;
    let done = env::var("ID_PROVIDER_BROWSER_DONE")?;
    ensure!(
        !Path::new(&output).exists() && !Path::new(&done).exists(),
        "fresh fixture paths required"
    );
    let identity = Uuid::new_v4();
    let owner = 1_400_000_000 + i32::try_from(rand::random::<u32>() % 300_000_000)?;
    let email = format!("unlink-{identity}@example.invalid");
    let token = Uuid::new_v4().simple().to_string();
    let password =
        tokio::task::spawn_blocking(|| id_compat::password::hash_new("synthetic-unlink-password"))
            .await??;
    let codec = SessionCodec::new(env::var("DJANGO_SECRET_KEY")?.as_bytes(), &[])?;
    let now = SystemTime::now();
    let seconds = now.duration_since(UNIX_EPOCH)?.as_secs();
    let data = json!({"_auth_user_id":owner.to_string(), "_auth_user_backend":id_runtime::session_store::LEGACY_BACKENDS[0],
        "_auth_user_hash":codec.auth_hash(&password)?, "account_authentication_methods":[{"method":"password","at":seconds}]});
    let encoded = codec.encode(
        data.as_object().context("session payload")?,
        i64::try_from(seconds)?,
        true,
    )?;
    let client = id_runtime::connect_ydb().await?;
    client.query_client().retry_tx(closure!([email = email.clone(), token = token.clone(), password, encoded], async |tx: &mut Transaction| {
        tx.exec("INSERT INTO auth_user (id,password,is_active,username,first_name,last_name,email,is_staff,is_superuser,date_joined) VALUES ($id,$password,true,$name,'','',$email,false,false,CurrentUtcDatetime())")
            .param("$id",owner).param("$password",password.clone()).param("$name",identity.to_string()).param("$email",email.clone()).await?;
        tx.exec("INSERT INTO usid_user (user_id,username,display_name,email,email_verified,status,system_admin,created_at) VALUES ($id,$name,$name,$email,true,'active',false,CurrentUtcDatetime())")
            .param("$id",identity).param("$name",identity.to_string()).param("$email",email.clone()).await?;
        tx.exec("INSERT INTO accounts_accountidentity (user_id,identity_id,public_subject,created_at) VALUES ($owner,$identity,$subject,CurrentUtcDatetime())")
            .param("$owner",owner).param("$identity",identity).param("$subject",identity.to_string()).await?;
        tx.exec("INSERT INTO account_emailaddress (id,user_id,email,verified,primary) VALUES ($id,$owner,$email,true,true)")
            .param("$id",-owner).param("$owner",owner).param("$email",email.clone()).await?;
        tx.exec("INSERT INTO accounts_accountemaillookup (user_id,email_key) VALUES ($owner,$email)")
            .param("$owner",owner).param("$email",email.clone()).await?;
        tx.exec("INSERT INTO django_session (session_key,session_data,expire_date) VALUES ($key,$data,CAST($expiry AS Datetime))")
            .param("$key",token.clone()).param("$data",encoded.clone()).param("$expiry",now+Duration::from_secs(600)).await?;
        for (offset, provider) in ["github","discord","steam"].iter().enumerate() {
            let id = -i64::from(owner) - offset as i64;
            tx.exec("INSERT INTO socialaccount_socialaccount (id,user_id,provider,uid,last_login,date_joined,extra_data) VALUES ($id,$owner,$provider,$subject,CurrentUtcDatetime(),CurrentUtcDatetime(),Unwrap(CAST('{}' AS Json)))")
                .param("$id",i32::try_from(id).map_err(ydb::YdbOrCustomerError::from_err)?).param("$owner",owner).param("$provider",provider.to_string()).param("$subject",identity.to_string()).await?;
            tx.exec("INSERT INTO usid_external_identity (id,user_id,provider,subject,created_at) VALUES ($id,$owner,$provider,$subject,CurrentUtcDatetime())")
                .param("$id",id).param("$owner",identity).param("$provider",provider.to_string()).param("$subject",identity.to_string()).await?;
        }
        Ok(())
    })).with_mode(TxMode::SerializableReadWrite).idempotent(false).await?;
    let result: Result<()> = async {
        let staged = format!("{output}.staged");
        fs::write(&staged,serde_json::to_vec(&json!({"synthetic":true,"session_token":token,"email":email,"providers":["github","discord","steam"]}))?)?;
        fs::rename(staged,&output)?;
        for _ in 0..480 {
            if Path::new(&done).exists() {
                for (sql, expected) in [
                    ("SELECT COUNT(*) AS total FROM socialaccount_socialaccount WHERE user_id=$owner",0),
                    ("SELECT COUNT(*) AS total FROM accounts_accountevent WHERE user_id=$owner AND action='provider.unlinked'",3),
                ] {
                    let mut row=client.query_client().query_row(sql).param("$owner",owner).await?;
                    let total:u64=row.remove_field_by_name("total")?.try_into()?;
                    ensure!(total==expected,"browser unlink postcondition failed");
                }
                let mut row=client.query_client().query_row("SELECT COUNT(*) AS total FROM usid_external_identity WHERE user_id=$owner").param("$owner",identity).await?;
                let total:u64=row.remove_field_by_name("total")?.try_into()?;
                ensure!(total==0,"legacy bindings survived browser unlink");
                ensure!(id_runtime::session_store::restore_django_principal(&client,std::sync::Arc::new(codec),&token,id_runtime::session_store::LEGACY_BACKENDS,SystemTime::now()).await?.is_some(),"browser unlink revoked session");
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        bail!("provider browser completion timed out")
    }.await;
    // The setup transaction committed all fixture-owned rows before reaching cleanup.
    for table in [
        "socialaccount_socialaccount",
        "accounts_accountevent",
        "account_emailaddress",
        "accounts_accountemaillookup",
        "accounts_accountidentity",
    ] {
        client
            .query_client()
            .exec(format!("DELETE FROM {table} WHERE user_id=$owner"))
            .param("$owner", owner)
            .await?;
    }
    client
        .query_client()
        .exec("DELETE FROM usid_external_identity WHERE user_id=$owner")
        .param("$owner", identity)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM usid_user WHERE user_id=$owner")
        .param("$owner", identity)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM django_session WHERE session_key=$key")
        .param("$key", token)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM auth_user WHERE id=$owner")
        .param("$owner", owner)
        .await?;
    result
}
