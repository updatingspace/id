// Included only in the private unit-test module: no production race hooks.

async fn committed_state(
    client: &Client,
    client_id: &str,
    actor: uuid::Uuid,
    expected: Option<&StoredClient>,
    audit_count: u64,
) -> Result<()> {
    let id = client_id.to_owned();
    let stored = client
        .query_client()
        .retry_tx(closure!([id], async |tx: &mut Transaction| {
            read_tx(tx, id).await
        }))
        .isolation(TxMode::SnapshotReadOnly)
        .await?;
    ensure!(
        stored.as_ref().map(StoredClient::revision).transpose()?
            == expected.map(StoredClient::revision).transpose()?,
        "unexpected committed client revision"
    );
    let mut row = client
        .query_client()
        .query_row("SELECT COUNT(*) AS count FROM usid_audit_log WHERE actor_user_id = $actor")
        .param("$actor", actor)
        .await?;
    let count: u64 = row.remove_field_by_name("count")?.try_into()?;
    ensure!(
        count == audit_count,
        "rejected mutation wrote an audit or successful mutation lost it"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires migrated local YDB on localhost:2136 and /local"]
async fn commit_guards_ydb() -> Result<()> {
    ensure!(
        matches!(
            std::env::var("YDB_ENDPOINT")?.as_str(),
            "grpc://localhost:2136" | "grpc://127.0.0.1:2136"
        ) && std::env::var("YDB_DATABASE")? == "/local",
        "commit guard test refuses non-local YDB"
    );
    let client = crate::connect_ydb().await?;
    let identity = uuid::Uuid::new_v4();
    let account_id = 1_700_000_000 + (rand::random::<u32>() % 100_000_000) as i32;
    let client_id = format!("commit-guards-{}", identity.simple());
    let token = format!("guard-session-{}", identity.simple());
    let codec = Arc::new(SessionCodec::new(
        b"synthetic-commit-guard-session-secret-at-least-32",
        &[],
    )?);
    let password = "synthetic-commit-guard-password";
    let password_hash =
        tokio::task::spawn_blocking(move || id_compat::password::hash_new(password)).await??;
    let payload = serde_json::json!({
        "_auth_user_id": account_id.to_string(),
        "_auth_user_backend": LEGACY_BACKENDS[0],
        "_auth_user_hash": codec.auth_hash(&password_hash)?,
        "id_mfa_verified_user_id": account_id.to_string(),
    });
    let now = now_seconds()?;
    let expires = now + Duration::from_secs(3600);
    let encoded = codec.encode(
        payload
            .as_object()
            .ok_or_else(|| anyhow!("session object"))?,
        i64::try_from(now.duration_since(UNIX_EPOCH)?.as_secs())?,
        true,
    )?;
    let record = StoredClient {
        id: i64::from(account_id),
        client_id: client_id.clone(),
        name: "Commit guard test".into(),
        description: String::new(),
        logo_url: String::new(),
        redirects: "[\"https://rp.example.invalid/callback\"]".into(),
        scopes: "[\"openid\"]".into(),
        grants: "[\"authorization_code\"]".into(),
        responses: "[\"code\"]".into(),
        is_public: false,
        is_first_party: false,
        secret_hash: password_hash.clone(),
        updated_at: now,
    };
    // All inserts either commit together or leave pre-existing fixture IDs alone.
    client.query_client().retry_tx(closure!([token, encoded, password_hash, client_id], async |tx: &mut Transaction| {
        tx.exec("INSERT INTO auth_user (id, password, is_active, username, first_name, last_name, email, is_staff, is_superuser, date_joined) VALUES ($id, $hash, true, $name, '', '', 'guard@example.invalid', true, true, CurrentUtcDatetime())")
            .param("$id", account_id).param("$hash", password_hash.clone()).param("$name", client_id.clone()).await?;
        tx.exec("INSERT INTO usid_user (user_id, username, display_name, email, email_verified, status, system_admin, created_at) VALUES ($id, $name, '', 'guard@example.invalid', true, 'active', false, CurrentUtcDatetime())")
            .param("$id", identity).param("$name", client_id.clone()).await?;
        tx.exec("INSERT INTO accounts_accountidentity (user_id, identity_id, public_subject, created_at) VALUES ($user, $identity, $subject, CurrentUtcDatetime())")
            .param("$user", account_id).param("$identity", identity).param("$subject", client_id.clone()).await?;
        tx.exec("INSERT INTO django_session (session_key, session_data, expire_date) VALUES ($key, $data, CAST($expires AS Datetime))")
            .param("$key", token.clone()).param("$data", encoded.clone()).param("$expires", expires).await?;
        tx.exec("INSERT INTO mfa_authenticator (id, user_id, type, data, created_at) VALUES ($id, $user, 'totp', Unwrap(CAST('{}' AS Json)), CurrentUtcDatetime())")
            .param("$id", i64::from(account_id)).param("$user", account_id).await?;
        Ok(())
    })).isolation(TxMode::SerializableReadWrite).idempotent(false).await?;

    let client_id = record.client_id.clone();
    let token = format!("guard-session-{}", identity.simple());
    let encoded = codec.encode(
        payload
            .as_object()
            .ok_or_else(|| anyhow!("session object"))?,
        i64::try_from(now.duration_since(UNIX_EPOCH)?.as_secs())?,
        true,
    )?;
    let result: Result<()> = async {
        let actor = operator(&client, codec.clone(), token.clone(), password.into()).await?;
        // Both contenders finish their real review before either can commit.
        for _ in 0..2 {
            ensure!(review(&client, codec.clone(), actor.clone(), client_id.clone()).await?.is_none());
        }
        client.query_client().exec("UPDATE auth_user SET is_staff = false WHERE id = $id")
            .param("$id", account_id).await?;
        ensure!(commit(&client, codec.clone(), actor.clone(), record.clone(), None).await.is_err(),
            "commit accepted authority revoked after review");
        committed_state(&client, &client_id, identity, None, 0).await?;
        client.query_client().exec("UPDATE auth_user SET is_staff = true WHERE id = $id")
            .param("$id", account_id).await?;

        client.query_client().exec("DELETE FROM django_session WHERE session_key = $key")
            .param("$key", token.clone()).await?;
        ensure!(commit(&client, codec.clone(), actor.clone(), record.clone(), None).await.is_err(),
            "commit accepted session revoked after review");
        committed_state(&client, &client_id, identity, None, 0).await?;
        client.query_client().exec("INSERT INTO django_session (session_key, session_data, expire_date) VALUES ($key, $data, CAST($expires AS Datetime))")
            .param("$key", token.clone()).param("$data", encoded).param("$expires", expires).await?;

        commit(&client, codec.clone(), actor.clone(), record.clone(), None).await?;
        let mut contender = record.clone();
        contender.id += 1;
        ensure!(commit(&client, codec.clone(), actor.clone(), contender, None).await.is_err(),
            "second reviewed create duplicated the client_id");
        committed_state(&client, &client_id, identity, Some(&record), 1).await?;

        let reviewed = review(&client, codec.clone(), actor.clone(), client_id.clone()).await?
            .ok_or_else(|| anyhow!("created client missing"))?;
        let previous = reviewed.revision()?;
        let mut rotated = reviewed.clone();
        rotated.secret_hash = new_secret().await?.1;
        client.query_client().exec("UPDATE idp_oidcclient SET description = 'changed after review' WHERE id = $id")
            .param("$id", record.id).await?;
        ensure!(commit(&client, codec.clone(), actor.clone(), rotated.clone(), Some(previous)).await.is_err(),
            "rotation accepted a revision changed after review");
        let mut changed = reviewed;
        changed.description = "changed after review".into();
        committed_state(&client, &client_id, identity, Some(&changed), 1).await?;
        // A fresh review of the same change remains usable: failures above are
        // guard rejections rather than invalid fixture data or broken writes.
        let fresh = review(&client, codec.clone(), actor.clone(), client_id.clone()).await?
            .ok_or_else(|| anyhow!("changed client missing"))?;
        let previous = fresh.revision()?;
        rotated.description = fresh.description;
        commit(&client, codec.clone(), actor, rotated.clone(), Some(previous)).await?;
        committed_state(&client, &client_id, identity, Some(&rotated), 2).await?;
        Ok(())
    }.await;

    client
        .query_client()
        .exec("DELETE FROM idp_oidcclient WHERE client_id = $id")
        .param("$id", client_id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM usid_audit_log WHERE actor_user_id = $id")
        .param("$id", identity)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM django_session WHERE session_key = $key")
        .param("$key", token)
        .await?;
    for table in ["mfa_authenticator", "accounts_accountidentity"] {
        client
            .query_client()
            .exec(format!("DELETE FROM `{table}` WHERE user_id = $id"))
            .param("$id", account_id)
            .await?;
    }
    client
        .query_client()
        .exec("DELETE FROM usid_user WHERE user_id = $id")
        .param("$id", identity)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM auth_user WHERE id = $id")
        .param("$id", account_id)
        .await?;
    result
}
