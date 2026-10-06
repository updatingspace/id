//! Conservative identity backfill on disposable local YDB.

use anyhow::{Result, ensure};
use id_runtime::identity_reconcile::reconcile;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires Rust-bootstrapped local YDB"]
async fn creates_only_unambiguous_bindings_and_preserves_subject() -> Result<()> {
    ensure!(
        matches!(
            std::env::var("YDB_ENDPOINT")?.as_str(),
            "grpc://localhost:2136" | "grpc://127.0.0.1:2136"
        ) && std::env::var("YDB_DATABASE")? == "/local",
        "test must use local YDB"
    );
    let client = id_runtime::connect_ydb().await?;
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros();
    let base = -i32::try_from(stamp % 1_000_000_000 + 100)?;
    let ids = [base, base - 1, base - 2, base - 3, base - 4];
    let existing_master = Uuid::new_v4();
    let preserved_subject = format!("fixed-sub-{stamp}");
    for (offset, id) in ids.iter().enumerate() {
        let email = format!("rust-identity-{stamp}-{offset}@example.invalid");
        client.query_client().exec("UPSERT INTO auth_user (id, password, is_active, username, first_name, last_name, email, is_staff, is_superuser, date_joined) VALUES ($id, '!', $active, $name, '', '', $email, false, false, CurrentUtcDatetime())")
            .param("$id", *id).param("$name", format!("identity-{stamp}-{offset}"))
            .param("$email", email.clone()).param("$active", offset != 4).await?;
        client
            .query_client()
            .exec(
                "UPSERT INTO accounts_accountemaillookup (user_id, email_key) VALUES ($id, $email)",
            )
            .param("$id", *id)
            .param("$email", email)
            .await?;
        if offset < 3 || offset == 4 {
            client.query_client().exec("UPSERT INTO account_emailaddress (id, user_id, email, verified, primary) VALUES ($id, $id, $email, true, true)")
                .param("$id", *id)
                .param("$email", format!("rust-identity-{stamp}-{offset}@example.invalid"))
                .await?;
        }
    }
    client.query_client().exec("UPSERT INTO accounts_accountidentity (user_id, identity_id, public_subject, created_at) VALUES ($id, NULL, $subject, CurrentUtcDatetime())")
        .param("$id", ids[1]).param("$subject", preserved_subject.clone()).await?;
    client.query_client().exec("UPSERT INTO usid_user (user_id, username, display_name, email, email_verified, status, system_admin, created_at) VALUES ($identity, $name, $name, $email, true, 'active', false, CurrentUtcDatetime())")
        .param("$identity", existing_master)
        .param("$name", format!("other-master-{stamp}"))
        .param("$email", format!("rust-identity-{stamp}-2@example.invalid"))
        .await?;

    let outcome: Result<()> = async {
        let dry = reconcile(&client, 1, false).await?;
        ensure!(dry.dry_run && dry.new_bindings == 1 && dry.new_masters_for_bindings == 1 && dry.needs_review == 3,
            "dry-run classification: {dry:?}");
        ensure!(dry.review_reasons.get("existing_master_email") == Some(&1)
            && dry.review_reasons.get("unverified_primary_email") == Some(&1)
            && dry.review_reasons.get("inactive_account") == Some(&1),
            "review reasons: {dry:?}");
        let (left, right) = tokio::join!(reconcile(&client, 1, true), reconcile(&client, 1, true));
        let left = left?;
        let right = right?;
        ensure!(left.new_bindings + right.new_bindings == 1
            && left.new_masters_for_bindings + right.new_masters_for_bindings == 1
            && left.needs_review == 3 && right.needs_review == 3,
            "concurrent apply classification: {left:?}, {right:?}");
        let repeated = reconcile(&client, 2, true).await?;
        ensure!(repeated.new_bindings == 0 && repeated.new_masters_for_bindings == 0 && repeated.needs_review == 3,
            "second run changed identity: {repeated:?}");
        for (id, expected) in [(ids[0], ids[0].to_string()), (ids[1], preserved_subject)] {
            let mut row = client.query_client().query_row("SELECT identity_id, public_subject FROM accounts_accountidentity WHERE user_id = $id")
                .param("$id", id).await?;
            let identity: Option<Uuid> = row.remove_field_by_name("identity_id")?.try_into()?;
            let subject: String = row.remove_field_by_name("public_subject")?.try_into()?;
            ensure!(identity.is_some() && subject == expected, "binding changed subject for {id}");
        }
        ensure!(client.query_client().query_row("SELECT identity_id FROM accounts_accountidentity WHERE user_id = $id")
            .param("$id", ids[2]).optional().await?.is_none(), "conflicted master was attached");
        ensure!(client.query_client().query_row("SELECT identity_id FROM accounts_accountidentity WHERE user_id = $id")
            .param("$id", ids[3]).optional().await?.is_none(), "unverified account gained a master");
        ensure!(client.query_client().query_row("SELECT identity_id FROM accounts_accountidentity WHERE user_id = $id")
            .param("$id", ids[4]).optional().await?.is_none(), "inactive account gained a master");
        Ok(())
    }.await;

    for id in ids {
        if let Some(mut row) = client
            .query_client()
            .query_row("SELECT identity_id FROM accounts_accountidentity WHERE user_id = $id")
            .param("$id", id)
            .optional()
            .await?
        {
            let identity: Option<Uuid> = row.remove_field_by_name("identity_id")?.try_into()?;
            if let Some(identity) = identity {
                client
                    .query_client()
                    .exec("DELETE FROM usid_user WHERE user_id = $identity")
                    .param("$identity", identity)
                    .await?;
            }
        }
        client
            .query_client()
            .exec("DELETE FROM accounts_accountidentity WHERE user_id = $id")
            .param("$id", id)
            .await?;
        client
            .query_client()
            .exec("DELETE FROM account_emailaddress WHERE id = $id")
            .param("$id", id)
            .await?;
        client
            .query_client()
            .exec("DELETE FROM accounts_accountemaillookup WHERE user_id = $id")
            .param("$id", id)
            .await?;
        client
            .query_client()
            .exec("DELETE FROM auth_user WHERE id = $id")
            .param("$id", id)
            .await?;
    }
    client
        .query_client()
        .exec("DELETE FROM usid_user WHERE user_id = $identity")
        .param("$identity", existing_master)
        .await?;
    outcome
}
