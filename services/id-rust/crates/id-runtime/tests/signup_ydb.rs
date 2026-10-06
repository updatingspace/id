//! New Rust account, identity and verification intent must commit together.

use anyhow::{Context, Result, ensure};
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use cookie::SameSite;
use id_runtime::cache_store::CacheStore;
use id_runtime::{
    email_verify::{self, VerifyKey},
    signup::{self, SignupInput, SignupResult},
};
use serde_json::{Value, json};
use std::{sync::Arc, time::SystemTime};
use tokio::sync::Semaphore;
use tower::ServiceExt;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires migrated local YDB"]
async fn creates_identity_once_and_verifies_new_email() -> Result<()> {
    ensure!(
        std::env::var("YDB_DATABASE")? == "/local",
        "test requires local YDB"
    );
    let client = Arc::new(id_runtime::connect_ydb().await?);
    email_verify::ensure_schema(&client).await?;
    let slots = Arc::new(Semaphore::new(2));
    let unique = Uuid::new_v4().simple().to_string();
    let email = format!("signup-{unique}@example.invalid");
    let input = |suffix: &str| SignupInput {
        username: format!("signup-{unique}-{suffix}"),
        email: email.clone(),
        password: "A strong, unusual registration password 2026!".into(),
        language: "ru".into(),
        timezone: "Europe/Moscow".into(),
        consent_data_processing: true,
        consent_marketing: false,
        is_minor: false,
        guardian_email: None,
        guardian_consent: false,
        birth_date: None,
    };
    let (first, second) = tokio::try_join!(
        signup::create(&client, &slots, input("one"), SystemTime::now()),
        signup::create(&client, &slots, input("two"), SystemTime::now()),
    )?;
    ensure!([first, second].contains(&SignupResult::Created));
    ensure!([first, second].contains(&SignupResult::EmailExists));
    let mut query = client.query_client();
    let mut rows = query.query("SELECT user_id FROM accounts_accountemaillookup VIEW acct_email_key_idx WHERE email_key = $email")
        .param("$email", email.clone()).await?;
    let mut users = Vec::<i32>::new();
    while let Some(set) = rows.next_result_set().await? {
        for mut row in set {
            users.push(row.remove_field_by_name("user_id")?.try_into()?);
        }
    }
    rows.close().await?;
    ensure!(
        users.len() == 1 && users[0] < 0,
        "email has multiple owners"
    );
    let user_id = users[0];
    let mut query = client.query_client();
    let mut row = query
        .query_row("SELECT password, is_active FROM auth_user WHERE id = $id")
        .param("$id", user_id)
        .await?;
    let hash: String = row.remove_field_by_name("password")?.try_into()?;
    let active: bool = row.remove_field_by_name("is_active")?.try_into()?;
    ensure!(
        active
            && id_compat::password::verify("A strong, unusual registration password 2026!", &hash)?
    );
    let mut query = client.query_client();
    let mut row = query
        .query_row(
            "SELECT identity_id, public_subject FROM accounts_accountidentity WHERE user_id = $id",
        )
        .param("$id", user_id)
        .await?;
    let identity: Option<Uuid> = row.remove_field_by_name("identity_id")?.try_into()?;
    let identity = identity.context("new account has no master identity")?;
    let subject: String = row.remove_field_by_name("public_subject")?.try_into()?;
    ensure!(subject == identity.to_string());
    let mut query = client.query_client();
    let mut row = query
        .query_row("SELECT email_verified FROM usid_user WHERE user_id = $id")
        .param("$id", identity)
        .await?;
    let verified: bool = row.remove_field_by_name("email_verified")?.try_into()?;
    ensure!(!verified);
    let mut query = client.query_client();
    let mut rows = query
        .query("SELECT id FROM id_email_verification WHERE user_id = $id")
        .param("$id", user_id)
        .await?;
    let mut mail_ids = Vec::<String>::new();
    while let Some(set) = rows.next_result_set().await? {
        for mut row in set {
            mail_ids.push(row.remove_field_by_name("id")?.try_into()?);
        }
    }
    rows.close().await?;
    ensure!(mail_ids.len() == 1, "signup lost verification intent");
    let key = VerifyKey::new([11; 32])?;
    let token = key.issue(Uuid::parse_str(
        mail_ids.first().context("missing mail intent")?,
    )?)?;
    ensure!(
        email_verify::confirm(&client, &key, &token, SystemTime::now()).await?
            == email_verify::ConfirmResult::Verified
    );
    ensure!(
        email_verify::confirm(&client, &key, &token, SystemTime::now()).await?
            == email_verify::ConfirmResult::Invalid
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires migrated local YDB"]
async fn minor_signup_persists_birth_date_and_parental_consent() -> Result<()> {
    ensure!(std::env::var("YDB_DATABASE")? == "/local");
    let client = Arc::new(id_runtime::connect_ydb().await?);
    email_verify::ensure_schema(&client).await?;
    let unique = Uuid::new_v4().simple().to_string();
    let email = format!("minor-{unique}@example.invalid");
    let birth_date = chrono::Utc::now()
        .date_naive()
        .checked_sub_months(chrono::Months::new(17 * 12))
        .context("birth date underflow")?;
    let result = signup::create(
        &client,
        &Semaphore::new(1),
        SignupInput {
            username: format!("minor-{unique}"),
            email: email.clone(),
            password: "A strong, unusual registration password 2026!".into(),
            language: "ru".into(),
            timezone: "Europe/Moscow".into(),
            consent_data_processing: true,
            consent_marketing: false,
            is_minor: false,
            guardian_email: Some(" Guardian@Example.Invalid ".into()),
            guardian_consent: true,
            birth_date: Some(birth_date),
        },
        SystemTime::now(),
    )
    .await?;
    assert_eq!(result, SignupResult::Created);
    let mut row = client
        .query_client()
        .query_row("SELECT user_id FROM accounts_accountemaillookup VIEW acct_email_key_idx WHERE email_key = $email")
        .param("$email", email)
        .await?;
    let user_id: i32 = row.remove_field_by_name("user_id")?.try_into()?;
    let mut row = client
        .query_client()
        .query_row("SELECT CAST(birth_date AS Utf8) AS birth_date FROM accounts_userprofile VIEW acct_profile_user_idx WHERE user_id = $id")
        .param("$id", user_id)
        .await?;
    let stored_birth: Option<String> = row.remove_field_by_name("birth_date")?.try_into()?;
    assert_eq!(stored_birth, Some(birth_date.to_string()));
    let mut row = client
        .query_client()
        .query_row("SELECT CAST(meta AS Utf8) AS meta FROM accounts_userconsent VIEW acct_consent_user_kind_idx WHERE user_id = $id AND kind = 'parental'")
        .param("$id", user_id)
        .await?;
    let meta: String = row.remove_field_by_name("meta")?.try_into()?;
    assert_eq!(
        serde_json::from_str::<Value>(&meta)?,
        json!({"guardian_email":"guardian@example.invalid"})
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires migrated local YDB and opt-in signup HTTP"]
async fn http_signup_requires_csrf_and_returns_no_session() -> Result<()> {
    ensure!(std::env::var("YDB_DATABASE")? == "/local");
    ensure!(std::env::var("ID_AUTH_SIGNUP_PILOT_ENABLED")? == "true");
    let client = Arc::new(id_runtime::connect_ydb().await?);
    email_verify::ensure_schema(&client).await?;
    client.query_client().exec("CREATE TABLE IF NOT EXISTS id_shared_cache (cache_key Utf8 NOT NULL, value String, expires_at Uint64, PRIMARY KEY (cache_key))").await?;
    let cache = CacheStore::new(client.clone(), "id_shared_cache", "", 1)?;
    let form = id_runtime::form_token_http::FormTokenConfig::new(
        cache,
        "csrftoken".into(),
        false,
        SameSite::Lax,
        None,
    )?;
    let signup = id_runtime::signup_http::SignupHttpConfig::from_env(client.clone())?
        .context("signup pilot disabled")?;
    let app = id_runtime::form_token_http::router(Arc::new(form))
        .merge(id_runtime::signup_http::router(signup));
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/form_token?purpose=register")
                .body(Body::empty())?,
        )
        .await?;
    ensure!(response.status() == StatusCode::OK);
    let csrf = cookie::Cookie::parse(
        response
            .headers()
            .get(header::SET_COOKIE)
            .context("CSRF cookie missing")?
            .to_str()?
            .to_owned(),
    )?
    .value()
    .to_owned();
    let form: Value = serde_json::from_slice(&to_bytes(response.into_body(), 4096).await?)?;
    let email = format!("http-signup-{}@example.invalid", Uuid::new_v4().simple());
    let payload = json!({"username":format!("http-{}", Uuid::new_v4().simple()),"email":email,"password":"A strong and unusual registration password 2026!","form_token":form["form_token"],"consent_data_processing":true,"consent_marketing":true});
    let post = |csrf_header: bool| {
        let app = app.clone();
        let payload = payload.clone();
        let csrf = csrf.clone();
        async move {
            let mut builder = Request::builder()
                .method("POST")
                .uri("/api/v1/auth/signup")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ORIGIN, "http://localhost:5175")
                .header(header::COOKIE, format!("csrftoken={csrf}"));
            if csrf_header {
                builder = builder.header("x-csrftoken", csrf);
            }
            Ok::<_, anyhow::Error>(
                app.oneshot(builder.body(Body::from(payload.to_string()))?)
                    .await?,
            )
        }
    };
    ensure!(post(false).await?.status() == StatusCode::FORBIDDEN);
    let response = post(true).await?;
    ensure!(
        response.status() == StatusCode::CREATED,
        "signup returned {}",
        response.status()
    );
    ensure!(
        response.headers().get(header::SET_COOKIE).is_none(),
        "signup issued a session cookie"
    );
    let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), 4096).await?)?;
    ensure!(body == json!({"meta":{"session_token":""},"verification_required":true}));
    let mut query = client.query_client();
    let mut row = query.query_row("SELECT user_id FROM accounts_accountemaillookup VIEW acct_email_key_idx WHERE email_key = $email")
        .param("$email", email).await?;
    let user_id: i32 = row.remove_field_by_name("user_id")?.try_into()?;
    let mut query = client.query_client();
    let mut row = query.query_row("SELECT marketing_opt_in, marketing_opt_in_at FROM accounts_userpreferences WHERE user_id = $id")
        .param("$id", user_id).await?;
    let opted_in: bool = row.remove_field_by_name("marketing_opt_in")?.try_into()?;
    let opted_at: Option<SystemTime> = row
        .remove_field_by_name("marketing_opt_in_at")?
        .try_into()?;
    ensure!(
        opted_in && opted_at.is_some(),
        "marketing consent not persisted coherently"
    );
    let replay = post(true).await?;
    ensure!(
        replay.status() == StatusCode::BAD_REQUEST,
        "signup form token was reusable"
    );
    let issued = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/form_token?purpose=register")
                .body(Body::empty())?,
        )
        .await?;
    let minor_csrf = cookie::Cookie::parse(
        issued
            .headers()
            .get(header::SET_COOKIE)
            .context("minor CSRF cookie missing")?
            .to_str()?
            .to_owned(),
    )?
    .value()
    .to_owned();
    let minor_form: Value = serde_json::from_slice(&to_bytes(issued.into_body(), 4096).await?)?;
    let birth_date = chrono::Utc::now()
        .date_naive()
        .checked_sub_months(chrono::Months::new(17 * 12))
        .context("birth date underflow")?;
    let mut minor = json!({
        "username": format!("http-minor-{}", Uuid::new_v4().simple()),
        "email": format!("http-minor-{}@example.invalid", Uuid::new_v4().simple()),
        "password": "A strong and unusual registration password 2026!",
        "form_token": minor_form["form_token"],
        "consent_data_processing": true,
        "birth_date": birth_date.to_string(),
    });
    let minor_post = |payload: Value| {
        let app = app.clone();
        let csrf = minor_csrf.clone();
        async move {
            Ok::<_, anyhow::Error>(
                app.oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/v1/auth/signup")
                        .header(header::CONTENT_TYPE, "application/json")
                        .header(header::ORIGIN, "http://localhost:5175")
                        .header(header::COOKIE, format!("csrftoken={csrf}"))
                        .header("x-csrftoken", csrf)
                        .body(Body::from(payload.to_string()))?,
                )
                .await?,
            )
        }
    };
    let rejected = minor_post(minor.clone()).await?;
    ensure!(rejected.status() == StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(&to_bytes(rejected.into_body(), 4096).await?)?;
    ensure!(body["code"] == "PARENTAL_CONSENT_REQUIRED");
    minor["guardian_consent"] = json!(true);
    let rejected = minor_post(minor.clone()).await?;
    ensure!(rejected.status() == StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(&to_bytes(rejected.into_body(), 4096).await?)?;
    ensure!(body["code"] == "GUARDIAN_EMAIL_REQUIRED");
    minor["guardian_email"] = json!("guardian@example.invalid");
    let created = minor_post(minor).await?;
    ensure!(created.status() == StatusCode::CREATED);
    ensure!(created.headers().get(header::SET_COOKIE).is_none());
    Ok(())
}
