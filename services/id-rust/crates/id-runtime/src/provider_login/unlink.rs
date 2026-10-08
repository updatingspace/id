//! Owner-scoped unlinking. Disabling a provider must not prevent removing its binding.
use super::*;
use crate::credential_methods::has_remaining_login_tx;

struct Config {
    login: Arc<LoginHttpConfig>,
    providers: Vec<Arc<ProviderLoginConfig>>,
}

pub fn router(login: Arc<LoginHttpConfig>, providers: Vec<Arc<ProviderLoginConfig>>) -> Router {
    Router::new()
        .route("/api/v1/auth/oauth/unlink", post(unlink).options(preflight))
        .with_state(Arc::new(Config { login, providers }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    provider: Provider,
}

fn response(config: &Config, headers: &HeaderMap, status: StatusCode, code: &str) -> Response {
    let body = if status == StatusCode::OK {
        json!({"ok":true,"message":"Провайдер отключён"})
    } else {
        json!({"code":code,"message":match code {
            "LAST_LOGIN_METHOD" => "Добавьте другой способ входа, прежде чем отключать провайдера",
            "REAUTH_REQUIRED" => "Подтвердите вход в аккаунт и повторите действие",
            _ => code,
        }})
    };
    login_http::json_response(
        headers,
        &config.login.options,
        status,
        body,
        login_http::make_csrf_cookie(headers, &config.login.options, false),
        None,
    )
}

async fn preflight(State(config): State<Arc<Config>>, headers: HeaderMap) -> Response {
    login_http::json_response(
        &headers,
        &config.login.options,
        StatusCode::NO_CONTENT,
        Value::Null,
        login_http::make_csrf_cookie(&headers, &config.login.options, false),
        None,
    )
}

async fn unlink(State(config): State<Arc<Config>>, request: Request) -> Response {
    let headers = request.headers().clone();
    let input: Input = match read_credential_json(&config.login, request).await {
        Ok(value) => value,
        Err((status, code)) => return response(&config, &headers, status, code),
    };
    let Some(token) = credential_cookie(&config.login, &headers) else {
        return response(
            &config,
            &headers,
            StatusCode::UNAUTHORIZED,
            "AUTHENTICATION_REQUIRED",
        );
    };
    let now = SystemTime::now();
    let outcome = retry_known_abort(|| {
        let config = config.clone();
        let token = token.clone();
        async move {
            config.login.client.query_client().retry_tx(closure!([config, token], async |tx: &mut Transaction| {
                let owner = match credential_owner(tx, &config.login, token, now).await? {
                    Ok(owner) => owner,
                    Err(code) => return Ok(code),
                };
                let provider = input.provider;
                // Collect both legacy representations before any write. Resolve every
                // exact subject with the login resolver, including cross-table conflicts.
                let mut subjects = std::collections::BTreeSet::<String>::new();
                let mut rows = tx.query("SELECT uid FROM socialaccount_socialaccount VIEW socialaccount_socialaccount_user_id_8146e70c WHERE user_id = $owner AND provider = $provider LIMIT 1001")
                    .param("$owner", owner.account_id).param("$provider", provider.id().to_owned()).await?;
                let mut count = 0;
                while let Some(set) = rows.next_result_set().await? {
                    for mut row in set { count += 1; subjects.insert(row.remove_field_by_name("uid")?.try_into()?); }
                }
                rows.close().await?;
                let mut rows = tx.query("SELECT subject FROM usid_external_identity VIEW usid_external_identity_user_id_b18cc632 WHERE user_id = $owner AND provider = $provider LIMIT 1001")
                    .param("$owner", owner.identity_id).param("$provider", provider.id().to_owned()).await?;
                while let Some(set) = rows.next_result_set().await? {
                    for mut row in set { count += 1; subjects.insert(row.remove_field_by_name("subject")?.try_into()?); }
                }
                rows.close().await?;
                if count > 1000 { return Ok("IDENTITY_CONFLICT"); }
                if subjects.is_empty() { return Ok("NOT_FOUND"); }
                let mut bindings = Vec::new();
                for subject in subjects {
                    match resolve_binding(tx, provider, &subject).await? {
                        BindingResolution::Linked(binding) if binding.account_id == owner.account_id && binding.identity_id == owner.identity_id => bindings.push(binding),
                        _ => return Ok("IDENTITY_CONFLICT"),
                    }
                }
                let remaining_providers = config.providers.iter().filter(|candidate| candidate.provider != provider).cloned().collect::<Vec<_>>();
                let passkeys = factors(tx, owner.account_id).await?.passkey_ids;
                if !has_remaining_login_tx(tx, owner.account_id, &passkeys, &remaining_providers).await? {
                    return Ok("LAST_LOGIN_METHOD");
                }
                // Pending provider/MFA proofs re-resolve these exact binding IDs
                // when issuing a session, so removal also invalidates those proofs.
                for binding in bindings {
                    if let Some(id) = binding.social_id {
                        tx.exec("DELETE FROM socialaccount_socialtoken WHERE account_id = $id").param("$id", id).await?;
                        tx.exec("DELETE FROM socialaccount_socialaccount WHERE id = $id").param("$id", id).await?;
                    }
                    if let Some(id) = binding.external_id {
                        tx.exec("DELETE FROM usid_external_identity WHERE id = $id").param("$id", id).await?;
                    }
                }
                let meta = json!({"provider":provider.id()}).to_string();
                tx.exec("INSERT INTO accounts_accountevent (user_id, action, meta, created_at) VALUES ($owner, 'provider.unlinked', Unwrap(CAST($meta AS Json)), CAST($now AS Datetime))")
                    .param("$owner", owner.account_id).param("$meta", meta).param("$now", now).await?;
                Ok("OK")
            })).with_mode(TxMode::SerializableReadWrite).idempotent(false).timeout(Duration::from_secs(10)).await
        }
    }).await;
    let (status, code) = match outcome {
        Ok("OK") => (StatusCode::OK, "OK"),
        Ok("AUTHENTICATION_REQUIRED") => (StatusCode::UNAUTHORIZED, "AUTHENTICATION_REQUIRED"),
        Ok("REAUTH_REQUIRED") => (StatusCode::FORBIDDEN, "REAUTH_REQUIRED"),
        Ok("NOT_FOUND") => (StatusCode::NOT_FOUND, "NOT_FOUND"),
        Ok("LAST_LOGIN_METHOD") => (StatusCode::CONFLICT, "LAST_LOGIN_METHOD"),
        Ok("IDENTITY_CONFLICT") => (StatusCode::CONFLICT, "IDENTITY_CONFLICT"),
        _ => (StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE"),
    };
    response(&config, &headers, status, code)
}
