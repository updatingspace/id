#![recursion_limit = "256"]
use anyhow::Result;
use axum::{
    Json, Router,
    extract::State,
    http::{StatusCode, header},
    response::IntoResponse,
    routing::get,
};
use serde_json::json;
use std::{net::SocketAddr, sync::Arc};

async fn ready(State(client): State<Arc<ydb::Client>>) -> impl IntoResponse {
    let ok = id_runtime::probe(&client).await.is_ok();
    (
        if ok {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({"status": if ok { "ready" } else { "unavailable" }})),
    )
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter("id_runtime=info")
        .init();
    let client = Arc::new(id_runtime::connect_ydb().await?);
    let mut app = Router::new()
        .route(
            "/healthz",
            get(|| async {
                (
                    [(header::CACHE_CONTROL, "no-store")],
                    Json(json!({"status":"alive"})),
                )
            }),
        )
        .route("/health", get(ready))
        .route("/readyz", get(ready))
        .with_state(client.clone());
    if let Some(config) =
        id_runtime::internal_identity_http::InternalIdentityConfig::from_env(client.clone())?
    {
        app = app.merge(id_runtime::internal_identity_http::router(config));
    }
    if let Some(config) = id_runtime::exchange_http::ExchangeHttpConfig::from_env(client.clone())? {
        app = app.merge(id_runtime::exchange_http::router(config));
    }
    if let Some(config) =
        id_runtime::magic_link_http::MagicLinkHttpConfig::from_env(client.clone())?
    {
        app = app.merge(id_runtime::magic_link_http::router(config));
    }
    if let Some(config) =
        id_runtime::oauth_providers_http::ProvidersHttpConfig::from_env(client.clone())?
    {
        app = app.merge(id_runtime::oauth_providers_http::router(config));
    }
    let me_enabled =
        if let Some(config) = id_runtime::me_http::MeHttpConfig::from_env(client.clone())? {
            app = app.merge(id_runtime::me_http::router(config));
            true
        } else {
            false
        };
    let form_token_enabled = if let Some(config) =
        id_runtime::form_token_http::FormTokenConfig::from_env(client.clone())?
    {
        app = app.merge(id_runtime::form_token_http::router(config));
        true
    } else {
        false
    };
    let login_pilot_enabled =
        if let Some(config) = id_runtime::login_http::LoginHttpConfig::from_env(client.clone())? {
            app = app.merge(id_runtime::login_http::router(config));
            true
        } else {
            false
        };
    let account_jwt_session_pilot_enabled = if let Some(config) =
        id_runtime::account_jwt_http::AccountJwtHttpConfig::from_env(client.clone())?
    {
        app = app.merge(id_runtime::account_jwt_http::router(config));
        true
    } else {
        false
    };
    let account_deletion_pilot_enabled = if let Some(config) =
        id_runtime::account_deletion_http::AccountDeletionHttpConfig::from_env(client.clone())?
    {
        app = app.merge(id_runtime::account_deletion_http::router(config));
        true
    } else {
        false
    };
    let export_pilot_enabled = if let Some(config) =
        id_runtime::data_export_http::ExportHttpConfig::from_env(client.clone())?
    {
        app = app.merge(id_runtime::data_export_http::router(config));
        true
    } else {
        false
    };
    let logout_pilot_enabled = if let Some(config) =
        id_runtime::logout_http::LogoutHttpConfig::from_env(client.clone())?
    {
        app = app.merge(id_runtime::logout_http::router(config));
        true
    } else {
        false
    };
    let profile_pilot_enabled = if let Some(config) =
        id_runtime::profile_http::ProfileHttpConfig::from_env(client.clone())?
    {
        app = app.merge(id_runtime::profile_http::router(config));
        true
    } else {
        false
    };
    let avatar_delete_enabled = if let Some(config) =
        id_runtime::avatar_delete_http::AvatarDeleteHttpConfig::from_env(client.clone())?
    {
        app = app.merge(id_runtime::avatar_delete_http::router(config));
        true
    } else {
        false
    };
    let preferences_pilot_enabled = if let Some(config) =
        id_runtime::preferences_http::PreferencesHttpConfig::from_env(client.clone())?
    {
        app = app.merge(id_runtime::preferences_http::router(config));
        true
    } else {
        false
    };
    let apps_pilot_enabled = if let Some(config) =
        id_runtime::authorized_apps_http::AuthorizedAppsHttpConfig::from_env(client.clone())?
    {
        app = app.merge(id_runtime::authorized_apps_http::router(config));
        true
    } else {
        false
    };
    let oidc_token_pilot_enabled = if let Some(config) =
        id_runtime::oidc_token_http::OidcTokenHttpConfig::from_env(client.clone())?
    {
        app = app.merge(id_runtime::oidc_token_http::router(config));
        true
    } else {
        false
    };
    let oidc_jwks_enabled =
        if let Some(config) = id_runtime::oidc_jwks_http::JwksHttpConfig::from_env()? {
            app = app.merge(id_runtime::oidc_jwks_http::router(config));
            true
        } else {
            false
        };
    let oidc_authorize_pilot_enabled = if let Some(config) =
        id_runtime::oidc_authorize_http::OidcAuthorizeHttpConfig::from_env(client.clone())?
    {
        app = app.merge(id_runtime::oidc_authorize_http::router(config));
        true
    } else {
        false
    };
    let security_read_pilot_enabled = if let Some(config) =
        id_runtime::security_http::SecurityReadHttpConfig::from_env(client.clone())?
    {
        app = app.merge(id_runtime::security_http::router(config));
        true
    } else {
        false
    };
    let email_cancel_pilot_enabled = if let Some(config) =
        id_runtime::email_cancel_http::EmailCancelHttpConfig::from_env(client.clone())?
    {
        app = app.merge(id_runtime::email_cancel_http::router(config));
        true
    } else {
        false
    };
    let totp_setup_pilot_enabled = if let Some(config) =
        id_runtime::totp_setup_http::TotpSetupHttpConfig::from_env(client.clone())?
    {
        app = app.merge(id_runtime::totp_setup_http::router(config));
        true
    } else {
        false
    };
    let password_change_pilot_enabled = if let Some(config) =
        id_runtime::password_change_http::PasswordChangeHttpConfig::from_env(client.clone())?
    {
        app = app.merge(id_runtime::password_change_http::router(config));
        true
    } else {
        false
    };
    let password_reset_pilot_enabled = if let Some(config) =
        id_runtime::password_reset_http::PasswordResetHttpConfig::from_env(client.clone())?
    {
        app = app.merge(id_runtime::password_reset_http::router(config));
        true
    } else {
        false
    };
    let email_verify_pilot_enabled = if let Some(config) =
        id_runtime::email_verify_http::EmailVerifyHttpConfig::from_env(client.clone())?
    {
        app = app.merge(id_runtime::email_verify_http::router(config));
        true
    } else {
        false
    };
    let signup_pilot_enabled = if let Some(config) =
        id_runtime::signup_http::SignupHttpConfig::from_env(client.clone())?
    {
        app = app.merge(id_runtime::signup_http::router(config));
        true
    } else {
        false
    };
    let sessions_pilot_enabled =
        if let Some(config) = id_runtime::sessions_http::SessionsHttpConfig::from_env(client)? {
            app = app.merge(id_runtime::sessions_http::router(config));
            true
        } else {
            false
        };
    let port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| "8081".into())
        .parse()?;
    let listener = tokio::net::TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], port))).await?;
    tracing::info!(
        port,
        me_enabled,
        form_token_enabled,
        login_pilot_enabled,
        account_jwt_session_pilot_enabled,
        account_deletion_pilot_enabled,
        export_pilot_enabled,
        logout_pilot_enabled,
        profile_pilot_enabled,
        avatar_delete_enabled,
        preferences_pilot_enabled,
        apps_pilot_enabled,
        oidc_token_pilot_enabled,
        oidc_jwks_enabled,
        oidc_authorize_pilot_enabled,
        security_read_pilot_enabled,
        email_cancel_pilot_enabled,
        totp_setup_pilot_enabled,
        password_change_pilot_enabled,
        password_reset_pilot_enabled,
        email_verify_pilot_enabled,
        signup_pilot_enabled,
        sessions_pilot_enabled,
        "Rust API pilot listening"
    );
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async {
        #[cfg(unix)]
        {
            if let Ok(mut term) =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            {
                tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = term.recv() => {} }
                return;
            }
        }
        let _ = tokio::signal::ctrl_c().await;
    })
    .await?;
    Ok(())
}
