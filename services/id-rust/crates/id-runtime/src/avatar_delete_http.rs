//! Avatar upload and deletion backed by Rust and private S3.

use crate::{
    avatar_delete::{DeleteResult, delete as delete_avatar, read as read_avatar},
    avatar_upload::{UploadResult, normalize, upload as upload_avatar},
    logout_http::{cookie_value, csrf_allowed},
    me_http::env_flag,
    media_delete::S3MediaDelete,
    media_url::MediaUrl,
    profile_http::{add_cors_methods, error, json_response},
    session_store::{LEGACY_BACKENDS, session_codec_from_env},
};
use anyhow::{Context, Result, bail};
use axum::{
    Router,
    extract::{DefaultBodyLimit, Multipart, Request, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
};
use id_compat::{headers::session_token, session::SessionCodec};
use serde_json::json;
use std::{env, sync::Arc, time::SystemTime};
use url::Url;
use ydb::Client;

pub struct AvatarDeleteHttpConfig {
    client: Arc<Client>,
    codec: Arc<SessionCodec>,
    media: S3MediaDelete,
    media_url: Option<MediaUrl>,
    session_cookie_name: String,
    csrf_cookie_name: String,
    trusted_origins: Vec<String>,
}

impl AvatarDeleteHttpConfig {
    pub fn new(
        client: Arc<Client>,
        codec: Arc<SessionCodec>,
        media: S3MediaDelete,
        media_url: Option<MediaUrl>,
        trusted_origins: Vec<String>,
    ) -> Arc<Self> {
        Arc::new(Self {
            client,
            codec,
            media,
            media_url,
            session_cookie_name: env::var("SESSION_COOKIE_NAME")
                .unwrap_or_else(|_| "sessionid".into()),
            csrf_cookie_name: env::var("CSRF_COOKIE_NAME").unwrap_or_else(|_| "csrftoken".into()),
            trusted_origins,
        })
    }

    pub fn from_env(client: Arc<Client>) -> Result<Option<Arc<Self>>> {
        let pilot = env_flag("ID_AUTH_AVATAR_DELETE_PILOT_ENABLED", false)?;
        let rollout = env_flag("ID_AUTH_AVATAR_DELETE_ROLLOUT_ENABLED", false)?;
        let upload_pilot = env_flag("ID_AUTH_AVATAR_UPLOAD_PILOT_ENABLED", false)?;
        let upload_rollout = env_flag("ID_AUTH_AVATAR_UPLOAD_ROLLOUT_ENABLED", false)?;
        if !pilot && !rollout && !upload_pilot && !upload_rollout {
            return Ok(None);
        }
        let endpoint = Url::parse(&env::var("YDB_ENDPOINT")?)?;
        let local = env_flag("DJANGO_DEBUG", false)?
            && matches!(
                endpoint.host_str(),
                Some("localhost" | "127.0.0.1" | "[::1]")
            )
            && env::var("YDB_DATABASE")?.as_str() == "/local";
        if (pilot || upload_pilot) && !local {
            bail!("avatar pilot requires local debug YDB")
        }
        if (rollout || upload_rollout)
            && !local
            && !env_flag("ID_RUST_EARLY_ROLLOUT_ENABLED", false)?
        {
            bail!("avatar rollout requires ID_RUST_EARLY_ROLLOUT_ENABLED")
        }
        let trusted_origins = env::var("CSRF_TRUSTED_ORIGINS")
            .unwrap_or_else(|_| "http://id.localhost,http://localhost:5175".into())
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|raw| {
                let url = Url::parse(raw)?;
                if !matches!(url.scheme(), "http" | "https")
                    || url.path() != "/"
                    || url.query().is_some()
                    || url.fragment().is_some()
                    || !url.username().is_empty()
                    || url.password().is_some()
                {
                    bail!("invalid trusted origin for avatar deletion")
                }
                Ok(url.origin().ascii_serialization())
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Some(Self::new(
            client,
            session_codec_from_env()?,
            S3MediaDelete::from_env()?.context("avatar deletion requires private S3")?,
            if upload_pilot || upload_rollout {
                Some(MediaUrl::from_env(&env::var("MEDIA_PUBLIC_BASE_URL")?)?)
            } else {
                None
            },
            trusted_origins,
        )))
    }
}

pub fn router(config: Arc<AvatarDeleteHttpConfig>) -> Router {
    Router::new()
        .route(
            "/api/v1/auth/avatar",
            post(upload).delete(remove).options(preflight),
        )
        .layer(DefaultBodyLimit::max(6 * 1024 * 1024 + 64 * 1024))
        .with_state(config)
}

async fn upload(
    State(config): State<Arc<AvatarDeleteHttpConfig>>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Response {
    let mut response = upload_inner(&config, &headers, &mut multipart).await;
    add_cors_methods(
        response.headers_mut(),
        &headers,
        &config.trusted_origins,
        "POST, DELETE, OPTIONS",
    );
    response
}

async fn upload_inner(
    config: &AvatarDeleteHttpConfig,
    headers: &HeaderMap,
    multipart: &mut Multipart,
) -> Response {
    let Some(media_url) = config.media_url.as_ref() else {
        return error(StatusCode::NOT_FOUND, "NOT_FOUND", "Маршрут недоступен");
    };
    let (token, explicit) = match authorized_token(config, headers) {
        Ok(value) => value,
        Err(response) => return *response,
    };
    let backends = LEGACY_BACKENDS
        .iter()
        .map(|value| (*value).to_owned())
        .collect();
    match read_avatar(
        &config.client,
        config.codec.clone(),
        token.clone(),
        backends,
        SystemTime::now(),
    )
    .await
    {
        Ok(Some(_)) => {}
        Ok(None) => return unauthorized(explicit),
        Err(failure) => {
            tracing::error!(?failure, "avatar upload session check failed");
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "SERVICE_UNAVAILABLE",
                "Временно недоступно",
            );
        }
    }
    let mut raw = None;
    loop {
        match multipart.next_field().await {
            Ok(Some(field)) => {
                if field.name() == Some("avatar") {
                    if raw.is_some() {
                        return error(
                            StatusCode::BAD_REQUEST,
                            "VALIDATION_ERROR",
                            "Укажите один файл аватара",
                        );
                    }
                    match field.bytes().await {
                        Ok(bytes) => raw = Some(bytes.to_vec()),
                        Err(_) => {
                            return error(
                                StatusCode::BAD_REQUEST,
                                "VALIDATION_ERROR",
                                "Не удалось прочитать файл",
                            );
                        }
                    }
                }
            }
            Ok(None) => break,
            Err(_) => {
                return error(
                    StatusCode::BAD_REQUEST,
                    "VALIDATION_ERROR",
                    "Неверный формат загрузки",
                );
            }
        }
    }
    let Some(raw) = raw else {
        return error(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "Файл аватара обязателен",
        );
    };
    let jpeg = match normalize(raw).await {
        Ok(jpeg) => jpeg,
        Err(failure) => {
            tracing::info!(?failure, "avatar image rejected");
            return error(
                StatusCode::BAD_REQUEST,
                "VALIDATION_ERROR",
                "Не удалось прочитать изображение",
            );
        }
    };
    match upload_avatar(
        &config.client,
        config.codec.clone(),
        &config.media,
        &token,
        jpeg,
        SystemTime::now(),
    )
    .await
    {
        Ok(UploadResult::Uploaded(key)) => match media_url.avatar_url(&key) {
            Ok(url) => json_response(
                StatusCode::OK,
                json!({
                    "ok": true, "message": "Аватар обновлён", "avatar_url": url,
                    "avatar_source": "upload", "avatar_gravatar_enabled": false,
                }),
            ),
            Err(failure) => {
                tracing::error!(?failure, "uploaded avatar URL could not be signed");
                error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "SERVICE_UNAVAILABLE",
                    "Временно недоступно",
                )
            }
        },
        Ok(UploadResult::Unauthorized) => unauthorized(explicit),
        Ok(UploadResult::Changed) => error(
            StatusCode::CONFLICT,
            "AVATAR_CHANGED",
            "Аватар изменился; повторите загрузку",
        ),
        Err(failure) => {
            tracing::error!(?failure, "Rust avatar upload failed");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "SERVICE_UNAVAILABLE",
                "Временно недоступно",
            )
        }
    }
}

async fn remove(State(config): State<Arc<AvatarDeleteHttpConfig>>, request: Request) -> Response {
    let headers = request.headers().clone();
    let mut response = remove_inner(&config, &headers).await;
    add_cors_methods(
        response.headers_mut(),
        &headers,
        &config.trusted_origins,
        "POST, DELETE, OPTIONS",
    );
    response
}

async fn remove_inner(config: &AvatarDeleteHttpConfig, headers: &HeaderMap) -> Response {
    let (token, explicit) = match authorized_token(config, headers) {
        Ok(value) => value,
        Err(response) => return *response,
    };
    match delete_avatar(
        &config.client,
        config.codec.clone(),
        &config.media,
        &token,
        SystemTime::now(),
    )
    .await
    {
        Ok(DeleteResult::Deleted) => json_response(
            StatusCode::OK,
            json!({
                "ok":true,
                "message":"Аватар удалён, будет показана заглушка",
                "avatar_url":null,
                "avatar_source":"none",
                "avatar_gravatar_enabled":false,
            }),
        ),
        Ok(DeleteResult::Unauthorized) => unauthorized(explicit),
        Ok(DeleteResult::Changed) => error(
            StatusCode::CONFLICT,
            "AVATAR_CHANGED",
            "Аватар изменился; повторите удаление",
        ),
        Err(failure) => {
            tracing::error!(?failure, "Rust avatar deletion failed");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "SERVICE_UNAVAILABLE",
                "Временно недоступно",
            )
        }
    }
}

fn authorized_token(
    config: &AvatarDeleteHttpConfig,
    headers: &HeaderMap,
) -> std::result::Result<(String, bool), Box<Response>> {
    let explicit = match session_token(headers) {
        Ok(token) => token,
        Err(_) => {
            return Err(Box::new(error(
                StatusCode::UNAUTHORIZED,
                "INVALID_OR_EXPIRED_TOKEN",
                "Сессия недействительна, пожалуйста, войдите заново",
            )));
        }
    };
    let cookie = cookie_value(headers, &config.session_cookie_name);
    let Some(token) = explicit.or(cookie.as_deref()) else {
        return Err(Box::new(error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Требуется авторизация",
        )));
    };
    if explicit.is_none()
        && !csrf_allowed(headers, &config.csrf_cookie_name, &config.trusted_origins)
    {
        return Err(Box::new(error(
            StatusCode::FORBIDDEN,
            "CSRF_FAILED",
            "CSRF verification failed",
        )));
    }
    Ok((token.to_owned(), explicit.is_some()))
}

fn unauthorized(explicit: bool) -> Response {
    error(
        StatusCode::UNAUTHORIZED,
        if explicit {
            "INVALID_OR_EXPIRED_TOKEN"
        } else {
            "UNAUTHORIZED"
        },
        "Сессия недействительна, пожалуйста, войдите заново",
    )
}

async fn preflight(
    State(config): State<Arc<AvatarDeleteHttpConfig>>,
    headers: HeaderMap,
) -> Response {
    let mut response = StatusCode::NO_CONTENT.into_response();
    add_cors_methods(
        response.headers_mut(),
        &headers,
        &config.trusted_origins,
        "POST, DELETE, OPTIONS",
    );
    response
}
