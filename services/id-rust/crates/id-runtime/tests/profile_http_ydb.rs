#![recursion_limit = "256"]
//! Profile mutation through Axum against the migrated local Django YDB schema.

use anyhow::{Context, Result, ensure};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use id_compat::session::SessionCodec;
use id_runtime::media_delete::S3MediaDelete;
use id_runtime::media_url::MediaUrl;
use image::{ImageFormat, Rgb, RgbImage};
use serde_json::{Value, json};
use std::{
    io::Cursor,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tower::ServiceExt;
use uuid::Uuid;

async fn patch(
    app: &Router,
    cookie: Option<&str>,
    header_token: Option<&str>,
    csrf: Option<&str>,
    body: Value,
) -> Result<(StatusCode, Value)> {
    let mut builder = Request::builder()
        .uri("/api/v1/auth/profile")
        .method("PATCH")
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    if let Some(token) = header_token {
        builder = builder.header("x-session-token", token);
    }
    if let Some(csrf) = csrf {
        builder = builder.header("x-csrftoken", csrf);
    }
    let response = app
        .clone()
        .oneshot(builder.body(Body::from(body.to_string()))?)
        .await?;
    let status = response.status();
    let body = serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await?)?;
    Ok((status, body))
}

async fn delete_avatar(
    app: &Router,
    cookie: Option<&str>,
    header_token: Option<&str>,
    csrf: Option<&str>,
) -> Result<(StatusCode, Value)> {
    let mut builder = Request::builder()
        .uri("/api/v1/auth/avatar")
        .method("DELETE");
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    if let Some(token) = header_token {
        builder = builder.header("x-session-token", token);
    }
    if let Some(csrf) = csrf {
        builder = builder.header("x-csrftoken", csrf);
    }
    let response = app.clone().oneshot(builder.body(Body::empty())?).await?;
    let status = response.status();
    let body = serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await?)?;
    Ok((status, body))
}

async fn post_avatar(
    app: &Router,
    cookie: Option<&str>,
    header_token: Option<&str>,
    csrf: Option<&str>,
    image: &[u8],
) -> Result<(StatusCode, Value)> {
    let boundary = "id-avatar-local-test-boundary";
    let mut body = format!("--{boundary}\r\nContent-Disposition: form-data; name=\"avatar\"; filename=\"picture.png\"\r\nContent-Type: image/png\r\n\r\n").into_bytes();
    body.extend_from_slice(image);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    let mut builder = Request::builder()
        .uri("/api/v1/auth/avatar")
        .method("POST")
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        );
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    if let Some(token) = header_token {
        builder = builder.header("x-session-token", token);
    }
    if let Some(csrf) = csrf {
        builder = builder.header("x-csrftoken", csrf);
    }
    let response = app.clone().oneshot(builder.body(Body::from(body))?).await?;
    let status = response.status();
    let body = serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await?)?;
    Ok((status, body))
}

#[tokio::test]
#[ignore = "requires migrated local YDB and ID_AUTH_PROFILE_PILOT_ENABLED=true"]
async fn profile_route_updates_existing_and_new_profiles_without_auth_bypass() -> Result<()> {
    ensure!(
        matches!(
            std::env::var("YDB_ENDPOINT")?.as_str(),
            "grpc://localhost:2136" | "grpc://127.0.0.1:2136"
        ) && std::env::var("YDB_DATABASE")? == "/local"
            && std::env::var("ID_AUTH_PROFILE_PILOT_ENABLED")? == "true",
        "test requires opt-in local YDB"
    );
    let client = Arc::new(id_runtime::connect_ydb().await?);
    let app = id_runtime::profile_http::router(
        id_runtime::profile_http::ProfileHttpConfig::from_env(client.clone())?
            .context("profile pilot disabled")?,
    );
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros();
    let id = -i32::try_from(stamp % 1_000_000_000 + 1)?;
    let identity_id = Uuid::from_u128((stamp << 32) | u128::from(std::process::id()));
    let token = format!("rustprofile{stamp:032x}session");
    let password = "pbkdf2_sha256$1000000$synthetic$synthetic";
    let codec = SessionCodec::new(std::env::var("DJANGO_SECRET_KEY")?.as_bytes(), &[])?;
    let now = SystemTime::now();
    let payload = json!({
        "_auth_user_id": id.to_string(),
        "_auth_user_backend": "django.contrib.auth.backends.ModelBackend",
        "_auth_user_hash": codec.auth_hash(password)?,
    });
    let encoded = codec.encode(
        payload.as_object().context("session payload")?,
        i64::try_from(now.duration_since(UNIX_EPOCH)?.as_secs())?,
        true,
    )?;
    client.query_client().exec("UPSERT INTO auth_user (id, password, is_active, username, first_name, last_name, email, is_staff, is_superuser, date_joined) VALUES ($id, $password, true, $username, 'Before', 'User', $email, false, false, CurrentUtcDatetime())")
        .param("$id", id).param("$password", password)
        .param("$username", format!("rust-profile-{stamp}"))
        .param("$email", format!("rust-profile-{stamp}@example.invalid")).await?;
    let result: Result<()> = async {
        client.query_client().exec("UPSERT INTO django_session (session_key, session_data, expire_date) VALUES ($key, $data, CAST($expires AS Datetime))")
            .param("$key", token.clone()).param("$data", encoded)
            .param("$expires", now + Duration::from_secs(3600)).await?;
        client.query_client().exec("UPSERT INTO usid_user (user_id, username, display_name, email, email_verified, status, system_admin, created_at) VALUES ($identity_id, $name, $name, $email, true, 'active', false, CurrentUtcDatetime())")
            .param("$identity_id", identity_id).param("$name", format!("rust-profile-{stamp}"))
            .param("$email", format!("rust-profile-{stamp}@example.invalid")).await?;
        client.query_client().exec("UPSERT INTO accounts_accountidentity (user_id, identity_id, public_subject, created_at) VALUES ($user_id, $identity_id, $subject, CurrentUtcDatetime())")
            .param("$user_id", id).param("$identity_id", identity_id)
            .param("$subject", format!("rust-profile-subject-{stamp}")).await?;

        let csrf = "a".repeat(32);
        let browser_cookie = format!("sessionid={token}; csrftoken={csrf}");
        let (status, body) = patch(&app, Some(&browser_cookie), None, None, json!({"first_name":"Rejected"})).await?;
        ensure!(status == StatusCode::FORBIDDEN && body["code"] == "CSRF_FAILED");
        let (status, body) = patch(&app, Some(&browser_cookie), Some("invalid"), Some(&csrf), json!({"first_name":"Rejected"})).await?;
        ensure!(status == StatusCode::UNAUTHORIZED && body["code"] == "INVALID_OR_EXPIRED_TOKEN");
        let (status, body) = patch(&app, None, Some(&token), None, json!({"birth_date":"2024-02-30"})).await?;
        ensure!(status == StatusCode::BAD_REQUEST && body["code"] == "VALIDATION_ERROR");

        // All requests observe a missing profile at the outset. The secondary-index
        // predicate must serialize creation despite the legacy schema lacking a
        // unique constraint on user_id.
        let mut concurrent = tokio::task::JoinSet::new();
        for _ in 0..20 {
            let app = app.clone();
            let token = token.clone();
            concurrent.spawn(async move {
                patch(&app, None, Some(&token), None, json!({"phone_number":"parallel"})).await
            });
        }
        let mut success = 0;
        while let Some(result) = concurrent.join_next().await {
            let (status, body) = result??;
            if status == StatusCode::OK { success += 1; }
            else { ensure!(status == StatusCode::SERVICE_UNAVAILABLE, "unexpected concurrent result: {status} {body}"); }
        }
        ensure!(success > 0, "concurrent creation had no confirmed writer");

        let (status, body) = patch(&app, None, Some(&token), None, json!({
            "first_name":" Ada ", "last_name":" Lovelace ",
            "phone_number":" +1 555 ", "birth_date":"1990-01-02"
        })).await?;
        ensure!(status == StatusCode::OK && body == json!({"ok":true,"message":"Профиль обновлён"}), "{body}");
        let mut row = client.query_client().query_row("SELECT first_name, last_name FROM auth_user WHERE id = $id")
            .param("$id", id).await?;
        let first: String = row.remove_field_by_name("first_name")?.try_into()?;
        let last: String = row.remove_field_by_name("last_name")?.try_into()?;
        ensure!(first == "Ada" && last == "Lovelace");
        let mut query_client = client.query_client();
        let mut stream = query_client.query("SELECT id, phone_number, phone_verified, birth_date FROM accounts_userprofile VIEW acct_profile_user_idx WHERE user_id = $id")
            .param("$id", id).await?;
        let mut profile_ids: Vec<i64> = Vec::new();
        while let Some(rows) = stream.next_result_set().await? {
            for mut row in rows {
                profile_ids.push(row.remove_field_by_name("id")?.try_into()?);
                let phone: String = row.remove_field_by_name("phone_number")?.try_into()?;
                let verified: bool = row.remove_field_by_name("phone_verified")?.try_into()?;
                ensure!(phone == "+1 555" && !verified);
            }
        }
        stream.close().await?;
        ensure!(profile_ids.len() == 1, "expected exactly one auto-ID profile row");

        let profile_id = profile_ids[0];
        let old_key = format!("avatars/user_{id}/upload_{}.jpg", Uuid::new_v4().simple());
        let newer_key = format!("avatars/user_{id}/upload_{}.jpg", Uuid::new_v4().simple());
        client.query_client().exec("UPDATE accounts_userprofile SET avatar = CAST($key AS String), avatar_source = 'upload', gravatar_enabled = false WHERE id = $id")
            .param("$key", old_key.clone()).param("$id", profile_id).await?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let server_client = client.clone();
        let old_key_for_server = old_key.clone();
        let newer_key_for_server = newer_key.clone();
        let server = tokio::spawn(async move {
            for attempt in 0..3 {
                let (mut stream, _) = listener.accept().await?;
                let mut request = Vec::new();
                let mut buffer = [0u8; 4096];
                while !request.windows(4).any(|part| part == b"\r\n\r\n") {
                    let count = stream.read(&mut buffer).await?;
                    ensure!(count > 0 && request.len() < 16_384, "invalid S3 mock request");
                    request.extend_from_slice(&buffer[..count]);
                }
                let request = String::from_utf8(request)?;
                ensure!(request.starts_with(&format!("DELETE /id-media/{old_key_for_server} ")),
                    "unexpected avatar DELETE path");
                ensure!(request.to_ascii_lowercase().contains("authorization: aws4-hmac-sha256"),
                    "avatar DELETE is unsigned");
                if attempt == 2 {
                    server_client.query_client().exec("UPDATE accounts_userprofile SET avatar = CAST($key AS String) WHERE id = $id")
                        .param("$key", newer_key_for_server.clone()).param("$id", profile_id).await?;
                }
                let status = if attempt == 0 { "500 Internal Server Error" } else { "204 No Content" };
                stream.write_all(format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).await?;
            }
            Ok::<_, anyhow::Error>(())
        });
        let media = S3MediaDelete::new(&format!("http://127.0.0.1:{port}/"), "id-media", "ru-central1", "test-access".into(), "test-secret".into())?;
        let codec = Arc::new(codec);
        let avatar_app = id_runtime::avatar_delete_http::router(
            id_runtime::avatar_delete_http::AvatarDeleteHttpConfig::new(client.clone(), codec.clone(), media,
                Some(MediaUrl::new("http://localhost:8080/id-media/")?),
                vec!["http://localhost:5175".into()]),
        );
        let preflight = avatar_app.clone().oneshot(Request::builder()
            .uri("/api/v1/auth/avatar").method("OPTIONS")
            .header(header::ORIGIN, "http://localhost:5175")
            .body(Body::empty())?).await?;
        ensure!(preflight.status() == StatusCode::NO_CONTENT
            && preflight.headers().get(header::ACCESS_CONTROL_ALLOW_METHODS)
                .is_some_and(|value| value == "POST, DELETE, OPTIONS"));
        let (status, _) = delete_avatar(&avatar_app, None, None, None).await?;
        ensure!(status == StatusCode::UNAUTHORIZED);
        let (status, _) = delete_avatar(&avatar_app, Some(&browser_cookie), None, None).await?;
        ensure!(status == StatusCode::FORBIDDEN);
        let (status, _) = delete_avatar(&avatar_app, Some(&browser_cookie), Some("invalid"), Some(&csrf)).await?;
        ensure!(status == StatusCode::UNAUTHORIZED);
        let (status, _) = delete_avatar(&avatar_app, Some(&browser_cookie), None, Some(&csrf)).await?;
        ensure!(status == StatusCode::SERVICE_UNAVAILABLE, "S3 failure should retain avatar key");
        let mut row = client.query_client().query_row("SELECT CAST(avatar AS Utf8) AS avatar_key FROM accounts_userprofile WHERE id = $id")
            .param("$id", profile_id).await?;
        let key: Option<String> = row.remove_field_by_name("avatar_key")?.try_into()?;
        ensure!(key.as_deref() == Some(old_key.as_str()));
        let (status, body) = delete_avatar(&avatar_app, Some(&browser_cookie), None, Some(&csrf)).await?;
        ensure!(status == StatusCode::OK && body["avatar_source"] == "none" && body["avatar_url"].is_null());
        let mut row = client.query_client().query_row("SELECT CAST(avatar AS Utf8) AS avatar_key, avatar_source, gravatar_enabled FROM accounts_userprofile WHERE id = $id")
            .param("$id", profile_id).await?;
        let key: Option<String> = row.remove_field_by_name("avatar_key")?.try_into()?;
        let source: String = row.remove_field_by_name("avatar_source")?.try_into()?;
        let gravatar: bool = row.remove_field_by_name("gravatar_enabled")?.try_into()?;
        ensure!(key.is_none() && source == "none" && !gravatar);
        let (status, _) = delete_avatar(&avatar_app, Some(&browser_cookie), None, Some(&csrf)).await?;
        ensure!(status == StatusCode::OK, "repeated avatar deletion must be idempotent");
        client.query_client().exec("UPDATE accounts_userprofile SET avatar = CAST($key AS String), avatar_source = 'upload' WHERE id = $id")
            .param("$key", "legacy/unsupported-avatar.jpg").param("$id", profile_id).await?;
        let (status, _) = delete_avatar(&avatar_app, Some(&browser_cookie), None, Some(&csrf)).await?;
        ensure!(status == StatusCode::OK, "unsupported legacy avatar pointer was not cleared");
        let mut row = client.query_client().query_row("SELECT CAST(avatar AS Utf8) AS avatar_key FROM accounts_userprofile WHERE id = $id")
            .param("$id", profile_id).await?;
        let key: Option<String> = row.remove_field_by_name("avatar_key")?.try_into()?;
        ensure!(key.is_none(), "unsupported avatar pointer remains");
        client.query_client().exec("UPDATE accounts_userprofile SET avatar = CAST($key AS String), avatar_source = 'upload' WHERE id = $id")
            .param("$key", old_key.clone()).param("$id", profile_id).await?;
        let (status, _) = delete_avatar(&avatar_app, Some(&browser_cookie), None, Some(&csrf)).await?;
        ensure!(status == StatusCode::CONFLICT, "concurrent avatar replacement was cleared");
        let mut row = client.query_client().query_row("SELECT CAST(avatar AS Utf8) AS avatar_key FROM accounts_userprofile WHERE id = $id")
            .param("$id", profile_id).await?;
        let key: Option<String> = row.remove_field_by_name("avatar_key")?.try_into()?;
        ensure!(key.as_deref() == Some(newer_key.as_str()));
        server.await??;

        let mut png = Cursor::new(Vec::new());
        image::DynamicImage::ImageRgb8(RgbImage::from_pixel(24, 12, Rgb([20, 60, 100])))
            .write_to(&mut png, ImageFormat::Png)?;
        let png = png.into_inner();
        let upload_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let upload_port = upload_listener.local_addr()?.port();
        let old_key_for_upload = newer_key.clone();
        let upload_server = tokio::spawn(async move {
            for attempt in 0..2 {
                let (mut stream, _) = upload_listener.accept().await?;
                let mut request = Vec::new();
                let mut buffer = [0u8; 4096];
                let header_end = loop {
                    let count = stream.read(&mut buffer).await?;
                    ensure!(count > 0 && request.len() < 8 * 1024 * 1024, "invalid S3 upload request");
                    request.extend_from_slice(&buffer[..count]);
                    if let Some(pos) = request.windows(4).position(|part| part == b"\r\n\r\n") {
                        break pos + 4;
                    }
                };
                let head = String::from_utf8(request[..header_end].to_vec())?;
                ensure!(head.to_ascii_lowercase().contains("authorization: aws4-hmac-sha256"),
                    "avatar object request is unsigned");
                let content_length = head.lines().find_map(|line| {
                    line.to_ascii_lowercase().strip_prefix("content-length: ").and_then(|value| value.trim().parse::<usize>().ok())
                }).unwrap_or(0);
                if attempt == 0 {
                    ensure!(head.starts_with(&format!("PUT /id-media/avatars/user_{id}/upload_"))
                        && head.to_ascii_lowercase().contains("content-type: image/jpeg"),
                        "unexpected signed avatar PUT");
                    while request.len() - header_end < content_length {
                        let count = stream.read(&mut buffer).await?;
                        ensure!(count > 0, "truncated JPEG upload");
                        request.extend_from_slice(&buffer[..count]);
                    }
                    let jpeg = image::load_from_memory(&request[header_end..header_end + content_length])?;
                    ensure!(jpeg.width() == 512 && jpeg.height() == 512,
                        "uploaded avatar was not normalized to 512 square");
                    stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await?;
                } else {
                    ensure!(head.starts_with(&format!("DELETE /id-media/{old_key_for_upload} ")),
                        "unexpected old avatar cleanup path");
                    stream.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await?;
                }
            }
            Ok::<_, anyhow::Error>(())
        });
        let upload_media = S3MediaDelete::new(&format!("http://127.0.0.1:{upload_port}/"),
            "id-media", "ru-central1", "test-access".into(), "test-secret".into())?;
        let upload_app = id_runtime::avatar_delete_http::router(
            id_runtime::avatar_delete_http::AvatarDeleteHttpConfig::new(client.clone(), codec,
                upload_media, Some(MediaUrl::new("http://localhost:8080/id-media/")?),
                vec!["http://localhost:5175".into()]),
        );
        let (status, _) = post_avatar(&upload_app, None, None, None, &png).await?;
        ensure!(status == StatusCode::UNAUTHORIZED);
        let (status, _) = post_avatar(&upload_app, Some(&browser_cookie), None, None, &png).await?;
        ensure!(status == StatusCode::FORBIDDEN);
        let (status, _) = post_avatar(&upload_app, Some(&browser_cookie), Some("invalid"), Some(&csrf), &png).await?;
        ensure!(status == StatusCode::UNAUTHORIZED);
        let (status, _) = post_avatar(&upload_app, Some(&browser_cookie), None, Some(&csrf), b"not an image").await?;
        ensure!(status == StatusCode::BAD_REQUEST);
        let (status, body) = post_avatar(&upload_app, Some(&browser_cookie), None, Some(&csrf), &png).await?;
        ensure!(status == StatusCode::OK && body["avatar_source"] == "upload"
            && body["avatar_gravatar_enabled"] == false);
        let mut row = client.query_client().query_row("SELECT CAST(avatar AS Utf8) AS avatar_key, avatar_source, gravatar_enabled FROM accounts_userprofile WHERE id = $id")
            .param("$id", profile_id).await?;
        let key: Option<String> = row.remove_field_by_name("avatar_key")?.try_into()?;
        let source: String = row.remove_field_by_name("avatar_source")?.try_into()?;
        let gravatar: bool = row.remove_field_by_name("gravatar_enabled")?.try_into()?;
        let key = key.context("uploaded avatar key not committed")?;
        ensure!(key.starts_with(&format!("avatars/user_{id}/upload_")) && source == "upload" && !gravatar
            && body["avatar_url"].as_str() == Some(format!("http://localhost:8080/id-media/{key}").as_str()));
        upload_server.await??;

        let race_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let race_port = race_listener.local_addr()?.port();
        let race_client = client.clone();
        let replacement = format!("avatars/user_{id}/upload_{}.jpg", Uuid::new_v4().simple());
        let replacement_for_server = replacement.clone();
        let race_server = tokio::spawn(async move {
            let mut uploaded_key = None;
            for attempt in 0..2 {
                let (mut stream, _) = race_listener.accept().await?;
                let mut request = Vec::new();
                let mut buffer = [0u8; 4096];
                while !request.windows(4).any(|part| part == b"\r\n\r\n") {
                    let count = stream.read(&mut buffer).await?;
                    ensure!(count > 0 && request.len() < 16_384, "invalid race S3 request");
                    request.extend_from_slice(&buffer[..count]);
                }
                let header_end = request.windows(4).position(|part| part == b"\r\n\r\n")
                    .context("missing race request headers")? + 4;
                let head = String::from_utf8(request[..header_end].to_vec())?;
                if attempt == 0 {
                    let line = head.lines().next().context("missing PUT line")?;
                    let path = line.split_whitespace().nth(1).context("missing PUT path")?;
                    ensure!(line.starts_with(&format!("PUT /id-media/avatars/user_{id}/upload_")),
                        "unexpected race PUT");
                    uploaded_key = Some(path.trim_start_matches("/id-media/").to_owned());
                    race_client.query_client().exec("UPDATE accounts_userprofile SET avatar = CAST($key AS String) WHERE id = $id")
                        .param("$key", replacement_for_server.clone()).param("$id", profile_id).await?;
                    stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await?;
                } else {
                    ensure!(head.starts_with(&format!("DELETE /id-media/{} ", uploaded_key.as_deref().context("missing uploaded key")?)),
                        "unused upload object was not cleaned after avatar race");
                    stream.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await?;
                }
            }
            Ok::<_, anyhow::Error>(())
        });
        let race_media = S3MediaDelete::new(&format!("http://127.0.0.1:{race_port}/"),
            "id-media", "ru-central1", "test-access".into(), "test-secret".into())?;
        let race_app = id_runtime::avatar_delete_http::router(
            id_runtime::avatar_delete_http::AvatarDeleteHttpConfig::new(client.clone(),
                Arc::new(SessionCodec::new(std::env::var("DJANGO_SECRET_KEY")?.as_bytes(), &[])?),
                race_media, Some(MediaUrl::new("http://localhost:8080/id-media/")?),
                vec!["http://localhost:5175".into()]),
        );
        let (status, _) = post_avatar(&race_app, Some(&browser_cookie), None, Some(&csrf), &png).await?;
        ensure!(status == StatusCode::CONFLICT, "concurrent avatar replacement was overwritten by upload");
        let mut row = client.query_client().query_row("SELECT CAST(avatar AS Utf8) AS avatar_key FROM accounts_userprofile WHERE id = $id")
            .param("$id", profile_id).await?;
        let current: Option<String> = row.remove_field_by_name("avatar_key")?.try_into()?;
        ensure!(current.as_deref() == Some(replacement.as_str()), "concurrent replacement was lost");
        race_server.await??;

        let (status, _) = patch(&app, Some(&browser_cookie), None, Some(&csrf), json!({"phone_number":" 42 "})).await?;
        ensure!(status == StatusCode::OK);
        client.query_client().exec("UPSERT INTO mfa_authenticator (id, user_id, type, data, created_at) VALUES ($id, $user_id, 'totp', Unwrap(CAST('{}' AS Json)), CurrentUtcDatetime())")
            .param("$id", i64::from(id)).param("$user_id", id).await?;
        let (status, _) = delete_avatar(&avatar_app, Some(&browser_cookie), None, Some(&csrf)).await?;
        ensure!(status == StatusCode::UNAUTHORIZED, "MFA-unproven session deleted avatar");
        let (status, _) = patch(&app, None, Some(&token), None, json!({"first_name":"Rejected"})).await?;
        ensure!(status == StatusCode::UNAUTHORIZED, "MFA-unproven session changed profile");
        Ok(())
    }.await;

    client
        .query_client()
        .exec("DELETE FROM mfa_authenticator WHERE id = $id")
        .param("$id", i64::from(id))
        .await?;
    client
        .query_client()
        .exec("DELETE FROM accounts_userprofile WHERE user_id = $id")
        .param("$id", id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM accounts_accountidentity WHERE user_id = $id")
        .param("$id", id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM usid_user WHERE user_id = $id")
        .param("$id", identity_id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM django_session WHERE session_key = $key")
        .param("$key", token)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM auth_user WHERE id = $id")
        .param("$id", id)
        .await?;
    result
}
