//! Bounded scheduled Gravatar refresh. The public API never fetches avatars.
//! The scheduler invokes this through the private jobs container IAM binding.

use crate::{media_delete::S3MediaDelete, tx_retry::retry_known_abort};
use anyhow::{Context, Result, bail, ensure};
use image::{ImageFormat, ImageReader, Limits, codecs::jpeg::JpegEncoder, imageops::FilterType};
use openssl::hash::{MessageDigest, hash};
use reqwest::{Client as HttpClient, StatusCode};
use serde::Serialize;
use std::{
    io::Cursor,
    sync::Arc,
    time::{Duration, SystemTime},
};
use url::Url;
use ydb::{Client, Transaction, TxMode, closure};

const MAX_DOWNLOAD: usize = 6 * 1024 * 1024;
const AVATAR_SIZE: u32 = 512;
const TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);

#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub struct GravatarResult {
    pub checked: usize,
    pub updated: usize,
    pub skipped: usize,
    pub failed: usize,
}

#[derive(Clone)]
struct Candidate {
    profile_id: i64,
    account_id: i32,
    checked_at: Option<SystemTime>,
}

pub struct GravatarJob {
    ydb: Arc<Client>,
    http: HttpClient,
    media: S3MediaDelete,
    base_url: Url,
}

impl GravatarJob {
    pub fn from_env(ydb: Arc<Client>) -> Result<Self> {
        let media = S3MediaDelete::from_env()?.context("Gravatar requires private S3 media")?;
        Ok(Self {
            ydb,
            http: HttpClient::builder()
                .timeout(Duration::from_secs(8))
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            media,
            base_url: Url::parse("https://www.gravatar.com/avatar/")?,
        })
    }

    pub async fn run(&self, limit: usize) -> Result<GravatarResult> {
        ensure!(
            (1..=100).contains(&limit),
            "Gravatar batch limit must be 1..100"
        );
        let now = SystemTime::now();
        let candidates = self.due_candidates(limit, now).await?;
        let mut report = GravatarResult::default();
        for candidate in candidates {
            report.checked += 1;
            match self.refresh(&candidate, now).await {
                Ok(Refresh::Updated) => report.updated += 1,
                Ok(Refresh::Skipped) => report.skipped += 1,
                Err(error) => {
                    report.failed += 1;
                    tracing::warn!(error = %error, "Gravatar profile refresh failed");
                }
            }
        }
        Ok(report)
    }

    async fn due_candidates(&self, limit: usize, now: SystemTime) -> Result<Vec<Candidate>> {
        let cutoff = now.checked_sub(TTL).context("invalid Gravatar cutoff")?;
        let mut after: Option<i64> = None;
        let mut result = Vec::with_capacity(limit);
        let mut query = self.ydb.query_client();
        while result.len() < limit {
            let sql = if after.is_some() {
                "SELECT id, user_id, avatar_source, gravatar_enabled, gravatar_checked_at FROM accounts_userprofile WHERE id > $after ORDER BY id LIMIT 100"
            } else {
                "SELECT id, user_id, avatar_source, gravatar_enabled, gravatar_checked_at FROM accounts_userprofile ORDER BY id LIMIT 100"
            };
            let request = query.query(sql).timeout(Duration::from_secs(10));
            let mut rows = if let Some(id) = after {
                request.param("$after", id).await?
            } else {
                request.await?
            };
            let mut page_count = 0;
            while let Some(page) = rows.next_result_set().await? {
                for mut row in page {
                    let id: i64 = row.remove_field_by_name("id")?.try_into()?;
                    let user_id: i32 = row.remove_field_by_name("user_id")?.try_into()?;
                    let source: String = row.remove_field_by_name("avatar_source")?.try_into()?;
                    let enabled: bool = row.remove_field_by_name("gravatar_enabled")?.try_into()?;
                    let checked_at: Option<SystemTime> = row
                        .remove_field_by_name("gravatar_checked_at")?
                        .try_into()?;
                    page_count += 1;
                    after = Some(id);
                    if enabled
                        && source != "upload"
                        && checked_at.is_none_or(|last| last < cutoff)
                        && result.len() < limit
                    {
                        result.push(Candidate {
                            profile_id: id,
                            account_id: user_id,
                            checked_at,
                        });
                    }
                }
            }
            rows.close().await?;
            if page_count == 0 {
                break;
            }
        }
        Ok(result)
    }

    async fn refresh(&self, candidate: &Candidate, now: SystemTime) -> Result<Refresh> {
        let Some(mut row) = self
            .ydb
            .query_client()
            .query_row("SELECT email FROM auth_user WHERE id = $id")
            .param("$id", candidate.account_id)
            .optional()
            .await?
        else {
            return Ok(Refresh::Skipped);
        };
        let email: String = row.remove_field_by_name("email")?.try_into()?;
        let Some(email) = normalize_email(&email) else {
            return Ok(Refresh::Skipped);
        };
        let digest = hash(MessageDigest::md5(), email.as_bytes())?;
        let url = self.base_url.join(&hex::encode(digest))?;
        let response = self
            .http
            .get(url)
            .query(&[("d", "404"), ("s", "512")])
            .header(reqwest::header::USER_AGENT, "UpdSpace ID avatar sync")
            .header(reqwest::header::ACCEPT, "image/jpeg,image/png,image/webp")
            .send()
            .await
            .context("Gravatar request failed")?;
        let jpeg = match response.status() {
            StatusCode::NOT_FOUND => None,
            StatusCode::OK => {
                let mut response = response;
                if response
                    .content_length()
                    .is_some_and(|size| size > MAX_DOWNLOAD as u64)
                {
                    bail!("Gravatar image exceeds download limit");
                }
                let mut raw = Vec::new();
                while let Some(chunk) = response.chunk().await? {
                    ensure!(
                        raw.len() + chunk.len() <= MAX_DOWNLOAD,
                        "Gravatar image exceeds download limit"
                    );
                    raw.extend_from_slice(&chunk);
                }
                tokio::task::spawn_blocking(move || normalize_image(&raw))
                    .await?
                    .ok()
            }
            _ => bail!("Gravatar returned unexpected HTTP status"),
        };

        let object_key = jpeg.as_ref().map(|_| {
            format!(
                "avatars/user_{}/gravatar_{}.jpg",
                candidate.account_id,
                uuid::Uuid::new_v4().simple()
            )
        });
        if let (Some(key), Some(bytes)) = (&object_key, jpeg) {
            self.media
                .put_avatar(candidate.account_id, key, bytes)
                .await?;
        }
        let candidate = candidate.clone();
        let key_for_tx = object_key.clone();
        let email_for_tx = email.clone();
        let cutoff = now.checked_sub(TTL).context("invalid Gravatar cutoff")?;
        let published = retry_known_abort(|| {
            let candidate = candidate.clone();
            let key = key_for_tx.clone();
            let email = email_for_tx.clone();
            async {
                self.ydb.query_client().retry_tx(closure!([candidate, key, email], async |tx: &mut Transaction| {
                    let Some(mut profile) = tx.query_row("SELECT user_id, avatar_source, gravatar_enabled, gravatar_checked_at, CAST(avatar AS Utf8) AS avatar_key FROM accounts_userprofile WHERE id = $id")
                        .param("$id", candidate.profile_id).optional().await? else { return Ok(None) };
                    let owner: i32 = profile.remove_field_by_name("user_id")?.try_into()?;
                    let source: String = profile.remove_field_by_name("avatar_source")?.try_into()?;
                    let enabled: bool = profile.remove_field_by_name("gravatar_enabled")?.try_into()?;
                    let checked: Option<SystemTime> = profile.remove_field_by_name("gravatar_checked_at")?.try_into()?;
                    let old_key: Option<String> = profile.remove_field_by_name("avatar_key")?.try_into()?;
                    if owner != candidate.account_id || !enabled || source == "upload" || checked != candidate.checked_at || checked.is_some_and(|last| last >= cutoff) {
                        return Ok(None);
                    }
                    let Some(mut user) = tx.query_row("SELECT email FROM auth_user WHERE id = $id")
                        .param("$id", candidate.account_id).optional().await? else { return Ok(None) };
                    let current_email: String = user.remove_field_by_name("email")?.try_into()?;
                    if normalize_email(&current_email).as_deref() != Some(email.as_str()) { return Ok(None) }
                    if let Some(key) = key.as_ref() {
                        tx.exec("UPDATE accounts_userprofile SET avatar = CAST($key AS String), avatar_source = 'gravatar', gravatar_checked_at = CAST($now AS Datetime), updated_at = CAST($now AS Datetime) WHERE id = $id")
                            .param("$key", key.clone()).param("$now", now).param("$id", candidate.profile_id).await?;
                    } else {
                        tx.exec("UPDATE accounts_userprofile SET gravatar_checked_at = CAST($now AS Datetime), updated_at = CAST($now AS Datetime) WHERE id = $id")
                            .param("$now", now).param("$id", candidate.profile_id).await?;
                    }
                    Ok(Some(old_key))
                })).with_mode(TxMode::SerializableReadWrite).idempotent(false)
                    .timeout(Duration::from_secs(10)).await
            }
        }).await?;
        if published.is_none() {
            if let Some(key) = object_key {
                let _ = self.media.delete_avatar(candidate.account_id, &key).await;
            }
            return Ok(Refresh::Skipped);
        }
        if let Some(old_key) = published
            .flatten()
            .filter(|old| Some(old) != object_key.as_ref())
        {
            // A failed cleanup leaves an orphan only; the new YDB key stays valid.
            let _ = self
                .media
                .delete_avatar(candidate.account_id, &old_key)
                .await;
        }
        Ok(if object_key.is_some() {
            Refresh::Updated
        } else {
            Refresh::Skipped
        })
    }
}

enum Refresh {
    Updated,
    Skipped,
}

fn normalize_email(email: &str) -> Option<String> {
    let email = email.trim().to_lowercase();
    (!email.is_empty() && email.len() <= 320).then_some(email)
}

fn normalize_image(raw: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        !raw.is_empty() && raw.len() <= MAX_DOWNLOAD,
        "invalid Gravatar response size"
    );
    let mut reader = ImageReader::new(Cursor::new(raw)).with_guessed_format()?;
    ensure!(
        matches!(
            reader.format(),
            Some(ImageFormat::Jpeg | ImageFormat::Png | ImageFormat::WebP)
        ),
        "unsupported Gravatar image format"
    );
    let mut limits = Limits::default();
    limits.max_image_width = Some(4096);
    limits.max_image_height = Some(4096);
    limits.max_alloc = Some(128 * 1024 * 1024);
    reader.limits(limits);
    let image = reader.decode()?;
    let rgb = image
        .resize_to_fill(AVATAR_SIZE, AVATAR_SIZE, FilterType::Lanczos3)
        .to_rgb8();
    let mut result = Vec::new();
    JpegEncoder::new_with_quality(&mut result, 88).encode(
        &rgb,
        AVATAR_SIZE,
        AVATAR_SIZE,
        image::ExtendedColorType::Rgb8,
    )?;
    ensure!(
        result.len() <= MAX_DOWNLOAD,
        "normalized Gravatar image exceeds limit"
    );
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::UNIX_EPOCH;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn normalizes_bounded_image_and_rejects_svg() -> Result<()> {
        let img = image::RgbImage::from_pixel(16, 8, image::Rgb([4, 8, 12]));
        let mut raw = Cursor::new(Vec::new());
        image::DynamicImage::ImageRgb8(img).write_to(&mut raw, ImageFormat::Png)?;
        let output = normalize_image(raw.get_ref())?;
        assert_eq!(image::load_from_memory(&output)?.width(), AVATAR_SIZE);
        assert!(normalize_image(b"<svg xmlns='http://www.w3.org/2000/svg'/>").is_err());
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires isolated local /local YDB with legacy schema"]
    async fn selects_only_due_opted_in_profiles() -> Result<()> {
        ensure!(
            matches!(
                std::env::var("YDB_ENDPOINT")?.as_str(),
                "grpc://localhost:2136" | "grpc://127.0.0.1:2136"
            ) && std::env::var("YDB_DATABASE")? == "/local",
            "Gravatar integration test requires local YDB"
        );
        let client = Arc::new(crate::connect_ydb().await?);
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros();
        let base = -i64::try_from(stamp % 1_000_000_000 + 1)?;
        let rows = [
            (base, true, "none", false),
            (base - 1, false, "none", false),
            (base - 2, true, "upload", false),
            (base - 3, true, "gravatar", true),
        ];
        let checked: Result<()> = async {
            for (id, enabled, source, fresh) in rows {
                let statement = if fresh {
                    "UPSERT INTO accounts_userprofile (id, user_id, avatar_source, gravatar_enabled, gravatar_checked_at, phone_number, phone_verified, created_at, updated_at) VALUES ($id, $user, $source, $enabled, CurrentUtcDatetime(), '', false, CurrentUtcDatetime(), CurrentUtcDatetime())"
                } else {
                    "UPSERT INTO accounts_userprofile (id, user_id, avatar_source, gravatar_enabled, phone_number, phone_verified, created_at, updated_at) VALUES ($id, $user, $source, $enabled, '', false, CurrentUtcDatetime(), CurrentUtcDatetime())"
                };
                client.query_client().exec(statement)
                    .param("$id", id).param("$user", i32::try_from(id)?)
                    .param("$source", source.to_owned()).param("$enabled", enabled).await?;
            }
            let job = GravatarJob {
                ydb: client.clone(),
                http: HttpClient::new(),
                media: S3MediaDelete::new("http://localhost:9000/", "test-bucket", "ru-central1", "access".into(), "secret".into())?,
                base_url: Url::parse("http://localhost:8080/avatar/")?,
            };
            let found = job.due_candidates(100, SystemTime::now()).await?;
            let matching: Vec<_> = found.iter().filter(|candidate| candidate.profile_id <= base && candidate.profile_id >= base - 3).collect();
            ensure!(matching.len() == 1 && matching[0].profile_id == base, "Gravatar due filter changed");
            Ok(())
        }.await;
        for (id, _, _, _) in rows {
            client
                .query_client()
                .exec("DELETE FROM accounts_userprofile WHERE id = $id")
                .param("$id", id)
                .await?;
        }
        checked
    }

    #[tokio::test]
    #[ignore = "requires isolated local /local YDB with legacy schema"]
    async fn refreshes_profile_through_mock_gravatar_and_s3() -> Result<()> {
        ensure!(
            matches!(
                std::env::var("YDB_ENDPOINT")?.as_str(),
                "grpc://localhost:2136" | "grpc://127.0.0.1:2136"
            ) && std::env::var("YDB_DATABASE")? == "/local",
            "Gravatar integration test requires local YDB"
        );
        let client = Arc::new(crate::connect_ydb().await?);
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros();
        let id = -i32::try_from(stamp % 1_000_000_000 + 1)?;
        let profile_id = i64::from(id);
        let email = format!("gravatar-test-{stamp}@example.invalid");
        let mut png = Cursor::new(Vec::new());
        image::DynamicImage::ImageRgb8(image::RgbImage::from_pixel(24, 12, image::Rgb([5, 9, 13])))
            .write_to(&mut png, ImageFormat::Png)?;
        let png = png.into_inner();
        let expected_md5 = hex::encode(hash(MessageDigest::md5(), email.as_bytes())?);

        let gravatar_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let gravatar_port = gravatar_listener.local_addr()?.port();
        let gravatar_server = tokio::spawn(async move {
            let (mut socket, _) = gravatar_listener.accept().await?;
            let mut request = [0u8; 2048];
            let size = socket.read(&mut request).await?;
            let request = String::from_utf8_lossy(&request[..size]);
            assert!(request.starts_with(&format!("GET /avatar/{expected_md5}?d=404&s=512 ")));
            socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", png.len()).as_bytes()).await?;
            socket.write_all(&png).await?;
            Result::<()>::Ok(())
        });
        let s3_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let s3_port = s3_listener.local_addr()?.port();
        let s3_server = tokio::spawn(async move {
            let (mut socket, _) = s3_listener.accept().await?;
            let mut request = [0u8; 4096];
            let size = socket.read(&mut request).await?;
            let head = String::from_utf8_lossy(&request[..size]).to_ascii_lowercase();
            assert!(head.starts_with(&format!("put /id-media/avatars/user_{id}/gravatar_")));
            assert!(head.contains("content-type: image/jpeg"));
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await?;
            Result::<()>::Ok(())
        });

        let checked: Result<()> = async {
            client.query_client().exec("UPSERT INTO auth_user (id, password, is_active, username, first_name, last_name, email, is_staff, is_superuser, date_joined) VALUES ($id, '!unusable', true, $username, '', '', $email, false, false, CurrentUtcDatetime())")
                .param("$id", id).param("$username", format!("gravatar-test-{stamp}"))
                .param("$email", email).await?;
            client.query_client().exec("UPSERT INTO accounts_userprofile (id, user_id, avatar_source, gravatar_enabled, phone_number, phone_verified, created_at, updated_at) VALUES ($id, $user, 'none', true, '', false, CurrentUtcDatetime(), CurrentUtcDatetime())")
                .param("$id", profile_id).param("$user", id).await?;
            let job = GravatarJob {
                ydb: client.clone(),
                http: HttpClient::new(),
                media: S3MediaDelete::new(&format!("http://127.0.0.1:{s3_port}/"), "id-media", "ru-central1", "access".into(), "secret".into())?,
                base_url: Url::parse(&format!("http://127.0.0.1:{gravatar_port}/avatar/"))?,
            };
            ensure!(matches!(job.refresh(&Candidate { profile_id, account_id: id, checked_at: None }, SystemTime::now()).await?, Refresh::Updated), "Gravatar update was skipped");
            let mut row = client.query_client().query_row("SELECT avatar_source, CAST(avatar AS Utf8) AS avatar_key, gravatar_checked_at FROM accounts_userprofile WHERE id = $id")
                .param("$id", profile_id).await?;
            let source: String = row.remove_field_by_name("avatar_source")?.try_into()?;
            let key: Option<String> = row.remove_field_by_name("avatar_key")?.try_into()?;
            let checked: Option<SystemTime> = row.remove_field_by_name("gravatar_checked_at")?.try_into()?;
            ensure!(source == "gravatar" && key.as_deref().is_some_and(|key| key.starts_with(&format!("avatars/user_{id}/gravatar_"))) && checked.is_some(), "Gravatar result not committed");
            Ok(())
        }.await;
        client
            .query_client()
            .exec("DELETE FROM accounts_userprofile WHERE id = $id")
            .param("$id", profile_id)
            .await?;
        client
            .query_client()
            .exec("DELETE FROM auth_user WHERE id = $id")
            .param("$id", id)
            .await?;
        if checked.is_ok() {
            gravatar_server.await??;
            s3_server.await??;
        } else {
            gravatar_server.abort();
            s3_server.abort();
        }
        checked
    }
}
