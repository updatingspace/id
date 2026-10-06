//! Normalize an uploaded image and publish a unique private object only after
//! the account's session and avatar pointer still match the initial snapshot.

use crate::{
    avatar_delete::{AvatarSnapshot, read, snapshot},
    media_delete::{S3MediaDelete, validate_avatar_key},
    session_store::LEGACY_BACKENDS,
    tx_retry::retry_known_abort,
};
use anyhow::{Context, Result, ensure};
use id_compat::session::SessionCodec;
use image::{
    DynamicImage, ImageDecoder, ImageReader, codecs::jpeg::JpegEncoder, imageops::FilterType,
};
use std::{
    io::Cursor,
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::sync::Semaphore;
use uuid::Uuid;
use ydb::{Client, Transaction, TxMode, closure};

const MAX_FILE_BYTES: usize = 6 * 1024 * 1024;
static IMAGE_WORKERS: Semaphore = Semaphore::const_new(2);

#[derive(Debug, PartialEq, Eq)]
pub enum UploadResult {
    Uploaded(String),
    Unauthorized,
    Changed,
}

pub async fn normalize(raw: Vec<u8>) -> Result<Vec<u8>> {
    ensure!(!raw.is_empty(), "avatar file is empty");
    ensure!(raw.len() <= MAX_FILE_BYTES, "avatar file exceeds 6 MiB");
    let permit = IMAGE_WORKERS
        .acquire()
        .await
        .context("image processor closed")?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        normalize_blocking(raw)
    })
    .await
    .context("image processor stopped")?
}

fn normalize_blocking(raw: Vec<u8>) -> Result<Vec<u8>> {
    let reader = ImageReader::new(Cursor::new(raw)).with_guessed_format()?;
    let mut reader = reader;
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(8192);
    limits.max_image_height = Some(8192);
    limits.max_alloc = Some(96 * 1024 * 1024);
    reader.limits(limits);
    let mut decoder = reader.into_decoder().context("unsupported avatar image")?;
    let orientation = decoder.orientation()?;
    let mut image = DynamicImage::from_decoder(decoder).context("invalid avatar image")?;
    image.apply_orientation(orientation);
    let (width, height) = (image.width(), image.height());
    ensure!(
        width > 0 && height > 0 && u64::from(width) * u64::from(height) <= 24_000_000,
        "avatar image dimensions are invalid"
    );
    let square = image
        .resize_to_fill(512, 512, FilterType::Lanczos3)
        .to_rgb8();
    let mut jpeg = Vec::new();
    JpegEncoder::new_with_quality(&mut jpeg, 88).encode_image(&square)?;
    ensure!(
        !jpeg.is_empty() && jpeg.len() <= MAX_FILE_BYTES,
        "normalized avatar is invalid"
    );
    Ok(jpeg)
}

pub async fn upload(
    client: &Client,
    codec: Arc<SessionCodec>,
    media: &S3MediaDelete,
    token: &str,
    jpeg: Vec<u8>,
    now: SystemTime,
) -> Result<UploadResult> {
    let backends: Vec<String> = LEGACY_BACKENDS
        .iter()
        .map(|value| (*value).to_owned())
        .collect();
    let Some(prior) = read(
        client,
        codec.clone(),
        token.to_owned(),
        backends.clone(),
        now,
    )
    .await?
    else {
        return Ok(UploadResult::Unauthorized);
    };
    ensure!(
        !jpeg.is_empty() && jpeg.len() <= MAX_FILE_BYTES,
        "invalid normalized avatar"
    );
    let key = format!(
        "avatars/user_{}/upload_{}.jpg",
        prior.account_id,
        Uuid::new_v4().simple()
    );
    media.put_avatar(prior.account_id, &key, jpeg).await?;
    let outcome = commit(client, codec, token.to_owned(), backends, &prior, &key, now).await;
    match outcome {
        Ok(UploadResult::Uploaded(_)) => {
            if let Some(old_key) = prior.key.as_deref()
                && validate_avatar_key(prior.account_id, old_key).is_ok()
                && media
                    .delete_avatar(prior.account_id, old_key)
                    .await
                    .is_err()
            {
                tracing::warn!("old avatar object cleanup needs retry");
            }
            Ok(UploadResult::Uploaded(key))
        }
        Ok(result @ (UploadResult::Changed | UploadResult::Unauthorized)) => {
            if media.delete_avatar(prior.account_id, &key).await.is_err() {
                tracing::warn!("unused uploaded avatar object cleanup needs retry");
            }
            Ok(result)
        }
        Err(failure) => {
            // A transaction timeout can mean that commit succeeded. Never
            // delete the newly uploaded object while the outcome is unknown.
            Err(failure)
        }
    }
}

async fn commit(
    client: &Client,
    codec: Arc<SessionCodec>,
    token: String,
    backends: Vec<String>,
    prior: &AvatarSnapshot,
    key: &str,
    now: SystemTime,
) -> Result<UploadResult> {
    let prior = prior.clone();
    let key = key.to_owned();
    retry_known_abort(|| {
        let codec = codec.clone();
        let token = token.clone();
        let backends = backends.clone();
        let prior = prior.clone();
        let key = key.clone();
        async {
            client.query_client().retry_tx(closure!([codec, token, backends, prior, key], async |tx: &mut Transaction| {
                let Some(current) = snapshot(tx, codec.as_ref(), token, backends, now).await? else {
                    return Ok(UploadResult::Unauthorized);
                };
                if current != *prior {
                    return Ok(UploadResult::Changed);
                }
                if let Some(profile_id) = current.profile_id {
                    tx.exec("UPDATE accounts_userprofile SET avatar = CAST($key AS String), avatar_source = 'upload', gravatar_enabled = false, gravatar_checked_at = CAST($now AS Datetime), updated_at = CAST($now AS Datetime) WHERE id = $id")
                        .param("$key", key.to_owned()).param("$now", now).param("$id", profile_id).await?;
                } else {
                    tx.exec("INSERT INTO accounts_userprofile (user_id, avatar, avatar_source, gravatar_enabled, phone_number, phone_verified, gravatar_checked_at, created_at, updated_at) VALUES ($user_id, CAST($key AS String), 'upload', false, '', false, CAST($now AS Datetime), CAST($now AS Datetime), CAST($now AS Datetime))")
                        .param("$user_id", current.account_id).param("$key", key.to_owned()).param("$now", now).await?;
                }
                Ok(UploadResult::Uploaded(key.to_owned()))
            })).with_mode(TxMode::SerializableReadWrite).idempotent(false)
                .timeout(Duration::from_secs(10)).await
        }
    }).await
}
