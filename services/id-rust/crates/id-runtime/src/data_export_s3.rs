//! Bounded-memory private S3 upload for an NDJSON account export.
//! Multipart upload uses one 5 MiB part buffer. Failed or uncertain uploads
//! are aborted and their unpublished object keys are deleted best-effort.

use crate::{
    data_export::{ExportManifest, write_ndjson_with_avatar, write_ndjson_with_avatar_for_escrow},
    data_export_operation::ExportClaim,
    media_delete::{EMPTY_HASH, PRODUCTION_ENDPOINT, SigningRequest, host_header, sign},
    media_url::MediaUrl,
};
use anyhow::{Context, Result, bail, ensure};
use chrono::Utc;
use reqwest::{Client, Method, StatusCode, header};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{env, sync::Arc, time::Duration};
use tokio::io::{AsyncRead, AsyncReadExt};
use url::Url;
use ydb::Client as YdbClient;

const PART_SIZE: usize = 5 * 1024 * 1024;
const MAX_XML: usize = 64 * 1024;

pub struct S3Export {
    http: Client,
    endpoint: Url,
    bucket: String,
    region: String,
    access_key: String,
    secret_key: String,
    avatar_source: Option<MediaUrl>,
}

#[derive(Deserialize)]
struct Initiated {
    #[serde(rename = "Bucket")]
    bucket: String,
    #[serde(rename = "Key")]
    key: String,
    #[serde(rename = "UploadId")]
    upload_id: String,
}

#[derive(Deserialize)]
struct Completed {
    #[serde(rename = "Bucket")]
    bucket: String,
    #[serde(rename = "Key")]
    key: String,
}

#[derive(Deserialize)]
struct ListedObjects {
    #[serde(rename = "Name")]
    bucket: String,
    #[serde(rename = "Prefix")]
    prefix: String,
    #[serde(rename = "IsTruncated")]
    truncated: bool,
    #[serde(rename = "Contents", default)]
    objects: Vec<ListedObject>,
    #[serde(rename = "NextContinuationToken")]
    next: Option<String>,
}

#[derive(Deserialize)]
struct ListedObject {
    #[serde(rename = "Key")]
    key: String,
}

pub struct ExportObjectPage {
    pub keys: Vec<String>,
    pub truncated: bool,
}

impl S3Export {
    pub fn from_env() -> Result<Self> {
        let endpoint = env::var("S3_ENDPOINT_URL").unwrap_or_else(|_| PRODUCTION_ENDPOINT.into());
        let region = env::var("S3_REGION").unwrap_or_else(|_| "ru-central1".into());
        let access_key = env::var("S3_ACCESS_KEY_ID").context("S3_ACCESS_KEY_ID is required")?;
        let secret_key =
            env::var("S3_SECRET_ACCESS_KEY").context("S3_SECRET_ACCESS_KEY is required")?;
        let mut storage = Self::new(
            &endpoint,
            &env::var("ID_EXPORT_S3_BUCKET_NAME")
                .context("ID_EXPORT_S3_BUCKET_NAME is required")?,
            &region,
            access_key.clone(),
            secret_key.clone(),
        )?;
        if let Ok(media_bucket) = env::var("S3_BUCKET_NAME") {
            let base = storage.endpoint.join(&format!("/{media_bucket}/"))?;
            storage.avatar_source = Some(MediaUrl::signed(
                base.as_str(),
                &region,
                access_key,
                secret_key,
                60,
            )?);
        }
        Ok(storage)
    }

    pub fn new(
        endpoint: &str,
        bucket: &str,
        region: &str,
        access_key: String,
        secret_key: String,
    ) -> Result<Self> {
        let endpoint = Url::parse(endpoint).context("invalid export S3 endpoint")?;
        let loopback = matches!(
            endpoint.host_str(),
            Some("localhost" | "127.0.0.1" | "[::1]")
        );
        ensure!(
            (endpoint.as_str() == PRODUCTION_ENDPOINT || (loopback && endpoint.scheme() == "http"))
                && endpoint.path() == "/"
                && endpoint.query().is_none()
                && endpoint.fragment().is_none()
                && endpoint.username().is_empty()
                && endpoint.password().is_none()
                && (3..=63).contains(&bucket.len())
                && bucket.bytes().all(|b| b.is_ascii_lowercase()
                    || b.is_ascii_digit()
                    || matches!(b, b'-' | b'.'))
                && !bucket.starts_with('.')
                && !bucket.ends_with('.')
                && !region.is_empty()
                && region
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && !access_key.is_empty()
                && !secret_key.is_empty(),
            "invalid private export S3 configuration"
        );
        Ok(Self {
            http: Client::builder()
                .timeout(Duration::from_secs(120))
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            endpoint,
            bucket: bucket.into(),
            region: region.into(),
            access_key,
            secret_key,
            avatar_source: None,
        })
    }

    pub fn object_key(claim: &ExportClaim) -> Result<String> {
        ensure!(
            claim.account_id > 0
                && claim.id.len() == 32
                && claim.id.bytes().all(|b| b.is_ascii_hexdigit())
                && uuid::Uuid::parse_str(&claim.token).is_ok(),
            "invalid export claim"
        );
        if claim.escrow {
            Ok(format!(
                "exports/escrow/{}/{}.ndjson",
                claim.id, claim.token
            ))
        } else {
            Ok(format!(
                "exports/user_{}/{}/{}.ndjson",
                claim.account_id, claim.id, claim.token
            ))
        }
    }

    pub fn download_url(&self, key: &str) -> Result<String> {
        validate_key(key)?;
        let base = self.endpoint.join(&format!("{}/", self.bucket))?;
        crate::media_url::MediaUrl::signed(
            base.as_str(),
            &self.region,
            self.access_key.clone(),
            self.secret_key.clone(),
            60,
        )?
        .object_url(key)
    }

    /// The YDB producer backpressures on a 64 KiB pipe. The S3 consumer holds
    /// at most one complete part plus a small HTTP/XML response.
    pub async fn upload_export(
        &self,
        client: Arc<YdbClient>,
        claim: &ExportClaim,
    ) -> Result<(String, ExportManifest)> {
        let key = Self::object_key(claim)?;
        let account_id = claim.account_id;
        let escrow = claim.escrow;
        let avatar_source = self.avatar_source.clone();
        let (mut writer, reader) = tokio::io::duplex(64 * 1024);
        let producer = tokio::spawn(async move {
            if escrow {
                write_ndjson_with_avatar_for_escrow(
                    &client,
                    account_id,
                    &mut writer,
                    avatar_source.as_ref(),
                )
                .await
            } else {
                write_ndjson_with_avatar(&client, account_id, &mut writer, avatar_source.as_ref())
                    .await
            }
        });
        // Bound a complete upload below the 15-minute YDB claim lease. A
        // deletion worker waits for that lease before sweeping the prefix.
        let uploaded = match tokio::time::timeout(
            Duration::from_secs(10 * 60),
            self.upload_stream(&key, reader),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => {
                producer.abort();
                let _ = producer.await;
                // Cancellation can race an S3 commit. This attempt's key is
                // never published to YDB, so removing it is always safe.
                self.remove_uncertain_object(&key).await;
                bail!("export upload exceeded claim lease safety window");
            }
        };
        match uploaded {
            Ok(()) => match producer.await {
                Ok(Ok(manifest)) => Ok((key, manifest)),
                Ok(Err(error)) => {
                    // A partial export must never be published. This key is
                    // unique to the claim; deletion is safe to retry.
                    self.remove_uncertain_object(&key).await;
                    Err(error.context("export producer failed"))
                }
                Err(error) => {
                    self.remove_uncertain_object(&key).await;
                    Err(error).context("export producer task failed")
                }
            },
            Err(error) => {
                producer.abort();
                let _ = producer.await;
                Err(error)
            }
        }
    }

    pub async fn upload_stream<R: AsyncRead + Unpin>(
        &self,
        key: &str,
        mut reader: R,
    ) -> Result<()> {
        validate_key(key)?;
        let mut buffer = vec![0u8; PART_SIZE];
        let first_size = fill(&mut reader, &mut buffer).await?;
        if first_size < PART_SIZE {
            buffer.truncate(first_size);
            let result = async {
                let response = self
                    .send(Method::PUT, key, "", buffer, Some("application/x-ndjson"))
                    .await?;
                ensure!(
                    response.status() == StatusCode::OK,
                    "export object PUT was not acknowledged"
                );
                Ok(())
            }
            .await;
            if result.is_err() {
                self.remove_uncertain_object(key).await;
            }
            return result;
        }
        let upload_id = self.start(key).await?;
        let result = self
            .upload_parts(key, &upload_id, &mut reader, buffer)
            .await;
        if result.is_err() {
            let _ = self.abort(key, &upload_id).await;
            // Abort cannot remove a multipart object whose completion reached
            // S3 but whose acknowledgement was lost.
            self.remove_uncertain_object(key).await;
        }
        result
    }

    async fn remove_uncertain_object(&self, key: &str) {
        if let Err(error) = self.delete_object(key).await {
            tracing::warn!(error = %error, "uncertain export object cleanup deferred to lifecycle");
        }
    }

    async fn upload_parts<R: AsyncRead + Unpin>(
        &self,
        key: &str,
        upload_id: &str,
        reader: &mut R,
        mut buffer: Vec<u8>,
    ) -> Result<()> {
        let mut parts = Vec::new();
        for number in 1..=10_000u32 {
            let query = format!(
                "partNumber={number}&uploadId={}",
                uri_encode(upload_id.as_bytes())
            );
            let response = self.send(Method::PUT, key, &query, buffer, None).await?;
            ensure!(
                response.status() == StatusCode::OK,
                "export part PUT was not acknowledged"
            );
            let etag = response
                .headers()
                .get(header::ETAG)
                .context("export part ETag missing")?
                .to_str()?
                .to_owned();
            validate_etag(&etag)?;
            parts.push((number, etag));
            buffer = vec![0u8; PART_SIZE];
            let size = fill(reader, &mut buffer).await?;
            if size == 0 {
                return self.finish(key, upload_id, &parts).await;
            }
            buffer.truncate(size);
            if number == 10_000 {
                bail!("export exceeds S3 multipart part limit");
            }
        }
        bail!("export exceeds S3 multipart part limit")
    }

    async fn start(&self, key: &str) -> Result<String> {
        let response = self
            .send(
                Method::POST,
                key,
                "uploads=",
                Vec::new(),
                Some("application/x-ndjson"),
            )
            .await?;
        ensure!(
            response.status() == StatusCode::OK,
            "export multipart initiation was not acknowledged"
        );
        let xml = bounded_xml(response).await?;
        let created: Initiated =
            quick_xml::de::from_str(&xml).context("invalid multipart initiation XML")?;
        ensure!(
            created.bucket == self.bucket
                && created.key == key
                && !created.upload_id.is_empty()
                && created.upload_id.len() <= 1024
                && !created.upload_id.chars().any(char::is_control),
            "invalid multipart initiation receipt"
        );
        Ok(created.upload_id)
    }

    async fn finish(&self, key: &str, upload_id: &str, parts: &[(u32, String)]) -> Result<()> {
        let mut xml = String::from("<CompleteMultipartUpload>");
        for (number, etag) in parts {
            validate_etag(etag)?;
            xml.push_str(&format!(
                "<Part><PartNumber>{number}</PartNumber><ETag>{etag}</ETag></Part>"
            ));
        }
        xml.push_str("</CompleteMultipartUpload>");
        let query = format!("uploadId={}", uri_encode(upload_id.as_bytes()));
        let response = self
            .send(
                Method::POST,
                key,
                &query,
                xml.into_bytes(),
                Some("application/xml"),
            )
            .await?;
        ensure!(
            response.status() == StatusCode::OK,
            "export multipart completion was not acknowledged"
        );
        // S3 can return 200 with an error XML body after starting completion.
        let xml = bounded_xml(response).await?;
        let completed: Completed =
            quick_xml::de::from_str(&xml).context("invalid multipart completion XML")?;
        ensure!(
            completed.bucket == self.bucket && completed.key == key,
            "export multipart completion receipt mismatch"
        );
        Ok(())
    }

    async fn abort(&self, key: &str, upload_id: &str) -> Result<()> {
        let query = format!("uploadId={}", uri_encode(upload_id.as_bytes()));
        let response = self
            .send(Method::DELETE, key, &query, Vec::new(), None)
            .await?;
        ensure!(
            matches!(
                response.status(),
                StatusCode::NO_CONTENT | StatusCode::NOT_FOUND
            ),
            "export multipart abort not acknowledged"
        );
        Ok(())
    }

    pub async fn delete_object(&self, key: &str) -> Result<()> {
        let response = self.send(Method::DELETE, key, "", Vec::new(), None).await?;
        ensure!(
            matches!(
                response.status(),
                StatusCode::NO_CONTENT | StatusCode::NOT_FOUND
            ),
            "export object deletion not acknowledged"
        );
        Ok(())
    }

    /// Reads only the first bounded page. Repeated cleanup passes start at
    /// the beginning, so deleted keys cannot be skipped by pagination races.
    pub async fn list_owner_objects(&self, account_id: i32) -> Result<ExportObjectPage> {
        ensure!(account_id > 0, "invalid export owner");
        let prefix = format!("exports/user_{account_id}/");
        self.list_objects_with_prefix(&prefix).await
    }

    /// List only one expired delayed request's objects. An earlier upload
    /// attempt may have committed without an acknowledgement, so the key
    /// stored in YDB is not necessarily the only private object to remove.
    pub async fn list_escrow_objects(&self, id: &str) -> Result<ExportObjectPage> {
        ensure!(
            id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "invalid export escrow ID"
        );
        self.list_objects_with_prefix(&format!("exports/escrow/{id}/"))
            .await
    }

    async fn list_objects_with_prefix(&self, prefix: &str) -> Result<ExportObjectPage> {
        let query = format!(
            "list-type=2&max-keys=25&prefix={}",
            uri_encode(prefix.as_bytes())
        );
        let response = self
            .send_path(
                Method::GET,
                &format!("/{}", self.bucket),
                &query,
                Vec::new(),
                None,
            )
            .await?;
        ensure!(
            response.status() == StatusCode::OK,
            "export S3 listing failed"
        );
        let xml = bounded_xml(response).await?;
        let listed: ListedObjects =
            quick_xml::de::from_str(&xml).context("invalid S3 listing XML")?;
        ensure!(
            listed.bucket == self.bucket
                && listed.prefix == prefix
                && listed.objects.len() <= 25
                && (!listed.truncated
                    || listed.next.as_ref().is_some_and(|token| !token.is_empty())),
            "invalid export S3 listing receipt"
        );
        let mut keys = Vec::with_capacity(listed.objects.len());
        for object in listed.objects {
            validate_key(&object.key)?;
            ensure!(
                object.key.starts_with(prefix),
                "S3 listed an object outside the requested export prefix"
            );
            keys.push(object.key);
        }
        Ok(ExportObjectPage {
            keys,
            truncated: listed.truncated,
        })
    }

    async fn send(
        &self,
        method: Method,
        key: &str,
        query: &str,
        body: Vec<u8>,
        content_type: Option<&str>,
    ) -> Result<reqwest::Response> {
        validate_key(key)?;
        let path = format!("/{}/{key}", self.bucket);
        self.send_path(method, &path, query, body, content_type)
            .await
    }

    async fn send_path(
        &self,
        method: Method,
        path: &str,
        query: &str,
        body: Vec<u8>,
        content_type: Option<&str>,
    ) -> Result<reqwest::Response> {
        let mut url = self.endpoint.join(path)?;
        if !query.is_empty() {
            url.set_query(Some(query));
        }
        let host = host_header(&url)?;
        let stamp = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let payload_hash = if body.is_empty() {
            EMPTY_HASH.to_owned()
        } else {
            hex::encode(Sha256::digest(&body))
        };
        let authorization = sign(
            SigningRequest {
                method: method.as_str(),
                path,
                query,
                host: &host,
                stamp: &stamp,
                region: &self.region,
                payload_hash: &payload_hash,
            },
            &self.access_key,
            &self.secret_key,
        )?;
        let mut request = self
            .http
            .request(method, url)
            .header(header::HOST, host)
            .header("x-amz-content-sha256", payload_hash)
            .header("x-amz-date", stamp)
            .header(header::AUTHORIZATION, authorization)
            .header(header::CONTENT_LENGTH, body.len())
            .body(body);
        if let Some(content_type) = content_type {
            request = request.header(header::CONTENT_TYPE, content_type);
        }
        request.send().await.context("export S3 request failed")
    }
}

async fn fill<R: AsyncRead + Unpin>(reader: &mut R, buffer: &mut [u8]) -> Result<usize> {
    let mut filled = 0;
    while filled < buffer.len() {
        let count = reader.read(&mut buffer[filled..]).await?;
        if count == 0 {
            break;
        }
        filled += count;
    }
    Ok(filled)
}

async fn bounded_xml(mut response: reqwest::Response) -> Result<String> {
    ensure!(
        response
            .content_length()
            .is_none_or(|length| length <= MAX_XML as u64),
        "export S3 XML too large"
    );
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            chunk.len() <= MAX_XML.saturating_sub(body.len()),
            "export S3 XML too large"
        );
        body.extend_from_slice(&chunk);
    }
    Ok(String::from_utf8(body)?)
}

fn validate_key(key: &str) -> Result<()> {
    ensure!(
        (key.starts_with("exports/user_") || key.starts_with("exports/escrow/"))
            && key.len() <= 512
            && key.split('/').all(|part| !part.is_empty())
            && key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'_' | b'-' | b'.')),
        "invalid export object key"
    );
    Ok(())
}

fn validate_etag(etag: &str) -> Result<()> {
    ensure!(
        etag.len() >= 3
            && etag.len() <= 100
            && etag.starts_with('"')
            && etag.ends_with('"')
            && etag[1..etag.len() - 1]
                .bytes()
                .all(|b| b.is_ascii_hexdigit() || b == b'-'),
        "invalid export part ETag"
    );
    Ok(())
}

fn uri_encode(value: &[u8]) -> String {
    let mut result = String::new();
    for &byte in value {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            result.push(byte as char);
        } else {
            result.push('%');
            result.push_str(&format!("{byte:02X}"));
        }
    }
    result
}
