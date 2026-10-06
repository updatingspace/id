//! Signed, owner-scoped deletion of avatar objects from Yandex Object Storage.
//! A caller may retry an ambiguous DELETE; it must retain the YDB avatar key
//! until Object Storage has acknowledged the request.

use anyhow::{Context, Result, bail, ensure};
use chrono::Utc;
use hmac::{Hmac, Mac};
use reqwest::{Client, StatusCode};
use sha2::{Digest, Sha256};
use std::{env, time::Duration};
use url::{Host, Url};

pub(crate) const PRODUCTION_ENDPOINT: &str = "https://storage.yandexcloud.net/";
pub(crate) const EMPTY_HASH: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const SIGNED_HEADERS: &str = "host;x-amz-content-sha256;x-amz-date";

pub struct S3MediaDelete {
    http: Client,
    endpoint: Url,
    bucket: String,
    region: String,
    access_key: String,
    secret_key: String,
}

impl S3MediaDelete {
    pub fn from_env() -> Result<Option<Self>> {
        match env::var("MEDIA_STORAGE_DRIVER").as_deref() {
            Ok("s3") => Ok(Some(Self::new(
                &env::var("S3_ENDPOINT_URL").unwrap_or_else(|_| PRODUCTION_ENDPOINT.into()),
                &env::var("S3_BUCKET_NAME").context("S3_BUCKET_NAME is required")?,
                &env::var("S3_REGION").unwrap_or_else(|_| "ru-central1".into()),
                env::var("S3_ACCESS_KEY_ID").context("S3_ACCESS_KEY_ID is required")?,
                env::var("S3_SECRET_ACCESS_KEY").context("S3_SECRET_ACCESS_KEY is required")?,
            )?)),
            Ok("local") | Err(env::VarError::NotPresent) => Ok(None),
            _ => bail!("unsupported media storage driver"),
        }
    }

    pub fn new(
        endpoint: &str,
        bucket: &str,
        region: &str,
        access_key: String,
        secret_key: String,
    ) -> Result<Self> {
        let endpoint = Url::parse(endpoint).context("invalid S3 endpoint")?;
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
                && bucket.bytes().all(|byte| byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'-' | b'.'))
                && !bucket.starts_with('.')
                && !bucket.ends_with('.')
                && !region.is_empty()
                && region
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                && !access_key.is_empty()
                && !secret_key.is_empty(),
            "invalid S3 media configuration"
        );
        Ok(Self {
            http: Client::builder()
                .timeout(Duration::from_secs(10))
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            endpoint,
            bucket: bucket.into(),
            region: region.into(),
            access_key,
            secret_key,
        })
    }

    pub async fn delete_avatar(&self, account_id: i32, key: &str) -> Result<()> {
        validate_avatar_key(account_id, key)?;
        let path = format!("/{}/{key}", self.bucket);
        let url = self.endpoint.join(&path)?;
        let host = host_header(&url)?;
        let stamp = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let authorization = sign(
            SigningRequest {
                method: "DELETE",
                path: &path,
                query: "",
                host: &host,
                stamp: &stamp,
                region: &self.region,
                payload_hash: EMPTY_HASH,
            },
            &self.access_key,
            &self.secret_key,
        )?;
        let response = self
            .http
            .delete(url)
            .header(reqwest::header::HOST, host)
            .header("x-amz-content-sha256", EMPTY_HASH)
            .header("x-amz-date", stamp)
            .header(reqwest::header::AUTHORIZATION, authorization)
            .send()
            .await
            .context("delete avatar object request failed")?;
        ensure!(
            response.status() == StatusCode::NO_CONTENT,
            "avatar object deletion was not acknowledged"
        );
        Ok(())
    }

    /// Store a normalized JPEG before publishing its unique key in YDB.
    pub async fn put_avatar(&self, account_id: i32, key: &str, jpeg: Vec<u8>) -> Result<()> {
        validate_avatar_key(account_id, key)?;
        ensure!(
            !jpeg.is_empty() && jpeg.len() <= 6 * 1024 * 1024,
            "invalid avatar size"
        );
        let path = format!("/{}/{key}", self.bucket);
        let url = self.endpoint.join(&path)?;
        let host = host_header(&url)?;
        let stamp = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let payload_hash = hex::encode(Sha256::digest(&jpeg));
        let authorization = sign(
            SigningRequest {
                method: "PUT",
                path: &path,
                query: "",
                host: &host,
                stamp: &stamp,
                region: &self.region,
                payload_hash: &payload_hash,
            },
            &self.access_key,
            &self.secret_key,
        )?;
        let response = self
            .http
            .put(url)
            .header(reqwest::header::HOST, host)
            .header("x-amz-content-sha256", payload_hash)
            .header("x-amz-date", stamp)
            .header(reqwest::header::AUTHORIZATION, authorization)
            .header(reqwest::header::CONTENT_TYPE, "image/jpeg")
            .body(jpeg)
            .send()
            .await
            .context("put avatar object request failed")?;
        ensure!(
            response.status() == StatusCode::OK,
            "avatar upload not acknowledged"
        );
        Ok(())
    }
}

pub fn validate_avatar_key(account_id: i32, key: &str) -> Result<()> {
    let prefix = format!("avatars/user_{account_id}/");
    let Some(name) = key.strip_prefix(&prefix) else {
        bail!("avatar key does not belong to deletion account");
    };
    ensure!(
        !name.is_empty()
            && name.len() <= 255
            && name != "."
            && name != ".."
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')),
        "avatar object key is invalid"
    );
    Ok(())
}

pub(crate) fn host_header(url: &Url) -> Result<String> {
    let host = match url.host().context("S3 host missing")? {
        Host::Domain(name) => name.to_owned(),
        Host::Ipv4(ip) => ip.to_string(),
        Host::Ipv6(ip) => format!("[{ip}]"),
    };
    Ok(url
        .port()
        .map_or(host.clone(), |port| format!("{host}:{port}")))
}

fn mac(key: &[u8], value: &[u8]) -> Result<Vec<u8>> {
    let mut signer = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|_| anyhow::anyhow!("invalid S3 signing key"))?;
    signer.update(value);
    Ok(signer.finalize().into_bytes().to_vec())
}

pub(crate) struct SigningRequest<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub query: &'a str,
    pub host: &'a str,
    pub stamp: &'a str,
    pub region: &'a str,
    pub payload_hash: &'a str,
}

pub(crate) fn sign(
    request: SigningRequest<'_>,
    access_key: &str,
    secret_key: &str,
) -> Result<String> {
    let SigningRequest {
        method,
        path,
        query,
        host,
        stamp,
        region,
        payload_hash,
    } = request;
    ensure!(
        stamp.len() == 16
            && stamp.as_bytes()[8] == b'T'
            && stamp.as_bytes()[15] == b'Z'
            && stamp[..8].bytes().all(|byte| byte.is_ascii_digit())
            && stamp[9..15].bytes().all(|byte| byte.is_ascii_digit()),
        "invalid S3 signing timestamp"
    );
    let date = &stamp[..8];
    let scope = format!("{date}/{region}/s3/aws4_request");
    let canonical = format!(
        "{method}\n{path}\n{query}\nhost:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{stamp}\n\n{SIGNED_HEADERS}\n{payload_hash}"
    );
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{}",
        hex::encode(Sha256::digest(canonical.as_bytes()))
    );
    let date_key = mac(format!("AWS4{secret_key}").as_bytes(), date.as_bytes())?;
    let region_key = mac(&date_key, region.as_bytes())?;
    let service_key = mac(&region_key, b"s3")?;
    let signing_key = mac(&service_key, b"aws4_request")?;
    let signature = hex::encode(mac(&signing_key, to_sign.as_bytes())?);
    Ok(format!(
        "AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={SIGNED_HEADERS}, Signature={signature}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn matches_published_s3_signature_vector() -> Result<()> {
        // AWS S3 SigV4 example: GET bucket lifecycle with an empty payload.
        let authorization = sign(
            SigningRequest {
                method: "GET",
                path: "/",
                query: "lifecycle=",
                host: "examplebucket.s3.amazonaws.com",
                stamp: "20130524T000000Z",
                region: "us-east-1",
                payload_hash: EMPTY_HASH,
            },
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        )?;
        ensure!(
            authorization.ends_with(
                "Signature=fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543"
            ),
            "S3 signature differs from published vector"
        );
        Ok(())
    }

    #[test]
    fn rejects_cross_account_keys_and_remote_endpoints() -> Result<()> {
        validate_avatar_key(42, "avatars/user_42/abc.jpg")?;
        S3MediaDelete::new(
            "https://storage.yandexcloud.net",
            "id-media",
            "ru-central1",
            "synthetic-key".into(),
            "synthetic-secret".into(),
        )?;
        for key in [
            "avatars/user_43/abc.jpg",
            "avatars/user_42/../secret",
            "avatars/user_42/a/b.jpg",
            "avatars/user_42/a%2Fb.jpg",
        ] {
            assert!(validate_avatar_key(42, key).is_err());
        }
        assert!(
            S3MediaDelete::new(
                "https://other.example/",
                "id-media",
                "ru-central1",
                "key".into(),
                "secret".into()
            )
            .is_err()
        );
        Ok(())
    }

    #[tokio::test]
    async fn sends_signed_delete_and_requires_acknowledgement() -> Result<()> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let mut request = vec![0u8; 4096];
            let size = stream.read(&mut request).await?;
            let request = String::from_utf8_lossy(&request[..size]).to_ascii_lowercase();
            assert!(request.starts_with("delete /id-media/avatars/user_42/abc.jpg http/1.1"));
            assert!(request.contains("authorization: aws4-hmac-sha256 "));
            assert!(request.contains("x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await?;
            Result::<()>::Ok(())
        });
        let cleaner = S3MediaDelete::new(
            &format!("http://127.0.0.1:{port}/"),
            "id-media",
            "ru-central1",
            "synthetic-key".into(),
            "synthetic-secret".into(),
        )?;
        cleaner.delete_avatar(42, "avatars/user_42/abc.jpg").await?;
        server.await??;
        Ok(())
    }

    #[tokio::test]
    async fn puts_only_owner_scoped_jpeg_with_signed_payload() -> Result<()> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let expected_hash = hex::encode(Sha256::digest(b"synthetic-jpeg"));
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let mut request = vec![0u8; 4096];
            let size = stream.read(&mut request).await?;
            let head = String::from_utf8_lossy(&request[..size]).to_ascii_lowercase();
            assert!(head.starts_with("put /id-media/avatars/user_42/gravatar_test.jpg http/1.1"));
            assert!(head.contains("content-type: image/jpeg"));
            assert!(head.contains(&format!("x-amz-content-sha256: {expected_hash}")));
            assert!(head.contains("authorization: aws4-hmac-sha256 "));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await?;
            Result::<()>::Ok(())
        });
        let store = S3MediaDelete::new(
            &format!("http://127.0.0.1:{port}/"),
            "id-media",
            "ru-central1",
            "synthetic-key".into(),
            "synthetic-secret".into(),
        )?;
        store
            .put_avatar(
                42,
                "avatars/user_42/gravatar_test.jpg",
                b"synthetic-jpeg".to_vec(),
            )
            .await?;
        server.await??;
        assert!(
            store
                .put_avatar(
                    43,
                    "avatars/user_42/gravatar_test.jpg",
                    b"synthetic-jpeg".to_vec()
                )
                .await
                .is_err()
        );
        Ok(())
    }
}
