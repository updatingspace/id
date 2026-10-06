//! Public avatar URLs and short-lived S3 SigV4 URLs for private media.

use anyhow::{Context, Result, bail, ensure};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::{env, fmt, sync::Arc};
use url::Url;

const PRODUCTION_ENDPOINT: &str = "https://storage.yandexcloud.net/";
const AVATAR_URL_SECONDS: u32 = 3600;

#[derive(Clone)]
pub struct MediaUrl {
    base: Url,
    signer: Option<Arc<Signer>>,
}

struct Signer {
    region: String,
    access_key: String,
    secret_key: String,
    expires_seconds: u32,
}

impl fmt::Debug for MediaUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MediaUrl")
            .field("base", &self.base)
            .field("signed", &self.signer.is_some())
            .finish()
    }
}

impl MediaUrl {
    pub fn new(base: &str) -> Result<Self> {
        let mut url = Url::parse(base)?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            bail!("media base must be an HTTP(S) URL without credentials or query");
        }
        if !url.path().ends_with('/') {
            url.set_path(&format!("{}/", url.path()));
        }
        Ok(Self {
            base: url,
            signer: None,
        })
    }

    pub fn from_env(base: &str) -> Result<Self> {
        let public = Self::new(base)?;
        let signed = match env::var("S3_QUERYSTRING_AUTH").as_deref() {
            Ok("true" | "True" | "1") => true,
            Ok("false" | "False" | "0") | Err(env::VarError::NotPresent) => false,
            _ => bail!("invalid S3_QUERYSTRING_AUTH"),
        };
        if !signed {
            return Ok(public);
        }
        ensure!(
            env::var("MEDIA_STORAGE_DRIVER")?.as_str() == "s3",
            "signed media requires S3 storage"
        );
        let endpoint = Url::parse(
            &env::var("S3_ENDPOINT_URL").unwrap_or_else(|_| PRODUCTION_ENDPOINT.into()),
        )?;
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
                && endpoint.password().is_none(),
            "unsupported S3 endpoint for signed media"
        );
        let bucket = env::var("S3_BUCKET_NAME").context("S3_BUCKET_NAME is required")?;
        ensure!(
            (3..=63).contains(&bucket.len())
                && bucket.bytes().all(|byte| byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'-' | b'.'))
                && !bucket.starts_with('.')
                && !bucket.ends_with('.'),
            "invalid S3 bucket name"
        );
        ensure!(
            public.base == endpoint.join(&format!("/{bucket}/"))?,
            "media base must match S3 endpoint and bucket"
        );
        Self::signed(
            public.base.as_str(),
            &env::var("S3_REGION").unwrap_or_else(|_| "ru-central1".into()),
            env::var("S3_ACCESS_KEY_ID").context("S3_ACCESS_KEY_ID is required")?,
            env::var("S3_SECRET_ACCESS_KEY").context("S3_SECRET_ACCESS_KEY is required")?,
            AVATAR_URL_SECONDS,
        )
    }

    pub fn signed(
        base: &str,
        region: &str,
        access_key: String,
        secret_key: String,
        expires_seconds: u32,
    ) -> Result<Self> {
        let mut media = Self::new(base)?;
        ensure!(
            !access_key.is_empty()
                && !secret_key.is_empty()
                && !region.is_empty()
                && region
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                && (1..=604_800).contains(&expires_seconds),
            "invalid S3 signing configuration"
        );
        media.signer = Some(Arc::new(Signer {
            region: region.into(),
            access_key,
            secret_key,
            expires_seconds,
        }));
        Ok(media)
    }

    pub fn avatar_url(&self, key: &str) -> Result<String> {
        self.object_url(key)
    }

    pub fn object_url(&self, key: &str) -> Result<String> {
        self.avatar_url_at(key, Utc::now())
    }

    fn avatar_url_at(&self, key: &str, now: DateTime<Utc>) -> Result<String> {
        if key.is_empty()
            || key.starts_with('/')
            || key
                .split('/')
                .any(|segment| matches!(segment, "" | "." | ".."))
            || key.chars().any(char::is_control)
        {
            bail!("invalid avatar object key");
        }
        let mut url = self.base.clone();
        url.path_segments_mut()
            .map_err(|()| anyhow::anyhow!("media URL cannot contain path segments"))?
            .pop_if_empty()
            .extend(key.split('/'));
        if let Some(signer) = &self.signer {
            signer.sign_get(&mut url, now)?;
        }
        Ok(url.into())
    }
}

impl Signer {
    fn sign_get(&self, url: &mut Url, now: DateTime<Utc>) -> Result<()> {
        let stamp = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date = &stamp[..8];
        let scope = format!("{date}/{}/s3/aws4_request", self.region);
        let credential = format!("{}/{}", self.access_key, scope);
        let query = format!(
            "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential={}&X-Amz-Date={stamp}&X-Amz-Expires={}&X-Amz-SignedHeaders=host",
            uri_encode(credential.as_bytes()),
            self.expires_seconds
        );
        let mut host = url.host_str().context("S3 media host missing")?.to_owned();
        if let Some(port) = url.port() {
            host.push_str(&format!(":{port}"));
        }
        let canonical = format!(
            "GET\n{}\n{query}\nhost:{host}\n\nhost\nUNSIGNED-PAYLOAD",
            url.path()
        );
        let to_sign = format!(
            "AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{}",
            hex::encode(Sha256::digest(canonical.as_bytes()))
        );
        let signing_key = mac(
            &mac(
                &mac(
                    &mac(
                        format!("AWS4{}", self.secret_key).as_bytes(),
                        date.as_bytes(),
                    )?,
                    self.region.as_bytes(),
                )?,
                b"s3",
            )?,
            b"aws4_request",
        )?;
        let signature = hex::encode(mac(&signing_key, to_sign.as_bytes())?);
        url.set_query(Some(&format!("{query}&X-Amz-Signature={signature}")));
        Ok(())
    }
}

fn mac(key: &[u8], value: &[u8]) -> Result<Vec<u8>> {
    let mut signer = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|_| anyhow::anyhow!("invalid S3 signing key"))?;
    signer.update(value);
    Ok(signer.finalize().into_bytes().to_vec())
}

fn uri_encode(value: &[u8]) -> String {
    let mut result = String::with_capacity(value.len());
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn builds_public_object_storage_url_without_losing_bucket_path() -> Result<()> {
        let media = MediaUrl::new("https://storage.yandexcloud.net/id-media")?;
        assert_eq!(
            media.avatar_url("avatars/user_7/photo with space.jpg")?,
            "https://storage.yandexcloud.net/id-media/avatars/user_7/photo%20with%20space.jpg"
        );
        Ok(())
    }

    #[test]
    fn matches_published_s3_presigned_get_vector() -> Result<()> {
        let media = MediaUrl::signed(
            "https://examplebucket.s3.amazonaws.com/",
            "us-east-1",
            "AKIAIOSFODNN7EXAMPLE".into(),
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
            86400,
        )?;
        let timestamp = Utc
            .with_ymd_and_hms(2013, 5, 24, 0, 0, 0)
            .single()
            .context("invalid test time")?;
        assert_eq!(
            media.avatar_url_at("test.txt", timestamp)?,
            "https://examplebucket.s3.amazonaws.com/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
        );
        ensure!(
            !format!("{media:?}").contains("wJalrXUtn"),
            "media signing secret leaked through Debug"
        );
        Ok(())
    }

    #[test]
    fn rejects_untrusted_or_ambiguous_media_paths() -> Result<()> {
        for base in [
            "file:///tmp/media",
            "https://user:password@example.com/media",
            "https://example.com/media?token=secret",
        ] {
            assert!(MediaUrl::new(base).is_err());
        }
        let media = MediaUrl::new("https://example.com/media/")?;
        for key in [
            "",
            "/other",
            "../secret",
            "avatars/../secret",
            "a//b",
            "a\nb",
        ] {
            assert!(media.avatar_url(key).is_err(), "{key:?}");
        }
        Ok(())
    }
}
