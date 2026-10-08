//! Best-effort YMQ wakeup for durable new-device mail intents.
//! The YDB outbox remains authoritative: a failed or ambiguous SendMessage
//! never changes its state, and timer recovery can publish it again.

use anyhow::{Context, Result, bail, ensure};
use chrono::Utc;
use hmac::{Hmac, KeyInit, Mac};
use reqwest::Client;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{env, time::Duration};
use url::{Host, Url};

const YMQ_ENDPOINT: &str = "https://message-queue.api.cloud.yandex.net/";
const CONTENT_TYPE: &str = "application/x-www-form-urlencoded";
const REGION: &str = "ru-central1";
const SERVICE: &str = "sqs";

type HmacSha256 = Hmac<Sha256>;

pub struct YmqPublisher {
    http: Client,
    endpoint: Url,
    queue_url: String,
    access_key: String,
    secret_key: String,
}

impl YmqPublisher {
    pub fn from_env() -> Result<Option<Self>> {
        let Ok(queue_url) = env::var("YMQ_QUEUE_URL") else {
            return Ok(None);
        };
        let access_key = env::var("YMQ_ACCESS_KEY_ID").context("YMQ_ACCESS_KEY_ID is required")?;
        let secret_key =
            env::var("YMQ_SECRET_ACCESS_KEY").context("YMQ_SECRET_ACCESS_KEY is required")?;
        Ok(Some(Self::new(
            YMQ_ENDPOINT,
            &queue_url,
            access_key,
            secret_key,
        )?))
    }

    pub fn new(
        endpoint: &str,
        queue_url: &str,
        access_key: String,
        secret_key: String,
    ) -> Result<Self> {
        let endpoint = Url::parse(endpoint).context("invalid YMQ endpoint")?;
        let queue = Url::parse(queue_url).context("invalid YMQ queue URL")?;
        let loopback = matches!(
            endpoint.host_str(),
            Some("localhost" | "127.0.0.1" | "[::1]")
        );
        ensure!(
            (endpoint.as_str() == YMQ_ENDPOINT || (loopback && endpoint.scheme() == "http"))
                && queue.scheme() == endpoint.scheme()
                && queue.host_str() == endpoint.host_str()
                && queue.port() == endpoint.port()
                && endpoint.path() == "/"
                && queue.path().len() > 1
                && !queue.path().ends_with('/')
                && endpoint.query().is_none()
                && queue.query().is_none()
                && endpoint.fragment().is_none()
                && queue.fragment().is_none()
                && endpoint.username().is_empty()
                && queue.username().is_empty()
                && endpoint.password().is_none()
                && queue.password().is_none()
                && !access_key.is_empty()
                && !secret_key.is_empty(),
            "invalid YMQ endpoint, queue or credentials"
        );
        Ok(Self {
            http: Client::builder().timeout(Duration::from_secs(3)).build()?,
            endpoint,
            queue_url: queue_url.to_owned(),
            access_key,
            secret_key,
        })
    }

    pub async fn send_new_device_mail(&self, event_id: i64) -> Result<()> {
        ensure!(event_id > 0, "invalid mail event ID");
        self.send_intent("new_device_mail", json!(event_id)).await
    }

    pub async fn send_password_changed_mail(&self, event_id: &str) -> Result<()> {
        uuid::Uuid::parse_str(event_id).context("invalid password mail event ID")?;
        self.send_intent("password_changed_mail", json!(event_id))
            .await
    }

    pub async fn send_security_mail(&self, event_id: &str) -> Result<()> {
        uuid::Uuid::parse_str(event_id).context("invalid security mail event ID")?;
        self.send_intent("security_mail", json!(event_id)).await
    }

    pub async fn send_password_reset_mail(&self, event_id: &str) -> Result<()> {
        uuid::Uuid::parse_str(event_id).context("invalid password reset event ID")?;
        self.send_intent("password_reset_mail", json!(event_id))
            .await
    }

    pub async fn send_email_verify_mail(&self, event_id: &str) -> Result<()> {
        uuid::Uuid::parse_str(event_id).context("invalid email verification event ID")?;
        self.send_intent("email_verify_mail", json!(event_id)).await
    }

    pub async fn send_magic_link_mail(&self, event_id: &str) -> Result<()> {
        uuid::Uuid::parse_str(event_id).context("invalid magic-link mail event ID")?;
        self.send_intent("magic_link_mail", json!(event_id)).await
    }

    async fn send_intent(&self, kind: &str, event_id: Value) -> Result<()> {
        let intent = json!({"version":1,"kind":kind,"event_id":event_id});
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("Action", "SendMessage")
            .append_pair("Version", "2012-11-05")
            .append_pair("QueueUrl", &self.queue_url)
            .append_pair("MessageBody", &intent.to_string())
            .finish();
        let stamp = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let host = host_header(&self.endpoint)?;
        let authorization = authorization(
            &self.access_key,
            &self.secret_key,
            &host,
            &stamp,
            body.as_bytes(),
        )?;
        let mut response = self
            .http
            .post(self.endpoint.clone())
            .header(reqwest::header::CONTENT_TYPE, CONTENT_TYPE)
            .header(reqwest::header::HOST, host)
            .header("x-amz-date", stamp)
            .header(reqwest::header::AUTHORIZATION, authorization)
            .body(body)
            .send()
            .await
            .context("YMQ send failed")?;
        ensure!(response.status().is_success(), "YMQ rejected send");
        let mut response_body = Vec::new();
        while let Some(chunk) = response.chunk().await.context("YMQ response failed")? {
            ensure!(
                response_body.len() + chunk.len() <= 8192,
                "YMQ response too large"
            );
            response_body.extend_from_slice(&chunk);
        }
        let response_text = std::str::from_utf8(&response_body)?;
        ensure!(
            response_text.contains("<SendMessageResponse") && response_text.contains("<MessageId>"),
            "YMQ send acknowledgement missing"
        );
        Ok(())
    }
}

fn host_header(endpoint: &Url) -> Result<String> {
    let host = match endpoint.host().context("YMQ host missing")? {
        Host::Domain(name) => name.to_owned(),
        Host::Ipv4(ip) => ip.to_string(),
        Host::Ipv6(ip) => format!("[{ip}]"),
    };
    Ok(endpoint
        .port()
        .map_or(host.clone(), |port| format!("{host}:{port}")))
}

fn mac(key: &[u8], value: &[u8]) -> Result<Vec<u8>> {
    let mut signer =
        HmacSha256::new_from_slice(key).map_err(|_| anyhow::anyhow!("invalid HMAC key"))?;
    signer.update(value);
    Ok(signer.finalize().into_bytes().to_vec())
}

fn authorization(
    access_key: &str,
    secret_key: &str,
    host: &str,
    stamp: &str,
    body: &[u8],
) -> Result<String> {
    if stamp.len() != 16 || !stamp.ends_with('Z') || !stamp[..8].bytes().all(|b| b.is_ascii_digit())
    {
        bail!("invalid YMQ signing timestamp");
    }
    let date = &stamp[..8];
    let scope = format!("{date}/{REGION}/{SERVICE}/aws4_request");
    let canonical = format!(
        "POST\n/\n\ncontent-type:{CONTENT_TYPE}\nhost:{host}\nx-amz-date:{stamp}\n\ncontent-type;host;x-amz-date\n{}",
        hex::encode(Sha256::digest(body))
    );
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{}",
        hex::encode(Sha256::digest(canonical.as_bytes()))
    );
    let date_key = mac(format!("AWS4{secret_key}").as_bytes(), date.as_bytes())?;
    let region_key = mac(&date_key, REGION.as_bytes())?;
    let service_key = mac(&region_key, SERVICE.as_bytes())?;
    let signing_key = mac(&service_key, b"aws4_request")?;
    let signature = hex::encode(mac(&signing_key, to_sign.as_bytes())?);
    Ok(format!(
        "AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders=content-type;host;x-amz-date, Signature={signature}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn rejects_untrusted_queue_and_incomplete_credentials() {
        assert!(
            YmqPublisher::new(
                YMQ_ENDPOINT,
                "https://other.invalid/queue",
                "id".into(),
                "secret".into()
            )
            .is_err()
        );
        assert!(
            YmqPublisher::new(
                YMQ_ENDPOINT,
                "http://message-queue.api.cloud.yandex.net/queue",
                "id".into(),
                "secret".into()
            )
            .is_err()
        );
        assert!(
            YmqPublisher::new(
                YMQ_ENDPOINT,
                "https://message-queue.api.cloud.yandex.net/queue",
                "".into(),
                "secret".into()
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn sends_signed_versioned_intent_to_loopback_sqs_fixture() -> Result<()> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let server = tokio::spawn(async move {
            let expected = [
                json!({"event_id":42,"kind":"new_device_mail","version":1}).to_string(),
                json!({"event_id":"123e4567-e89b-42d3-a456-426614174000","kind":"password_changed_mail","version":1}).to_string(),
            ];
            for intent in expected {
                let (mut socket, _) = listener.accept().await?;
                let mut bytes = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    let count = socket.read(&mut chunk).await?;
                    if count == 0 {
                        bail!("request ended early");
                    }
                    bytes.extend_from_slice(&chunk[..count]);
                    if let Some(header_end) = bytes.windows(4).position(|part| part == b"\r\n\r\n")
                    {
                        let headers = String::from_utf8(bytes[..header_end].to_vec())?;
                        let length: usize = headers
                            .lines()
                            .find_map(|line| {
                                line.to_ascii_lowercase()
                                    .strip_prefix("content-length: ")
                                    .and_then(|value| value.parse().ok())
                            })
                            .context("missing content length")?;
                        if bytes.len() >= header_end + 4 + length {
                            let body = &bytes[header_end + 4..header_end + 4 + length];
                            let params: std::collections::HashMap<_, _> =
                                url::form_urlencoded::parse(body).into_owned().collect();
                            ensure!(
                                params.get("Action").map(String::as_str) == Some("SendMessage")
                            );
                            ensure!(
                                params.get("MessageBody").map(String::as_str)
                                    == Some(intent.as_str())
                            );
                            ensure!(headers.contains("AWS4-HMAC-SHA256 Credential=test-id/"));
                            ensure!(
                                headers
                                    .to_ascii_lowercase()
                                    .contains("signedheaders=content-type;host;x-amz-date")
                            );
                            let acknowledgement = b"<SendMessageResponse><SendMessageResult><MessageId>test-message</MessageId></SendMessageResult></SendMessageResponse>";
                            socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", acknowledgement.len()).as_bytes()).await?;
                            socket.write_all(acknowledgement).await?;
                            break;
                        }
                    }
                }
            }
            Ok::<(), anyhow::Error>(())
        });
        let endpoint = format!("http://127.0.0.1:{port}/");
        let queue = format!("http://127.0.0.1:{port}/test-queue");
        let publisher =
            YmqPublisher::new(&endpoint, &queue, "test-id".into(), "test-secret".into())?;
        publisher.send_new_device_mail(42).await?;
        publisher
            .send_password_changed_mail("123e4567-e89b-42d3-a456-426614174000")
            .await?;
        server.await??;
        Ok(())
    }
}
