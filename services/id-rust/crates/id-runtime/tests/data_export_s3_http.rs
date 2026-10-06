//! Loopback S3 fixture exercises PUT, multipart, acknowledgement and abort.

use anyhow::{Result, ensure};
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{Method, Response, StatusCode},
    routing::any,
};
use id_runtime::data_export_s3::S3Export;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Default)]
struct Recording {
    single: Vec<u8>,
    parts: Vec<Vec<u8>>,
    completed: usize,
    aborted: usize,
    fail_complete: bool,
}

async fn s3(State(recording): State<Arc<Mutex<Recording>>>, request: Request) -> Response<Body> {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let query = request.uri().query().unwrap_or("").to_owned();
    let headers = request.headers().clone();
    let body = match to_bytes(request.into_body(), 6 * 1024 * 1024).await {
        Ok(body) => body,
        Err(_) => return response(StatusCode::BAD_REQUEST, "", None),
    };
    assert_eq!(path, "/private-exports/exports/user_7/test/attempt.ndjson");
    assert_eq!(
        headers
            .get("x-amz-content-sha256")
            .and_then(|v| v.to_str().ok()),
        Some(hex::encode(Sha256::digest(&body)).as_str())
    );
    assert!(
        headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with("AWS4-HMAC-SHA256 Credential=synthetic-key/"))
    );
    let mut state = recording.lock().await;
    match (method, query.as_str()) {
        (Method::PUT, "") => {
            state.single = body.to_vec();
            response(StatusCode::OK, "", None)
        }
        (Method::POST, "uploads=") => response(
            StatusCode::OK,
            "<InitiateMultipartUploadResult><Bucket>private-exports</Bucket><Key>exports/user_7/test/attempt.ndjson</Key><UploadId>synthetic+id</UploadId></InitiateMultipartUploadResult>",
            None,
        ),
        (Method::PUT, q)
            if q.starts_with("partNumber=") && q.contains("uploadId=synthetic%2Bid") =>
        {
            state.parts.push(body.to_vec());
            response(StatusCode::OK, "", Some("\"abcd1234\""))
        }
        (Method::POST, "uploadId=synthetic%2Bid") => {
            assert!(String::from_utf8_lossy(&body).contains("<ETag>\"abcd1234\"</ETag>"));
            if state.fail_complete {
                response(
                    StatusCode::OK,
                    "<Error><Code>InternalError</Code></Error>",
                    None,
                )
            } else {
                state.completed += 1;
                response(
                    StatusCode::OK,
                    "<CompleteMultipartUploadResult><Bucket>private-exports</Bucket><Key>exports/user_7/test/attempt.ndjson</Key></CompleteMultipartUploadResult>",
                    None,
                )
            }
        }
        (Method::DELETE, "uploadId=synthetic%2Bid") => {
            state.aborted += 1;
            response(StatusCode::NO_CONTENT, "", None)
        }
        _ => response(StatusCode::BAD_REQUEST, "", None),
    }
}

fn response(status: StatusCode, body: &str, etag: Option<&str>) -> Response<Body> {
    let mut builder = Response::builder().status(status);
    if let Some(etag) = etag {
        builder = builder.header("etag", etag);
    }
    match builder.body(Body::from(body.to_owned())) {
        Ok(response) => response,
        Err(error) => panic!("fixture response error: {error}"),
    }
}

async fn fixture(
    fail_complete: bool,
) -> Result<(S3Export, Arc<Mutex<Recording>>, tokio::task::JoinHandle<()>)> {
    let state = Arc::new(Mutex::new(Recording {
        fail_complete,
        ..Recording::default()
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let app = Router::new().fallback(any(s3)).with_state(state.clone());
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let uploader = S3Export::new(
        &format!("http://127.0.0.1:{port}/"),
        "private-exports",
        "ru-central1",
        "synthetic-key".into(),
        "synthetic-secret".into(),
    )?;
    Ok((uploader, state, server))
}

#[tokio::test]
async fn puts_small_archive_and_uses_multipart_for_large_archive() -> Result<()> {
    let (uploader, state, server) = fixture(false).await?;
    let key = "exports/user_7/test/attempt.ndjson";
    let small = b"{\"category\":\"account\"}\n";
    uploader.upload_stream(key, &small[..]).await?;
    let large = vec![b'X'; 5 * 1024 * 1024 + 17];
    uploader.upload_stream(key, &large[..]).await?;
    let result = state.lock().await;
    ensure!(
        result.single == small
            && result.parts.len() == 2
            && result.parts[0].len() == 5 * 1024 * 1024
            && result.parts[1].len() == 17
            && result.completed == 1
            && result.aborted == 0,
        "S3 upload did not preserve bytes or multipart boundaries"
    );
    server.abort();
    Ok(())
}

#[tokio::test]
async fn rejects_embedded_completion_error_and_aborts_upload() -> Result<()> {
    let (uploader, state, server) = fixture(true).await?;
    let large = vec![b'X'; 5 * 1024 * 1024 + 1];
    ensure!(
        uploader
            .upload_stream("exports/user_7/test/attempt.ndjson", &large[..])
            .await
            .is_err()
    );
    let result = state.lock().await;
    ensure!(
        result.completed == 0 && result.aborted == 1,
        "failed completion was not aborted"
    );
    server.abort();
    Ok(())
}
