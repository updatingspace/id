use std::{
    io::{Read, Write},
    net::TcpListener,
    thread,
    time::Duration,
};

use ydb::{Credentials, MetadataUrlCredentials};

// The vendored SDK patch changes reqwest, which its production metadata
// credentials use synchronously. Exercise that real SDK transport across
// repeated acquisitions and reject a malformed successful HTTP response.
#[test]
fn metadata_transport_fetches_each_token_and_rejects_malformed_json() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let server = thread::spawn(move || -> anyhow::Result<()> {
        for body in [
            r#"{"access_token":"first-test-token","expires_in":1,"token_type":"Bearer"}"#,
            r#"{"access_token":"second-test-token","expires_in":3600,"token_type":"Bearer"}"#,
            r#"{"error":"metadata unavailable"}"#,
        ] {
            let (mut stream, _) = listener.accept()?;
            stream.set_read_timeout(Some(Duration::from_secs(5)))?;
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            while !request.windows(4).any(|part| part == b"\r\n\r\n") {
                let read = stream.read(&mut buffer)?;
                anyhow::ensure!(read > 0, "metadata request ended before its headers");
                request.extend_from_slice(&buffer[..read]);
                anyhow::ensure!(request.len() <= 16_384, "metadata headers exceeded limit");
            }
            let request = String::from_utf8(request)?;
            anyhow::ensure!(request.starts_with("GET /token HTTP/1.1\r\n"));
            anyhow::ensure!(
                request
                    .to_ascii_lowercase()
                    .contains("\r\nmetadata-flavor: google\r\n")
            );
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )?;
        }
        Ok(())
    });

    let credentials = MetadataUrlCredentials::from_url(format!("http://{address}/token"))?;
    credentials.create_token()?;
    credentials.create_token()?;
    anyhow::ensure!(credentials.create_token().is_err());
    server
        .join()
        .map_err(|_| anyhow::anyhow!("metadata test server panicked"))??;
    Ok(())
}
