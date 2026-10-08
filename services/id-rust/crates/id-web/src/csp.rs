//! Cloudflare JSD reads the response CSP and nonces its injected scripts.
use topcoat::{
    context::Cx,
    router::{Body, LayerFn, LayerFuture, Next, Path},
};

pub(crate) fn layer() -> LayerFn {
    LayerFn::new(None::<&Path>, nonce_html)
}

fn nonce_html<'a>(cx: &'a Cx, body: Body, next: Next<'a>) -> LayerFuture<'a> {
    Box::pin(async move {
        let mut response = next.run(cx, body).await?;
        let headers = response.headers_mut();
        let is_html = headers
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value
                    .split(';')
                    .next()
                    .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("text/html"))
            });
        if is_html {
            let mut policy = headers
                .get("content-security-policy")
                .ok_or_else(|| topcoat::Error::msg("HTML response requires a CSP"))?
                .to_str()?
                .to_owned();
            // 128 random bits from rand's OS-seeded cryptographic generator.
            let source = format!("'nonce-{:032x}'", rand::random::<u128>());
            if let Some(directive) = policy
                .split(';')
                .find(|part| part.split_whitespace().next() == Some("script-src"))
            {
                policy = policy.replacen(directive, &format!("{directive} {source}"), 1);
            } else {
                // Pages that disallow scripts keep disallowing unnonced scripts.
                policy.push_str(&format!("; script-src {source}"));
            }
            headers.insert("content-security-policy", policy.parse()?);
            // A nonce must never be reused by an HTML cache or revalidation.
            headers.insert("cache-control", "no-store".parse()?);
            headers.remove("etag");
            headers.remove("last-modified");
        }
        Ok(response)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use topcoat::router::{Router, request::Request, response::Response, route, to_bytes};

    fn request(path: &str) -> topcoat::Result<Request> {
        Ok(Request::builder().uri(path).body(Body::empty())?)
    }

    #[tokio::test]
    async fn html_nonce_is_fresh_and_preserves_page_policies() -> topcoat::Result<()> {
        let routes = || {
            Router::builder()
                .route(crate::home::page)
                .route(crate::login::page)
                .route(crate::export_redeem::page)
                .route(crate::recovery::forgot_page)
                .route(policy_fixture)
        };
        let nonce_router = routes().layer(layer()).build();
        let plain_router = routes().build();
        let mut seen = std::collections::HashSet::new();
        for path in [
            "/",
            "/login",
            "/data/export",
            "/forgot-password",
            "/fixture",
        ] {
            let original = plain_router.handle(request(path)?).await;
            let original_policy = original.headers()["content-security-policy"]
                .to_str()?
                .to_owned();
            let original_body = to_bytes(original.into_body(), 1_000_000).await?;
            for _ in 0..2 {
                let response = nonce_router.handle(request(path)?).await;
                assert_eq!(response.headers()["cache-control"], "no-store");
                assert!(!response.headers().contains_key("etag"));
                assert!(!response.headers().contains_key("last-modified"));
                let policy = response.headers()["content-security-policy"].to_str()?;
                let nonce = policy
                    .split("'nonce-")
                    .nth(1)
                    .and_then(|value| value.split('\'').next())
                    .ok_or_else(|| topcoat::Error::msg("missing nonce"))?;
                assert_eq!(nonce.len(), 32);
                assert!(nonce.bytes().all(|byte| byte.is_ascii_hexdigit()));
                assert!(
                    seen.insert(nonce.to_owned()),
                    "nonce reused across responses"
                );
                assert_eq!(
                    policy.replace(&format!(" 'nonce-{nonce}'"), ""),
                    original_policy
                );
                assert_eq!(
                    to_bytes(response.into_body(), 1_000_000).await?,
                    original_body
                );
            }
        }
        Ok(())
    }

    #[route(GET "/no-script")]
    async fn no_script_fixture() -> topcoat::Result<Response> {
        Ok(Response::builder()
            .status(503)
            .header("content-type", "text/html; charset=utf-8")
            .header(
                "content-security-policy",
                "default-src 'none'; style-src 'self'; form-action 'self'",
            )
            .header("set-cookie", "fixture=unchanged; Secure; HttpOnly")
            .body(Body::from("<p>Unavailable</p>"))?)
    }

    #[tokio::test]
    async fn scriptless_html_errors_allow_only_the_nonce() -> topcoat::Result<()> {
        let router = Router::builder()
            .layer(layer())
            .route(no_script_fixture)
            .build();
        let response = router.handle(request("/no-script")?).await;
        assert_eq!(response.status(), 503);
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(
            response.headers()["set-cookie"],
            "fixture=unchanged; Secure; HttpOnly"
        );
        let policy = response.headers()["content-security-policy"].to_str()?;
        assert!(policy.starts_with(
            "default-src 'none'; style-src 'self'; form-action 'self'; script-src 'nonce-"
        ));
        assert!(!policy.contains("script-src 'self'"));
        assert!(!policy.contains("unsafe-inline"));
        Ok(())
    }

    #[route(GET "/fixture")]
    async fn policy_fixture() -> topcoat::Result<Response> {
        Ok(Response::builder()
            .header("content-type", "text/html; charset=utf-8")
            .header("content-security-policy", "default-src 'none'; script-src 'self'; img-src 'self' data: https://storage.yandexcloud.net; form-action 'none'; style-src 'self'; frame-ancestors 'none'")
            .header("cache-control", "public, max-age=60")
            .header("etag", "\"fixture\"")
            .header("last-modified", "Wed, 07 Oct 2026 00:00:00 GMT")
            .body(Body::from("<p>Unchanged HTML</p>"))?)
    }

    #[tokio::test]
    async fn assets_and_non_html_responses_are_unchanged() -> topcoat::Result<()> {
        let router = Router::builder()
            .layer(layer())
            .route(crate::ui::style)
            .route(crate::ui::script)
            .build();
        for (path, content_type) in [
            ("/_id/ui.css", "text/css; charset=utf-8"),
            ("/_id/ui.js", "text/javascript; charset=utf-8"),
        ] {
            let response = router.handle(request(path)?).await;
            assert_eq!(response.status(), 200);
            assert_eq!(response.headers()["content-type"], content_type);
            assert_eq!(response.headers()["cache-control"], "public, max-age=3600");
            assert!(!response.headers().contains_key("content-security-policy"));
        }
        let missing = router.handle(request("/missing")?).await;
        assert_eq!(missing.status(), 404);
        assert!(!missing.headers().contains_key("content-security-policy"));
        Ok(())
    }
}
