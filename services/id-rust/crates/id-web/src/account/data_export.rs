//! Server-rendered export form and owner-scoped operation status.

use super::{AccountApi, api::ExportStatus, page_response};
use askama::Template;
use topcoat::{
    context::{Cx, app_context},
    router::{Body, response::Response, route},
};

#[derive(Template)]
#[template(path = "account-export.html")]
struct ExportPage<'a> {
    logout_enabled: bool,
    delayed_enabled: bool,
    refreshing: bool,
    requested: bool,
    has_mfa: bool,
    operation: Option<&'a ExportStatus>,
    download: Option<&'a str>,
}

pub(super) async fn page(
    cx: &Cx,
    operation: Option<ExportStatus>,
    requested: bool,
    has_mfa: bool,
    cookies: Vec<String>,
) -> topcoat::Result<Response> {
    let api = app_context::<AccountApi>(cx);
    let refreshing = operation.as_ref().is_some_and(|value| {
        matches!(
            value.status.as_str(),
            "pending" | "running" | "pending_delayed" | "running_delayed"
        )
    });
    let download = operation.as_ref().and_then(|value| {
        (value.status == "succeeded")
            .then(|| format!("/api/v1/auth/data/exports/{}/download", value.id))
    });
    let html = ExportPage {
        logout_enabled: api.logout_enabled,
        delayed_enabled: std::env::var("ID_WEB_EXPORT_REDEEM_PILOT_ENABLED").as_deref()
            == Ok("true")
            || std::env::var("ID_WEB_EXPORT_REDEEM_ENABLED").as_deref() == Ok("true"),
        refreshing,
        requested,
        has_mfa,
        operation: operation.as_ref(),
        download: download.as_deref(),
    }
    .render()
    .map_err(|error| topcoat::Error::msg(error.to_string()))?;
    page_response(html, cookies, true)
}

#[route(GET "/_id/export.js")]
pub(crate) async fn script() -> topcoat::Result<Response> {
    Ok(Response::builder()
        .header("Content-Type", "text/javascript; charset=utf-8")
        .header("Cache-Control", "no-store")
        .header("X-Content-Type-Options", "nosniff")
        .body(Body::from(include_str!("../../static/export.js")))?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::api::{ExportCategory, ExportManifest};

    #[test]
    fn export_template_escapes_manifest_and_keeps_download_hook() -> Result<(), askama::Error> {
        let operation = ExportStatus {
            id: "0123456789abcdef0123456789abcdef".into(),
            status: "succeeded".into(),
            release_at: None,
            manifest: Some(ExportManifest {
                format: "ndjson".into(),
                categories: vec![ExportCategory {
                    category: "<script>bad()</script>".into(),
                    records: 205,
                }],
                excluded: vec!["<img src=x onerror=bad()>".into()],
                consistency: "paged".into(),
            }),
            expires_at: Some("2026-10-07T12:00:00Z".into()),
        };
        let html = ExportPage {
            logout_enabled: true,
            delayed_enabled: false,
            refreshing: false,
            requested: true,
            has_mfa: true,
            operation: Some(&operation),
            download: Some("/api/v1/auth/data/exports/0123456789abcdef0123456789abcdef/download"),
        }
        .render()?;
        assert!(!html.contains("<script>bad()</script>"));
        assert!(!html.contains("<img src=x onerror=bad()>"));
        assert!(html.contains("id=\"export-form\""));
        assert!(html.contains("id=\"export-mfa\""));
        assert!(html.contains("id=\"export-error\""));
        assert!(html.contains("/download\" rel=\"noreferrer\""));
        assert!(!html.contains("не раньше чем через 24 часа"));
        Ok(())
    }

    #[test]
    fn delayed_export_shows_email_delivery_without_direct_download() -> Result<(), askama::Error> {
        let operation = ExportStatus {
            id: "0123456789abcdef0123456789abcdef".into(),
            status: "ready".into(),
            manifest: None,
            expires_at: Some("2026-10-08T12:00:00Z".into()),
            release_at: Some("2026-10-07T12:00:00Z".into()),
        };
        let html = ExportPage {
            logout_enabled: false,
            delayed_enabled: true,
            refreshing: false,
            requested: true,
            has_mfa: false,
            operation: Some(&operation),
            download: None,
        }
        .render()?;
        assert!(html.contains("Ссылка для получения отправлена"));
        assert!(html.contains("не раньше чем через 24 часа"));
        assert!(!html.contains("/download\""));
        Ok(())
    }
}
