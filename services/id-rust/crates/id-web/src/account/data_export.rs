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
    features: super::OverviewFeatures,
    delayed_enabled: bool,
    refreshing: bool,
    requested: bool,
    has_mfa: bool,
    delivery_email: &'a str,
    email_verified: bool,
    operation: Option<&'a ExportStatus>,
    download: Option<&'a str>,
    release_label: String,
    expiry_label: String,
    categories: Vec<CategoryView>,
    consistency_note: &'static str,
}

struct CategoryView {
    label: String,
    records: u64,
}

fn readable_time(value: Option<&str>) -> String {
    value
        .and_then(|raw| chrono::DateTime::parse_from_rfc3339(raw).ok())
        .map(|time| {
            time.with_timezone(&chrono::Utc)
                .format("%d.%m.%Y в %H:%M UTC")
                .to_string()
        })
        .unwrap_or_else(|| "время уточняется".to_owned())
}

fn category_label(name: &str) -> &str {
    match name {
        "account" => "Основные сведения аккаунта",
        "email_addresses" => "Адреса почты",
        "profile" => "Профиль",
        "preferences" => "Настройки",
        "consents" => "Согласия",
        "login_events" => "История входов",
        "account_events" => "События аккаунта",
        "devices" => "Устройства",
        "oidc_consents" => "Разрешения приложений",
        "linked_accounts" => "Связанные аккаунты",
        "avatar_bytes" => "Аватар",
        _ => name,
    }
}

pub(super) async fn page(
    cx: &Cx,
    operation: Option<ExportStatus>,
    requested: bool,
    has_mfa: bool,
    delivery_email: &str,
    email_verified: bool,
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
    let release_label = readable_time(
        operation
            .as_ref()
            .and_then(|value| value.release_at.as_deref()),
    );
    let expiry_label = readable_time(
        operation
            .as_ref()
            .and_then(|value| value.expires_at.as_deref()),
    );
    let categories = operation
        .as_ref()
        .and_then(|value| value.manifest.as_ref())
        .map(|manifest| {
            manifest
                .categories
                .iter()
                .map(|category| CategoryView {
                    label: category_label(&category.category).to_owned(),
                    records: category.records,
                })
                .collect()
        })
        .unwrap_or_default();
    let consistency_note = match operation
        .as_ref()
        .and_then(|value| value.manifest.as_ref())
        .map(|manifest| manifest.consistency.as_str())
    {
        Some("paged-live-read") => {
            "Данные собирались по частям. Если аккаунт менялся во время подготовки, записи могут относиться к разным моментам."
        }
        Some("snapshot") => "Данные отражают состояние на момент подготовки копии.",
        _ => "Способ подготовки данных не указан.",
    };
    let html = ExportPage {
        features: super::OverviewFeatures::from(api),
        delayed_enabled: std::env::var("ID_WEB_EXPORT_REDEEM_PILOT_ENABLED").as_deref()
            == Ok("true")
            || std::env::var("ID_WEB_EXPORT_REDEEM_ENABLED").as_deref() == Ok("true"),
        refreshing,
        requested,
        has_mfa,
        delivery_email,
        email_verified,
        operation: operation.as_ref(),
        download: download.as_deref(),
        release_label,
        expiry_label,
        categories,
        consistency_note,
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
    fn export_deadline_is_readable_and_explicit_about_timezone() {
        assert_eq!(
            readable_time(Some("2026-10-08T15:30:00+03:00")),
            "08.10.2026 в 12:30 UTC"
        );
        assert_eq!(readable_time(Some("invalid")), "время уточняется");
    }

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
            features: crate::account::OverviewFeatures::default(),
            delayed_enabled: false,
            refreshing: false,
            requested: true,
            has_mfa: true,
            delivery_email: "owner@example.invalid",
            email_verified: true,
            operation: Some(&operation),
            download: Some("/api/v1/auth/data/exports/0123456789abcdef0123456789abcdef/download"),
            release_label: readable_time(None),
            expiry_label: readable_time(operation.expires_at.as_deref()),
            categories: vec![CategoryView {
                label: "<script>bad()</script>".into(),
                records: 205,
            }],
            consistency_note: "Данные собирались по частям.",
        }
        .render()?;
        assert!(!html.contains("<script>bad()</script>"));
        assert!(!html.contains("<img src=x onerror=bad()>"));
        assert!(html.contains("Новые запросы временно недоступны"));
        assert!(!html.contains("id=\"export-form\""));
        assert!(html.contains("id=\"export-error\""));
        assert!(html.contains("/download\" rel=\"noreferrer\""));
        assert!(!html.contains("Подождите 24 часа"));
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
            features: crate::account::OverviewFeatures::default(),
            delayed_enabled: true,
            refreshing: false,
            requested: true,
            has_mfa: false,
            delivery_email: "owner@example.invalid",
            email_verified: true,
            operation: Some(&operation),
            download: None,
            release_label: readable_time(operation.release_at.as_deref()),
            expiry_label: readable_time(operation.expires_at.as_deref()),
            categories: Vec::new(),
            consistency_note: "Данные отражают состояние на момент подготовки копии.",
        }
        .render()?;
        assert!(html.contains("Ссылка для получения отправлена"));
        assert!(html.contains("Адрес доставки: <strong>owner@example.invalid</strong>"));
        assert!(html.contains("Подождите 24 часа"));
        assert!(
            html.contains("Ссылка отмены из первого письма работает и после удаления аккаунта")
        );
        assert!(html.contains("Если письмо недоступно, обратитесь к оператору"));
        assert!(html.contains("id=\"export-cancel-confirm\""));
        assert!(!html.contains("http-equiv=\"refresh\""));
        assert!(!html.contains("/download\""));
        Ok(())
    }

    #[test]
    fn unverified_email_cannot_start_delayed_export() -> Result<(), askama::Error> {
        let html = ExportPage {
            features: crate::account::OverviewFeatures::default(),
            delayed_enabled: true,
            refreshing: false,
            requested: false,
            has_mfa: false,
            delivery_email: "<script>bad()</script>@example.invalid",
            email_verified: false,
            operation: None,
            download: None,
            release_label: readable_time(None),
            expiry_label: readable_time(None),
            categories: Vec::new(),
            consistency_note: "Способ подготовки данных не указан.",
        }
        .render()?;
        assert!(html.contains("Сначала подтвердите адрес"));
        assert!(html.contains("href=\"/account?section=profile\""));
        assert!(!html.contains("id=\"export-form\""));
        assert!(!html.contains("<script>bad()</script>@example.invalid"));
        Ok(())
    }
}
