mod account;
mod admin;
mod consent;
mod export_redeem;
mod home;
mod login;
mod recovery;
mod signup;

use topcoat::router::Router;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut router = Router::builder().route(home::page).route(home::style);
    let login_enabled = std::env::var("ID_WEB_LOGIN_PILOT_ENABLED").as_deref() == Ok("true");
    let recovery_enabled = std::env::var("ID_WEB_RECOVERY_PILOT_ENABLED").as_deref() == Ok("true");
    let email_verify_enabled =
        std::env::var("ID_WEB_EMAIL_VERIFY_PILOT_ENABLED").as_deref() == Ok("true");
    let signup_enabled = std::env::var("ID_WEB_SIGNUP_PILOT_ENABLED").as_deref() == Ok("true");
    if login_enabled {
        router = router.route(login::page).route(login::script);
    }
    if login_enabled || recovery_enabled || email_verify_enabled || signup_enabled {
        router = router.route(login::style);
    }
    if signup_enabled {
        router = router
            .route(signup::page)
            .route(signup::script)
            .route(signup::style);
    }
    if recovery_enabled {
        router = router
            .route(recovery::forgot_page)
            .route(recovery::reset_page);
    }
    if email_verify_enabled {
        router = router.route(recovery::verify_page);
    }
    if recovery_enabled || email_verify_enabled {
        router = router.route(recovery::script);
    }
    let account_enabled = std::env::var("ID_WEB_ACCOUNT_PILOT_ENABLED").as_deref() == Ok("true");
    let export_redeem_enabled = std::env::var("ID_WEB_EXPORT_REDEEM_PILOT_ENABLED").as_deref()
        == Ok("true")
        || std::env::var("ID_WEB_EXPORT_REDEEM_ENABLED").as_deref() == Ok("true");
    if account_enabled {
        router = router
            .app_context(account::AccountApi::from_env()?)
            .route(account::page)
            .route(account::style)
            .route(account::account_script)
            .route(account::profile_script)
            .route(account::avatar_script)
            .route(account::export_script)
            .route(account::email_script)
            .route(account::preferences_script)
            .route(account::apps_script)
            .route(account::totp_script)
            .route(account::totp_disable_script)
            .route(account::recovery_rotate_script)
            .route(account::passkeys_script)
            .route(account::password_change_script)
            .route(account::sessions_script);
    }
    if export_redeem_enabled {
        if !account_enabled {
            router = router.route(account::style);
        }
        router = router
            .route(export_redeem::page)
            .route(export_redeem::script)
            .route(export_redeem::cancel_page)
            .route(export_redeem::cancel_script);
    }
    let admin_enabled = std::env::var("ID_WEB_ADMIN_ENABLED").as_deref() == Ok("true");
    let admin_suspend_enabled =
        std::env::var("ID_WEB_ADMIN_SUSPEND_ENABLED").as_deref() == Ok("true");
    anyhow::ensure!(
        !admin_suspend_enabled || admin_enabled,
        "operator suspension review requires operator pages"
    );
    if admin_enabled {
        router = router
            .app_context(admin::AdminApi::from_env()?)
            .route(admin::page)
            .route(admin::page_slash)
            .route(admin::export_page)
            .route(admin::account_page)
            .route(admin::account_page_slash)
            .route(admin::account_search_page)
            .route(admin::style);
        if admin_suspend_enabled {
            router = router
                .route(admin::suspend_review)
                .route(admin::suspend_script);
        }
    }
    if std::env::var("ID_WEB_CONSENT_PILOT_ENABLED").as_deref() == Ok("true") {
        router = router
            .app_context(consent::ConsentApi::from_env()?)
            .route(consent::page)
            .route(consent::legacy_page)
            .route(consent::script)
            .route(consent::style);
    }
    topcoat::start(router.build()).await?;
    Ok(())
}
