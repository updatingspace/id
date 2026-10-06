//! Public recovery pages. The browser submits to the API; this SSR process
//! never reads reset keys, YDB, signing keys or SMTP credentials.

use topcoat::{
    Result,
    context::Cx,
    router::{Body, response::Response, route},
    view::{ViewExt, view},
};

fn html_response(body: String) -> Result<Response> {
    Ok(Response::builder()
        .header("Content-Type", "text/html; charset=utf-8")
        .header("Cache-Control", "no-store")
        .header("X-Content-Type-Options", "nosniff")
        .header("Referrer-Policy", "no-referrer")
        .header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        )
        .body(Body::from(body))?)
}

#[route(GET "/forgot-password")]
pub(crate) async fn forgot_page(cx: &Cx) -> Result<Response> {
    let html = view! {
        <!DOCTYPE html>
        <html lang="ru">
        <head>
            <meta charset="utf-8" />
            <meta name="viewport" content="width=device-width,initial-scale=1" />
            <title>"Восстановление доступа — UpdSpace ID"</title>
            <link rel="stylesheet" href="/_id/login.css" />
            <script src="/_id/recovery.js" defer="defer"></script>
        </head>
        <body>
            <main class="auth-shell">
                <section class="auth-card" aria-labelledby="recovery-title">
                    <a class="brand" href="/">"UpdSpace ID"</a>
                    <h1 id="recovery-title">"Забыли пароль?"</h1>
                    <p class="intro">"Укажите адрес аккаунта. Если он существует, мы отправим ссылку для восстановления."</p>
                    <p id="status" role="status" aria-live="polite" hidden="hidden"></p>
                    <p id="error" role="alert" aria-live="assertive" hidden="hidden"></p>
                    <form id="forgot-form" method="post" action="/forgot-password">
                        <label for="email">"Электронная почта"</label>
                        <input id="email" name="email" type="email" autocomplete="email" maxlength="254" required="required" />
                        <button id="submit" type="submit">"Отправить ссылку"</button>
                    </form>
                    <noscript>"Для отправки запроса включите JavaScript."</noscript>
                    <p class="help"><a href="/login">"Вернуться ко входу"</a></p>
                </section>
            </main>
        </body>
        </html>
    }.single().await?.render(cx);
    html_response(html)
}

#[route(GET "/reset-password")]
pub(crate) async fn reset_page(cx: &Cx) -> Result<Response> {
    let html = view! {
        <!DOCTYPE html>
        <html lang="ru">
        <head>
            <meta charset="utf-8" />
            <meta name="viewport" content="width=device-width,initial-scale=1" />
            <title>"Новый пароль — UpdSpace ID"</title>
            <link rel="stylesheet" href="/_id/login.css" />
            <script src="/_id/recovery.js" defer="defer"></script>
        </head>
        <body>
            <main class="auth-shell">
                <section class="auth-card" aria-labelledby="reset-title">
                    <a class="brand" href="/">"UpdSpace ID"</a>
                    <h1 id="reset-title">"Новый пароль"</h1>
                    <p class="intro">"Введите новый пароль для вашего аккаунта."</p>
                    <p id="status" role="status" aria-live="polite" hidden="hidden"></p>
                    <p id="error" role="alert" aria-live="assertive" hidden="hidden"></p>
                    <form id="reset-form" method="post" action="/reset-password" hidden="hidden">
                        <label for="password">"Новый пароль"</label>
                        <input id="password" name="password" type="password" autocomplete="new-password" minlength="10" maxlength="4096" required="required" />
                        <label for="confirmation">"Повторите пароль"</label>
                        <input id="confirmation" name="confirmation" type="password" autocomplete="new-password" minlength="10" maxlength="4096" required="required" />
                        <button id="submit" type="submit">"Сохранить пароль"</button>
                    </form>
                    <noscript>"Для проверки ссылки и смены пароля включите JavaScript."</noscript>
                    <p class="help"><a href="/forgot-password">"Запросить новую ссылку"</a></p>
                    <p class="help"><a href="/login">"Вернуться ко входу"</a></p>
                </section>
            </main>
        </body>
        </html>
    }.single().await?.render(cx);
    html_response(html)
}

#[route(GET "/verify-email")]
pub(crate) async fn verify_page(cx: &Cx) -> Result<Response> {
    let html = view! {
        <!DOCTYPE html>
        <html lang="ru">
        <head>
            <meta charset="utf-8" />
            <meta name="viewport" content="width=device-width,initial-scale=1" />
            <title>"Подтверждение email — UpdSpace ID"</title>
            <link rel="stylesheet" href="/_id/login.css" />
            <script src="/_id/recovery.js" defer="defer"></script>
        </head>
        <body>
            <main class="auth-shell">
                <section class="auth-card" aria-labelledby="verify-title">
                    <a class="brand" href="/">"UpdSpace ID"</a>
                    <h1 id="verify-title">"Подтверждение email"</h1>
                    <p class="intro">"Подтвердите адрес, чтобы завершить регистрацию и войти в аккаунт."</p>
                    <p id="status" role="status" aria-live="polite" hidden="hidden"></p>
                    <p id="error" role="alert" aria-live="assertive" hidden="hidden"></p>
                    <form id="verify-form" method="post" action="/verify-email" hidden="hidden">
                        <button id="submit" type="submit">"Подтвердить адрес"</button>
                    </form>
                    <form id="verify-request-form" method="post" action="/verify-email">
                        <label for="email">"Отправить ссылку повторно"</label>
                        <input id="email" name="email" type="email" autocomplete="email" maxlength="254" required="required" />
                        <button id="resend-submit" type="submit">"Отправить письмо"</button>
                    </form>
                    <noscript>"Для подтверждения адреса включите JavaScript."</noscript>
                    <p class="help"><a href="/login">"Вернуться ко входу"</a></p>
                </section>
            </main>
        </body>
        </html>
    }.single().await?.render(cx);
    html_response(html)
}

#[route(GET "/_id/recovery.js")]
pub(crate) async fn script() -> Result<Response> {
    Ok(Response::builder()
        .header("Content-Type", "text/javascript; charset=utf-8")
        .header("Cache-Control", "no-store")
        .header("X-Content-Type-Options", "nosniff")
        .body(Body::from(include_str!("../static/recovery.js")))?)
}
