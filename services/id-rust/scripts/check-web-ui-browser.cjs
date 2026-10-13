// Actual Topcoat pages with a synthetic API: presentation and browser state only.
// Authentication, consent and cryptographic acceptance have separate live tests.
const assert = require('node:assert/strict');
const http = require('node:http');
const path = require('node:path');
const { spawn } = require('node:child_process');
const root = path.resolve(__dirname, '..');
const { chromium } = require(process.env.ID_PLAYWRIGHT_MODULE || path.join(root, 'browser-tests/node_modules/@playwright/test'));
const preview = process.argv.includes('--preview');
const freePort = async () => {
  const server = http.createServer();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
};
async function main() {
  const webPort = await freePort();
  let user = { username: 'alex', first_name: 'Александр', last_name: 'Соколов', email: 'alex@example.invalid', email_verified: false, has_2fa: false };
  let empty = false;
  let profileFailure = false;
  let unavailable = false;
  let marketingRevoked = false;
  let consentRequired = true;
  const preferenceWrites = [];
  const preferences = { language: 'ru', timezone: 'Europe/Moscow', marketing_opt_in: true, privacy_scope_defaults: { email: 'deny' } };
  const reply = (res, status, data) => { res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', 'set-cookie': 'csrftoken=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; Path=/; SameSite=Lax' }); res.end(JSON.stringify(data)); };
  const proxy = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    const api = url.pathname.replace('/api/v1/auth/', '');
    if (api === 'form_token') return reply(res, 200, { form_token: 'synthetic-register-token' });
    if (api === 'me') return reply(res, 200, { user });
    if (api === 'profile') {
      assert.equal(req.method, 'PATCH');
      assert.equal(req.headers['x-csrftoken'], 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
      let raw = ''; for await (const chunk of req) raw += chunk;
      if (profileFailure) return reply(res, 503, { message: 'Сохранение временно недоступно. Введённые данные сохранены в форме.' });
      Object.assign(user, JSON.parse(raw)); return reply(res, 200, { ok: true });
    }
    if (api === 'email') return reply(res, 200, { email: user.email, verified: user.email_verified, pending_email: null });
    if (api === 'sessions') return reply(res, 200, { sessions: empty ? [] : [
      { id: 'current', user_agent: 'Mozilla/5.0 (X11; Linux x86_64) Chrome/131 Safari/537.36', ip: '192.0.2.1', current: true, revoked: false, last_seen: '2026-10-08T09:15:00Z' },
      { id: 'phone', user_agent: 'Mozilla/5.0 (iPhone) Safari/605', ip: '192.0.2.2', current: false, revoked: false },
      { id: 'revoked', user_agent: 'Mozilla/5.0 (Windows NT 10.0) Firefox/129', ip: '192.0.2.3', current: false, revoked: true },
    ] });
    if (api === 'login-history') return reply(res, 200, { events: empty ? [] : [ { status: 'success', ip_address: '192.0.2.1', user_agent: 'Mozilla/5.0 (X11; Linux x86_64) Chrome/131 Safari/537.36', is_new_device: false, reason: null, created_at: '2026-10-08T09:15:00Z' } ] });
    if (api === 'security' && unavailable) return reply(res, 503, {});
    if (api === 'security') return reply(res, 200, { mfa: { has_totp: false, has_webauthn: false, has_recovery_codes: false, recovery_codes_left: 0 }, authenticators: [] });
    if (api === 'preferences') {
      if (req.method === 'PATCH') { let raw = ''; for await (const chunk of req) raw += chunk; const patch = JSON.parse(raw); preferenceWrites.push(patch); Object.assign(preferences, patch); return reply(res, 200, preferences); }
      return reply(res, 200, preferences);
    }
    if (api === 'timezones') return reply(res, 200, { timezones: [{ name: 'Europe/Moscow', display_name: 'Москва (UTC+3)' }, { name: 'UTC', display_name: 'UTC' }] });
    if (api === 'consents') return reply(res, 200, { consents: [{ kind: 'data_processing', version: 'v1', granted_at: '2026-10-01T12:00:00Z', revoked_at: null }, { kind: 'marketing', version: 'v1', granted_at: '2026-10-01T12:00:00Z', revoked_at: marketingRevoked ? '2026-10-13T12:00:00Z' : null }] });
    if (api === 'consents/revoke') {
      assert.equal(req.method, 'POST');
      assert.equal(url.searchParams.get('kind'), 'marketing');
      assert.equal(req.headers['x-csrftoken'], 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
      marketingRevoked = true; preferences.marketing_opt_in = false;
      return reply(res, 200, { ok: true });
    }
    if (api === 'oauth/apps') return reply(res, 200, { items: empty ? [] : [{ client_id: 'portal', name: 'UpdSpace Portal', scopes: ['openid', 'email', 'profile'], last_used_at: '2026-10-08T09:15:00Z' }] });
    if (url.pathname === '/oauth/authorize/prepare') return reply(res, 200, { action: 'consent', request_id: 'synthetic-consent', account_label: user.email, consent_required: consentRequired, blocked: '', client: { name: 'UpdSpace Portal' }, redirect_uri: 'https://portal.example.invalid/callback', scopes: [{ name: 'openid', description: 'Идентификатор аккаунта', required: true }, { name: 'email', description: 'Электронная почта', required: false }] });
    if (url.pathname.startsWith('/api/')) return reply(res, 501, { code: 'SYNTHETIC_PREVIEW', message: 'Это локальный макет API. Действие не выполнено.' });
    const forwarded = http.request({ hostname: '127.0.0.1', port: webPort, path: req.url, method: req.method, headers: { ...req.headers, host: `127.0.0.1:${webPort}` } }, upstream => { res.writeHead(upstream.statusCode, upstream.headers); upstream.pipe(res); });
    forwarded.on('error', () => { if (!res.headersSent) res.writeHead(502); res.end(); });
    req.pipe(forwarded);
  });
  await new Promise(resolve => proxy.listen(preview ? Number(process.env.ID_UI_PREVIEW_PORT || 0) : 0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${proxy.address().port}`;
  const flags = ['ACCOUNT_PILOT', 'LOGIN_PILOT', 'LOGOUT_PILOT', 'PROFILE_PILOT', 'SESSIONS_PILOT', 'SECURITY_PILOT', 'TOTP_PILOT', 'PREFERENCES_PILOT', 'CONSENTS_PILOT', 'APPS_PILOT', 'LOGIN_HISTORY_PILOT', 'PASSWORD_CHANGE_PILOT', 'EMAIL_MANAGEMENT', 'PASSKEY_REGISTRATION', 'PASSKEY_PILOT', 'SIGNUP_PILOT', 'RECOVERY_PILOT', 'EMAIL_VERIFY_PILOT', 'CONSENT_PILOT', 'EXPORTS', 'EXPORT_REDEEM', 'DELETION'];
  const web = spawn(path.join(process.env.ID_RUST_BIN_DIR || path.join(root, 'target/debug'), 'id-web'), [], { env: { ...process.env, HOST: '127.0.0.1', PORT: String(webPort), ID_WEB_API_ORIGIN: origin, ...Object.fromEntries(flags.map(flag => [`ID_WEB_${flag}_ENABLED`, 'true'])) }, stdio: 'ignore' });
  let browser;
  try {
    for (let i = 0; i < 40; i++) { try { if ((await fetch(`${origin}/`)).ok) break; } catch {} if (i === 39 || web.exitCode !== null) throw new Error('Topcoat startup failed'); await new Promise(resolve => setTimeout(resolve, 100)); }
    if (preview) { console.log(`Synthetic UI preview: ${origin}`); await new Promise(resolve => { process.once('SIGTERM', resolve); process.once('SIGINT', resolve); }); return; }
    browser = await chromium.launch({ headless: true, ...(process.env.ID_CHROMIUM_PATH ? { executablePath: process.env.ID_CHROMIUM_PATH } : {}) });
    const context = await browser.newContext();
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', e => errors.push(e.message));
    const nav = ['Обзор', 'Профиль', 'Вход и защита', 'Приложения', 'Приватность и данные'];
    const luminance = hex => {
      const rgb = hex.replace('#', '').match(/.{2}/g).map(value => parseInt(value, 16) / 255).map(value => value <= .04045 ? value / 12.92 : ((value + .055) / 1.055) ** 2.4);
      return rgb[0] * .2126 + rgb[1] * .7152 + rgb[2] * .0722;
    };
    const contrast = (a, b) => { const values = [luminance(a), luminance(b)].sort((x, y) => y - x); return (values[0] + .05) / (values[1] + .05); };
    const accountPages = ['', 'profile', 'security', 'sessions', 'activity', 'apps', 'privacy', 'settings', 'data', 'delete'];
    const pages = ['/', '/data', '/privacy', '/terms', '/contacts', '/login', '/signup', '/forgot-password', '/reset-password', '/verify-email', '/oauth/consent?client_id=synthetic', ...accountPages.map(section => '/account' + (section ? `?section=${section}` : ''))];
    for (const width of [320, 390, 1280]) for (const theme of ['light', 'dark']) {
      await page.setViewportSize({ width, height: 844 });
      await page.emulateMedia({ colorScheme: theme, reducedMotion: 'reduce' });
      for (const route of pages) {
        const response = await page.goto(origin + route);
        assert.equal(response.status(), 200, route);
        assert.equal(await page.locator('[data-theme-choice]').count(), route === '/account?section=profile' ? 3 : 0, route + ' theme controls');
        if (route.startsWith('/account')) assert.deepEqual(await page.locator('.account-sidebar .account-links a').allTextContents(), nav, route);
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, `overflow ${route} ${width} ${theme}`);
        const tokens = await page.evaluate(() => Object.fromEntries(['ink', 'muted', 'surface', 'canvas', 'soft', 'action', 'on-action'].map(name => [name, getComputedStyle(document.documentElement).getPropertyValue('--' + name).trim().replace(/^#([0-9a-f])([0-9a-f])([0-9a-f])$/i, '#$1$1$2$2$3$3')])));
        for (const fg of ['ink', 'muted', 'action']) for (const bg of ['surface', 'canvas', 'soft']) assert.ok(contrast(tokens[fg], tokens[bg]) >= 4.5, `contrast ${fg}/${bg} ${theme}`);
        assert.ok(contrast(tokens['action'], tokens['on-action']) >= 4.5);
        // Model 200% text enlargement, retaining the mobile viewport.
        await page.evaluate(() => document.documentElement.style.fontSize = '200%');
        assert.deepEqual(await page.evaluate(() => [...document.querySelectorAll("body *")].filter(e => e.getBoundingClientRect().right > innerWidth + 1).map(e => e.outerHTML.slice(0, 120))), [], `200% overflow ${route} ${width} ${theme}`);
        assert.deepEqual(await page.locator('fieldset > legend:visible').evaluateAll(legends => legends.filter(e => e.getBoundingClientRect().right > e.parentElement.getBoundingClientRect().right + 1).map(e => e.textContent)), [], `200% legend overflow ${route} ${width} ${theme}`);
        const dialogIds = new Set(await page.locator('[data-dialog-open]').evaluateAll(nodes => nodes.map(node => node.dataset.dialogOpen)));
        for (const id of dialogIds) {
          await page.locator(`[data-dialog-open="${id}"]`).first().click();
          assert.equal(await page.locator(`#${id}`).evaluate(dialog => dialog.scrollWidth <= dialog.clientWidth + 1), true, `dialog overflow ${id} ${width} ${theme}`);
          await page.locator(`#${id} [data-dialog-close]`).first().click();
        }
        for (const summary of await page.locator('details:not(.mobile-navigation) > summary:visible').all()) {
          await summary.click();
          assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, `expanded 200% overflow ${route} ${width} ${theme}`);
        }
      }
    }
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto(origin + '/account?section=profile');
    assert.equal(await page.getByRole('button', { name: 'Изменить фото', exact: true }).isVisible(), true);
    assert.equal(await page.locator('#avatar-form').isVisible(), false, 'upload form stays out of the profile summary');
    assert.equal(await page.locator('#preferences-form').isVisible(), false);
    assert.equal(await page.locator('details[data-profile-editor]').count(), 0);
    await page.getByRole('button', { name: 'Изменить имя и фамилию', exact: true }).click();
    assert.equal(await page.locator('#first-name').evaluate(e => e === document.activeElement), true);
    await page.locator('#first-name').fill('Оченьдлинноеимябезпробелов'.repeat(6));
    profileFailure = true;
    await page.locator('#profile-form button[type=submit]').click();
    await page.locator('#profile-error:visible').waitFor();
    assert.ok((await page.locator('#first-name').inputValue()).startsWith('Очень'));
    assert.equal(await page.locator('#profile-error').evaluate(e => e === document.activeElement), true);
    await page.keyboard.press('Escape');
    assert.equal(await page.locator('#personal-editor').isVisible(), false);
    assert.equal(await page.getByRole('button', { name: 'Изменить имя и фамилию', exact: true }).evaluate(e => e === document.activeElement), true, 'closing restores focus');
    await page.getByRole('button', { name: 'Изменить имя и фамилию', exact: true }).click();
    assert.ok((await page.locator('#first-name').inputValue()).startsWith('Очень'), 'draft lost across editors');
    profileFailure = false;
    await page.locator('#profile-form button[type=submit]').click();
    await page.locator('#profile-message:visible').waitFor();
    assert.equal(await page.locator('#personal-editor').isVisible(), false);
    assert.ok((await page.locator('#profile-display-name').textContent()).startsWith('Очень'));
    await page.reload();
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, 'long name overflow');

    const photo = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aWZkAAAAASUVORK5CYII=', 'base64');
    let photoFailure = true;
    await page.route('**/synthetic-avatar.png', route => route.fulfill({ contentType: 'image/png', body: photo }));
    await page.route('**/api/v1/auth/avatar', async route => {
      assert.equal(route.request().headers()['x-csrftoken'], 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
      if (route.request().method() === 'DELETE') { user.avatar_url = null; return route.fulfill({ json: { ok: true } }); }
      assert.equal(route.request().method(), 'POST');
      assert.match(route.request().headers()['content-type'], /multipart\/form-data; boundary=/);
      assert.ok(route.request().postDataBuffer().includes(Buffer.from('filename="photo.png"')));
      if (photoFailure) return route.fulfill({ status: 503, json: { message: 'Не удалось сохранить фото.' } });
      user.avatar_url = origin + '/synthetic-avatar.png';
      return route.fulfill({ json: { ok: true, avatar_url: user.avatar_url } });
    });
    await page.getByRole('button', { name: 'Изменить фото', exact: true }).click();
    assert.equal(await page.locator('#avatar-delete').isVisible(), false);
    assert.equal(await page.locator('#avatar-form button[type=submit]').isDisabled(), true);
    await page.locator('#avatar-file').setInputFiles({ name: 'photo.png', mimeType: 'image/png', buffer: photo });
    await page.locator('#avatar-form button[type=submit]').click();
    await page.locator('#avatar-error:visible').waitFor();
    assert.equal(await page.locator('#photo-editor').isVisible(), true);
    assert.equal(await page.locator('#avatar-file-name').textContent(), 'photo.png');
    photoFailure = false;
    await page.locator('#avatar-form button[type=submit]').click();
    await page.locator('#avatar-message:visible').waitFor();
    assert.equal(await page.locator('#photo-editor').isVisible(), false);
    await page.waitForFunction(() => document.getElementById('avatar-image').naturalWidth === 1);
    await page.goto(origin + '/account');
    assert.equal(await page.locator('.identity-photo').getAttribute('src'), user.avatar_url);
    await page.goto(origin + '/account?section=profile');
    await page.getByRole('button', { name: 'Изменить фото', exact: true }).click();
    await page.locator('#avatar-delete').click();
    await page.getByText('Фото профиля удалено.', { exact: true }).waitFor();
    assert.equal(await page.locator('#avatar-placeholder').isVisible(), true);
    assert.equal(await page.locator('#avatar-image').isVisible(), false);
    await page.unroute('**/api/v1/auth/avatar');
    await page.goto(origin + '/account?section=sessions');
    assert.equal(await page.locator('ul[aria-label="Действующие сеансы"] li').count(), 2);
    assert.equal(await page.getByText('Firefox · Windows', { exact: true }).isVisible(), false, 'revoked session in active group');
    assert.ok((await page.locator('time').first().textContent()).includes('2026'));
    assert.notEqual(await page.locator('time').first().textContent(), await page.locator('time').first().getAttribute('datetime'));
    assert.equal(await page.getByText('Технические сведения', { exact: true }).count(), 0);
    assert.equal(await page.locator('.session-actions #revoke-others').count(), 1);
    await page.goto(origin + '/account?section=apps');
    assert.deepEqual(await page.locator('.app-permissions li').allTextContents(), ['Идентификатор аккаунта', 'Электронная почта', 'Основные сведения профиля']);
    assert.equal(await page.locator('.session-row .item-meta time').count(), 1);
    // An old settings tab must not overwrite a later consent revocation.
    await page.goto(origin + '/account?section=profile');
    const privacyTab = await page.context().newPage();
    await privacyTab.goto(origin + '/account?section=privacy');
    assert.equal(await privacyTab.locator('#preferences-marketing').count(), 0);
    assert.equal(await privacyTab.locator('#preferences-form').count(), 0);
    assert.equal(await privacyTab.locator('select[id^="scope-"]').count(), 0);
    assert.equal(await page.locator('#preferences-marketing').isVisible(), false);
    await page.getByRole('button', { name: 'Изменить язык', exact: true }).click();
    await page.locator('#preferences-language').selectOption('en');
    await page.locator('#preferences-timezone').selectOption('UTC');
    await page.locator('#preferences-form button[type=submit]').click();
    await page.locator('#locale-editor').waitFor({ state: 'hidden' });
    assert.deepEqual(Object.keys(preferenceWrites.at(-1)).sort(), ['language', 'timezone']);
    assert.equal(preferences.marketing_opt_in, true, 'stale settings must preserve newer consent');
    assert.equal(preferences.privacy_scope_defaults.email, 'deny');
    await privacyTab.locator('button.consent-revoke').click();
    await privacyTab.getByText('Отозвано', { exact: true }).waitFor();
    assert.equal(marketingRevoked, true);
    assert.equal(preferences.marketing_opt_in, false);
    await page.getByRole('button', { name: 'Изменить язык', exact: true }).click();
    await page.locator('#preferences-form button[type=submit]').click();
    await page.locator('#locale-editor').waitFor({ state: 'hidden' });
    assert.equal(preferences.marketing_opt_in, false, 'settings must preserve revoked consent');
    assert.equal(preferences.privacy_scope_defaults.email, 'deny', 'settings must preserve existing policies');
    assert.equal(preferences.language, 'en');
    assert.equal(preferences.timezone, 'UTC');
    await privacyTab.close();
    await page.getByRole('button', { name: 'Изменить язык', exact: true }).click();
    await page.route('**/api/v1/auth/preferences', route => route.fulfill({ status: 401, contentType: 'application/json', body: '{}' }));
    await page.locator('#preferences-form button[type=submit]').click();
    await page.waitForURL(origin + '/login?next=%2Faccount%3Fsection%3Dprofile');
    await page.unroute('**/api/v1/auth/preferences');
    await page.goto(origin + '/oauth/consent?client_id=synthetic');
    assert.equal(await page.locator('input[name=scope]:checked').count(), 0);
    assert.equal(await page.locator('#remember').count(), 0);
    consentRequired = false;
    await page.reload();
    assert.equal(await page.locator('details').count(), 0);
    assert.equal(await page.locator('input[type=checkbox]').count(), 0);
    assert.equal(await page.getByRole('button', { name: 'Продолжить', exact: true }).isVisible(), true);
    assert.equal(await page.getByRole('link', { name: 'Посмотреть разрешения' }).isVisible(), true);
    for (const section of ['sessions', 'apps', 'activity']) { empty = true; await page.goto(origin + '/account?section=' + section); assert.equal(await page.locator('.session-row').count(), 0); }
    await page.goto(origin + '/login');
    await page.locator('#session-choice:visible').waitFor();
    assert.equal(await page.locator('#login-form').isVisible(), false);
    await page.locator('#choose-another').click();
    assert.equal(await page.locator('#login-form').isVisible(), true);
    assert.equal(await page.locator('#email').evaluate(e => e === document.activeElement), true);
    await page.goto(origin + '/login?next=%2Faccount%3Fsection%3Dsecurity');
    assert.equal(await page.locator('#session-choice').isVisible(), false, 'sensitive reauth must not be bypassed');
    await page.goto(origin + '/');
    assert.equal(await page.getByRole('heading', { name: 'Один аккаунт для сервисов UpdSpace', exact: true }).isVisible(), true);
    assert.equal(await page.getByText(user.email, { exact: false }).count(), 0);
    assert.equal(await page.locator('[data-theme-select]').count(), 0);
    await page.goto(origin + '/account?section=security');
    assert.equal(await page.locator('main > section:visible h2').first().innerText(), 'Пароль');
    assert.equal(await page.locator('#passkey-create-panel summary').count(), 0);
    assert.equal(await page.locator('#passkeys-empty').count(), 0);
    let passwordRequests = 0;
    await page.route('**/api/v1/auth/change_password', async route => {
      passwordRequests += 1;
      assert.deepEqual(route.request().postDataJSON(), { current_password: 'old-test-password', new_password: 'new-test-password' });
      assert.equal(route.request().headers()['x-csrftoken'], 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
      await route.fulfill({ status: passwordRequests === 1 ? 400 : 200, contentType: 'application/json', body: JSON.stringify(passwordRequests === 1 ? { code: 'WEAK_PASSWORD' } : { ok: true }) });
    });
    await page.locator('#current-password').fill('old-test-password');
    await page.locator('#new-password').fill('new-test-password');
    await page.locator('#confirm-password').fill('mismatched-test-password');
    await page.locator('#password-change-form button[type=submit]').click();
    await page.getByText('Пароли не совпадают. Повторите новый пароль.', { exact: true }).waitFor();
    assert.equal(passwordRequests, 0, 'mismatched passwords must not reach the API');
    await page.locator('#confirm-password').fill('new-test-password');
    await page.locator('#password-change-form button[type=submit]').click();
    await page.getByText('Новый пароль не подходит. Проверьте правила под полем и выберите другой.', { exact: true }).waitFor();
    assert.equal(await page.locator('#confirm-password').getAttribute('aria-invalid'), null,
      'a corrected confirmation must not keep its mismatch state');
    await page.locator('#password-change-form button[type=submit]').click();
    await page.waitForURL(origin + '/login');
    assert.equal(passwordRequests, 2);
    await page.unroute('**/api/v1/auth/change_password');
    user = null;
    await page.goto(origin + '/data');
    assert.equal(await page.getByRole('heading', { name: 'Ваши данные', exact: true }).isVisible(), true);
    assert.equal(await page.getByRole('link', { name: 'admin@updspace.com' }).getAttribute('href'), 'mailto:admin@updspace.com');
    await page.goto(origin + '/signup');
    assert.equal(await page.locator('#consent-marketing').count(), 0);
    await page.route('**/api/v1/auth/signup', async route => {
      assert.equal(route.request().postDataJSON().consent_marketing, false);
      assert.equal(route.request().postDataJSON().age_confirmed, true);
      await route.fulfill({ status: 201, contentType: 'application/json', body: JSON.stringify({ verification_required: true }) });
    });
    await page.locator('#email').fill('new@example.invalid');
    await page.locator('#password').fill('local-signup-test-only');
    await page.locator('#confirmation').fill('local-signup-test-only');
    await page.locator('#consent-data').check();
    await page.locator('#age-confirmed').check();
    const signupRequest = page.waitForRequest('**/api/v1/auth/signup');
    await page.locator('#submit').click();
    assert.equal((await signupRequest).postDataJSON().consent_marketing, false);
    await page.locator('#status').getByText('Аккаунт создан.', { exact: false }).waitFor();
    await page.unroute('**/api/v1/auth/signup');
    await page.goto(origin + '/login');
    assert.equal(await page.locator('#session-choice').isVisible(), false);
    user = { username: 'alex', email: 'alex@example.invalid', email_verified: true, has_2fa: false };
    unavailable = true;
    assert.equal((await page.goto(origin + '/account?section=security')).status(), 503);
    await page.getByRole('heading', { name: 'Не удалось загрузить страницу' }).waitFor();
    unavailable = false;
    await page.getByRole('link', { name: 'Повторить загрузку' }).click();
    await page.getByRole('heading', { name: 'Вход и защита', exact: true }).waitFor();
    await page.locator('.mobile-navigation > summary').press('Enter');
    await page.locator('.mobile-navigation').getByRole('link', { name: 'Профиль', exact: true }).click();
    await page.getByRole('button', { name: 'Изменить оформление', exact: true }).click();
    await page.getByRole('radio', { name: 'Тёмная', exact: true }).check();
    assert.equal(await page.locator('html').getAttribute('data-theme'), 'dark');
    await page.reload();
    assert.equal(await page.locator('html').getAttribute('data-theme'), 'dark');
    assert.equal(await page.locator('[data-theme-choice][value=dark]').isChecked(), true);
    const themeTab = await context.newPage();
    await themeTab.goto(origin + '/account?section=profile');
    await themeTab.getByRole('button', { name: 'Изменить оформление', exact: true }).click();
    await themeTab.getByRole('radio', { name: 'Светлая', exact: true }).check();
    await page.waitForFunction(() => document.documentElement.dataset.theme === 'light');
    assert.equal(await page.locator('[data-theme-choice][value=light]').isChecked(), true, 'theme choice must follow changes from another tab');
    await page.getByRole('button', { name: 'Изменить оформление', exact: true }).click();
    await page.getByRole('radio', { name: 'Светлая', exact: true }).focus();
    await page.keyboard.press('ArrowLeft');
    assert.equal(await page.getByRole('radio', { name: 'Авто', exact: true }).isChecked(), true, 'theme supports native radio keyboard navigation');
    assert.equal(await page.locator('html').getAttribute('data-theme'), 'system');
    await themeTab.close();
    await page.goto(origin + '/login');
    assert.equal(await page.locator('[data-theme-select]').count(), 0);
    assert.equal(await page.locator('html').getAttribute('data-theme'), 'system');
    await page.goto(origin + '/privacy');
    assert.equal(await page.locator('.document-note').count(), 0);
    assert.equal(await page.locator('article .document-meta time').count(), 2);
    assert.deepEqual(errors, []);
    console.log(`PASS: ${pages.length * 6} page/theme/viewport layouts, 200% text, navigation, profile drafts/errors, sessions, consent defaults, adult registration, consent revocation and session choice`);
  } finally {
    if (browser) await browser.close();
    if (web.exitCode === null) { web.kill('SIGTERM'); await new Promise(resolve => web.once('exit', resolve)); }
    await new Promise(resolve => proxy.close(resolve));
  }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
