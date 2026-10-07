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
  const preferenceWrites = [];
  const preferences = { language: 'ru', timezone: 'Europe/Moscow', marketing_opt_in: false, privacy_scope_defaults: {} };
  const reply = (res, status, data) => { res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', 'set-cookie': 'csrftoken=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; Path=/; SameSite=Lax' }); res.end(JSON.stringify(data)); };
  const proxy = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    const api = url.pathname.replace('/api/v1/auth/', '');
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
    if (api === 'consents') return reply(res, 200, { consents: [{ kind: 'data_processing', version: 'v1', granted_at: '2026-10-01T12:00:00Z', revoked_at: null }] });
    if (api === 'oauth/apps') return reply(res, 200, { items: empty ? [] : [{ client_id: 'portal', name: 'UpdSpace Portal', scopes: ['openid', 'email', 'profile'], last_used_at: '2026-10-08T09:15:00Z' }] });
    if (url.pathname === '/oauth/authorize/prepare') return reply(res, 200, { action: 'consent', request_id: 'synthetic-consent', client: { name: 'UpdSpace Portal' }, redirect_uri: 'https://portal.example.invalid/callback', scopes: [{ name: 'openid', description: 'Идентификатор аккаунта', required: true }, { name: 'email', description: 'Электронная почта', required: false }] });
    if (url.pathname.startsWith('/api/')) return reply(res, 501, { code: 'SYNTHETIC_PREVIEW', message: 'Это локальный макет API. Действие не выполнено.' });
    const forwarded = http.request({ hostname: '127.0.0.1', port: webPort, path: req.url, method: req.method, headers: { ...req.headers, host: `127.0.0.1:${webPort}` } }, upstream => { res.writeHead(upstream.statusCode, upstream.headers); upstream.pipe(res); });
    forwarded.on('error', () => { if (!res.headersSent) res.writeHead(502); res.end(); });
    req.pipe(forwarded);
  });
  await new Promise(resolve => proxy.listen(0, '127.0.0.1', resolve));
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
    const nav = ['Обзор', 'Профиль', 'Вход и защита', 'Устройства', 'Приложения', 'Приватность и данные'];
    const luminance = hex => {
      const rgb = hex.replace('#', '').match(/.{2}/g).map(value => parseInt(value, 16) / 255).map(value => value <= .04045 ? value / 12.92 : ((value + .055) / 1.055) ** 2.4);
      return rgb[0] * .2126 + rgb[1] * .7152 + rgb[2] * .0722;
    };
    const contrast = (a, b) => { const values = [luminance(a), luminance(b)].sort((x, y) => y - x); return (values[0] + .05) / (values[1] + .05); };
    const accountPages = ['', 'profile', 'security', 'sessions', 'activity', 'apps', 'privacy', 'settings', 'data', 'delete'];
    const pages = ['/', '/login', '/signup', '/forgot-password', '/reset-password', '/verify-email', '/oauth/consent?client_id=synthetic', ...accountPages.map(section => '/account' + (section ? `?section=${section}` : ''))];
    for (const width of [320, 390, 1280]) for (const theme of ['light', 'dark']) {
      await page.setViewportSize({ width, height: 844 });
      await page.emulateMedia({ colorScheme: theme, reducedMotion: 'reduce' });
      for (const route of pages) {
        const response = await page.goto(origin + route);
        assert.equal(response.status(), 200, route);
        if (route.startsWith('/account')) assert.deepEqual(await page.locator('.account-sidebar .account-links a').allTextContents(), nav, route);
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, `overflow ${route} ${width} ${theme}`);
        const tokens = await page.evaluate(() => Object.fromEntries(['ink', 'muted', 'surface', 'canvas', 'soft', 'action', 'on-action'].map(name => [name, getComputedStyle(document.documentElement).getPropertyValue('--' + name).trim().replace(/^#([0-9a-f])([0-9a-f])([0-9a-f])$/i, '#$1$1$2$2$3$3')])));
        for (const fg of ['ink', 'muted', 'action']) for (const bg of ['surface', 'canvas', 'soft']) assert.ok(contrast(tokens[fg], tokens[bg]) >= 4.5, `contrast ${fg}/${bg} ${theme}`);
        assert.ok(contrast(tokens['action'], tokens['on-action']) >= 4.5);
        // Model 200% text enlargement, retaining the mobile viewport.
        await page.evaluate(() => document.documentElement.style.fontSize = '200%');
        assert.deepEqual(await page.evaluate(() => [...document.querySelectorAll("body *")].filter(e => e.getBoundingClientRect().right > innerWidth + 1).map(e => e.outerHTML.slice(0, 120))), [], `200% overflow ${route} ${width} ${theme}`);
        assert.deepEqual(await page.locator('fieldset > legend:visible').evaluateAll(legends => legends.filter(e => e.getBoundingClientRect().right > e.parentElement.getBoundingClientRect().right + 1).map(e => e.textContent)), [], `200% legend overflow ${route} ${width} ${theme}`);
        for (const summary of await page.locator('details:not(.mobile-navigation) > summary').all()) {
          await summary.click();
          assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, `expanded 200% overflow ${route} ${width} ${theme}`);
        }
      }
    }
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto(origin + '/account?section=profile');
    await page.locator('[data-profile-editor] > summary').first().click();
    await page.locator('#first-name').fill('Оченьдлинноеимябезпробелов'.repeat(6));
    profileFailure = true;
    await page.locator('#profile-form button[type=submit]').click();
    await page.locator('#profile-error:visible').waitFor();
    assert.ok((await page.locator('#first-name').inputValue()).startsWith('Очень'));
    assert.equal(await page.locator('#profile-error').evaluate(e => e === document.activeElement), true);
    await page.locator('[data-profile-editor] > summary').nth(1).click();
    assert.equal(await page.locator('details[data-profile-editor][open]').count(), 1);
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, 'avatar form overflow');
    await page.locator('[data-profile-editor] > summary').first().click();
    assert.ok((await page.locator('#first-name').inputValue()).startsWith('Очень'), 'draft lost across editors');
    profileFailure = false;
    await page.locator('#profile-form button[type=submit]').click();
    await page.locator('#profile-message:visible').waitFor();
    await page.reload();
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, 'long name overflow');
    await page.goto(origin + '/account?section=sessions');
    assert.equal(await page.locator('ul[aria-label="Действующие сеансы"] li').count(), 2);
    assert.equal(await page.getByText('Firefox · Windows', { exact: true }).isVisible(), false, 'revoked session in active group');
    assert.ok((await page.locator('time').first().textContent()).includes('2026'));
    assert.notEqual(await page.locator('time').first().textContent(), await page.locator('time').first().getAttribute('datetime'));
    // Keep both pages open: each contains an older snapshot of the other section.
    await page.goto(origin + '/account?section=settings');
    const privacyTab = await page.context().newPage();
    await privacyTab.goto(origin + '/account?section=privacy');
    await privacyTab.locator('#preferences-marketing').check();
    await privacyTab.locator('#scope-email').selectOption('deny');
    await privacyTab.locator('#preferences-form button[type=submit]').click();
    await privacyTab.locator('#preferences-message:visible').waitFor();
    assert.deepEqual(Object.keys(preferenceWrites.at(-1)).sort(), ['marketing_opt_in', 'privacy_scope_defaults']);
    assert.equal(await page.locator('#preferences-marketing').isVisible(), false);
    await page.locator('#preferences-language').selectOption('en');
    await page.locator('#preferences-timezone').selectOption('UTC');
    await page.locator('#preferences-form button[type=submit]').click();
    await page.locator('#preferences-message:visible').waitFor();
    assert.deepEqual(Object.keys(preferenceWrites.at(-1)).sort(), ['language', 'timezone']);
    assert.equal(preferences.marketing_opt_in, true, 'stale settings must preserve newer consent');
    assert.equal(preferences.privacy_scope_defaults.email, 'deny');
    await privacyTab.locator('#preferences-marketing').uncheck();
    await privacyTab.locator('#preferences-form button[type=submit]').click();
    await privacyTab.locator('#preferences-message:visible').waitFor();
    assert.equal(preferences.language, 'en', 'stale privacy must preserve newer language');
    assert.equal(preferences.timezone, 'UTC');
    assert.equal(preferences.marketing_opt_in, false);
    await privacyTab.close();
    await page.route('**/api/v1/auth/preferences', route => route.fulfill({ status: 401, contentType: 'application/json', body: '{}' }));
    await page.locator('#preferences-form button[type=submit]').click();
    await page.waitForURL(origin + '/login?next=%2Faccount%3Fsection%3Dsettings');
    await page.unroute('**/api/v1/auth/preferences');
    await page.goto(origin + '/oauth/consent?client_id=synthetic');
    assert.equal(await page.locator('input[name=scope]:checked').count(), 0);
    assert.equal(await page.locator('#remember').isChecked(), false);
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
    await page.getByText(`Вы вошли как ${user.email}`, { exact: false }).waitFor();
    user = null;
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
    await page.locator('.mobile-navigation select').selectOption('dark');
    await page.locator('.mobile-navigation').getByRole('link', { name: 'Профиль', exact: true }).click();
    assert.equal(await page.locator('html').getAttribute('data-theme'), 'dark');
    await page.reload();
    assert.equal(await page.locator('html').getAttribute('data-theme'), 'dark');
    await page.goBack();
    assert.equal(new URL(page.url()).searchParams.get('section'), 'security');
    assert.deepEqual(errors, []);
    console.log('PASS: 102 page/theme/viewport layouts, 200% text, navigation, profile drafts/errors, sessions, consent defaults and session choice');
  } finally {
    if (browser) await browser.close();
    if (web.exitCode === null) { web.kill('SIGTERM'); await new Promise(resolve => web.once('exit', resolve)); }
    await new Promise(resolve => proxy.close(resolve));
  }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
