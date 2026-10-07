// Browser-to-Topcoat-to-Rust-API preferences smoke against a real local YDB.
const assert = require('node:assert/strict');

const baseUrl = process.env.ID_LIVE_BASE_URL;
const sessionToken = process.env.ID_LIVE_SESSION_TOKEN;
const playwrightModule = process.env.ID_PLAYWRIGHT_MODULE;
if (!baseUrl || !sessionToken || !playwrightModule) {
  console.error('Set ID_LIVE_BASE_URL, ID_LIVE_SESSION_TOKEN and ID_PLAYWRIGHT_MODULE');
  process.exit(2);
}
const { chromium } = require(playwrightModule);

async function main() {
  const browser = await chromium.launch({
    headless: true,
    ...(process.env.ID_CHROMIUM_PATH ? { executablePath: process.env.ID_CHROMIUM_PATH } : {}),
  });
  try {
    const origin = new URL(baseUrl).origin;
    const context = await browser.newContext();
    await context.addCookies([{ name: 'sessionid', value: sessionToken, url: origin, httpOnly: true }]);
    const page = await context.newPage();
    await page.goto(origin + '/account?section=settings');
    assert.equal(await page.locator('h1').textContent(), 'Язык и часовой пояс');
    assert.equal(await page.locator('#preferences-form').count(), 1);
    assert((await page.locator('#preferences-timezone option').count()) > 400);

    const denied = await page.evaluate(async () => {
      const response = await fetch('/api/v1/auth/preferences', {
        method: 'PATCH', credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ language: 'ru' }),
      });
      return { status: response.status, body: await response.json() };
    });
    assert.equal(denied.status, 403);
    assert.equal(denied.body.code, 'CSRF_FAILED');
    assert.equal(await page.locator('#preferences-language').inputValue(), 'en');

    const privacy = await context.newPage();
    await privacy.goto(origin + '/account?section=privacy');
    await privacy.locator('#preferences-marketing').check();
    await privacy.locator('#scope-email').selectOption('deny');
    const [privacyUpdate] = await Promise.all([
      privacy.waitForResponse(response => new URL(response.url()).pathname === '/api/v1/auth/preferences' && response.request().method() === 'PATCH'),
      privacy.locator('#preferences-form button[type="submit"]').click(),
    ]);
    assert.equal(privacyUpdate.status(), 200, await privacyUpdate.text());
    assert.deepEqual(Object.keys(privacyUpdate.request().postDataJSON()).sort(), ['marketing_opt_in', 'privacy_scope_defaults']);
    await page.locator('#preferences-language').selectOption('ru');
    await page.locator('#preferences-timezone').selectOption('Europe/Moscow');
    const [updated] = await Promise.all([
      page.waitForResponse(response => new URL(response.url()).pathname === '/api/v1/auth/preferences'
        && response.request().method() === 'PATCH'),
      page.locator('#preferences-form button[type="submit"]').click(),
    ]);
    assert.equal(updated.status(), 200, await updated.text());
    assert.deepEqual(Object.keys(updated.request().postDataJSON()).sort(), ['language', 'timezone']);
    await page.locator('#preferences-message:visible').waitFor();
    const prefs = await page.evaluate(async () => {
      const response = await fetch('/api/v1/auth/preferences', { credentials: 'include', cache: 'no-store' });
      return { status: response.status, body: await response.json() };
    });
    assert.equal(prefs.status, 200);
    assert.equal(prefs.body.language, 'ru');
    assert.equal(prefs.body.timezone, 'Europe/Moscow');
    assert.equal(prefs.body.marketing_opt_in, true);
    assert.equal(prefs.body.privacy_scope_defaults.email, 'deny');
    assert.equal(typeof prefs.body.marketing_opt_in_at, 'string');

    await page.reload();
    assert.equal(await page.locator('#preferences-language').inputValue(), 'ru');
    assert.equal(await page.locator('#preferences-timezone').inputValue(), 'Europe/Moscow');
    await privacy.reload();
    assert.equal(await privacy.locator('#preferences-marketing').isChecked(), true);
    assert.equal(await privacy.locator('#scope-email').inputValue(), 'deny');

    await privacy.locator('#preferences-marketing').uncheck();
    const [optedOut] = await Promise.all([
      privacy.waitForResponse(response => new URL(response.url()).pathname === '/api/v1/auth/preferences'
        && response.request().method() === 'PATCH'),
      privacy.locator('#preferences-form button[type="submit"]').click(),
    ]);
    assert.equal(optedOut.status(), 200, await optedOut.text());
    const after = await optedOut.json();
    assert.equal(after.marketing_opt_in, false);
    assert.equal(typeof after.marketing_opt_out_at, 'string');
    console.log('PASS: Topcoat settings → Rust preferences → YDB → SSR reload; marketing transition and CSRF denial');
  } finally {
    await browser.close();
  }
}

main().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
