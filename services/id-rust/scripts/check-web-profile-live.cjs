// Browser-to-Topcoat-to-Rust-API profile update against a real local YDB.
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
    await page.goto(origin + '/account?section=profile');
    assert.equal(await page.locator('h1').textContent(), 'Профиль');
    assert.equal(await page.locator('#profile-form').count(), 1);

    const denied = await page.evaluate(async () => {
      const response = await fetch('/api/v1/auth/profile', {
        method: 'PATCH', credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ first_name: 'Denied' }),
      });
      return { status: response.status, body: await response.json() };
    });
    assert.equal(denied.status, 403);
    assert.equal(denied.body.code, 'CSRF_FAILED');
    const before = await page.evaluate(async () =>
      (await fetch('/api/v1/auth/me', { credentials: 'include', cache: 'no-store' })).json());
    assert.notEqual(before.user.first_name, 'Denied');

    await page.locator('[data-profile-editor] > summary').first().click();
    await page.locator('#first-name').fill('  Ada  ');
    await page.locator('#last-name').fill('  Lovelace  ');
    await page.locator('#phone-number').fill(' +1 555 ');
    await page.locator('#birth-date').fill('1990-01-02');
    const [updated] = await Promise.all([
      page.waitForResponse(response => new URL(response.url()).pathname === '/api/v1/auth/profile'
        && response.request().method() === 'PATCH'),
      page.locator('#profile-form button[type="submit"]').click(),
    ]);
    assert.equal(updated.status(), 200, await updated.text());
    await page.locator('#profile-message:visible').waitFor();

    const profile = await page.evaluate(async () => {
      const response = await fetch('/api/v1/auth/me', { credentials: 'include', cache: 'no-store' });
      return { status: response.status, body: await response.json() };
    });
    assert.equal(profile.status, 200);
    assert.equal(profile.body.user.first_name, 'Ada');
    assert.equal(profile.body.user.last_name, 'Lovelace');
    assert.equal(profile.body.user.phone_number, '+1 555');
    assert.equal(profile.body.user.birth_date, '1990-01-02');

    await page.reload();
    assert.equal(await page.locator('#first-name').inputValue(), 'Ada');
    assert.equal(await page.locator('#last-name').inputValue(), 'Lovelace');
    assert.equal(await page.locator('#phone-number').inputValue(), '+1 555');
    assert.equal(await page.locator('#birth-date').inputValue(), '1990-01-02');
    console.log('PASS: Topcoat profile form → Rust PATCH → YDB → Rust /me → Topcoat SSR reload; missing CSRF denied');
  } finally {
    await browser.close();
  }
}

main().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
