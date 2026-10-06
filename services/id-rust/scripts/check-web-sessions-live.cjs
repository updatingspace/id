// Real browser and Rust API smoke against an already running same-origin deployment.
const assert = require('node:assert/strict');

const baseUrl = process.env.ID_LIVE_BASE_URL;
const email = process.env.ID_LIVE_EMAIL;
const password = process.env.ID_LIVE_PASSWORD;
const playwrightModule = process.env.ID_PLAYWRIGHT_MODULE;
if (!baseUrl || !email || !password || !playwrightModule) {
  console.error('Set ID_LIVE_BASE_URL, ID_LIVE_EMAIL, ID_LIVE_PASSWORD and ID_PLAYWRIGHT_MODULE');
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
    async function login() {
      const context = await browser.newContext();
      const page = await context.newPage();
      await page.goto(origin + '/login?next=%2Faccount%3Fsection%3Dsessions');
      await page.locator('#email').fill(email);
      await page.locator('#password').fill(password);
      await page.locator('#submit').click();
      await page.waitForURL(origin + '/account?section=sessions', { timeout: 30000 });
      assert.equal(await page.locator('h1').textContent(), 'Активные устройства');
      return { context, page };
    }
    async function signedIn(page) {
      const result = await page.evaluate(async () => {
        const response = await fetch('/api/v1/auth/me', { credentials: 'include' });
        return { status: response.status, body: await response.json() };
      });
      return result.status === 200 && result.body.user?.email?.toLowerCase() === email.toLowerCase();
    }

    const first = await login();
    const second = await login();
    await second.page.reload();
    assert.equal(await second.page.locator('.session-row').count(), 2);
    assert.equal(await second.page.locator('[data-revoke-session]').count(), 1);
    const [singleResponse] = await Promise.all([
      second.page.waitForResponse(response => response.request().method() === 'DELETE' &&
        new URL(response.url()).pathname.startsWith('/api/v1/auth/sessions/')),
      second.page.waitForNavigation({ waitUntil: 'load' }),
      second.page.locator('[data-revoke-session]').click(),
    ]);
    assert.equal(singleResponse.status(), 200);
    assert.equal(await signedIn(first.page), false, 'revoked device must lose access');
    assert.equal(await signedIn(second.page), true, 'current device must remain signed in');

    const third = await login();
    await second.page.reload();
    assert.equal(await second.page.locator('#revoke-others').count(), 1);
    const [bulkResponse] = await Promise.all([
      second.page.waitForResponse(response => response.request().method() === 'POST' &&
        new URL(response.url()).pathname === '/api/v1/auth/sessions/bulk'),
      second.page.waitForNavigation({ waitUntil: 'load' }),
      second.page.locator('#revoke-others').click(),
    ]);
    assert.equal(bulkResponse.status(), 200);
    assert.equal(await signedIn(third.page), false, 'bulk revoke must close the other device');
    assert.equal(await signedIn(second.page), true, 'bulk revoke must preserve the current device');
    console.log('PASS: Topcoat SSR sessions, single and bulk revoke on Rust API/YDB');
  } finally {
    await browser.close();
  }
}

main().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
