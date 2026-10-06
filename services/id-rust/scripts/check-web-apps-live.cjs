// Browser → Topcoat → Rust API → local YDB OAuth application revocation smoke.
const assert = require('node:assert/strict');

const baseUrl = process.env.ID_LIVE_BASE_URL;
const sessionToken = process.env.ID_LIVE_SESSION_TOKEN;
const clientId = process.env.ID_LIVE_CLIENT_ID;
const playwrightModule = process.env.ID_PLAYWRIGHT_MODULE;
if (!baseUrl || !sessionToken || !clientId || !playwrightModule) {
  console.error('Set ID_LIVE_BASE_URL, ID_LIVE_SESSION_TOKEN, ID_LIVE_CLIENT_ID and ID_PLAYWRIGHT_MODULE');
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
    await page.goto(origin + '/account?section=apps');
    assert.equal(await page.locator('h1').textContent(), 'Подключённые приложения');
    const target = page.locator(`[data-revoke-app="${clientId}"]`);
    assert.equal(await target.count(), 1);

    const denied = await page.evaluate(async (id) => {
      const response = await fetch('/api/v1/auth/oauth/apps/revoke', {
        method: 'POST', credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ client_id: id }),
      });
      return { status: response.status, body: await response.json() };
    }, clientId);
    assert.equal(denied.status, 403);
    assert.equal(denied.body.code, 'CSRF_FAILED');
    assert.equal(await target.count(), 1);

    await context.addCookies([{ name: 'csrftoken', value: 'a'.repeat(32), url: origin }]);
    const [revoked] = await Promise.all([
      page.waitForResponse(response => new URL(response.url()).pathname === '/api/v1/auth/oauth/apps/revoke'),
      target.click(),
    ]);
    assert.equal(revoked.status(), 200);
    await target.waitFor({ state: 'detached' });
    await page.reload();
    assert.equal(await page.locator(`[data-revoke-app="${clientId}"]`).count(), 0);
    const listed = await page.evaluate(async () => {
      const response = await fetch('/api/v1/auth/oauth/apps', { credentials: 'include', cache: 'no-store' });
      return { status: response.status, body: await response.json() };
    });
    assert.equal(listed.status, 200);
    assert(!listed.body.items.some(item => item.client_id === clientId));
    console.log('PASS: Topcoat OAuth applications → Rust revoke → YDB → SSR reload; CSRF denial');
  } finally {
    await browser.close();
  }
}

main().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
