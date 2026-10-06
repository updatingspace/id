// Browser smoke for Topcoat logout against the real Rust API and YDB.
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
    async function login(next) {
      const context = await browser.newContext();
      const page = await context.newPage();
      await page.goto(origin + '/login?next=' + encodeURIComponent(next));
      await page.locator('#email').fill(email);
      await page.locator('#password').fill(password);
      await page.locator('#submit').click();
      await page.waitForURL(origin + next, { timeout: 30000 });
      return { context, page };
    }
    async function me(page) {
      return page.evaluate(async () => {
        const response = await fetch('/api/v1/auth/me', { credentials: 'include' });
        return { status: response.status, body: await response.json() };
      });
    }
    async function logout(page) {
      const [response] = await Promise.all([
        page.waitForResponse(result => new URL(result.url()).pathname === '/api/v1/auth/logout' &&
          result.request().method() === 'POST'),
        page.waitForURL(origin + '/login', { waitUntil: 'load' }),
        page.locator('#logout').click(),
      ]);
      assert.equal(response.status(), 200);
      const result = await me(page);
      assert.equal(result.status, 200);
      assert.equal(result.body.user, null);
      assert.equal(await page.evaluate(() => sessionStorage.getItem('id_session_token')), null);
    }

    const first = await login('/account');
    const second = await login('/account?section=sessions');
    await first.page.evaluate(() => sessionStorage.setItem('id_session_token', 'stale-test-token'));
    const missingCsrf = await first.page.evaluate(async () => {
      const response = await fetch('/api/v1/auth/logout', {
        method: 'POST', credentials: 'include', headers: { Accept: 'application/json' },
      });
      return response.status;
    });
    assert.equal(missingCsrf, 403);
    assert((await me(first.page)).body.user);
    await logout(first.page);
    assert((await me(second.page)).body.user, 'logging out one device must preserve the other');
    await logout(second.page);
    console.log('PASS: CSRF denial, Topcoat logout from profile and sessions, independent device preserved');
  } finally {
    await browser.close();
  }
}

main().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
