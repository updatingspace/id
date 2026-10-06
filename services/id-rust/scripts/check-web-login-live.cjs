// Browser-to-API smoke against an already running same-origin UI/API deployment.
// All credentials and runtime paths are supplied by the caller.
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
    const context = await browser.newContext();
    const page = await context.newPage();
    const apiFailures = [];
    page.on('response', response => {
      if (new URL(response.url()).pathname.startsWith('/api/') && response.status() >= 400) {
        apiFailures.push(response.status() + ' ' + new URL(response.url()).pathname);
      }
    });
    const origin = new URL(baseUrl).origin;
    if (process.env.ID_LIVE_ACCOUNT_SSR === 'true') {
      await page.goto(origin + '/account');
      assert.equal(new URL(page.url()).pathname, '/login');
    }
    await page.goto(origin + '/login?next=%2Faccount');
    await page.evaluate(() => sessionStorage.setItem('id_session_token', 'stale-test-token'));
    await page.locator('#email').fill(email);
    await page.locator('#password').fill(password);
    await page.locator('#submit').click();
    try {
      await page.waitForURL(origin + '/account', { timeout: 30000 });
    } catch (error) {
      console.error('Login failed:', await page.locator('#error').textContent(), apiFailures);
      throw error;
    }
    const me = await page.evaluate(async () => {
      const response = await fetch('/api/v1/auth/me', { credentials: 'include' });
      return { status: response.status, body: await response.json() };
    });
    assert.equal(me.status, 200, 'Rust /me must restore the browser session');
    assert.equal(me.body.user.email.toLowerCase(), email.toLowerCase());
    if (process.env.ID_LIVE_ACCOUNT_SSR === 'true') {
      assert.equal(await page.locator('h1').textContent(), 'Аккаунт');
      assert(await page.locator('main').textContent().then(text => text.includes(email)));
      assert.equal((await page.locator('html').getAttribute('lang')), 'ru');
    }
    assert.equal(await page.evaluate(() => sessionStorage.getItem('id_session_token')), null);
    const cookies = await context.cookies(origin);
    assert(cookies.some(cookie => cookie.name === 'sessionid' && cookie.httpOnly));
    assert(cookies.some(cookie => cookie.name === 'csrftoken' && !cookie.httpOnly));
    assert.deepEqual(apiFailures, []);
    console.log(process.env.ID_LIVE_ACCOUNT_SSR === 'true'
      ? 'PASS: Topcoat login and SSR account, Rust /me, HttpOnly session and stale-token cleanup'
      : 'PASS: Topcoat browser login, Rust /me, HttpOnly session and stale-token cleanup');
  } finally {
    await browser.close();
  }
}

main().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
