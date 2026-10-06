// Browser smoke for the transition from React's explicit token to a cookie session.
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
    const issuer = await browser.newContext();
    const issuerPage = await issuer.newPage();
    await issuerPage.goto(origin + '/login?next=%2Faccount');
    await issuerPage.locator('#email').fill(email);
    await issuerPage.locator('#password').fill(password);
    await issuerPage.locator('#submit').click();
    await issuerPage.waitForURL(origin + '/account', { timeout: 30000 });
    const original = (await issuer.cookies(origin)).find(cookie => cookie.name === 'sessionid');
    assert(original?.httpOnly && original.value, 'login must issue an HttpOnly session');

    const legacy = await browser.newContext();
    const legacyPage = await legacy.newPage();
    await legacyPage.goto(origin + '/');
    await legacyPage.evaluate(token => sessionStorage.setItem('id_session_token', token), original.value);
    await legacyPage.goto(origin + '/login?next=%2Faccount');
    await legacyPage.waitForURL(origin + '/account', { timeout: 30000 });
    assert.equal(await legacyPage.locator('h1').textContent(), 'Аккаунт');
    assert.equal(await legacyPage.evaluate(() => sessionStorage.getItem('id_session_token')), null);
    const bridged = (await legacy.cookies(origin)).find(cookie => cookie.name === 'sessionid');
    assert(bridged?.httpOnly && bridged.value === original.value);

    const expired = await browser.newContext();
    const expiredPage = await expired.newPage();
    await expiredPage.goto(origin + '/');
    await expiredPage.evaluate(() => sessionStorage.setItem('id_session_token', 'invalid-token'));
    await expiredPage.goto(origin + '/login?next=%2Faccount');
    await expiredPage.locator('#error').getByText('Старая сессия истекла. Войдите заново.').waitFor();
    assert.equal(await expiredPage.evaluate(() => sessionStorage.getItem('id_session_token')), null);
    assert.equal(new URL(expiredPage.url()).pathname, '/login');
    assert(!(await expired.cookies(origin)).some(cookie => cookie.name === 'sessionid'));

    await issuerPage.evaluate(() => sessionStorage.setItem('id_session_token', 'invalid-token'));
    let explicitRequests = 0;
    issuerPage.on('request', request => {
      if (new URL(request.url()).pathname === '/api/v1/auth/me' && request.headers()['x-session-token']) {
        explicitRequests += 1;
      }
    });
    await issuerPage.goto(origin + '/login?next=%2Faccount');
    await issuerPage.waitForFunction(() => sessionStorage.getItem('id_session_token') === null);
    assert.equal(explicitRequests, 0, 'a stale explicit token must not replace a valid cookie');
    assert.equal((await issuer.cookies(origin)).find(cookie => cookie.name === 'sessionid')?.value, original.value);
    console.log('PASS: legacy token bridged to cookie; invalid token rejected; valid cookie kept authoritative');
  } finally {
    await browser.close();
  }
}

main().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
