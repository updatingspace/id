// Real Chromium → Topcoat → Rust API → local YDB OIDC authorization flow.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');

const origin = process.env.ID_LIVE_BASE_URL;
const fixturePath = process.env.ID_OIDC_BROWSER_FIXTURE_OUTPUT;
const playwrightModule = process.env.ID_PLAYWRIGHT_MODULE;
if (!origin || !fixturePath || !playwrightModule) {
  console.error('Set ID_LIVE_BASE_URL, ID_OIDC_BROWSER_FIXTURE_OUTPUT and ID_PLAYWRIGHT_MODULE');
  process.exit(2);
}
const fixture = JSON.parse(fs.readFileSync(fixturePath, 'utf8'));
assert.equal(fixture.synthetic, true);
assert.equal(fixture.format_version, 1);
const { chromium } = require(playwrightModule);

function authorizeUrl(state, nonce, verifier, prompt) {
  const url = new URL('/oauth/authorize', origin);
  for (const [key, value] of Object.entries({
    response_type: 'code', client_id: fixture.client_id,
    redirect_uri: fixture.redirect_uri, scope: 'openid email', state, nonce,
    code_challenge: crypto.createHash('sha256').update(verifier).digest('base64url'),
    code_challenge_method: 'S256',
    ...(prompt ? { prompt } : {}),
  })) url.searchParams.set(key, value);
  return url.toString();
}

async function main() {
  const browser = await chromium.launch({
    headless: true,
    ...(process.env.ID_CHROMIUM_PATH ? { executablePath: process.env.ID_CHROMIUM_PATH } : {}),
  });
  try {
    const context = await browser.newContext();
    await context.addCookies([{ name: 'sessionid', value: fixture.session_token, url: origin, httpOnly: true }]);
    const page = await context.newPage();
    const verifier = crypto.randomBytes(48).toString('base64url');
    await page.goto(authorizeUrl('browser-approve', 'browser-nonce', verifier));
    assert.equal(new URL(page.url()).pathname, '/oauth/consent');
    assert.equal(await page.locator('h1').textContent(), 'Какие сведения передать приложению?');
    assert.equal(await page.locator('input[name="scope"][value="openid"]').count(), 0);
    assert.equal(await page.locator('input[name="scope"][value="email"]').isChecked(), false);
    assert((await context.cookies(origin)).some(cookie => cookie.name === 'csrftoken'));

    const requestId = await page.locator('#consent-form').getAttribute('data-request-id');
    const deniedWithoutCsrf = await page.evaluate(async (id) => {
      const response = await fetch('/oauth/authorize/approve', {
        method: 'POST', credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ request_id: id, scopes: ['openid', 'email'], remember: true }),
      });
      return response.status;
    }, requestId);
    assert.equal(deniedWithoutCsrf, 403);

    await page.locator('#approve').click();
    await page.waitForURL(url => url.pathname === '/callback' && url.searchParams.has('code'));
    const approved = new URL(page.url());
    assert.equal(approved.searchParams.get('state'), 'browser-approve');
    const code = approved.searchParams.get('code');
    const body = new URLSearchParams({
      grant_type: 'authorization_code', code, client_id: fixture.client_id,
      redirect_uri: fixture.redirect_uri, code_verifier: verifier,
    });
    const tokenResponse = await context.request.post(origin + '/oauth/token', {
      data: body.toString(), headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    });
    assert.equal(tokenResponse.status(), 200, await tokenResponse.text());
    const tokens = await tokenResponse.json();
    const claims = JSON.parse(Buffer.from(tokens.id_token.split('.')[1], 'base64url').toString());
    assert.equal(claims.sub, fixture.subject);
    assert.equal(claims.email, fixture.email);
    assert.equal(claims.nonce, 'browser-nonce');
    const replay = await context.request.post(origin + '/oauth/token', {
      data: body.toString(), headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    });
    assert.equal(replay.status(), 400);
    assert.equal((await replay.json()).error, 'invalid_grant');

    await page.goto(authorizeUrl('browser-deny', 'deny-nonce', crypto.randomBytes(48).toString('base64url'), 'consent'));
    assert.equal(new URL(page.url()).pathname, '/oauth/consent');
    await page.locator('#deny').click();
    await page.waitForURL(url => url.pathname === '/callback' && url.searchParams.get('error') === 'access_denied');
    assert.equal(new URL(page.url()).searchParams.get('state'), 'browser-deny');
    console.log('PASS: real browser consent, CSRF denial, PKCE exchange, replay denial and consent denial on local YDB');
  } finally {
    await browser.close();
  }
}

main().catch(error => { console.error(error); process.exitCode = 1; });
