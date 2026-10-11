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
    redirect_uri: fixture.redirect_uri, scope: 'openid email profile phone', state, nonce,
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
    assert.equal(await page.locator('h1').textContent(), 'Войти в Browser fixture client?');
    for (const name of ['openid', 'email', 'profile']) {
      assert.equal(await page.locator(`input[name="required-scope"][value="${name}"]`).count(), 1);
      assert.equal(await page.locator(`input[name="scope"][value="${name}"]`).count(), 0);
    }
    assert.equal(await page.locator('input[name="scope"][value="phone"]').isChecked(), false);
    assert.equal(await page.locator('#remember').count(), 0);
    assert.equal(await page.locator('.account strong').textContent(), fixture.email);
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

    const missingRequired = await page.evaluate(async id => {
      const csrf = document.cookie.split('; ').find(value => value.startsWith('csrftoken=')).slice('csrftoken='.length);
      const response = await fetch('/oauth/authorize/approve', {
        method: 'POST', credentials: 'include',
        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrf },
        body: JSON.stringify({ request_id: id, scopes: ['openid'] }),
      });
      return response.status;
    }, requestId);
    assert.equal(missingRequired, 400);

    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    async function checkLayout(stage) {
      for (const width of [320, 390, 900]) {
        for (const colorScheme of ['light', 'dark']) {
          await page.setViewportSize({ width, height: 800 });
          await page.emulateMedia({ colorScheme });
          assert(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth));
          if (process.env.ID_CONSENT_SCREENSHOT_DIR && width === 390) {
            fs.mkdirSync(process.env.ID_CONSENT_SCREENSHOT_DIR, { recursive: true });
            await page.screenshot({ path: `${process.env.ID_CONSENT_SCREENSHOT_DIR}/${stage}-${colorScheme}.png`, fullPage: true });
          }
        }
      }
    }
    await checkLayout('first');
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

    assert.equal(tokens.scope, 'openid email profile');
    await page.goto(authorizeUrl('browser-confirm', 'confirm-nonce', crypto.randomBytes(48).toString('base64url')));
    assert.equal(new URL(page.url()).pathname, '/oauth/consent');
    assert.equal(await page.locator('#approve').textContent(), 'Продолжить');
    assert.equal(await page.locator('input[name="scope"]').count(), 0);
    assert.equal(await page.locator('details').getAttribute('open'), null);
    await checkLayout('returning');
    await page.locator('#approve').focus();
    await page.keyboard.press('Enter');
    await page.waitForURL(url => url.pathname === '/callback' && url.searchParams.has('code'));

    await page.goto(authorizeUrl('browser-deny', 'deny-nonce', crypto.randomBytes(48).toString('base64url'), 'consent'));
    assert.equal(new URL(page.url()).pathname, '/oauth/consent');
    await page.locator('#deny').click();
    await page.waitForURL(url => url.pathname === '/callback' && url.searchParams.get('error') === 'access_denied');
    assert.equal(new URL(page.url()).searchParams.get('state'), 'browser-deny');
    // Denying an entry must not revoke the saved permissions.
    await page.goto(authorizeUrl('browser-revoke', 'revoke-nonce', crypto.randomBytes(48).toString('base64url')));
    assert.equal(await page.locator('#approve').textContent(), 'Продолжить');
    const revoked = await page.evaluate(async clientId => {
      const csrf = document.cookie.split('; ').find(value => value.startsWith('csrftoken=')).slice('csrftoken='.length);
      const response = await fetch('/api/v1/auth/oauth/apps/revoke', {
        method: 'POST', credentials: 'include', headers: { 'X-CSRFToken': csrf, 'Content-Type': 'application/json' },
        body: JSON.stringify({ client_id: clientId }),
      });
      return response.status;
    }, fixture.client_id);
    assert.equal(revoked, 200);
    await page.goto(authorizeUrl('browser-regrant', 'regrant-nonce', crypto.randomBytes(48).toString('base64url')));
    assert.equal(await page.locator('input[name="scope"][value="phone"]').isChecked(), false);
    await page.locator('input[name="scope"][value="phone"]').check();
    await page.locator('#approve').click();
    await page.waitForURL(url => url.pathname === '/callback' && url.searchParams.has('code'));
    assert.deepEqual(errors, []);
    console.log('PASS: required/optional scopes, persistent choice, account confirmation, revocation/regrant, CSRF, PKCE, replay, responsive themes');
  } finally {
    await browser.close();
  }
}

main().catch(error => { console.error(error); process.exitCode = 1; });
