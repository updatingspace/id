// Real Chromium → Topcoat → Rust API → local YDB. No API mocks or external OAuth login.
const assert = require('node:assert/strict');
const fs = require('node:fs');

async function main() {
  const { ID_LIVE_BASE_URL: base, ID_PROVIDER_BROWSER_FIXTURE_OUTPUT: fixturePath, ID_PLAYWRIGHT_MODULE: modulePath } = process.env;
  assert.ok(base && fixturePath && modulePath, 'Set ID_LIVE_BASE_URL, ID_PROVIDER_BROWSER_FIXTURE_OUTPUT and ID_PLAYWRIGHT_MODULE');
  const url = new URL(base);
  assert.ok(['http:', 'https:'].includes(url.protocol) && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname), 'Only a local fixture server is allowed');
  assert.ok(!url.username && !url.password && url.pathname === '/' && !url.search && !url.hash, 'Use a bare local origin');
  const origin = url.origin;
  const fixture = JSON.parse(fs.readFileSync(fixturePath, 'utf8'));
  assert.equal(fixture.synthetic, true, 'A synthetic fixture is required');
  assert.ok(typeof fixture.session_token === 'string' && fixture.session_token.length > 0, 'Fixture session is required');
  assert.ok(typeof fixture.email === 'string' && fixture.email.length > 0, 'Fixture email is required');
  assert.deepEqual([...fixture.providers].sort(), ['discord', 'github', 'steam']);
  const { chromium } = require(modulePath);
  const browser = await chromium.launch({ headless: true,
    ...(process.env.ID_CHROMIUM_PATH ? { executablePath: process.env.ID_CHROMIUM_PATH } : {}) });
  try {
    const context = await browser.newContext({ viewport: { width: 390, height: 844 } });
    await context.addCookies([{ name: 'sessionid', value: fixture.session_token, url: origin, httpOnly: true, sameSite: 'Lax' }]);
    const page = await context.newPage();
    const errors = [];
    const posts = [];
    page.on('pageerror', error => errors.push(error.message));
    page.on('console', message => { if (message.type() === 'error') errors.push(message.text()); });
    page.on('requestfailed', request => errors.push(`Request failed: ${new URL(request.url()).pathname}`));
    page.on('request', request => { if (request.method() === 'POST') posts.push(request); });
    const [capabilityResponse, document] = await Promise.all([
      page.waitForResponse(response => new URL(response.url()).pathname === '/api/v1/auth/oauth/providers'),
      page.goto(`${origin}/account?section=security`),
    ]);
    assert.equal(document.status(), 200, 'Account SSR must authenticate the fixture');
    const html = await document.text();
    for (const provider of fixture.providers) {
      assert.ok(html.includes(`data-link-provider="${provider}" data-linked="true"`), `${provider} missing from SSR links`);
    }
    assert.equal(capabilityResponse.status(), 200);
    const inventory = (await capabilityResponse.json()).providers;
    assert.ok(Array.isArray(inventory) && inventory.every(provider => provider.login_enabled !== true), 'External provider login gates must be off');
    const idle = () => page.locator('#provider-links[aria-busy=false]').waitFor({ state: 'attached' });
    await idle();
    assert.ok((await page.locator('#provider-link-account').textContent()).trim() === fixture.email, 'Unexpected displayed fixture account');
    for (const provider of fixture.providers) {
      const row = page.locator(`[data-link-provider="${provider}"]`);
      const review = row.locator('[data-unlink-review]');
      assert.equal(await row.isVisible(), true, `${provider} link missing from UI`);
      await review.locator('summary').click();
      await row.locator('[data-unlink-cancel]').click();
      assert.equal(await review.evaluate(element => element.open), false, 'Cancel must close review');
      assert.equal(posts.length, 0, 'Review/cancel must not send a POST');
    }
    for (const [index, provider] of fixture.providers.entries()) {
      const row = page.locator(`[data-link-provider="${provider}"]`);
      await row.locator('[data-unlink-review] > summary').click();
      const [response] = await Promise.all([
        page.waitForResponse(response => response.request().method() === 'POST' && new URL(response.url()).pathname === '/api/v1/auth/oauth/unlink'),
        row.locator('[data-unlink-confirm]').click(),
      ]);
      assert.equal(response.status(), 200, `Unlink ${provider} must succeed`);
      assert.equal((await response.json()).ok, true);
      assert.deepEqual(response.request().postDataJSON(), { provider });
      const headers = await response.request().allHeaders();
      assert.ok(!headers['x-session-token'], 'Unlink must use the cookie session');
      assert.ok(headers['x-csrftoken'] && headers.cookie?.includes(`csrftoken=${headers['x-csrftoken']}`), 'Unlink must send the real API-issued CSRF cookie and header');
      await idle();
      await row.waitFor({ state: 'hidden' });
      assert.equal(posts.length, index + 1, 'Each confirmed unlink must send exactly one POST');
      assert.equal(await page.locator('#provider-link-status').isVisible(), true);
    }
    const current = await page.evaluate(async () => {
      const response = await fetch('/api/v1/auth/me', { credentials: 'include', cache: 'no-store' });
      const body = await response.json();
      return { status: response.status, email: body.user?.email, providers: body.user?.oauth_providers };
    });
    assert.equal(current.status, 200);
    assert.ok(current.email === fixture.email, 'Current session no longer authenticates the fixture owner');
    assert.deepEqual(current.providers, [], '/me must confirm all three bindings are removed');
    assert.ok((await context.cookies(origin)).some(cookie => cookie.name === 'sessionid' && cookie.value === fixture.session_token), 'Unlink must preserve the existing session cookie');
    const refreshed = await page.goto(`${origin}/account?section=security`);
    assert.equal(refreshed.status(), 200, 'Existing session must still open account SSR');
    await idle();
    assert.equal(await page.locator('#provider-links').isVisible(), false, 'No stored links or enabled providers should remain');
    assert.equal(posts.length, 3, 'Reload must not replay unlink');
    assert.deepEqual(errors, [], 'Browser errors during the live unlink flow');
    console.log('PASS: existing provider links in SSR, cancel without POST, GitHub/Discord/Steam unlink, empty /me bindings and preserved session through Topcoat/Rust API/local YDB; external OAuth login not exercised');
  } finally {
    await browser.close();
  }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
