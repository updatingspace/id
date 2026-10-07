// Exercise the browser's real WebAuthn implementation through Topcoat and Rust/YDB.
// The DevTools virtual authenticator is local to this disposable Chromium context.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const playwrightPath = process.env.ID_PLAYWRIGHT_MODULE || path.resolve(root, 'browser-tests/node_modules/@playwright/test');
const { chromium } = require(playwrightPath);

async function main() {
  const fixture = JSON.parse(fs.readFileSync(process.env.ID_PASSKEY_BROWSER_FIXTURE_OUTPUT, 'utf8'));
  assert.equal(fixture.synthetic, true);
  const origin = process.env.ID_LIVE_BASE_URL;
  const browser = await chromium.launch({ headless: true,
    ...(process.env.ID_CHROMIUM_PATH ? { executablePath: process.env.ID_CHROMIUM_PATH } : {}) });
  try {
    const context = await browser.newContext();
    await context.addCookies([
      { name: 'sessionid', value: fixture.session_token, url: origin, sameSite: 'Lax' },
      { name: 'csrftoken', value: 'a'.repeat(32), url: origin, sameSite: 'Lax' },
    ]);
    const page = await context.newPage();
    const cdp = await context.newCDPSession(page);
    await cdp.send('WebAuthn.enable');
    await cdp.send('WebAuthn.addVirtualAuthenticator', { options: {
      protocol: 'ctap2', transport: 'internal', hasResidentKey: true,
      hasUserVerification: true, isUserVerified: true,
      automaticPresenceSimulation: true,
    } });
    const ceremony = [];
    page.on('response', async response => {
      if (!/\/api\/v1\/auth\/passkeys\/(begin|complete)$/.test(new URL(response.url()).pathname)) return;
      let code = '';
      if (!response.ok()) {
        try { code = (await response.json()).code || ''; } catch { /* invalid response is reported below */ }
      }
      ceremony.push({ path: new URL(response.url()).pathname, status: response.status(), code });
    });
    await page.goto(`${origin}/account?section=security`);
    assert.equal(await page.locator('#passkey-register').count(), 1,
      `registration form missing at ${page.url()}`);
    await page.locator('#passkey-name').fill('Browser passkey');
    await page.locator('#passkey-register').click();
    await Promise.race([
      page.locator('#passkey-recovery').waitFor({ state: 'visible', timeout: 20000 }),
      page.locator('#passkey-error:not([hidden])').waitFor({ state: 'visible', timeout: 20000 })
        .then(async () => { throw new Error(`registration failed: ${await page.locator('#passkey-error').innerText()}; ${JSON.stringify(ceremony)}`); }),
    ]);
    assert.equal(await page.locator('#passkey-recovery-codes li').count(), 10);
    assert.deepEqual(ceremony.map(step => step.status), [200, 200]);
    console.log('PASS: native Chromium WebAuthn registration through Topcoat, Rust API and YDB');
  } finally {
    await browser.close();
  }
}

main().catch(error => { console.error(error); process.exitCode = 1; });
