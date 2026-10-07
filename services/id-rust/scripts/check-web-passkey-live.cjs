// Topcoat -> Rust API -> YDB with a synthetic P-256 WebAuthn authenticator.
// The browser API is substituted; this does not validate a physical key.
const assert = require('node:assert/strict');
const fs = require('node:fs');

const base = process.env.ID_LIVE_BASE_URL;
const fixturePath = process.env.ID_PASSKEY_BROWSER_FIXTURE_OUTPUT;
const playwrightPath = process.env.ID_PLAYWRIGHT_MODULE;
if (!base || !fixturePath || !playwrightPath) {
  throw new Error('ID_LIVE_BASE_URL, ID_PASSKEY_BROWSER_FIXTURE_OUTPUT and ID_PLAYWRIGHT_MODULE required');
}
const fixture = JSON.parse(fs.readFileSync(fixturePath, 'utf8'));
const { chromium } = require(playwrightPath);

async function main() {
  const browser = await chromium.launch({ headless: true,
    ...(process.env.ID_CHROMIUM_PATH ? { executablePath: process.env.ID_CHROMIUM_PATH } : {}) });
  try {
    const context = await browser.newContext();
    const page = await context.newPage();
    const failures = [];
    page.on('pageerror', error => failures.push(error.message));
    await page.addInitScript((key) => {
      const from64 = value => Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), char => char.charCodeAt(0));
      const to64 = value => btoa(String.fromCharCode(...value)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
      const derInt = value => {
        let first = 0;
        while (first < value.length - 1 && value[first] === 0) first += 1;
        let bytes = value.slice(first);
        if (bytes[0] & 0x80) bytes = Uint8Array.from([0, ...bytes]);
        return Uint8Array.from([2, bytes.length, ...bytes]);
      };
      window.AuthenticatorAssertionResponse = class AuthenticatorAssertionResponse {
        constructor(clientDataJSON, authenticatorData, signature) {
          this.clientDataJSON = clientDataJSON;
          this.authenticatorData = authenticatorData;
          this.signature = signature;
          this.userHandle = null;
        }
      };
      window.PublicKeyCredential = class PublicKeyCredential {};
      Object.defineProperty(navigator, 'credentials', { configurable: true, value: {
        get: async ({ publicKey }) => {
          const challenge = to64(new Uint8Array(publicKey.challenge));
          const clientDataJSON = new TextEncoder().encode(JSON.stringify({
            type: 'webauthn.get', challenge, origin: key.origin, crossOrigin: false,
          }));
          const rpHash = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(key.rp_id)));
          const authenticatorData = Uint8Array.from([...rpHash, 0x05, 0, 0, 0, 1]);
          const clientHash = new Uint8Array(await crypto.subtle.digest('SHA-256', clientDataJSON));
          const signed = Uint8Array.from([...authenticatorData, ...clientHash]);
          const privateKey = await crypto.subtle.importKey('pkcs8', from64(key.private_key_pkcs8),
            { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
          const rawSignature = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, signed));
          const r = derInt(rawSignature.slice(0, 32));
          const s = derInt(rawSignature.slice(32));
          const signature = Uint8Array.from([0x30, r.length + s.length, ...r, ...s]);
          const rawId = from64(key.credential_id);
          return { id: key.credential_id, rawId: rawId.buffer, type: 'public-key',
            response: new window.AuthenticatorAssertionResponse(clientDataJSON.buffer, authenticatorData.buffer, signature.buffer),
            getClientExtensionResults: () => ({}) };
        },
      } });
    }, fixture);
    const origin = new URL(base).origin;
    await page.goto(`${origin}/login?next=%2F`);
    await page.locator('#passkey-login').waitFor({ state: 'visible' });
    await page.locator('#passkey-login').click();
    try { await page.waitForURL(`${origin}/`, { timeout: 30000 }); }
    catch (error) { throw new Error(`Passkey login failed: ${await page.locator('#error').textContent()} (${error.message})`); }
    // The landing page deliberately has no connect-src; use the browser
    // context's shared cookie jar to verify the authenticated API session.
    const response = await context.request.get(`${origin}/api/v1/auth/me`);
    const me = { status: response.status(), body: await response.json() };
    assert.equal(me.status, 200, JSON.stringify(me.body));
    assert.equal(me.body.user.email, fixture.email);
    const cookies = await context.cookies(origin);
    assert(cookies.some(cookie => cookie.name === 'sessionid' && cookie.httpOnly));
    assert.deepEqual(failures, []);
    console.log('PASS: Topcoat → Rust passkey login → YDB → Rust /me');
  } finally {
    await browser.close();
  }
}

main().catch(error => { console.error(error); process.exitCode = 1; });
