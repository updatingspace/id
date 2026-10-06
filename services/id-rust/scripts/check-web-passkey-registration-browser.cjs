// Test the Topcoat registration bridge with a synthetic authenticator. The
// cryptographic ceremony and YDB transaction have separate Rust tests.
const assert = require('node:assert/strict');
const http = require('node:http');
const { spawn } = require('node:child_process');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const playwrightPath = process.env.ID_PLAYWRIGHT_MODULE || path.resolve(root, 'browser-tests/node_modules/@playwright/test');
const { chromium } = require(playwrightPath);

async function port() {
  const server = http.createServer();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const value = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return value;
}

function reply(response, status, body, headers = {}) {
  response.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...headers });
  response.end(JSON.stringify(body));
}

async function main() {
  const webPort = await port();
  const proxyPort = await port();
  const origin = `http://127.0.0.1:${proxyPort}`;
  const binary = path.resolve(process.env.ID_RUST_BIN_DIR || path.join(root, 'target/debug'), 'id-web');
  const web = spawn(binary, [], { env: { ...process.env, HOST: '127.0.0.1', PORT: String(webPort),
    ID_WEB_API_ORIGIN: origin, ID_WEB_ACCOUNT_PILOT_ENABLED: 'true',
    ID_WEB_SECURITY_PILOT_ENABLED: 'true', ID_WEB_PASSKEY_REGISTRATION_ENABLED: 'true',
    ID_WEB_PASSKEY_MANAGEMENT_ENABLED: 'false' }, stdio: ['ignore', 'pipe', 'pipe'] });
  let webLog = '';
  web.stdout.on('data', chunk => { webLog += chunk.toString(); });
  web.stderr.on('data', chunk => { webLog += chunk.toString(); });
  let begun = 0;
  let completed = 0;
  const proxy = http.createServer(async (request, response) => {
    const pathname = new URL(request.url, origin).pathname;
    if (pathname === '/api/v1/auth/me') {
      reply(response, 200, { user: { username: 'pilot', email: 'pilot@example.invalid',
        email_verified: true, has_2fa: false } },
        { 'Set-Cookie': 'csrftoken=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; Path=/; SameSite=Lax' });
      return;
    }
    if (pathname === '/api/v1/auth/security') {
      reply(response, 200, { mfa: { has_totp: false, has_webauthn: false,
        has_recovery_codes: false, recovery_codes_left: 0 }, authenticators: [] });
      return;
    }
    if (pathname === '/api/v1/auth/passkeys/begin' || pathname === '/api/v1/auth/passkeys/complete') {
      assert.equal(request.method, 'POST');
      assert.equal(request.headers['x-csrftoken'], 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
      assert.match(request.headers.cookie || '', /sessionid=synthetic/);
      let raw = '';
      for await (const chunk of request) raw += chunk;
      const payload = JSON.parse(raw);
      if (pathname.endsWith('/begin')) {
        begun += 1;
        assert.deepEqual(payload, { passwordless: true });
        reply(response, 200, { creation_options: { publicKey: {
          challenge: Buffer.alloc(32, 7).toString('base64url'),
          rp: { id: 'localhost', name: 'UpdSpace ID' },
          user: { id: Buffer.from([1, 2, 3]).toString('base64url'), name: 'pilot', displayName: 'pilot' },
          pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
          excludeCredentials: [{ type: 'public-key', id: Buffer.from([4, 5]).toString('base64url') }],
        } } });
      } else {
        completed += 1;
        assert.equal(payload.name, 'My passkey');
        assert.equal(payload.credential.rawId, Buffer.from([8, 9]).toString('base64url'));
        assert.equal(payload.credential.response.attestationObject, Buffer.from([10, 11]).toString('base64url'));
        assert.equal(payload.credential.response.clientDataJSON, Buffer.from([12, 13]).toString('base64url'));
        reply(response, 200, { recovery_codes: ['12345678', '87654321'], authenticator: { id: '42' } });
      }
      return;
    }
    const forwarded = http.request({ hostname: '127.0.0.1', port: webPort, path: request.url,
      method: request.method, headers: { ...request.headers, host: `127.0.0.1:${webPort}` } }, upstream => {
      response.writeHead(upstream.statusCode, upstream.headers);
      upstream.pipe(response);
    });
    forwarded.on('error', error => { response.writeHead(502); response.end(error.message); });
    request.pipe(forwarded);
  });
  await new Promise(resolve => proxy.listen(proxyPort, '127.0.0.1', resolve));
  let browser;
  try {
    for (let attempt = 0; attempt < 40; attempt += 1) {
      if (web.exitCode !== null) throw new Error(`id-web exited: ${webLog}`);
      try { if ((await fetch(`${origin}/_id/passkeys.js`)).ok) break; }
      catch { /* startup */ }
      if (attempt === 39) throw new Error(`id-web did not become ready: ${webLog}`);
      await new Promise(resolve => setTimeout(resolve, 250));
    }
    browser = await chromium.launch({ headless: true,
      ...(process.env.ID_CHROMIUM_PATH ? { executablePath: process.env.ID_CHROMIUM_PATH } : {}) });
    const context = await browser.newContext();
    await context.addCookies([{ name: 'sessionid', value: 'synthetic', url: origin }]);
    const page = await context.newPage();
    await page.addInitScript(() => {
      window.PublicKeyCredential = class PublicKeyCredential {};
      Object.defineProperty(navigator, 'credentials', { configurable: true, value: {
        create: async ({ publicKey }) => {
          if (!(publicKey.challenge instanceof Uint8Array) || publicKey.challenge.length !== 32 ||
              !(publicKey.user.id instanceof Uint8Array) || publicKey.user.id.length !== 3 ||
              !(publicKey.excludeCredentials[0].id instanceof Uint8Array)) {
            throw new Error('WebAuthn creation options were not decoded');
          }
          return { id: 'CAk', rawId: new Uint8Array([8, 9]).buffer, type: 'public-key',
            response: { attestationObject: new Uint8Array([10, 11]).buffer,
              clientDataJSON: new Uint8Array([12, 13]).buffer, getTransports: () => ['internal'] },
            getClientExtensionResults: () => ({}) };
        },
      } });
    });
    await page.goto(`${origin}/account?section=security`);
    if (await page.locator('#passkey-register').count() === 0) {
      throw new Error(`Registration form missing at ${page.url()}: ${(await page.locator('body').innerText()).slice(0, 600)}; web: ${webLog.slice(-600)}`);
    }
    assert.equal(await page.locator('text=Ключей доступа нет.').count(), 1);
    await page.locator('#passkey-name').fill('My passkey');
    await page.locator('#passkey-register').click();
    await page.locator('#passkey-recovery').waitFor({ state: 'visible' });
    assert.deepEqual(await page.locator('#passkey-recovery-codes li').allTextContents(), ['12345678', '87654321']);
    assert.equal(begun, 1);
    assert.equal(completed, 1);
    assert.equal(await page.locator('#passkey-register').isHidden(), true);
    console.log('PASS: Topcoat passkey registration bridge, CSRF and one-time recovery codes');
  } finally {
    if (browser) await browser.close();
    await new Promise(resolve => proxy.close(resolve));
    if (web.exitCode === null) {
      web.kill('SIGTERM');
      await new Promise(resolve => web.once('exit', resolve));
    }
  }
}

main().catch(error => { console.error(error); process.exitCode = 1; });
