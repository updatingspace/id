// Exercise Topcoat's WebAuthn browser bridge with a synthetic assertion and
// same-origin HTTP fixtures. Cryptographic verification is covered separately
// by passkey_login_ydb.rs against real YDB.
const assert = require('node:assert/strict');
const http = require('node:http');
const { spawn } = require('node:child_process');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const playwrightPath = process.env.ID_PLAYWRIGHT_MODULE || path.resolve(root, '../../web/id-frontend/node_modules/@playwright/test');
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
  const binary = path.resolve(process.env.ID_RUST_BIN_DIR || path.join(root, 'target/debug'), 'id-web');
  const web = spawn(binary, [], { env: { ...process.env, HOST: '127.0.0.1', PORT: String(webPort),
    ID_WEB_LOGIN_PILOT_ENABLED: 'true', ID_WEB_PASSKEY_PILOT_ENABLED: 'true' }, stdio: ['ignore', 'pipe', 'pipe'] });
  let webLog = '';
  web.stdout.on('data', chunk => { webLog += chunk.toString(); });
  web.stderr.on('data', chunk => { webLog += chunk.toString(); });
  let begun = 0;
  let completed = 0;
  const proxy = http.createServer(async (request, response) => {
    const pathname = new URL(request.url, `http://${request.headers.host}`).pathname;
    if (pathname === '/api/v1/auth/form_token') {
      reply(response, 200, { form_token: 'synthetic-form-token', expires_in: 300 },
        { 'Set-Cookie': 'csrftoken=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; Path=/; SameSite=Lax' });
      return;
    }
    if (pathname === '/api/v1/auth/passkeys/login/begin') {
      assert.equal(request.method, 'POST');
      assert.equal(request.headers['x-csrftoken'], 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
      assert.match(request.headers.cookie || '', /csrftoken=aaaaaaaa/);
      begun += 1;
      reply(response, 200, { request_options: { publicKey: {
        challenge: Buffer.alloc(32, 7).toString('base64url'), rpId: 'id.example.invalid',
        timeout: 60000, userVerification: 'required', allowCredentials: [],
      } } }, { 'Set-Cookie': 'id_passkey_ceremony=synthetic; Path=/; HttpOnly; SameSite=Lax' });
      return;
    }
    if (pathname === '/api/v1/auth/passkeys/login/complete') {
      assert.equal(request.method, 'POST');
      assert.match(request.headers.cookie || '', /id_passkey_ceremony=synthetic/);
      assert.equal(request.headers['x-csrftoken'], 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
      let raw = '';
      for await (const chunk of request) raw += chunk;
      const credential = JSON.parse(raw).credential;
      assert.equal(credential.rawId, Buffer.from([1, 2, 3]).toString('base64url'));
      assert.equal(credential.response.authenticatorData, Buffer.from([4, 5]).toString('base64url'));
      assert.equal(credential.response.signature, Buffer.from([6, 7]).toString('base64url'));
      assert.equal(credential.response.userHandle, null);
      completed += 1;
      reply(response, 200, { meta: { session_token: 'synthetic-session' } },
        { 'Set-Cookie': 'sessionid=synthetic-session; Path=/; HttpOnly; SameSite=Lax' });
      return;
    }
    if (pathname === '/account') {
      response.writeHead(200, { 'Content-Type': 'text/html' });
      response.end('<!doctype html><html><body><h1>Account fixture</h1></body></html>');
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
    const origin = `http://127.0.0.1:${proxyPort}`;
    for (let attempt = 0; attempt < 40; attempt += 1) {
      if (web.exitCode !== null) throw new Error(`id-web exited: ${webLog}`);
      try {
        const response = await fetch(`${origin}/login`);
        if (response.ok) break;
      } catch { /* startup */ }
      if (attempt === 39) throw new Error(`id-web did not become ready: ${webLog}`);
      await new Promise(resolve => setTimeout(resolve, 250));
    }
    browser = await chromium.launch({ headless: true,
      ...(process.env.ID_CHROMIUM_PATH ? { executablePath: process.env.ID_CHROMIUM_PATH } : {}) });
    const context = await browser.newContext();
    const page = await context.newPage();
    await page.addInitScript(() => {
      window.AuthenticatorAssertionResponse = class AuthenticatorAssertionResponse {
        constructor() {
          this.clientDataJSON = new Uint8Array([8, 9]).buffer;
          this.authenticatorData = new Uint8Array([4, 5]).buffer;
          this.signature = new Uint8Array([6, 7]).buffer;
          this.userHandle = null;
        }
      };
      window.PublicKeyCredential = class PublicKeyCredential {};
      Object.defineProperty(navigator, 'credentials', { configurable: true, value: {
        get: async ({ publicKey }) => {
          if (!(publicKey.challenge instanceof Uint8Array) || publicKey.challenge.length !== 32) {
            throw new Error('WebAuthn challenge was not decoded');
          }
          return { id: 'AQID', rawId: new Uint8Array([1, 2, 3]).buffer, type: 'public-key',
            response: new window.AuthenticatorAssertionResponse(),
            getClientExtensionResults: () => ({}) };
        },
      } });
    });
    await page.goto(`${origin}/login?next=%2Faccount`);
    await page.evaluate(() => sessionStorage.setItem('id_session_token', 'stale-token'));
    await page.locator('#passkey-login').waitFor({ state: 'visible' });
    await page.locator('#passkey-login').click();
    try { await page.waitForURL(`${origin}/account`, { timeout: 15000 }); }
    catch (error) { throw new Error(`Passkey UI failed: ${await page.locator('#error').textContent()} (${error.message})`); }
    assert.equal(begun, 1);
    assert.equal(completed, 1);
    assert.equal(await page.evaluate(() => sessionStorage.getItem('id_session_token')), null);
    const cookies = await context.cookies(origin);
    assert(cookies.some(cookie => cookie.name === 'sessionid' && cookie.httpOnly));
    console.log('PASS: Topcoat passkey browser bridge, CSRF, cookies and redirect');
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
