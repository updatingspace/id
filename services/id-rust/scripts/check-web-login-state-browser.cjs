// Exercise native form validation and delayed replies through real Topcoat pages.
// The API is synthetic; credential verification has separate YDB integration tests.
const assert = require('node:assert/strict');
const http = require('node:http');
const path = require('node:path');
const { spawn } = require('node:child_process');
const root = path.resolve(__dirname, '..');
const { chromium } = require(process.env.ID_PLAYWRIGHT_MODULE ||
  path.join(root, 'browser-tests/node_modules/@playwright/test'));

async function freePort() {
  const server = http.createServer();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}

function responseGate() {
  let started;
  let release;
  const received = new Promise(resolve => { started = resolve; });
  const released = new Promise(resolve => { release = resolve; });
  return { received, release, wait: () => { started(); return released; } };
}

async function main() {
  const webPort = await freePort();
  const proxyPort = await freePort();
  const origin = `http://127.0.0.1:${proxyPort}`;
  const binary = path.resolve(process.env.ID_RUST_BIN_DIR || path.join(root, 'target/debug'), 'id-web');
  const web = spawn(binary, [], { env: { ...process.env, HOST: '127.0.0.1', PORT: String(webPort),
    ID_WEB_API_ORIGIN: origin, ID_WEB_LOGIN_PILOT_ENABLED: 'true',
    ID_WEB_ACCOUNT_PILOT_ENABLED: 'true', ID_WEB_SECURITY_PILOT_ENABLED: 'true' },
  stdio: ['ignore', 'pipe', 'pipe'] });
  let webLog = '';
  web.stdout.on('data', chunk => { webLog += chunk.toString(); });
  web.stderr.on('data', chunk => { webLog += chunk.toString(); });
  const loginCalls = [];
  let tokenGate;
  let loginGate;
  const reply = (response, status, body, headers = {}) => {
    response.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...headers });
    response.end(JSON.stringify(body));
  };
  const proxy = http.createServer(async (request, response) => {
    const pathname = new URL(request.url, origin).pathname;
    if (pathname === '/api/v1/auth/me') {
      reply(response, 200, { user: request.headers.cookie?.includes('sessionid=synthetic')
        ? { username: 'pilot', email: 'plain@example.invalid', email_verified: true, has_2fa: false }
        : null });
      return;
    }
    if (pathname === '/api/v1/auth/security') {
      reply(response, 200, { mfa: { has_totp: false, has_webauthn: false,
        has_recovery_codes: false, recovery_codes_left: 0 }, authenticators: [] });
      return;
    }
    if (pathname === '/api/v1/auth/form_token') {
      if (tokenGate) await tokenGate.wait();
      if (!response.destroyed) reply(response, 200, { form_token: 'synthetic-token' },
        { 'Set-Cookie': 'csrftoken=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; Path=/; SameSite=Lax' });
      return;
    }
    if (pathname === '/api/v1/auth/login') {
      let raw = '';
      for await (const chunk of request) raw += chunk;
      const payload = JSON.parse(raw);
      loginCalls.push(payload);
      if (loginGate) await loginGate.wait();
      if (payload.email === 'mfa@example.invalid') {
        reply(response, 401, { code: 'MFA_REQUIRED' });
      } else {
        reply(response, 200, { ok: true },
          { 'Set-Cookie': 'sessionid=synthetic; Path=/; HttpOnly; SameSite=Lax' });
      }
      return;
    }
    const forwarded = http.request({ hostname: '127.0.0.1', port: webPort,
      path: request.url, method: request.method, headers: { ...request.headers, host: `127.0.0.1:${webPort}` } }, upstream => {
      response.writeHead(upstream.statusCode, upstream.headers);
      upstream.pipe(response);
    });
    forwarded.on('error', () => { if (!response.headersSent) response.writeHead(502); response.end(); });
    request.pipe(forwarded);
  });
  await new Promise(resolve => proxy.listen(proxyPort, '127.0.0.1', resolve));
  let browser;
  try {
    for (let attempt = 0; attempt < 40; attempt += 1) {
      if (web.exitCode !== null) throw new Error(`id-web exited: ${webLog}`);
      try { if ((await fetch(`${origin}/login`)).ok) break; } catch { /* startup */ }
      if (attempt === 39) throw new Error(`id-web did not become ready: ${webLog}`);
      await new Promise(resolve => setTimeout(resolve, 250));
    }
    browser = await chromium.launch({ headless: true,
      ...(process.env.ID_CHROMIUM_PATH ? { executablePath: process.env.ID_CHROMIUM_PATH } : {}) });
    const page = await browser.newPage({ viewport: { width: 390, height: 844 } });
    const securityUrl = `${origin}/account?section=security`;
    await page.goto(securityUrl);
    assert.equal(new URL(page.url()).searchParams.get('next'), '/account?section=security');
    await page.locator('#email').fill('mfa@example.invalid');
    await page.locator('#password').fill('SyntheticPass123!');
    await page.locator('#submit').click();
    await page.locator('#mfa-fields').waitFor({ state: 'visible' });
    await page.locator('#mfa-code').fill('123456');
    await page.locator('#email').fill('plain@example.invalid');
    assert.equal(await page.locator('#mfa-fields').isHidden(), true);
    assert.equal(await page.locator('#mfa-code').inputValue(), '');
    assert.equal(await page.locator('#mfa-code').evaluate(input => input.required), false);
    await page.locator('#submit').click();
    await page.waitForURL(securityUrl);
    assert.equal(await page.locator('h1').innerText(), 'Безопасность');
    assert.equal(loginCalls.length, 2);
    assert.equal(loginCalls[1].email, 'plain@example.invalid');
    assert.equal('mfa_code' in loginCalls[1], false);
    assert.equal('recovery_code' in loginCalls[1], false);
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);

    const passwordPage = await browser.newPage();
    await passwordPage.goto(`${origin}/login`);
    await passwordPage.locator('#email').fill('mfa@example.invalid');
    await passwordPage.locator('#password').fill('SyntheticPass123!');
    await passwordPage.locator('#submit').click();
    await passwordPage.locator('#mfa-fields').waitFor({ state: 'visible' });
    await passwordPage.locator('#password').fill('ChangedPass123!');
    assert.equal(await passwordPage.locator('#mfa-fields').isHidden(), true);
    assert.equal(await passwordPage.locator('#login-form').evaluate(form => form.checkValidity()), true);

    // Editing while the token is loading cancels preparation and never sends
    // a password request for the former identity.
    tokenGate = responseGate();
    const callsBeforeToken = loginCalls.length;
    await passwordPage.locator('#submit').click();
    await tokenGate.received;
    await passwordPage.locator('#email').fill('plain@example.invalid');
    assert.equal(await passwordPage.locator('#submit').isEnabled(), true);
    assert.equal(loginCalls.length, callsBeforeToken);
    tokenGate.release();
    tokenGate = null;
    await passwordPage.locator('#submit').click();
    await passwordPage.waitForURL(`${origin}/account`);
    assert.equal(loginCalls.length, callsBeforeToken + 1);
    assert.equal(loginCalls.at(-1).email, 'plain@example.invalid');

    // A login POST is not cancellable in the UI: the server may issue a cookie.
    // Autofill or script-dispatched input must still not apply an old MFA error
    // to changed credentials.
    const delayed = await browser.newPage();
    await delayed.goto(`${origin}/login?next=%2Faccount%3Fsection%3Dsecurity`);
    await delayed.locator('#email').fill('mfa@example.invalid');
    await delayed.locator('#password').fill('SyntheticPass123!');
    loginGate = responseGate();
    await delayed.locator('#submit').click();
    await loginGate.received;
    assert.equal(await delayed.locator('#email').evaluate(input => input.readOnly), true);
    assert.equal(await delayed.locator('#password').evaluate(input => input.readOnly), true);
    await delayed.locator('#email').evaluate(input => {
      input.value = 'plain@example.invalid';
      input.dispatchEvent(new Event('input', { bubbles: true }));
    });
    loginGate.release();
    await delayed.waitForFunction(() => !document.getElementById('submit').disabled);
    assert.equal(await delayed.locator('#mfa-fields').isHidden(), true);
    assert.equal(await delayed.locator('#mfa-code').evaluate(input => input.required), false);
    assert.equal(await delayed.locator('#email').evaluate(input => input.readOnly), false);
    assert.equal(await delayed.locator('#error').isHidden(), true);

    loginGate = responseGate();
    await delayed.locator('#submit').click();
    await loginGate.received;
    await delayed.locator('#email').evaluate(input => {
      input.value = 'edited@example.invalid';
      input.dispatchEvent(new Event('input', { bubbles: true }));
    });
    loginGate.release();
    await delayed.waitForURL(securityUrl);
    assert.equal(await delayed.locator('h1').innerText(), 'Безопасность',
      'a successful submitted login must complete even if a script edited the fields');
    console.log('PASS: account return section; MFA reset; cancelled token preparation; delayed login state and readonly credentials');
  } finally {
    tokenGate?.release();
    loginGate?.release();
    if (browser) await browser.close();
    proxy.closeAllConnections();
    await new Promise(resolve => proxy.close(resolve));
    if (web.exitCode === null) {
      web.kill('SIGTERM');
      await new Promise(resolve => web.once('exit', resolve));
    }
  }
}

main().catch(error => { console.error(error); process.exitCode = 1; });
