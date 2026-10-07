// Browser state regression; Rust/YDB tests own the cryptographic ceremony.
const assert = require('node:assert/strict');
const http = require('node:http');
const path = require('node:path');
const { spawn } = require('node:child_process');
const root = path.resolve(__dirname, '..');
const { chromium } = require(process.env.ID_PLAYWRIGHT_MODULE || path.join(root, 'browser-tests/node_modules/@playwright/test'));

async function port() {
  const server = http.createServer();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const value = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return value;
}

async function main() {
  const webPort = await port();
  const proxyPort = await port();
  const origin = `http://127.0.0.1:${proxyPort}`;
  const codes = Array.from({ length: 10 }, (_, index) => String(10000000 + index));
  let hasTotp = false;
  let recoveryLeft = 0;
  let securityReads = 0;
  let confirmations = 0;
  const reply = (response, status, body) => {
    response.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store',
      'Set-Cookie': 'csrftoken=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; Path=/; SameSite=Lax' });
    response.end(JSON.stringify(body));
  };
  const proxy = http.createServer(async (request, response) => {
    const pathname = new URL(request.url, origin).pathname;
    if (pathname === '/api/v1/auth/me') return reply(response, 200, { user: {
      username: 'synthetic', email: 'synthetic@example.invalid', email_verified: true, has_2fa: hasTotp,
    } });
    if (pathname === '/api/v1/auth/security') {
      securityReads += 1;
      return reply(response, 200, { mfa: { has_totp: hasTotp, has_webauthn: false,
        has_recovery_codes: hasTotp, recovery_codes_left: recoveryLeft }, authenticators: [] });
    }
    if (pathname === '/api/v1/auth/mfa/totp/begin') return reply(response, 200, {
      ok: true, secret: 'SYNTHETIC', svg_data_uri: 'data:image/svg+xml;base64,' +
        Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"/>').toString('base64'),
    });
    if (pathname === '/api/v1/auth/mfa/totp/confirm') {
      assert.equal(request.method, 'POST');
      assert.equal(request.headers['x-csrftoken'], 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
      let raw = '';
      for await (const chunk of request) raw += chunk;
      confirmations += 1;
      if (JSON.parse(raw).code !== '123456') return reply(response, 400, { code: 'INVALID_CODE', message: 'Неверный код.' });
      hasTotp = true;
      recoveryLeft = codes.length;
      return reply(response, 200, { ok: true, recovery_codes: codes });
    }
    if (pathname === '/api/v1/auth/mfa/recovery/regenerate') {
      assert.equal(request.method, 'POST');
      assert.equal(request.headers['x-csrftoken'], 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
      assert.ok(request.headers['idempotency-key']);
      recoveryLeft = codes.length;
      return reply(response, 200, { ok: true, recovery_codes: codes });
    }
    const upstream = http.request({ hostname: '127.0.0.1', port: webPort, path: request.url,
      method: request.method, headers: { ...request.headers, host: `127.0.0.1:${webPort}` } }, incoming => {
      response.writeHead(incoming.statusCode, incoming.headers);
      incoming.pipe(response);
    });
    upstream.on('error', () => { response.writeHead(502); response.end(); });
    request.pipe(upstream);
  });
  await new Promise(resolve => proxy.listen(proxyPort, '127.0.0.1', resolve));
  const web = spawn(path.join(process.env.ID_RUST_BIN_DIR || path.join(root, 'target/debug'), 'id-web'), [], {
    env: { ...process.env, HOST: '127.0.0.1', PORT: String(webPort), ID_WEB_API_ORIGIN: origin,
      ID_WEB_ACCOUNT_PILOT_ENABLED: 'true', ID_WEB_SECURITY_PILOT_ENABLED: 'true', ID_WEB_TOTP_PILOT_ENABLED: 'true' },
    stdio: 'ignore',
  });
  let browser;
  try {
    for (let attempt = 0; attempt < 40; attempt += 1) {
      if (web.exitCode !== null) throw new Error('id-web exited during startup');
      try { if ((await fetch(`${origin}/_id/totp.js`)).ok) break; } catch { /* startup */ }
      if (attempt === 39) throw new Error('id-web did not become ready');
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    browser = await chromium.launch({ headless: true,
      ...(process.env.ID_CHROMIUM_PATH ? { executablePath: process.env.ID_CHROMIUM_PATH } : {}) });
    const page = await browser.newPage({ viewport: { width: 390, height: 844 } });
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    const totpStatus = page.locator('section[aria-labelledby="totp-title"] > p strong');
    const recoveryStatus = page.locator('section[aria-labelledby="recovery-title"] > p strong');
    await page.goto(`${origin}/account?section=security`);
    const initialReads = securityReads;
    assert.equal(await totpStatus.innerText(), 'Не включена');
    await page.locator('#totp-begin').click();
    await page.locator('#totp-pending').waitFor({ state: 'visible' });
    await page.locator('#totp-code').fill('000000');
    await page.locator('#totp-confirm-form button').click();
    await page.locator('#totp-error').waitFor({ state: 'visible' });
    assert.equal(await totpStatus.innerText(), 'Не включена');
    assert.equal(await page.locator('#totp-recovery').isHidden(), true);
    await page.locator('#totp-code').fill('123456');
    await page.locator('#totp-confirm-form button').click();
    await page.locator('#totp-message').waitFor({ state: 'visible' });
    assert.equal(await totpStatus.innerText(), 'Включена', 'successful setup must replace the stale SSR status');
    assert.deepEqual(await recoveryStatus.allTextContents(), ['Есть', '10']);
    assert.deepEqual(await page.locator('#totp-recovery-codes li').allTextContents(), codes);
    assert.equal(await page.locator('#totp-secret').innerText(), '');
    assert.equal(securityReads, initialReads, 'codes must stay visible without an automatic reload');
    assert.equal(confirmations, 2, 'invalid and valid confirmation are each sent only once');
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    let allowRotation = false;
    page.on('dialog', async dialog => {
      if (!(allowRotation && dialog.type() === 'confirm')) errors.push(`Unexpected ${dialog.type()} after acknowledging saved codes`);
      await dialog.accept();
    });
    await page.locator('#totp-recovery-saved').click();
    await page.locator('#totp-disable').waitFor();
    assert.equal(await totpStatus.innerText(), 'Включена');
    assert.equal(await page.locator('#totp-recovery-codes').count(), 0, 'codes are not rendered on the next SSR page');
    recoveryLeft = 3;
    await page.reload();
    assert.equal(await page.locator('#recovery-left').innerText(), '3');
    allowRotation = true;
    await page.locator('#recovery-rotate').click();
    await page.locator('#recovery-rotation-result').waitFor({ state: 'visible' });
    allowRotation = false;
    assert.equal(await page.locator('#recovery-left').innerText(), '10');
    assert.deepEqual(await page.locator('#recovery-rotation-codes li').allTextContents(), codes);
    await page.locator('#recovery-rotation-saved').click();
    await page.locator('#recovery-rotate').waitFor({ state: 'visible' });
    assert.equal(await page.locator('#recovery-rotation-result').isHidden(), true);
    assert.deepEqual(errors, []);
    console.log('PASS: failed/successful TOTP setup, consistent security state, preserved codes and explicit completion');
  } finally {
    if (browser) await browser.close();
    if (web.exitCode === null) { web.kill('SIGTERM'); await new Promise(resolve => web.once('exit', resolve)); }
    proxy.closeAllConnections();
    await new Promise(resolve => proxy.close(resolve));
  }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
