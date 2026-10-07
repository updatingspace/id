// Verify passkey actions stay in the page instead of opening browser dialogs.
const assert = require('node:assert/strict');
const http = require('node:http');
const path = require('node:path');
const { spawn } = require('node:child_process');
const root = path.resolve(__dirname, '..');
const playwrightPath = process.env.ID_PLAYWRIGHT_MODULE || path.resolve(root, 'browser-tests/node_modules/@playwright/test');
const { chromium } = require(playwrightPath);

async function freePort() {
  const server = http.createServer();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}

async function main() {
  const webPort = await freePort();
  const proxyPort = await freePort();
  const origin = `http://127.0.0.1:${proxyPort}`;
  const binary = path.resolve(process.env.ID_RUST_BIN_DIR || path.join(root, 'target/debug'), 'id-web');
  const web = spawn(binary, [], { env: { ...process.env, HOST: '127.0.0.1', PORT: String(webPort),
    ID_WEB_API_ORIGIN: origin, ID_WEB_ACCOUNT_PILOT_ENABLED: 'true',
    ID_WEB_SECURITY_PILOT_ENABLED: 'true', ID_WEB_PASSKEY_MANAGEMENT_ENABLED: 'true' },
  stdio: ['ignore', 'pipe', 'pipe'] });
  let webLog = '';
  web.stdout.on('data', chunk => { webLog += chunk.toString(); });
  web.stderr.on('data', chunk => { webLog += chunk.toString(); });
  let name = 'Ключ для телефона';
  let deleted = false;
  const calls = [];
  const reply = (response, status, body, headers = {}) => {
    response.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...headers });
    response.end(JSON.stringify(body));
  };
  const proxy = http.createServer(async (request, response) => {
    const pathname = new URL(request.url, origin).pathname;
    if (pathname === '/api/v1/auth/me') {
      reply(response, 200, { user: { username: 'pilot', email: 'pilot@example.invalid',
        email_verified: true, has_2fa: true } },
      { 'Set-Cookie': 'csrftoken=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; Path=/; SameSite=Lax' });
      return;
    }
    if (pathname === '/api/v1/auth/security') {
      reply(response, 200, { mfa: { has_totp: false, has_webauthn: !deleted,
        has_recovery_codes: !deleted, recovery_codes_left: deleted ? 0 : 8 },
      authenticators: deleted ? [] : [{ id: '42', name, type: 'webauthn', created_at: 1,
        last_used_at: null, is_passwordless: true }] });
      return;
    }
    if (pathname === '/api/v1/auth/passkeys/rename' || pathname === '/api/v1/auth/passkeys/delete') {
      assert.equal(request.method, 'POST');
      assert.equal(request.headers['x-csrftoken'], 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
      assert.match(request.headers.cookie || '', /sessionid=synthetic/);
      let raw = '';
      for await (const chunk of request) raw += chunk;
      const payload = JSON.parse(raw);
      calls.push({ pathname, payload });
      if (pathname.endsWith('/rename')) {
        assert.equal(payload.authenticator_id, '42');
        name = payload.new_name;
      } else {
        assert.deepEqual(payload.ids, ['42']);
        deleted = true;
      }
      reply(response, 200, { ok: true });
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
      try { if ((await fetch(`${origin}/_id/passkeys.js`)).ok) break; }
      catch { /* startup */ }
      if (attempt === 39) throw new Error(`id-web did not become ready: ${webLog}`);
      await new Promise(resolve => setTimeout(resolve, 250));
    }
    browser = await chromium.launch({ headless: true,
      ...(process.env.ID_CHROMIUM_PATH ? { executablePath: process.env.ID_CHROMIUM_PATH } : {}) });
    const context = await browser.newContext();
    await context.addCookies([{ name: 'sessionid', value: 'synthetic', url: origin }]);
    let dialogCalls = 0;
    for (const width of [320, 390, 1280]) {
      const page = await context.newPage();
      await page.setViewportSize({ width, height: 820 });
      page.on('dialog', async dialog => { dialogCalls += 1; await dialog.dismiss(); });
      await page.goto(`${origin}/account?section=security`);
      await page.locator('[data-passkey-rename="42"]').click();
      assert.equal(await page.locator('[data-passkey-editor]').isVisible(), true);
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
      await page.locator('[data-passkey-editor] input').press('Escape');
      assert.equal(await page.locator('[data-passkey-editor]').isHidden(), true);
      assert.equal(await page.locator('[data-passkey-rename="42"]').evaluate(node => node === document.activeElement), true);
      await page.locator('[data-passkey-delete="42"]').click();
      assert.equal(await page.locator('[data-passkey-delete-review]').isVisible(), true);
      assert.match(await page.locator('[data-passkey-delete-review]').innerText(), /Ключ для телефона/);
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
      if (width === 390 && process.env.ID_PASSKEY_SCREENSHOT_PATH) {
        await page.screenshot({ path: process.env.ID_PASSKEY_SCREENSHOT_PATH, fullPage: true });
      }
      if (width === 390) {
        await page.emulateMedia({ colorScheme: 'dark' });
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
        if (process.env.ID_PASSKEY_DARK_SCREENSHOT_PATH) {
          await page.screenshot({ path: process.env.ID_PASSKEY_DARK_SCREENSHOT_PATH, fullPage: true });
        }
      }
      await page.locator('[data-passkey-delete-review] [data-passkey-cancel]').click();
      assert.equal(await page.locator('[data-passkey-delete-review]').isHidden(), true);
      assert.equal(await page.locator('[data-passkey-delete="42"]').evaluate(node => node === document.activeElement), true);
      await page.close();
    }
    assert.equal(calls.length, 0, 'cancel sent an API mutation');
    const page = await context.newPage();
    await page.setViewportSize({ width: 390, height: 820 });
    page.on('dialog', async dialog => { dialogCalls += 1; await dialog.dismiss(); });
    await page.goto(`${origin}/account?section=security`);
    await page.locator('[data-passkey-rename="42"]').click();
    await page.locator('[data-passkey-editor] input').fill('Ключ iPhone');
    await page.locator('[data-passkey-rename-save="42"]').click();
    await page.getByText('Ключ iPhone', { exact: true }).waitFor();
    assert.deepEqual(calls[0], { pathname: '/api/v1/auth/passkeys/rename',
      payload: { authenticator_id: '42', new_name: 'Ключ iPhone' } });
    await page.locator('[data-passkey-delete="42"]').click();
    assert.match(await page.locator('[data-passkey-delete-review]').innerText(), /Ключ iPhone/);
    await page.locator('[data-passkey-delete-confirm="42"]').click();
    await page.getByText('Ключей доступа нет.').waitFor();
    assert.deepEqual(calls[1], { pathname: '/api/v1/auth/passkeys/delete', payload: { ids: ['42'] } });
    assert.equal(dialogCalls, 0, 'browser prompt or confirm was opened');
    console.log('PASS: passkey rename/delete use inline review, keyboard cancel and real page reload');
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
