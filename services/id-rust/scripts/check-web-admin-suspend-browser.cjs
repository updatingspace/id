// Browser behavior with a synthetic operator API. Authorization and YDB effects
// are covered by admin_http_ydb; this checks Topcoat layout and request handling.
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
    ID_WEB_ADMIN_ENABLED: 'true', ID_WEB_ADMIN_SUSPEND_ENABLED: 'true', ID_WEB_API_ORIGIN: origin },
  stdio: ['ignore', 'pipe', 'pipe'] });
  let webLog = '';
  web.stdout.on('data', chunk => { webLog += chunk.toString(); });
  web.stderr.on('data', chunk => { webLog += chunk.toString(); });
  let suspended = false;
  const attempts = [];
  const proxy = http.createServer(async (request, response) => {
    const pathname = new URL(request.url, origin).pathname;
    if (pathname.startsWith('/api/v1/auth/admin/')) {
      response.setHeader('content-type', 'application/json');
      response.setHeader('cache-control', 'no-store');
      if (!(request.headers.cookie || '').includes('sessionid=valid')) {
        response.writeHead(401); response.end('{}'); return;
      }
      if (pathname === '/api/v1/auth/admin/me') {
        response.end('{"operator":true}'); return;
      }
      if (pathname === '/api/v1/auth/admin/accounts/43' && request.method === 'GET') {
        response.end(JSON.stringify({ account: { id: 43, email: 'active@example.invalid',
          is_staff: false, is_superuser: false, has_mfa: false,
          identity_id: '00000000-0000-0000-0000-000000000043', public_subject: 'subject-43',
          access_state: suspended ? 'account_disabled' : 'active' } }));
        return;
      }
      if (pathname === '/api/v1/auth/admin/accounts/43/suspend' && request.method === 'POST') {
        let raw = '';
        for await (const chunk of request) raw += chunk;
        const body = JSON.parse(raw);
        attempts.push({ body, csrf: request.headers['x-csrftoken'], cookie: request.headers.cookie });
        if (body.current_password === 'unknown') {
          response.writeHead(503); response.end('{"code":"STATE_UNCERTAIN"}'); return;
        }
        if (body.current_password !== 'correct') {
          response.writeHead(400); response.end('{"code":"INVALID_PASSWORD"}'); return;
        }
        assert.equal(body.expected_subject, 'subject-43');
        suspended = true;
        response.end('{"status":"suspended"}'); return;
      }
      response.writeHead(404); response.end('{}'); return;
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
      try { if ((await fetch(`${origin}/_id/admin-suspend.js`)).ok) break; }
      catch { /* startup */ }
      if (attempt === 39) throw new Error(`id-web did not become ready: ${webLog}`);
      await new Promise(resolve => setTimeout(resolve, 250));
    }
    browser = await chromium.launch({ headless: true,
      ...(process.env.ID_CHROMIUM_PATH ? { executablePath: process.env.ID_CHROMIUM_PATH } : {}) });
    const context = await browser.newContext();
    await context.addCookies([
      { name: 'sessionid', value: 'valid', url: origin },
      { name: 'csrftoken', value: 'abcdefghijklmnopqrstuvwxyzABCDEF', url: origin },
    ]);
    for (const width of [320, 390, 1280]) {
      const page = await context.newPage();
      await page.setViewportSize({ width, height: 820 });
      const html = await page.goto(`${origin}/admin/accounts/suspend?id=43`);
      assert.equal(html.status(), 200);
      assert.equal(html.headers()['cache-control'], 'no-store');
      assert.match(html.headers()['content-security-policy'], /script-src 'self'/);
      const button = page.getByRole('button', { name: 'Заблокировать вход для аккаунта № 43' });
      assert.equal(await button.isVisible(), true);
      await button.focus();
      assert.equal(await button.evaluate(node => node === document.activeElement), true);
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
      if (width === 390 && process.env.ID_ADMIN_SCREENSHOT_PATH) {
        await page.screenshot({ path: process.env.ID_ADMIN_SCREENSHOT_PATH, fullPage: true });
      }
      if (width === 390) {
        await page.emulateMedia({ colorScheme: 'dark' });
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
        if (process.env.ID_ADMIN_DARK_SCREENSHOT_PATH) {
          await page.screenshot({ path: process.env.ID_ADMIN_DARK_SCREENSHOT_PATH, fullPage: true });
        }
        await page.emulateMedia({ colorScheme: 'light' });
      }
      await page.locator('#suspend-reason').selectOption('security_incident');
      await page.locator('#operator-password').fill(width === 320 ? 'wrong' : width === 390 ? 'unknown' : 'correct');
      await button.click();
      await page.locator('#suspend-result:not([hidden])').waitFor();
      assert.equal(await page.locator('#operator-password').inputValue(), '');
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
      if (width === 320) assert.match(await page.locator('#suspend-result').innerText(), /пароль/);
      else if (width === 390) assert.match(await page.locator('#suspend-result').innerText(), /Результат неизвестен/);
      else {
        assert.match(await page.locator('#suspend-result').innerText(), /Вход заблокирован/);
        assert.equal(await page.locator('#suspend-form').isHidden(), true);
      }
      await page.close();
    }
    assert.equal(attempts.length, 3);
    for (const attempt of attempts) {
      assert.equal(attempt.csrf, 'abcdefghijklmnopqrstuvwxyzABCDEF');
      assert.match(attempt.cookie, /sessionid=valid/);
      assert.equal(attempt.body.expected_subject, 'subject-43');
      assert.equal(attempt.body.reason, 'security_incident');
    }
    console.log('Topcoat operator suspension browser: 320/390/1280 layout and request states passed');
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
