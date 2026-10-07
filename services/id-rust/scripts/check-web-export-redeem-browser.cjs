// Browser contract for the public export link; the API response is synthetic.
// The cryptographic capability, deletion and 24-hour boundary use local-YDB tests.
const assert = require('node:assert/strict');
const http = require('node:http');
const path = require('node:path');
const fs = require('node:fs/promises');
const { spawn } = require('node:child_process');

const root = path.resolve(__dirname, '..');
const playwrightPath = process.env.ID_PLAYWRIGHT_MODULE || path.resolve(root, 'browser-tests/node_modules/@playwright/test');
const { chromium } = require(playwrightPath);
const operation = '0123456789abcdef0123456789abcdef';
const validToken = Buffer.alloc(32, 0x42).toString('base64url');
const invalidToken = Buffer.alloc(32, 0x43).toString('base64url');
const cancelToken = Buffer.alloc(32, 0x44).toString('base64url');

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
    ID_WEB_EXPORT_REDEEM_PILOT_ENABLED: 'true', ID_WEB_ACCOUNT_PILOT_ENABLED: 'true',
    ID_WEB_EXPORTS_ENABLED: 'true', ID_WEB_API_ORIGIN: origin }, stdio: ['ignore', 'pipe', 'pipe'] });
  let webLog = '';
  web.stdout.on('data', chunk => { webLog += chunk.toString(); });
  web.stderr.on('data', chunk => { webLog += chunk.toString(); });
  const requests = [];
  const redemptions = [];
  const cancellations = [];
  const ownerRequests = [];
  const ownerCancellations = [];
  const proxy = http.createServer(async (request, response) => {
    requests.push({ url: request.url, referer: request.headers.referer || '' });
    const pathname = new URL(request.url, origin).pathname;
    if (pathname === '/api/v1/auth/me') {
      response.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
      response.end(JSON.stringify({ user: request.headers.cookie?.includes('sessionid=owner') ? {
        username: 'owner', email: 'owner@example.invalid', email_verified: true, has_2fa: true,
      } : null }));
      return;
    }
    if (pathname === '/api/v1/auth/data/exports' && request.method === 'POST') {
      let raw = '';
      for await (const chunk of request) raw += chunk;
      ownerRequests.push({ cookie: request.headers.cookie || '', csrf: request.headers['x-csrftoken'],
        idempotency: request.headers['idempotency-key'], body: JSON.parse(raw) });
      response.writeHead(202, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
      response.end(JSON.stringify({ id: operation, status: 'pending_delayed' }));
      return;
    }
    if (pathname === `/api/v1/auth/data/exports/${operation}` && request.method === 'GET') {
      response.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
      response.end(JSON.stringify({ id: operation, status: 'cooldown', release_at: '2026-10-08T12:00:00Z',
        expires_at: null, manifest: { format: 'updspace-id-ndjson-v1', consistency: 'snapshot',
          categories: [{ category: 'profile', records: 1 }], excluded: [] } }));
      return;
    }
    if (pathname === `/api/v1/auth/data/exports/${operation}` && request.method === 'DELETE') {
      ownerCancellations.push({ cookie: request.headers.cookie || '', csrf: request.headers['x-csrftoken'] });
      response.writeHead(202, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
      response.end(JSON.stringify({ status: 'cancelled' }));
      return;
    }
    if (pathname === `/api/v1/auth/data/exports/${operation}/redeem`) {
      let raw = '';
      for await (const chunk of request) raw += chunk;
      let body;
      try { body = JSON.parse(raw); } catch { body = null; }
      redemptions.push({ method: request.method, cookie: request.headers.cookie || '', body });
      response.setHeader('content-type', 'application/json');
      response.setHeader('cache-control', 'no-store');
      if (body?.token === validToken) {
        response.end(JSON.stringify({ download_url: `${origin}/archive/${operation}`, expires_in_seconds: 60 }));
      } else {
        response.writeHead(404);
        response.end(JSON.stringify({ code: 'NOT_FOUND' }));
      }
      return;
    }
    if (pathname === `/api/v1/auth/data/exports/${operation}/cancel`) {
      let raw = '';
      for await (const chunk of request) raw += chunk;
      let body;
      try { body = JSON.parse(raw); } catch { body = null; }
      cancellations.push({ method: request.method, cookie: request.headers.cookie || '', body });
      response.setHeader('content-type', 'application/json');
      response.setHeader('cache-control', 'no-store');
      if (body?.token === cancelToken) {
        response.writeHead(202);
        response.end(JSON.stringify({ status: 'cancelled', cleanup_pending: false }));
      } else {
        response.writeHead(404);
        response.end(JSON.stringify({ code: 'NOT_FOUND' }));
      }
      return;
    }
    if (pathname === `/archive/${operation}`) {
      response.writeHead(200, { 'Content-Type': 'application/x-ndjson',
        'Content-Disposition': 'attachment; filename="account-export.ndjson"',
        'Cache-Control': 'no-store' });
      response.end('{"synthetic":true}\n');
      return;
    }
    const forwarded = http.request({ hostname: '127.0.0.1', port: webPort, path: request.url,
      method: request.method, headers: { ...request.headers, host: `127.0.0.1:${webPort}` } }, upstream => {
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
      try { if ((await fetch(`${origin}/_id/export-redeem.js`)).ok) break; }
      catch { /* startup */ }
      if (attempt === 39) throw new Error(`id-web did not become ready: ${webLog}`);
      await new Promise(resolve => setTimeout(resolve, 250));
    }
    browser = await chromium.launch({ headless: true,
      ...(process.env.ID_CHROMIUM_PATH ? { executablePath: process.env.ID_CHROMIUM_PATH } : {}) });
    const ownerContext = await browser.newContext({ viewport: { width: 390, height: 844 } });
    await ownerContext.addCookies([
      { name: 'sessionid', value: 'owner', url: origin },
      { name: 'csrftoken', value: 'a'.repeat(32), url: origin },
    ]);
    const owner = await ownerContext.newPage();
    const ownerHtml = await owner.goto(`${origin}/account?section=data`);
    assert.equal(ownerHtml.status(), 200);
    assert.match(await owner.locator('main').innerText(), /Подождите 24 часа/);
    await owner.getByText('Отмена запроса и удаление аккаунта', { exact: true }).click();
    assert.match(await owner.locator('main').innerText(), /Ссылка отмены из первого письма работает и после удаления аккаунта/);
    assert.equal(await owner.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true,
      'export request page overflows a phone viewport');
    await owner.locator('#export-password').fill('synthetic-password');
    await owner.locator('#export-mfa').fill('123456');
    await owner.locator('#export-form button[type="submit"]').click();
    await owner.waitForURL(`${origin}/account?section=data&export=${operation}`);
    assert.equal(ownerRequests.length, 1);
    assert.equal(ownerRequests[0].csrf, 'a'.repeat(32));
    assert.match(ownerRequests[0].cookie, /sessionid=owner/);
    assert.match(ownerRequests[0].idempotency, /^[0-9a-f-]{36}$/);
    assert.deepEqual(ownerRequests[0].body, { password: 'synthetic-password', mfa_code: '123456' });
    assert.match(await owner.locator('main').innerText(), /Копия подготовлена и хранится приватно/);
    assert.equal(await owner.locator('a[href$="/download"]').count(), 0);
    await owner.locator('#export-cancel-start').click();
    assert.equal(await owner.locator('#export-cancel-confirm').isVisible(), true);
    await owner.locator('#export-cancel-keep').click();
    assert.equal(ownerCancellations.length, 0);
    await owner.locator('#export-cancel-start').click();
    await owner.locator('#export-cancel-confirm').click();
    await owner.getByRole('heading', { name: 'Запрос отозван' }).waitFor();
    assert.deepEqual(ownerCancellations, [{ cookie: 'sessionid=owner; csrftoken=' + 'a'.repeat(32),
      csrf: 'a'.repeat(32) }]);
    await ownerContext.close();
    const context = await browser.newContext({ acceptDownloads: true });
    await context.addCookies([{ name: 'sessionid', value: 'deleted-account', url: origin }]);
    const page = await context.newPage();
    const html = await page.goto(`${origin}/data/export?id=${operation}#${validToken}`);
    assert.equal(html.status(), 200);
    assert.equal(html.headers()['cache-control'], 'no-store');
    assert.equal(html.headers()['referrer-policy'], 'no-referrer');
    assert.equal(page.url(), `${origin}/data/export?id=${operation}`);
    assert.equal(await page.locator('#export-download').isEnabled(), true);
    const downloadEvent = page.waitForEvent('download');
    await page.locator('#export-download').click();
    const download = await downloadEvent;
    assert.equal(download.suggestedFilename(), 'account-export.ndjson');
    assert.equal(await fs.readFile(await download.path(), 'utf8'), '{"synthetic":true}\n');
    assert.equal(redemptions.length, 1);
    assert.deepEqual(redemptions[0], { method: 'POST', cookie: '', body: { token: validToken } });

    const expired = await context.newPage();
    await expired.goto(`${origin}/data/export?id=${operation}#${invalidToken}`);
    assert.equal(expired.url(), `${origin}/data/export?id=${operation}`);
    await expired.locator('#export-download').click();
    await expired.locator('#export-error:not([hidden])').waitFor();
    assert.match(await expired.locator('#export-error').innerText(), /недействительна|истёк/);
    assert.equal(await expired.locator('#export-download').isEnabled(), true);
    assert.equal(redemptions.length, 2);
    assert.deepEqual(redemptions[1], { method: 'POST', cookie: '', body: { token: invalidToken } });

    const incomplete = await context.newPage();
    await incomplete.goto(`${origin}/data/export?id=${operation}#short`);
    assert.equal(await incomplete.locator('#export-download').isDisabled(), true);
    assert.equal(redemptions.length, 2);
    const cancel = await context.newPage();
    const cancelHtml = await cancel.goto(`${origin}/data/export/cancel?id=${operation}#${cancelToken}`);
    assert.equal(cancelHtml.status(), 200);
    assert.equal(cancelHtml.headers()['cache-control'], 'no-store');
    assert.equal(cancelHtml.headers()['referrer-policy'], 'no-referrer');
    assert.equal(cancel.url(), `${origin}/data/export/cancel?id=${operation}`);
    await cancel.locator('#export-cancel').click();
    await cancel.waitForFunction(() => document.getElementById('export-status')?.textContent.includes('отменён'));
    assert.match(await cancel.locator('#export-status').innerText(), /отменён/);
    assert.deepEqual(cancellations[0], { method: 'POST', cookie: '', body: { token: cancelToken } });
    const wrongCancel = await context.newPage();
    await wrongCancel.goto(`${origin}/data/export/cancel?id=${operation}#${validToken}`);
    await wrongCancel.locator('#export-cancel').click();
    await wrongCancel.locator('#export-error:not([hidden])').waitFor();
    assert.deepEqual(cancellations[1], { method: 'POST', cookie: '', body: { token: validToken } });
    const incompleteCancel = await context.newPage();
    await incompleteCancel.goto(`${origin}/data/export/cancel?id=${operation}#short`);
    assert.equal(await incompleteCancel.locator('#export-cancel').isDisabled(), true);
    assert.equal(cancellations.length, 2);
    const mobile = await browser.newContext({ viewport: { width: 390, height: 844 } });
    const mobileCancel = await mobile.newPage();
    await mobileCancel.goto(`${origin}/data/export/cancel?id=${operation}#${cancelToken}`);
    assert.equal(await mobileCancel.locator('#export-cancel').isVisible(), true);
    assert.equal(await mobileCancel.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true,
      'cancellation page overflows a phone viewport');
    await mobile.close();
    assert.equal(requests.filter(request => request.url.startsWith('/archive/')).length, 1);
    for (const request of requests) {
      assert.equal([validToken, invalidToken, cancelToken].some(token => request.url.includes(token)), false);
      assert.equal([validToken, invalidToken, cancelToken].some(token => request.referer.includes(token)), false);
    }
    console.log('PASS: Topcoat export request, cooldown, owner cancellation and post-deletion bearer links');
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
