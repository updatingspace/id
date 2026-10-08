// Real Topcoat pages, synthetic API/provider destinations. No real account linking.
const assert = require('node:assert/strict');
const http = require('node:http');
const path = require('node:path');
const { spawn } = require('node:child_process');
const root = path.resolve(__dirname, '..');
const { chromium } = require(process.env.ID_PLAYWRIGHT_MODULE || path.join(root, 'browser-tests/node_modules/@playwright/test'));
const csrf = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const preview = process.argv.includes('--preview');
const providers = [
  ['github', 'https://github.com/login/oauth/authorize?state=synthetic&code_challenge=synthetic'],
  ['discord', 'https://discord.com/oauth2/authorize?state=synthetic&code_challenge=synthetic'],
  ['steam', 'https://steamcommunity.com/openid/login?openid.mode=checkid_setup&openid.return_to=https%3A%2F%2Fid.example.invalid%2Fcallback%3Fstate%3Dsynthetic'],
];
async function main() {
  const portServer = http.createServer();
  await new Promise(resolve => portServer.listen(0, '127.0.0.1', resolve));
  const webPort = portServer.address().port;
  await new Promise(resolve => portServer.close(resolve));
  let user = { email: 'synthetic@example.invalid', username: 'pilot', oauth_providers: [], has_2fa: true, email_verified: true };
  let browserUser = user;
  let ssrUser = user;
  let capabilityStatus = 200;
  let inventory = providers.map(([id]) => ({ id, ...(preview ? { login_enabled: true } : {}) }));
  let resultStatus = 403, result = { code: 'REAUTH_REQUIRED' };
  let cancelStatus = 200;
  let pauseBegin;
  let unlinkStatus = 200, unlinkResult = { ok: true }, unlinkCommit = true;
  let pauseUnlink;
  let browserReads = 0;
  const writes = [];
  const reply = (res, status, body, headers = {}) => {
    res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', ...headers });
    res.end(JSON.stringify(body));
  };
  const proxy = http.createServer(async (req, res) => {
    const route = new URL(req.url, 'http://localhost').pathname;
    assert.equal(req.headers['x-session-token'], undefined, 'link/reauth never restores a legacy explicit token');
    if (route === '/api/v1/auth/me') {
      const browserRead = Boolean(req.headers['sec-fetch-mode']);
      if (browserRead) browserReads++;
      return reply(res, 200, { user: browserRead ? browserUser : ssrUser });
    }
    if (route === '/api/v1/auth/security') return reply(res, 200, { mfa: { has_totp: true, has_webauthn: false, has_recovery_codes: true, recovery_codes_left: 3 }, authenticators: [] });
    if (route === '/api/v1/auth/oauth/providers') return reply(res, capabilityStatus, { providers: inventory });
    if (route === '/api/v1/auth/form_token') return reply(res, 200, { form_token: 'synthetic-token' }, { 'set-cookie': `csrftoken=${csrf}; Path=/; SameSite=Lax` });
    if (req.method === 'POST' && route.startsWith('/api/')) {
      assert.equal(req.headers['x-csrftoken'], csrf);
      assert.equal(req.headers['content-type'], 'application/json');
      assert.equal(req.headers.origin, origin);
      let raw = ''; for await (const chunk of req) raw += chunk;
      const body = JSON.parse(raw);
      writes.push({ route, body });
      if (route === '/api/v1/auth/login') return reply(res, body.mfa_code ? 200 : 401, body.mfa_code ? { ok: true } : { code: 'MFA_REQUIRED' });
      if (route === '/api/v1/auth/oauth/unlink') {
        assert.deepEqual(Object.keys(body), ['provider']);
        assert.ok(providers.some(([id]) => id === body.provider));
        assert.match(req.headers.cookie || '', /sessionid=synthetic/);
        if (pauseUnlink) await pauseUnlink;
        if (unlinkCommit) browserUser = { ...browserUser, oauth_providers: browserUser.oauth_providers.filter(id => id !== body.provider) };
        if (unlinkStatus === 0) {
          // Lose the response after headers; closing before headers lets Chromium
          // retry a stale pooled connection and obscures the UI double-click check.
          res.writeHead(200, { 'content-type': 'application/json' });
          res.write('{');
          setTimeout(() => res.destroy(), 10);
          return;
        }
        return reply(res, unlinkStatus, unlinkResult);
      }
      assert.deepEqual(body, {}, 'link and cancel carry no client-selected owner, intent, email, next or form token');
      if (route.endsWith('/cancel')) return reply(res, cancelStatus, { ok: cancelStatus === 200 });
      assert.ok(providers.some(([id]) => route === `/api/v1/auth/oauth/link/${id}`));
      if (pauseBegin) await pauseBegin;
      if (resultStatus === 0) { req.socket.destroy(); return; }
      return reply(res, resultStatus, result, { 'Retry-After': '1' });
    }
    if (route.startsWith('/api/')) return reply(res, 404, {});
    const forwarded = http.request({ hostname: '127.0.0.1', port: webPort, path: req.url, method: req.method,
      headers: { ...req.headers, host: `127.0.0.1:${webPort}` } }, response => { res.writeHead(response.statusCode, response.headers); response.pipe(res); });
    forwarded.on('error', () => { if (!res.headersSent) res.writeHead(502); res.end(); });
    req.pipe(forwarded);
  });
  await new Promise(resolve => proxy.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${proxy.address().port}`;
  const web = spawn(path.join(process.env.ID_RUST_BIN_DIR || path.join(root, 'target/debug'), 'id-web'), [], { env: {
    ...process.env, HOST: '127.0.0.1', PORT: String(webPort), ID_WEB_API_ORIGIN: origin,
    ID_WEB_LOGIN_PILOT_ENABLED: 'true', ID_WEB_ACCOUNT_PILOT_ENABLED: 'true', ID_WEB_SECURITY_PILOT_ENABLED: 'true',
  }, stdio: 'ignore' });
  let browser;
  try {
    for (let i = 0; i < 40; i++) { try { if ((await fetch(origin + '/login')).ok) break; } catch {}
      if (i === 39 || web.exitCode !== null) throw new Error('Topcoat startup failed');
      await new Promise(resolve => setTimeout(resolve, 100)); }
    if (preview) {
      console.log(`Synthetic provider-link UI: ${origin}/account?section=security`);
      await new Promise(resolve => { process.once('SIGTERM', resolve); process.once('SIGINT', resolve); });
      return;
    }
    browser = await chromium.launch({ headless: true, ...(process.env.ID_CHROMIUM_PATH ? { executablePath: process.env.ID_CHROMIUM_PATH } : {}) });
    const page = await browser.newPage({ viewport: { width: 390, height: 844 } });
    await page.context().addCookies([{ name: 'sessionid', value: 'synthetic', url: origin }]);
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    const load = async (query = '') => {
      ssrUser = browserUser || user;
      const reads = browserReads;
      await page.goto(`${origin}/account?section=security${query}`);
      await page.locator('#provider-links[aria-busy=false]').waitFor({ state: 'attached' });
      assert.equal(browserReads, reads, 'initial SSR already read the profile; browser must not duplicate it');
    };
    const idle = () => page.locator('#provider-links[aria-busy=false]').waitFor({ state: 'attached' });
    const row = id => page.locator(`[data-link-provider=${id}]`);
    const begin = async id => {
      const details = row(id).locator('[data-link-review]');
      if (!await details.evaluate(element => element.open)) await details.locator('summary').press('Enter');
      await row(id).locator('[data-link-begin]').click();
    };
    await load();
    assert.equal(await page.locator('#provider-links').isVisible(), false, 'inventory is not capability');
    inventory = providers.map(([id]) => ({ id, login_enabled: false }));
    await load();
    assert.equal(await page.locator('#provider-links').isVisible(), false);
    inventory = providers.map(([id]) => ({ id, login_enabled: true }));
    capabilityStatus = 503;
    await load();
    for (const [id] of providers) assert.equal(await row(id).isVisible(), false);
    capabilityStatus = 200;
    browserUser = { ...user, oauth_providers: undefined };
    await load();
    for (const [id] of providers) assert.equal(await row(id).locator('[data-link-review]').isVisible(), false, 'missing read model is not unlinked');
    browserUser = user;
    await load('&provider_linked=github');
    await page.locator('#provider-link-error:visible').waitFor();
    assert.equal(await row('github').locator('[data-link-state]').textContent(), 'Не подключён', 'query cannot prove a link');
    browserUser = { ...user, oauth_providers: ['github'] };
    await load('&provider_linked=github');
    assert.equal(await row('github').locator('[data-link-state]').textContent(), 'Связан');
    assert.equal(await row('github').locator('[data-link-review]').isVisible(), false, 'linked accounts cannot be replaced');
    const noJs = await browser.newContext({ javaScriptEnabled: false });
    const noJsPage = await noJs.newPage();
    await noJsPage.goto(origin + '/account?section=security');
    assert.equal(await noJsPage.locator('#provider-links').isVisible(), true, 'stored links render without JavaScript');
    assert.equal(await noJsPage.locator('#provider-link-account').textContent(), user.email);
    assert.equal(await noJsPage.locator('[data-link-provider=github] [data-link-state]').textContent(), 'Связан');
    assert.equal(await noJsPage.locator('[data-link-provider=github] [data-link-review]').isVisible(), false);
    await noJs.close();
    inventory[0].login_enabled = false;
    await load();
    assert.match(await row('github').locator('[data-link-state]').textContent(), /вход сейчас недоступен/);
    inventory[0].login_enabled = true;
    browserUser = user;
    for (const code of ['PROVIDER_DENIED', 'INVALID_STATE', 'IDENTITY_CONFLICT', 'REAUTH_REQUIRED', 'AUTHENTICATION_REQUIRED', '<img src=x onerror=alert(1)>']) {
      await load('&provider_link_error=' + encodeURIComponent(code));
      assert.equal(await page.locator('#provider-link-error').isVisible(), true);
      assert.equal(await page.locator('#provider-link-error img').count(), 0);
      assert.equal(await page.locator('#provider-link-reauth').isVisible(), ['REAUTH_REQUIRED', 'AUTHENTICATION_REQUIRED'].includes(code));
    }
    browserUser = { ...user, email: 'verylongaccountname'.repeat(10) + '@example.invalid' };
    await load();
    for (const width of [320, 390]) for (const theme of ['light', 'dark']) {
      await page.setViewportSize({ width, height: 844 });
      await page.emulateMedia({ colorScheme: theme });
      await page.evaluate(() => document.documentElement.style.fontSize = '200%');
      for (const [id] of providers) {
        await row(id).locator('[data-link-review] > summary').press('Enter');
        assert.equal(await row(id).locator('[data-link-review]').evaluate(element => element.open), true);
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, `${width}/${theme} overflow`);
      }
    }
    await page.evaluate(() => document.documentElement.style.fontSize = '100%');
    browserUser = null;
    const beforeExpiry = writes.length;
    await begin('github'); await idle();
    assert.equal(writes.length, beforeExpiry, 'expired session cannot begin a link');
    assert.equal(await page.locator('#provider-link-reauth').isVisible(), true);
    browserUser = user;
    await load();
    browserUser = { ...user, email: 'another@example.invalid' };
    const beforeSwitch = writes.length;
    await begin('github'); await idle();
    assert.equal(writes.length, beforeSwitch, 'changed account requires another explicit review');
    assert.equal(await page.locator('#provider-link-account').textContent(), browserUser.email);
    await begin('github'); await idle();
    assert.equal(await page.locator('#provider-link-reauth').isVisible(), true);
    const beforeAuth = writes.length;
    const beforeReads = browserReads;
    await page.addInitScript(() => sessionStorage.setItem('id_session_token', 'synthetic-legacy-token'));
    await page.locator('#provider-link-reauth').click();
    await page.waitForLoadState('networkidle');
    assert.equal(browserReads, beforeReads, 'reauth skips legacy and current-session continuation');
    await page.getByRole('heading', { name: 'Подтвердите личность' }).waitFor();
    assert.equal(await page.locator('#session-choice').isVisible(), false);
    await page.goto(origin + '/login?reauth=provider-link&next=%2Faccount%3Fsection%3Dapps');
    await page.getByRole('heading', { name: 'Подтвердите личность' }).waitFor();
    await page.locator('#email').fill('synthetic@example.invalid');
    await page.locator('#password').fill('SyntheticPass123!');
    await page.locator('#submit').click();
    await page.locator('#mfa-fields:visible').waitFor();
    await page.locator('#mfa-code').fill('123456');
    await page.locator('#submit').click();
    await page.waitForURL(origin + '/account?section=security'); await idle();
    assert.equal(writes.length, beforeAuth + 2, 'password/MFA return does not auto-link');
    browserUser = user;
    await load();
    resultStatus = 429; result = { code: 'LOGIN_RATE_LIMITED' };
    await begin('github'); await idle();
    for (const [id] of providers) assert.equal(await row(id).locator('[data-link-begin]').isEnabled(), false);
    await row('github').locator('[data-link-begin]:enabled').waitFor();
    let release;
    pauseBegin = new Promise(resolve => { release = resolve; });
    resultStatus = 0;
    await begin('github');
    for (const [id] of providers) assert.equal(await row(id).locator('[data-link-begin]').isEnabled(), false, 'no parallel begin');
    release(); pauseBegin = null;
    await idle();
    assert.equal(await page.locator('#provider-link-cancel').isVisible(), true);
    const uncertainWrites = writes.length;
    await page.locator('#provider-link-refresh').click(); await idle();
    assert.equal(writes.length, uncertainWrites, 'checking an unknown result is read-only');
    assert.equal(await row('github').locator('[data-link-begin]').isEnabled(), false, 'read does not replay or clear uncertain mutation');
    cancelStatus = 503;
    await page.locator('#provider-link-cancel').click(); await idle();
    assert.equal(await row('github').locator('[data-link-begin]').isEnabled(), false, 'failed cancel blocks a new mutation');
    cancelStatus = 200;
    await page.locator('#provider-link-cancel').click(); await idle();
    assert.equal(await row('github').locator('[data-link-begin]').isEnabled(), true);
    for (const [id, target] of providers) {
      for (const invalid of ['https://untrusted.example.invalid/', target.replace('?', '/extra?'), target.replace('https:', 'http:'), target.replace('https://', 'https://user@')]) {
        resultStatus = 200; result = { authorize_url: invalid, method: 'GET' };
        await begin(id); await idle();
        assert.equal(new URL(page.url()).origin, origin);
        await page.locator('#provider-link-cancel').click(); await idle();
      }
      result = { authorize_url: target, method: 'POST' };
      await begin(id); await idle();
      assert.equal(new URL(page.url()).origin, origin);
      await page.locator('#provider-link-cancel').click(); await idle();
      await page.route(target, route => route.fulfill({ status: 200, contentType: 'text/html', body: '<h1>Synthetic provider</h1>' }));
      result = { authorize_url: target, method: 'GET' };
      await begin(id); await page.waitForURL(target);
      assert.equal(page.url(), target, 'server query is preserved, including Steam OpenID');
      await load();
    }

    const linked = async (ids = ['github']) => {
      browserUser = { ...user, oauth_providers: ids };
      await load();
    };
    const unlink = id => row(id).locator('[data-unlink-review]');
    const openUnlink = async id => {
      if (!await unlink(id).evaluate(element => element.open)) await unlink(id).locator('summary').press('Enter');
    };
    const confirmUnlink = async id => { await openUnlink(id); await row(id).locator('[data-unlink-confirm]').click(); await idle(); };
    inventory = providers.map(([id]) => ({ id, login_enabled: false }));
    await linked(providers.map(([id]) => id));
    const beforeCancel = writes.length;
    for (const width of [320, 390]) for (const theme of ['light', 'dark']) {
      await page.setViewportSize({ width, height: 844 });
      await page.emulateMedia({ colorScheme: theme });
      await page.evaluate(() => document.documentElement.style.fontSize = '200%');
      for (const [id] of providers) {
        await openUnlink(id);
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, `unlink ${id} ${width}/${theme}`);
        await row(id).locator('[data-unlink-confirm]').press('Escape');
        assert.equal(await unlink(id).evaluate(element => element.open), false);
        assert.equal(await unlink(id).locator('summary').evaluate(element => element === document.activeElement), true);
        await openUnlink(id);
        await row(id).locator('[data-unlink-cancel]').click();
        assert.equal(await unlink(id).evaluate(element => element.open), false);
      }
    }
    assert.equal(writes.length, beforeCancel, 'review/cancel never mutates');
    await page.evaluate(() => document.documentElement.style.fontSize = '100%');
    for (const [id] of providers) {
      await confirmUnlink(id);
      assert.deepEqual(writes.at(-1), { route: '/api/v1/auth/oauth/unlink', body: { provider: id } });
      assert.equal(await row(id).isVisible(), false, 'disabled provider removed only after confirmed API success');
      assert.equal(await page.locator('#provider-link-status').isVisible(), true);
    }
    assert.equal(await page.locator('#provider-links').isVisible(), true, 'receipt remains after the last displayed provider');
    unlinkCommit = false;
    for (const [code, status, text] of [
      ['LAST_LOGIN_METHOD', 409, 'Добавьте другой способ входа'],
      ['IDENTITY_CONFLICT', 409, 'Связь аккаунтов требует проверки'],
      ['REAUTH_REQUIRED', 403, 'Подтвердите личность'],
      ['AUTHENTICATION_REQUIRED', 401, 'Сессия завершена'],
      ['<img src=x onerror=alert(1)>', 409, 'Не удалось проверить связь'],
    ]) {
      await linked();
      unlinkStatus = status; unlinkResult = { code };
      const before = writes.length;
      await confirmUnlink('github');
      assert.equal(writes.length, before + 1);
      assert.ok((await row('github').locator('[data-unlink-error]').textContent()).includes(text));
      assert.equal(await row('github').locator('[data-unlink-error]').evaluate(element => element === document.activeElement), true);
      assert.equal(await row('github').locator('[data-unlink-error] img').count(), 0);
      assert.match(await row('github').locator('[data-link-state]').textContent(), /Связан/);
    }
    await linked();
    unlinkStatus = 403; unlinkResult = { code: 'REAUTH_REQUIRED' };
    await confirmUnlink('github');
    const beforeUnlinkAuth = writes.length;
    const readsBeforeUnlinkAuth = browserReads;
    await row('github').locator('[data-unlink-reauth]').click();
    await page.waitForLoadState('networkidle');
    assert.equal(browserReads, readsBeforeUnlinkAuth, 'unlink reauth does not restore a stale session');
    await page.getByRole('heading', { name: 'Подтвердите личность' }).waitFor();
    await page.locator('#email').fill(user.email);
    await page.locator('#password').fill('SyntheticPass123!');
    await page.locator('#submit').click();
    await page.locator('#mfa-fields:visible').waitFor();
    await page.locator('#mfa-code').fill('123456');
    await page.locator('#submit').click();
    await page.waitForURL(origin + '/account?section=security&review_unlink=github'); await idle();
    assert.equal(await unlink('github').evaluate(element => element.open), true);
    assert.equal(writes.length, beforeUnlinkAuth + 2, 'reauth and its return never auto-unlink');

    for (const change of [null, { ...user, email: 'other@example.invalid', oauth_providers: ['github'] }]) {
      await linked();
      browserUser = change;
      const before = writes.length;
      await confirmUnlink('github');
      assert.equal(writes.length, before, 'expired/changed account requires new authentication/review');
      assert.equal(await row('github').locator('[data-unlink-error]').isVisible(), true);
    }
    // A lost response blocks every provider mutation. Checking is read-only,
    // and a still-present binding cannot prove that an in-flight commit failed.
    inventory[2].login_enabled = true;
    await linked(['github', 'discord']);
    unlinkStatus = 0; unlinkCommit = false;
    const beforeUncertainUnlink = writes.length;
    let releaseUnlink;
    pauseUnlink = new Promise(resolve => { releaseUnlink = resolve; });
    await openUnlink('github');
    await row('github').locator('[data-unlink-confirm]').click();
    await row('github').locator('[data-unlink-confirm]').evaluate(element => element.click());
    assert.equal(await row('github').locator('[data-unlink-cancel]').isEnabled(), false);
    assert.equal(await row('discord').locator('[data-unlink-confirm]').isEnabled(), false);
    assert.equal(await row('steam').locator('[data-link-begin]').isEnabled(), false);
    releaseUnlink(); pauseUnlink = null; await idle();
    assert.equal(writes.length, beforeUncertainUnlink + 1, 'double click must submit once');
    const uncertainUnlinkWrites = writes.length;
    await row('github').locator('[data-unlink-refresh]').click(); await idle();
    assert.equal(writes.length, uncertainUnlinkWrites);
    assert.equal(await row('github').locator('[data-unlink-confirm]').isEnabled(), false);
    assert.equal(await row('steam').locator('[data-link-begin]').isEnabled(), false);
    assert.equal(await row('github').locator('[data-unlink-error]').isVisible(), true);
    browserUser = { ...user, email: 'other@example.invalid', oauth_providers: [] };
    await row('github').locator('[data-unlink-refresh]').click(); await idle();
    assert.equal(writes.length, uncertainUnlinkWrites);
    assert.match(await row('github').locator('[data-unlink-error]').textContent(), /аккаунт изменился/);
    assert.equal(await page.locator('#provider-link-status').isVisible(), false, 'another account without this link is not proof of removal');
    browserUser = { ...user, oauth_providers: undefined };
    await row('github').locator('[data-unlink-refresh]').click(); await idle();
    assert.equal(writes.length, uncertainUnlinkWrites);
    assert.equal(await row('github').locator('[data-unlink-error]').isVisible(), true, 'read failure keeps recovery available');
    browserUser = { ...user, oauth_providers: [] }; // A later authoritative read confirms removal.
    await row('github').locator('[data-unlink-refresh]').click(); await idle();
    assert.equal(writes.length, uncertainUnlinkWrites);
    assert.equal(await row('github').isVisible(), false);
    for (const [status, body] of [[503, { code: 'SERVICE_UNAVAILABLE' }], [200, {}]]) {
      await linked(); unlinkStatus = status; unlinkResult = body;
      await confirmUnlink('github');
      assert.equal(await row('github').locator('[data-unlink-confirm]').isEnabled(), false, 'unknown results cannot be retried');
    }
    await linked(); unlinkStatus = 404; unlinkResult = { code: 'NOT_FOUND' }; unlinkCommit = true;
    const beforeNotFoundRead = browserReads;
    await confirmUnlink('github');
    assert.equal(browserReads, beforeNotFoundRead + 2, '404 requires a fresh authoritative binding read');
    assert.equal(await row('github').isVisible(), false);
    await linked(); unlinkCommit = false;
    await confirmUnlink('github');
    assert.equal(await row('github').locator('[data-unlink-confirm]').isEnabled(), false, '404 with a still-present binding is not confirmed removal');
    assert.deepEqual(errors, []);
    console.log('PASS provider link/unlink: gates, CSRF, reauth/MFA, account switch, confirmation/cancel, last-method/conflict errors, unknown result/read-only recovery, keyboard and mobile themes');
  } finally {
    if (browser) await browser.close();
    web.kill('SIGTERM');
    await new Promise(resolve => proxy.close(resolve));
  }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
