// Real Topcoat UI with a synthetic API. This does not validate GitHub/Discord OAuth,
// Steam OpenID 2.0, provider cookies or credentials; those need separate live checks.
const assert = require('node:assert/strict');
const http = require('node:http');
const path = require('node:path');
const { spawn } = require('node:child_process');
const root = path.resolve(__dirname, '..');
const { chromium } = require(process.env.ID_PLAYWRIGHT_MODULE || path.join(root, 'browser-tests/node_modules/@playwright/test'));
const csrf = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
async function freePort() {
  const server = http.createServer();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}
function gate() {
  let start, release;
  const received = new Promise(resolve => { start = resolve; });
  const released = new Promise(resolve => { release = resolve; });
  return { received, release, wait: () => { start(); return released; } };
}
async function main(provider, otherProvider) {
  const loginPath = `/api/v1/auth/oauth/login/${provider.id}`;
  const button = `#${provider.id}-login`;
  const otherButton = `#${otherProvider.id}-login`;
  const otherProviders = providers.filter(item => item !== provider);
  const otherLoginPath = `/api/v1/auth/oauth/login/${otherProvider.id}`;
  const authorizeTarget = `${provider.authorizeUrl}?${provider.query || 'client_id=synthetic&state=synthetic'}`;
  const otherTarget = `${otherProvider.authorizeUrl}?${otherProvider.query || 'client_id=synthetic&state=synthetic'}`;
  const webPort = await freePort();
  let inventory = { providers: [{ id: provider.id, name: provider.name }, ...otherProviders.map(item => ({ id: item.id, login_enabled: true }))] };
  let inventoryStatus = 200;
  let authenticated = false;
  let pending = { active: true, expires_at: Math.floor(Date.now() / 1000) + 300, methods: ['totp', 'recovery_codes'], restart_required: false, next: '/account?section=security' };
  let pendingStatus = 200;
  let completeStatus = 401;
  let completeBody = { code: 'INVALID_MFA' };
  let cancelStatus = 200;
  let beginStatus = 200;
  let authorizeUrl = authorizeTarget;
  let authorizeMethod = 'GET';
  let beginGate, cancelGate, meGate;
  let meCalls = 0, pendingCalls = 0;
  const writes = [];
  const reply = (res, status, body, headers = {}) => {
    res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', ...headers });
    res.end(JSON.stringify(body));
  };
  const proxy = http.createServer(async (req, res) => {
    const route = new URL(req.url, 'http://localhost').pathname;
    if (route === '/api/v1/auth/oauth/providers') return reply(res, inventoryStatus, inventory);
    if (route === '/api/v1/auth/me') {
      meCalls++;
      if (meGate) await meGate.wait();
      return reply(res, 200, { user: authenticated ? { email: 'synthetic@example.invalid', username: 'pilot', has_2fa: true, email_verified: true } : null });
    }
    if (route === '/api/v1/auth/security') return reply(res, 200, { mfa: { has_totp: true, has_webauthn: false, has_recovery_codes: true, recovery_codes_left: 3 }, authenticators: [] });
    if (route === '/api/v1/auth/form_token') return reply(res, 200, { form_token: 'synthetic-form-token' }, { 'set-cookie': `csrftoken=${csrf}; Path=/; SameSite=Lax` });
    if (route === loginPath + '/pending') {
      pendingCalls++;
      assert.equal(req.method, 'GET');
      assert.equal(req.headers['x-session-token'], undefined);
      return reply(res, pendingStatus, pending);
    }
    if (route.startsWith(loginPath) || route === otherLoginPath) {
      assert.equal(req.method, 'POST');
      assert.equal(req.headers['x-csrftoken'], csrf);
      assert.equal(req.headers.origin, origin);
      let raw = ''; for await (const chunk of req) raw += chunk;
      const body = JSON.parse(raw);
      writes.push({ route, body });
      if (route.endsWith('/complete')) {
        assert.equal(req.headers.cookie?.includes('provider_fixture=opaque'), true);
        if (completeStatus === 0) { req.socket.destroy(); return; }
        if (completeStatus === 200) authenticated = true;
        return reply(res, completeStatus, completeBody, { 'Retry-After': '1' });
      }
      if (route.endsWith('/cancel')) {
        assert.deepEqual(body, {});
        if (cancelGate) await cancelGate.wait();
        return reply(res, cancelStatus, cancelStatus === 200 ? { ok: true } : { code: 'SERVICE_UNAVAILABLE' });
      }
      assert.deepEqual(Object.keys(body).sort(), ['form_token', 'next']);
      assert.equal(body.form_token, 'synthetic-form-token');
      if (route === otherLoginPath) return reply(res, 200, { authorize_url: otherTarget, method: 'GET' });
      if (beginGate) await beginGate.wait();
      return reply(res, beginStatus, beginStatus === 400 ? { code: 'INVALID_REDIRECT' } : { authorize_url: authorizeUrl, method: authorizeMethod }, { 'Retry-After': '1' });
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
    ID_WEB_LOGIN_PILOT_ENABLED: 'true', ID_WEB_ACCOUNT_PILOT_ENABLED: 'true',
    ID_WEB_SECURITY_PILOT_ENABLED: 'true', ID_WEB_PASSKEY_PILOT_ENABLED: 'true',
  }, stdio: 'ignore' });
  let browser;
  try {
    for (let i = 0; i < 40; i++) { try { if ((await fetch(origin + '/login')).ok) break; } catch {}
      if (i === 39 || web.exitCode !== null) throw new Error('Topcoat startup failed');
      await new Promise(resolve => setTimeout(resolve, 100)); }
    browser = await chromium.launch({ headless: true, ...(process.env.ID_CHROMIUM_PATH ? { executablePath: process.env.ID_CHROMIUM_PATH } : {}) });
    const context = await browser.newContext({ viewport: { width: 390, height: 844 } });
    await context.addCookies([{ name: 'provider_fixture', value: 'opaque', url: origin, httpOnly: true }]);
    const page = await context.newPage();
    await page.clock.install();
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    const ordinary = async () => {
      await page.goto(origin + '/login?next=%2Faccount%3Fsection%3Dsecurity');
      await page.waitForLoadState('networkidle');
    };
    const mfa = async () => {
      await page.goto(`${origin}/login?provider_mfa=${provider.id}&next=%2Faccount%3Fsection%3Dapps`);
      await page.waitForFunction(() => document.getElementById('login-form').getAttribute('aria-busy') === 'false');
    };
    const postCode = async code => {
      await page.locator('#mfa-code').fill(code);
      await page.locator('#submit').click();
      await page.waitForFunction(() => document.getElementById('login-form')?.getAttribute('aria-busy') === 'false');
    };

    await ordinary();
    assert.equal(await page.locator(button).isVisible(), false, 'SocialApp inventory is not a login capability');
    inventory.providers[0].login_enabled = false;
    await ordinary();
    assert.equal(await page.locator(button).isVisible(), false);
    for (const other of otherProviders) assert.equal(await page.locator(`#${other.id}-login`).isVisible(), true, 'provider capabilities are independent');
    inventoryStatus = 503;
    inventory.providers[0].login_enabled = true;
    await ordinary();
    assert.equal(await page.locator(button).isVisible(), false);
    for (const other of otherProviders) assert.equal(await page.locator(`#${other.id}-login`).isVisible(), false);
    assert.equal(await page.locator('#provider-hint').isVisible(), false);
    inventoryStatus = 200;
    await ordinary();
    assert.equal(await page.locator(button).isVisible(), true);
    for (const other of otherProviders) assert.equal(await page.locator(`#${other.id}-login`).isVisible(), true);
    assert.equal(await page.locator('#provider-hint').isVisible(), true);
    assert.ok(await page.locator('#github-login, #discord-login, #steam-login').evaluateAll(buttons =>
      buttons.every((button, i) => !i || button.getBoundingClientRect().top - buttons[i - 1].getBoundingClientRect().bottom >= 10)
    ), 'provider buttons have distinct touch areas');
    for (const width of [320, 390]) for (const theme of ['light', 'dark']) {
      await page.setViewportSize({ width, height: 844 });
      await page.emulateMedia({ colorScheme: theme });
      await page.evaluate(() => document.documentElement.style.fontSize = '200%');
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, `Provider actions overflow ${width}/${theme}`);
    }
    await page.evaluate(() => document.documentElement.style.fontSize = '100%');

    // Each known provider accepts only its own exact HTTPS authorization endpoint.
    for (const invalid of ['https://untrusted.example.invalid/login', otherProvider.authorizeUrl,
      provider.authorizeUrl.replace('https:', 'http:'), provider.authorizeUrl + '/extra',
      provider.authorizeUrl.replace('https://', 'https://user@')]) {
      authorizeUrl = invalid;
      await page.locator(button).click();
      await page.getByText(`Сервис вернул неверный адрес ${provider.name}. Вход остановлен.`).waitFor();
      assert.equal(new URL(page.url()).origin, origin);
    }
    authorizeUrl = authorizeTarget; authorizeMethod = 'POST';
    await page.locator(button).click();
    await page.getByText(`Сервис вернул неверный адрес ${provider.name}. Вход остановлен.`).waitFor();
    authorizeMethod = 'GET';
    beginStatus = 400;
    await page.locator(button).click();
    await page.getByText(`${provider.name} пока не поддерживает этот переход.`, { exact: false }).waitFor();
    beginStatus = 429;
    await page.locator(button).click();
    await page.getByText(/Слишком много попыток/).waitFor();
    assert.equal(await page.locator(button).isEnabled(), false);
    await page.locator(`${button}:enabled`).waitFor();

    beginStatus = 200;
    authorizeUrl = authorizeTarget;
    await page.route(`${provider.authorizeUrl}?*`, route => route.fulfill({ status: 200, contentType: 'text/html', body: `<h1>Synthetic ${provider.name} destination</h1>` }));
    meGate = gate();
    await page.goto(origin + '/login');
    await meGate.received;
    await page.locator(`${button}:visible`).waitFor();
    beginGate = gate();
    await page.locator(button).click();
    await beginGate.received;
    authenticated = true;
    const meResponse = page.waitForResponse(response => new URL(response.url()).pathname === '/api/v1/auth/me');
    meGate.release(); meGate = null;
    await (await meResponse).finished();
    await page.evaluate(() => new Promise(requestAnimationFrame));
    assert.equal(await page.locator('#submit').isEnabled(), false);
    assert.equal(await page.locator('#passkey-login').isEnabled(), false);
    for (const other of otherProviders) assert.equal(await page.locator(`#${other.id}-login`).isEnabled(), false, 'no parallel provider begin in this page');
    assert.equal(await page.locator('#session-choice').isVisible(), false, 'late /me cannot replace a provider attempt');
    beginGate.release(); beginGate = null;
    await page.waitForURL(`${provider.authorizeUrl}?*`);
    assert.equal(page.url(), authorizeTarget, 'server query, including OpenID return_to, is preserved');
    assert.equal(writes.at(-1).body.next, '/account');
    authenticated = false;

    await page.addInitScript(id => {
      if (new URLSearchParams(location.search).get('provider_mfa') === id) sessionStorage.setItem('id_session_token', 'synthetic-legacy-token');
    }, provider.id);
    const readsBeforeMfa = meCalls;
    await mfa();
    assert.equal(meCalls, readsBeforeMfa, 'provider MFA must not restore or continue another session');
    assert.equal(await page.locator('#credential-fields').isVisible(), false);
    assert.equal(await page.locator('#email').evaluate(input => input.disabled && !input.required), true);
    assert.equal(await page.locator('#password').evaluate(input => input.disabled && !input.required), true);
    assert.equal(await page.locator(button).isVisible(), false);
    for (const other of otherProviders) assert.equal(await page.locator(`#${other.id}-login`).isVisible(), false);
    assert.equal(await page.locator('#provider-hint').isVisible(), false);
    await page.getByText(`${provider.name} подтвердил связанный аккаунт.`, { exact: false }).waitFor();
    assert.equal(await page.locator('#passkey-login').isVisible(), false);
    assert.equal(await page.evaluate(() => document.cookie.includes('opaque')), false, 'opaque proof is not readable by UI');
    const reads = pendingCalls;
    await page.reload();
    await page.locator('#submit:enabled').waitFor();
    assert.equal(pendingCalls, reads + 1, 'reload reads server pending context');
    await postCode('111111');
    assert.equal(await page.locator('#mfa-code').inputValue(), '111111');
    assert.deepEqual(writes.at(-1).body, { mfa_code: '111111' });
    assert.equal(await page.locator('#mfa-code').getAttribute('aria-invalid'), 'true');
    assert.equal(await page.locator('#submit').isEnabled(), true);

    completeStatus = 429; completeBody = { code: 'LOGIN_RATE_LIMITED' };
    await page.clock.pauseAt(await page.evaluate(() => Date.now()) + 1000);
    await postCode('222222');
    assert.equal(await page.locator('#submit').isEnabled(), false);
    // A wall-clock correction must neither release early nor strand the button.
    await page.clock.setSystemTime(await page.evaluate(() => Date.now()) - 500);
    await page.clock.runFor(999);
    assert.equal(await page.locator('#submit').isEnabled(), false);
    await page.clock.runFor(1);
    assert.equal(await page.locator('#submit').isEnabled(), true, 'rate limit eventually releases after a clock correction');
    await page.clock.resume();
    completeStatus = 200; completeBody = { user: {}, next: '/account?section=security' };
    await page.locator('#mfa-method').selectOption('recovery');
    await page.locator('#mfa-code').fill('synthetic-recovery-code');
    await page.locator('#submit').click();
    await page.waitForURL(origin + '/account?section=security');
    assert.deepEqual(writes.at(-1).body, { recovery_code: 'synthetic-recovery-code' });
    assert.equal(await page.evaluate(() => sessionStorage.getItem('id_session_token')), null);
    authenticated = false;

    pending.methods = ['recovery_codes'];
    await mfa();
    assert.equal(await page.locator('#mfa-method').inputValue(), 'recovery');
    assert.equal(await page.locator('#mfa-code').getAttribute('inputmode'), 'text');
    for (const width of [320, 390]) for (const theme of ['light', 'dark']) {
      await page.setViewportSize({ width, height: 844 });
      await page.emulateMedia({ colorScheme: theme });
      await page.evaluate(() => document.documentElement.style.fontSize = '200%');
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, `MFA overflow ${width}/${theme}`);
    }
    await page.evaluate(() => document.documentElement.style.fontSize = '100%');

    // A POST can succeed even when its reply is lost. Never resubmit a recovery code automatically.
    completeStatus = 0;
    await postCode('synthetic-once-only');
    assert.equal(await page.locator('#submit').isEnabled(), false);
    assert.equal(await page.locator('#provider-account').isVisible(), true);
    const completedWrites = writes.filter(write => write.route.endsWith('/complete')).length;
    await page.locator('#provider-retry').click();
    await page.locator('#mfa-back:enabled').waitFor();
    assert.equal(await page.locator('#submit').isEnabled(), false, 'pending refresh cannot silently retry an uncertain completion');
    assert.equal(writes.filter(write => write.route.endsWith('/complete')).length, completedWrites);

    cancelStatus = 503;
    await page.locator('#mfa-back').click();
    await page.getByText(/Не удалось подтвердить отмену/).waitFor();
    assert.equal(await page.locator('#credential-fields').isVisible(), false);
    for (const other of otherProviders) assert.equal(await page.locator(`#${other.id}-login`).isVisible(), false, 'failed cancel cannot expose another provider');
    cancelStatus = 200; cancelGate = gate();
    await page.locator('#mfa-back').click();
    await cancelGate.received;
    assert.equal(await page.locator('#mfa-back').isEnabled(), false);
    assert.equal(await page.locator('#credential-fields').isVisible(), false);
    cancelGate.release(); cancelGate = null;
    await page.waitForURL(origin + '/login?next=%2Faccount%3Fsection%3Dsecurity');
    assert.equal(await page.locator('#password').evaluate(input => !input.disabled && input.required), true);
    await page.locator(`${otherButton}:visible:enabled`).waitFor();
    await page.route(`${otherProvider.authorizeUrl}?*`, route => route.fulfill({ status: 200, contentType: 'text/html', body: '<h1>Switched provider fixture</h1>' }));
    await page.locator(otherButton).click();
    await page.waitForURL(`${otherProvider.authorizeUrl}?*`);
    assert.equal(page.url(), otherTarget);
    assert.equal(writes.at(-2).route, loginPath + '/cancel');
    assert.equal(writes.at(-1).route, otherLoginPath, 'other provider begins only after confirmed cancellation');
    assert.equal(writes.at(-1).body.next, '/account?section=security', 'switch uses saved API next, not query next');

    pending.methods = []; pending.restart_required = true;
    await mfa();
    assert.equal(await page.locator('#submit').isEnabled(), false, 'passkey-only account must not be trapped in a code form');
    await page.getByText(/нет доступного кода/).waitFor();
    pendingStatus = 401; pending = { active: false, restart_required: true, code: 'PROVIDER_FLOW_EXPIRED' };
    await mfa();
    assert.equal(await page.locator('#submit').isEnabled(), false);
    await page.locator('#mfa-back').click();
    await page.waitForURL(origin + '/login');

    pendingStatus = 503; pending = { code: 'SERVICE_UNAVAILABLE' };
    await mfa();
    assert.equal(await page.locator('#provider-retry').isVisible(), true);
    pendingStatus = 200; pending = { active: true, expires_at: Math.floor(Date.now() / 1000) + 300, methods: ['totp'], restart_required: false, next: '/account' };
    await page.locator('#provider-retry').click();
    await page.locator('#submit:enabled').waitFor();
    completeStatus = 401; completeBody = { code: 'PROVIDER_FLOW_EXPIRED', active: false, restart_required: true };
    await postCode('333333');
    assert.equal(await page.locator('#submit').isEnabled(), false);
    await page.getByText(/истёк, отменён или уже завершён/).waitFor();

    for (const code of ['PROVIDER_DENIED', 'ACCOUNT_NOT_LINKED', '__proto__', '<script>untrusted</script>']) {
      await page.goto(origin + '/login?provider_error=' + encodeURIComponent(code));
      const message = await page.locator('#error').innerText();
      assert.ok(message.length > 20);
      assert.equal(message.includes('<script>'), false);
      assert.equal(message.includes('[object'), false);
      assert.equal(/GitHub|Discord|Steam/.test(message), false, 'callback does not identify its provider');
      assert.equal(await page.locator('#credential-fields').isVisible(), true);
    }
    const pendingBeforeUnknown = pendingCalls;
    await page.goto(origin + '/login?provider_mfa=__proto__');
    await page.waitForLoadState('networkidle');
    assert.equal(pendingCalls, pendingBeforeUnknown, 'query cannot choose an arbitrary provider endpoint');
    assert.equal(await page.locator('#credential-fields').isVisible(), true);
    assert.deepEqual(errors, []);
    console.log(`PASS: ${provider.name} capability gate, safe redirect, MFA reload/methods, CSRF, expiry, rate limit, cancellation and unknown-result handling`);
  } finally {
    beginGate?.release(); cancelGate?.release(); meGate?.release();
    if (browser) await browser.close();
    proxy.closeAllConnections();
    await new Promise(resolve => proxy.close(resolve));
    if (web.exitCode === null) { web.kill('SIGTERM'); await new Promise(resolve => web.once('exit', resolve)); }
  }
}
const providers = [
  { id: 'github', name: 'GitHub', authorizeUrl: 'https://github.com/login/oauth/authorize' },
  { id: 'discord', name: 'Discord', authorizeUrl: 'https://discord.com/oauth2/authorize' },
  { id: 'steam', name: 'Steam', authorizeUrl: 'https://steamcommunity.com/openid/login',
    query: new URLSearchParams({ 'openid.ns': 'http://specs.openid.net/auth/2.0', 'openid.mode': 'checkid_setup',
      'openid.return_to': 'https://id.example.invalid/api/v1/auth/oauth/callback/steam?state=synthetic%2Fproof' }).toString() },
];
(async () => {
  for (let i = 0; i < providers.length; i++) await main(providers[i], providers[(i + 1) % providers.length]);
})().catch(error => { console.error(error); process.exitCode = 1; });
