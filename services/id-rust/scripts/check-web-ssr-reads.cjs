// Real Topcoat HTTP with a synthetic API. Barriers prove overlapping reads;
// this does not measure production latency or replace backend owner checks.
const assert = require('node:assert/strict');
const http = require('node:http');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { once } = require('node:events');
const { setTimeout: delay } = require('node:timers/promises');
const root = path.resolve(__dirname, '..');
const cookie = 'sessionid=synthetic-owner; csrftoken=synthetic-csrf';
const profileCookies = ['sessionid=synthetic-renewed; Path=/; HttpOnly', 'csrftoken=synthetic-new; Path=/'];
const bodies = {
  me: { user: { username: 'owner', email: 'owner@example.invalid', email_verified: true, has_2fa: false } },
  security: { mfa: { has_totp: false, has_webauthn: true, has_recovery_codes: false, recovery_codes_left: 0 }, authenticators: [{ id: '1', name: 'private-key-marker', is_passwordless: true }] },
  preferences: { language: 'ru', timezone: '', marketing_opt_in: false, privacy_scope_defaults: {} },
  timezones: { timezones: [] },
  consents: { consents: [] },
  sessions: { sessions: [] },
  'oauth/apps': { items: [] },
};
async function listen(server) {
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return server.address().port;
}
async function main() {
  let scenario;
  const sockets = new Set();
  const api = http.createServer(async (req, res) => {
    const current = scenario;
    const name = req.url.replace('/api/v1/auth/', '');
    assert.equal(req.method, 'GET');
    assert.ok(Object.hasOwn(bodies, name), `unexpected read ${req.url}`);
    assert.equal(req.headers.cookie, name === 'timezones' ? undefined : cookie);
    const record = { name, start: performance.now(), end: null };
    current.reads.push(record);
    const config = current.responses?.[name] || {};
    if (config.hold) return; // Intentionally never responds: profile denial must not wait.
    if (current.barrier?.includes(name)) {
      if (current.barrier.every(key => current.reads.some(read => read.name === key))) current.release();
      await Promise.race([current.ready, delay(800).then(() => { throw new Error('SSR reads did not overlap'); })]).catch(error => {
        current.barrierError = error.message;
      });
    }
    await delay(config.delay ?? 40);
    record.end = performance.now();
    res.writeHead(config.status ?? 200, {
      'content-type': 'application/json',
      'set-cookie': name === 'me' ? profileCookies : ['secondary=must-not-forward; Path=/'],
    });
    res.end(Object.hasOwn(config, 'raw') ? config.raw : JSON.stringify(config.body ?? bodies[name]));
  });
  api.on('connection', socket => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
  const apiPort = await listen(api);
  let web;
  let origin;
  async function stopWeb() {
    if (web && web.exitCode === null) { const exited = once(web, 'exit'); web.kill(); await exited; }
  }
  async function startWeb(overrides = {}) {
    await stopWeb();
    const portProbe = http.createServer();
    const port = await listen(portProbe);
    await new Promise(resolve => portProbe.close(resolve));
    const flags = Object.fromEntries(['ACCOUNT', 'SECURITY', 'PREFERENCES', 'CONSENTS', 'SESSIONS', 'APPS'].map(name => [`ID_WEB_${name}_PILOT_ENABLED`, 'true']));
    web = spawn(path.join(process.env.ID_RUST_BIN_DIR || path.join(root, 'target/debug'), 'id-web'), [], {
      env: { ...process.env, ...flags, ID_WEB_DELETION_ENABLED: 'false', ...overrides, HOST: '127.0.0.1', PORT: String(port), ID_WEB_API_ORIGIN: `http://127.0.0.1:${apiPort}` }, stdio: 'inherit',
    });
    origin = `http://127.0.0.1:${port}`;
    for (let i = 0; i < 40; i++) {
      try { if ((await fetch(origin)).ok) return; } catch {}
      assert.equal(web.exitCode, null, 'Topcoat exited');
      await delay(50);
    }
    throw new Error('Topcoat startup failed');
  }
  async function check(section, options = {}) {
    scenario = { ...options, reads: [], ready: null, release: null };
    scenario.ready = new Promise(resolve => { scenario.release = resolve; });
    const started = performance.now();
    const response = await fetch(`${origin}/account?section=${section}`, {
      redirect: 'manual', headers: { cookie }, signal: AbortSignal.timeout(2000),
    });
    const html = await response.text();
    assert.equal(response.status, options.status ?? 200, html.slice(0, 200));
    assert.equal(response.headers.get('cache-control'), 'no-store');
    assert.equal(scenario.barrierError, undefined, scenario.barrierError);
    assert.deepEqual(response.headers.getSetCookie(), response.status === 200 || response.status === 303 ? profileCookies : []);
    if (options.text) assert.ok(html.includes(options.text), html.slice(0, 200));
    if (response.status !== 200) assert.ok(!html.includes('private-key-marker'), 'private security data rendered after denial');
    if (response.status === 303) assert.equal(response.headers.get('location'), `/login?next=${encodeURIComponent(`/account?section=${section}`)}`);
    if (options.barrier) {
      const reads = scenario.reads.filter(read => options.barrier.includes(read.name));
      assert.equal(reads.length, options.barrier.length);
      assert.ok(Math.max(...reads.map(read => read.start)) < Math.min(...reads.map(read => read.end)), 'reads must overlap');
      console.log(`${section}: ${Math.round(performance.now() - started)} ms; ${reads.map(read => read.name).join(' + ')} overlap`);
    }
    for (const socket of sockets) socket.destroy();
    return scenario.reads;
  }
  try {
    await startWeb();
    await check('security', { barrier: ['me', 'security'], text: 'private-key-marker' });
    const reads = await check('privacy', { barrier: ['preferences', 'timezones', 'consents'] });
    assert.ok(reads.slice(1).every(read => read.start >= reads[0].end), 'privacy reads require an authenticated profile');
    await check('settings', { barrier: ['preferences', 'timezones', 'consents'] });
    // A guest or failed profile wins even if the independent read never returns.
    for (const profile of [{ body: { user: null } }, { status: 401 }, { status: 503 }, { raw: '{' }]) {
      await check('security', { status: profile.body ? 303 : 503, responses: { me: profile, security: { hold: true } }, ...(profile.body ? {} : { text: 'Не удалось загрузить кабинет' }) });
    }
    // A completed security success or error must not beat the later profile denial.
    await check('security', { status: 303, responses: { me: { delay: 80, body: { user: null } }, security: { delay: 0 } } });
    await check('security', { status: 303, responses: { me: { delay: 80, body: { user: null } }, security: { status: 401, delay: 0 } } });
    await check('security', { status: 503, text: 'Не удалось загрузить кабинет', responses: { me: { delay: 80, status: 503 }, security: { status: 403, delay: 0 } } });
    for (const failure of [{ status: 401 }, { status: 403 }, { status: 503 }, { raw: '{' }]) {
      await check('security', { status: 503, text: 'Не удалось загрузить настройки безопасности', responses: { security: failure } });
    }
    for (const [name, text] of [['preferences', 'настройки'], ['timezones', 'часовые пояса'], ['consents', 'согласия']]) {
      const responses = Object.fromEntries(['preferences', 'timezones', 'consents'].slice(['preferences', 'timezones', 'consents'].indexOf(name)).map(key => [key, { status: 403, delay: key === name ? 80 : 0 }]));
      await check('privacy', { status: 503, text: `Не удалось загрузить ${text}`, responses });
    }
    // Higher-priority failures must cancel lower-priority reads that never finish.
    await check('privacy', { status: 503, text: 'Не удалось загрузить настройки', responses: { preferences: { status: 503 }, timezones: { hold: true }, consents: { hold: true } } });
    await check('privacy', { status: 503, text: 'Не удалось загрузить часовые пояса', responses: { timezones: { status: 503 }, consents: { hold: true } } });
    const guestReads = await check('privacy', { status: 303, responses: { me: { body: { user: null } } } });
    assert.deepEqual(guestReads.map(read => read.name), ['me']);
    for (const section of ['sessions', 'privacy', 'apps', 'delete']) {
      const reads = await check(`security&section=${section}`, { status: section === 'delete' ? 404 : 200 });
      assert.ok(!reads.some(read => read.name === 'security'), `precedence: ${section}`);
    }
    await startWeb({ ID_WEB_SECURITY_PILOT_ENABLED: 'false', ID_WEB_CONSENTS_PILOT_ENABLED: 'false' });
    assert.deepEqual((await check('security')).map(read => read.name), ['me']);
    assert.deepEqual((await check('privacy', { barrier: ['preferences', 'timezones'] })).map(read => read.name).sort(), ['me', 'preferences', 'timezones']);
    await startWeb({ ID_WEB_PREFERENCES_PILOT_ENABLED: 'false' });
    assert.deepEqual((await check('privacy')).map(read => read.name), ['me']);
    console.log('SSR reads: overlap, profile denial priority, fail-closed errors, cookies and feature/section gates PASS');
  } finally {
    await stopWeb();
    for (const socket of sockets) socket.destroy();
    await new Promise(resolve => api.close(resolve));
  }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
