#!/usr/bin/env node
// Check the public Rust API/Topcoat routes after deploying their existing containers.
const target = process.argv[2];
const baseUrl = (process.env.SMOKE_BASE_URL ?? 'https://id.updspace.com').replace(/\/$/, '');
const checks = {
  api: [
    ['/health', 200, 'application/json'],
    ['/readyz', 200, 'application/json'],
    ['/api/v1/auth/me', 200, 'application/json'],
  ],
  sessions: [
    ['/api/v1/auth/sessions', 401, 'application/json'],
  ],
  mutations: [
    ['/api/v1/auth/data/exports/not-an-id', 401, 'application/json'],
  ],
  web: [
    ['/', 200, 'text/html', '/_id/home.css'],
    ['/login', 200, 'text/html'],
    ['/signup', 200, 'text/html'],
    ['/_id/login.js', 200, 'javascript'],
    ['/_id/login.css', 200, 'text/css'],
    ['/_id/signup.js', 200, 'javascript'],
    ['/_id/signup.css', 200, 'text/css'],
    ['/legacy/account', 404, 'text/plain'],
    ['/assets/__retired_react_smoke__.js', 404, 'text/plain'],
    ['/__unknown_id_page_smoke__', 404, 'text/plain'],
  ],
}[target];
if (!checks) throw new Error('usage: smoke-yc-rust-http.mjs api|sessions|mutations|web');

for (const [path, status, type, expectedBody] of checks) {
  let lastError;
  for (let attempt = 0; attempt < 12; attempt++) {
    try {
      const response = await fetch(`${baseUrl}${path}`, {
        redirect: 'manual',
        signal: AbortSignal.timeout(15_000),
      });
      const marker = expectedBody ?? (path === '/login' ? 'id="login-form"' : path === '/signup' ? 'id="signup-form"' : null);
      const bodyMatches = marker ? (await response.text()).includes(marker) : true;
      if (response.status === status && response.headers.get('content-type')?.includes(type) && bodyMatches) {
        lastError = undefined;
        console.log(`${path}: ${status} ${type}`);
        break;
      }
      lastError = `${response.status} ${response.headers.get('content-type') ?? '<none>'}`;
    } catch (error) {
      lastError = error.message;
    }
    if (attempt < 11) await new Promise((resolve) => setTimeout(resolve, 5_000));
  }
  if (lastError) throw new Error(`${path}: expected ${status} ${type}, got ${lastError}`);
}
