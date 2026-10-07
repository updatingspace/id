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
  'delayed-export': [
    ['/data/export', 200, 'text/html', 'id="export-download"'],
    ['/data/export/cancel', 200, 'text/html', 'id="export-cancel"'],
    ['/_id/export-redeem.js', 200, 'javascript'],
    ['/_id/export-cancel.js', 200, 'javascript'],
  ],
}[target];
if (!checks) throw new Error('usage: smoke-yc-rust-http.mjs api|sessions|mutations|web|delayed-export');

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

if (target === 'delayed-export') {
  const id = '00000000000000000000000000000000';
  for (const action of ['redeem', 'cancel']) {
    const path = `/api/v1/auth/data/exports/${id}/${action}`;
    let verified = false;
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        const response = await fetch(`${baseUrl}${path}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token: 'invalid' }),
          redirect: 'manual',
          signal: AbortSignal.timeout(15_000),
        });
        const body = await response.json().catch(() => null);
        verified = response.status === 404 &&
          response.headers.get('content-type')?.includes('application/json') &&
          response.headers.get('cache-control') === 'no-store' &&
          body?.error === 'NOT_FOUND';
        if (verified) break;
      } catch { /* retry only this harmless invalid bearer after a cold start */ }
      if (attempt < 2) await new Promise((resolve) => setTimeout(resolve, 2_000));
    }
    if (!verified) throw new Error(`${path}: invalid bearer was not rejected by the Rust API`);
    console.log(`${path}: 404 invalid bearer`);
  }
}
