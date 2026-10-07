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
  oidc: [
    ['/.well-known/openid-configuration', 200, 'application/json'],
    ['/.well-known/jwks.json', 200, 'application/json'],
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
if (!checks) throw new Error('usage: smoke-yc-rust-http.mjs api|oidc|sessions|mutations|web|delayed-export');

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
      lastError = [error.message, error.cause?.code].filter(Boolean).join(' ');
    }
    if (attempt < 11) await new Promise((resolve) => setTimeout(resolve, 5_000));
  }
  if (lastError) {
    const message = `${path}: expected ${status} ${type}, got ${lastError}`;
    console.error(`::error title=ID production smoke::${message}`);
    throw new Error(message);
  }
}

if (target === 'oidc') {
  const issuer = new URL(baseUrl).origin;
  const discovery = await fetch(`${issuer}/.well-known/openid-configuration`, {
    signal: AbortSignal.timeout(15_000),
  }).then(response => response.json());
  const endpoints = {
    issuer,
    authorization_endpoint: `${issuer}/oauth/authorize`,
    token_endpoint: `${issuer}/oauth/token`,
    userinfo_endpoint: `${issuer}/oauth/userinfo`,
    revocation_endpoint: `${issuer}/oauth/revoke`,
    jwks_uri: `${issuer}/.well-known/jwks.json`,
  };
  for (const [field, expected] of Object.entries(endpoints)) {
    if (discovery[field] !== expected) throw new Error(`OIDC ${field} differs from the public issuer`);
  }
  for (const [field, required] of Object.entries({
    response_types_supported: 'code',
    grant_types_supported: 'authorization_code',
    subject_types_supported: 'public',
    id_token_signing_alg_values_supported: 'RS256',
    code_challenge_methods_supported: 'S256',
    scopes_supported: 'openid',
  })) {
    if (!Array.isArray(discovery[field]) || !discovery[field].includes(required)) {
      throw new Error(`OIDC ${field} omits ${required}`);
    }
  }
  const jwks = await fetch(discovery.jwks_uri, {
    signal: AbortSignal.timeout(15_000),
  }).then(response => response.json());
  if (!Array.isArray(jwks.keys) || jwks.keys.length === 0) throw new Error('OIDC JWKS has no public keys');
  const kids = new Set();
  let signingKeys = 0;
  for (const key of jwks.keys) {
    if (typeof key.kid !== 'string' || !key.kid || kids.has(key.kid)) {
      throw new Error('OIDC JWKS has a missing or duplicate kid');
    }
    kids.add(key.kid);
    if (key.kty === 'RSA' && key.use === 'sig' && key.alg === 'RS256' &&
      typeof key.n === 'string' && key.n.length >= 256 && typeof key.e === 'string' && key.e) {
      signingKeys += 1;
    }
  }
  if (!signingKeys) throw new Error('OIDC JWKS has no usable RS256 signing key');
  console.log(`OIDC issuer, PKCE and ${signingKeys} signing key(s): valid`);
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
