#!/usr/bin/env node
// Check the public Rust API/Topcoat routes after deploying their existing containers.
const target = process.argv[2];
const checks = {
  api: [
    ['/health', 200, 'application/json'],
    ['/readyz', 200, 'application/json'],
    ['/api/v1/auth/me', 200, 'application/json'],
  ],
  web: [
    ['/login', 200, 'text/html'],
    ['/signup', 200, 'text/html'],
    ['/_id/login.js', 200, 'javascript'],
    ['/_id/login.css', 200, 'text/css'],
    ['/_id/signup.js', 200, 'javascript'],
    ['/_id/signup.css', 200, 'text/css'],
  ],
}[target];
if (!checks) throw new Error('usage: smoke-yc-rust-http.mjs api|web');

for (const [path, status, type] of checks) {
  let lastError;
  for (let attempt = 0; attempt < 12; attempt++) {
    try {
      const response = await fetch(`https://id.updspace.com${path}`, {
        redirect: 'manual',
        signal: AbortSignal.timeout(15_000),
      });
      const expectedForm = path === '/login' ? 'id="login-form"' : path === '/signup' ? 'id="signup-form"' : null;
      const bodyMatches = expectedForm ? (await response.text()).includes(expectedForm) : true;
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
