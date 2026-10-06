const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, '../crates/id-web/static/recovery.js'), 'utf8');

async function submitWithCookie(cookie) {
  let onSubmit;
  const calls = [];
  const status = { hidden: true, textContent: '' };
  const error = { hidden: true, textContent: '' };
  const submit = { disabled: false };
  const form = {
    elements: { namedItem: () => ({ value: 'nobody@example.invalid' }) },
    addEventListener: (_, listener) => { onSubmit = listener; },
    reset: () => {},
  };
  vm.runInNewContext(source, {
    document: {
      cookie,
      getElementById: id => ({ 'forgot-form': form, submit, status, error })[id] ?? null,
    },
    fetch: async (url, options) => {
      calls.push([url, options]);
      return { ok: true, json: async () => url.includes('form_token')
        ? { form_token: 'one-use-token' } : { ok: true } };
    },
    AbortController,
    setTimeout,
    clearTimeout,
  });
  onSubmit({ preventDefault: () => {} });
  for (let attempt = 0; attempt < 20 && submit.disabled; attempt += 1) {
    await new Promise(resolve => setTimeout(resolve, 0));
  }
  assert.equal(error.hidden, true);
  assert.match(status.textContent, /Если аккаунт с таким адресом существует/);
  assert.equal(calls.length, 2);
  assert.equal(calls[1][0], '/api/v1/auth/password/reset/request');
  assert.equal(JSON.parse(calls[1][1].body).form_token, 'one-use-token');
  return calls[1][1].headers;
}

(async () => {
  const legacyHeaders = await submitWithCookie('');
  assert.equal(legacyHeaders['X-CSRFToken'], undefined);
  const rustHeaders = await submitWithCookie('csrftoken=readable-secret');
  assert.equal(rustHeaders['X-CSRFToken'], 'readable-secret');
  console.log('Recovery forms support legacy one-use tokens and readable Rust CSRF cookies');
})().catch(error => { console.error(error); process.exitCode = 1; });
