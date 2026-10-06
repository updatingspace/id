const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, '../crates/id-web/static/email.js'), 'utf8');

function page(responses) {
  const calls = [];
  const listeners = {};
  const pending = { removed: false, remove() { this.removed = true; } };
  const verify = {
    disabled: false,
    dataset: { email: 'owner@example.invalid' },
    addEventListener(event, callback) { listeners[`verify:${event}`] = callback; },
  };
  const cancel = {
    disabled: false,
    removed: false,
    previousElementSibling: pending,
    addEventListener(event, callback) { listeners[`cancel:${event}`] = callback; },
    remove() { this.removed = true; },
  };
  const input = { value: 'new@example.invalid' };
  const submit = { disabled: false };
  const change = {
    addEventListener(event, callback) { listeners[`change:${event}`] = callback; },
    querySelector(selector) {
      return selector.startsWith('input') ? input : submit;
    },
    reportValidity() { return true; },
  };
  const message = { hidden: true, textContent: '' };
  const error = { hidden: true, textContent: '' };
  vm.runInNewContext(source, {
    document: {
      cookie: 'csrftoken=readable-secret',
      getElementById(id) {
        return ({
          'email-verify-request': verify,
          'email-change-cancel': cancel,
          'email-change-form': change,
          'email-message': message,
          'email-error': error,
        })[id] ?? null;
      },
    },
    window: { location: { replace: () => assert.fail('unexpected login redirect') } },
    fetch: async (url, options) => {
      calls.push([url, options]);
      const reply = responses.shift();
      assert.ok(reply, `unexpected request to ${url}`);
      return reply;
    },
    AbortController,
    setTimeout,
    clearTimeout,
  });
  return { calls, listeners, verify, cancel, change, input, submit, pending, message, error };
}

const reply = (status, body) => ({ status, ok: status < 400, json: async () => body });

(async () => {
  const verify = page([
    reply(200, { form_token: 'one-use-token' }),
    reply(200, { ok: true }),
  ]);
  await verify.listeners['verify:click']();
  assert.equal(verify.calls.length, 2);
  assert.equal(verify.calls[0][0], '/api/v1/auth/form_token?purpose=email_verification');
  assert.equal(verify.calls[1][0], '/api/v1/auth/email/verification/request');
  assert.equal(verify.calls[1][1].headers['X-CSRFToken'], 'readable-secret');
  assert.deepEqual(JSON.parse(verify.calls[1][1].body), {
    email: 'owner@example.invalid', form_token: 'one-use-token',
  });
  assert.equal(verify.error.hidden, true);
  assert.equal(verify.message.hidden, false);

  const cancel = page([reply(200, { ok: true })]);
  await cancel.listeners['cancel:click']();
  assert.equal(cancel.calls[0][0], '/api/v1/auth/email/change');
  assert.equal(cancel.calls[0][1].method, 'DELETE');
  assert.equal(cancel.calls[0][1].headers['X-CSRFToken'], 'readable-secret');
  assert.equal(cancel.pending.removed, true);
  assert.equal(cancel.cancel.removed, true);

  const failed = page([reply(503, { message: 'Временно недоступно' })]);
  await failed.listeners['cancel:click']();
  assert.equal(failed.pending.removed, false);
  assert.equal(failed.cancel.removed, false);
  assert.equal(failed.error.hidden, false);
  assert.equal(failed.error.textContent, 'Временно недоступно');

  const changed = page([reply(200, { ok: true })]);
  let prevented = false;
  await changed.listeners['change:submit']({ preventDefault() { prevented = true; } });
  assert.equal(prevented, true);
  assert.equal(changed.calls[0][0], '/api/v1/auth/email/change');
  assert.equal(changed.calls[0][1].method, 'POST');
  assert.equal(changed.calls[0][1].headers['X-CSRFToken'], 'readable-secret');
  assert.deepEqual(JSON.parse(changed.calls[0][1].body), { new_email: 'new@example.invalid' });
  assert.equal(changed.input.value, '');
  assert.equal(changed.message.hidden, false);

  const rejected = page([reply(401, { code: 'REAUTH_REQUIRED', message: 'Требуется повторный вход' })]);
  await rejected.listeners['change:submit']({ preventDefault() {} });
  assert.equal(rejected.input.value, 'new@example.invalid');
  assert.equal(rejected.error.textContent, 'Требуется повторный вход');
  console.log('Topcoat email verification, change and cancellation browser contracts passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
