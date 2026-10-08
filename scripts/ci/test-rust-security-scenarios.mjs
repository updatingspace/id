import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const script = fileURLToPath(new URL('./run-rust-security-scenarios.sh', import.meta.url));
const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'id-security-scenarios-'));
const log = path.join(directory, 'commands.jsonl');
const ownedContainer = 'abc123-owned-disposable-container';
const recordedKeys = ['YDB_ENDPOINT', 'YDB_DATABASE', 'YDB_CREDENTIALS_MODE', 'ID_DISPOSABLE_YDB',
  'ID_AUTH_PASSWORD_CHANGE_PILOT_ENABLED', 'ID_AUTH_EMAIL_VERIFY_PILOT_ENABLED',
  'ID_AUTH_EMAIL_RESEND_ENABLED', 'ID_AUTH_SIGNUP_PILOT_ENABLED', 'ID_EMAIL_VERIFY_HMAC_KEY',
  'ID_AUTH_FORM_TOKEN_ENABLED', 'ID_AUTH_PASSWORD_RESET_PILOT_ENABLED', 'ID_PASSWORD_RESET_HMAC_KEY',
  'ID_AUTH_EMAIL_CHANGE_PILOT_ENABLED', 'ID_AUTH_EMAIL_CANCEL_PILOT_ENABLED', 'CSRF_TRUSTED_ORIGINS',
  'ID_AUTH_ADMIN_READ_ENABLED', 'ID_AUTH_ADMIN_SUSPEND_ENABLED', 'ID_AUTH_ADMIN_CLIENT_REDIRECTS_ENABLED',
  'ID_EXPORT_TEST_REAL_S3', 'CARGO_TARGET_DIR', 'RUSTFLAGS', 'LLVM_PROFILE_FILE', 'RUSTUP_TOOLCHAIN'];
try {
  const fake = path.join(directory, 'fake-command.cjs');
  fs.writeFileSync(fake, `#!${process.execPath}
const fs = require('node:fs'), path = require('node:path');
const command = path.basename(process.argv[1]), args = process.argv.slice(2);
fs.appendFileSync(process.env.SCENARIO_LOG, JSON.stringify({ command, args,
  env: Object.fromEntries(${JSON.stringify(recordedKeys)}.map(key => [key, process.env[key]])) }) + '\\n');
if (command === 'docker' && args[0] === 'run') {
  if (process.env.FAIL_CREATE === 'true') process.exit(42);
  console.log(${JSON.stringify(ownedContainer)});
}
if (command === 'docker' && args[0] === 'stop' && process.env.FAIL_CLEANUP === 'true') process.exit(53);
if (command === 'cargo' && args.includes(process.env.FAIL_TEST)) process.exit(37);
if (command === 'bash' && args[0] === ${JSON.stringify(script)}) {
  const result = require('node:child_process').spawnSync('/bin/bash', args, { stdio: 'inherit', env: process.env });
  if (result.error) throw result.error;
  process.exit(result.status ?? 1);
}
if (command === 'bash' && args.includes(process.env.FAIL_SCRIPT)) process.exit(39);
`, { mode: 0o700 });
  for (const name of ['cargo', 'docker', 'idctl', 'bash', 'node']) fs.symlinkSync(fake, path.join(directory, name));
  const env = {
    ...process.env, PATH: `${directory}:${process.env.PATH}`, SCENARIO_LOG: log,
    YDB_ENDPOINT: 'grpc://localhost:2136', YDB_DATABASE: '/local', YDB_CREDENTIALS_MODE: 'anonymous',
    DJANGO_DEBUG: 'true', ID_RUST_BIN_DIR: '',
    CARGO_TARGET_DIR: '/synthetic/instrumented-target', RUSTFLAGS: '-Zcoverage-options=branch -C instrument-coverage',
    LLVM_PROFILE_FILE: '/synthetic/rust-%p-%m.profraw', RUSTUP_TOOLCHAIN: 'synthetic-pinned-nightly',
    FAIL_TEST: '', FAIL_SCRIPT: '', FAIL_CLEANUP: '', FAIL_CREATE: '',
  };
  function run(scenario, overrides = {}) {
    fs.writeFileSync(log, '');
    const result = spawnSync('/bin/bash', [script, scenario], { env: { ...env, ...overrides }, encoding: 'utf8' });
    assert.ifError(result.error);
    const commands = fs.readFileSync(log, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse);
    return { result, commands };
  }
  function tests(commands) {
    return commands.filter(item => item.command === 'cargo' && item.args.includes('--test'))
      .map(item => item.args[item.args.indexOf('--test') + 1]);
  }
  const cases = {
    'password-change': ['password_change_http_ydb'],
    'password-reset': ['password_reset_http_ydb'],
    'email-verification': ['email_verify_http_ydb', 'signup_ydb'],
    'email-change': ['email_change_ydb', 'email_cancel_http_ydb'],
    'export-escrow': ['data_export_escrow_ydb'],
    'isolated-deletion': ['legacy_unbound_deletion_ydb', 'legacy_cutover_reset_ydb', 'data_export_delete_flow_ydb', 'admin_http_ydb'],
    'recovery-browser': [],
    'deletion-browser': ['legacy_cutover_reset_ydb'],
    'deletion-review-browser': [],
    'admin-browser': [],
    'admin-live': [],
    'signup-browser': [],
  };
  const libraries = {
    'password-change': ['password_mail::tests::sends_once_from_durable_intent',
      'password_mail::tests::two_clients_claim_one_password_mail',
      'password_mail::tests::deleted_account_cancels_and_scrubs_pending_mail'],
    'password-reset': ['password_reset::tests::mail_claim_is_single_owner_and_expiry_is_cleaned'],
    'email-verification': ['email_verify::tests::mail_claim_is_single_owner_and_expiry_is_cleaned'],
  };
  const browsers = {
    'recovery-browser': 'scripts/smoke-web-recovery-live.sh',
    'deletion-browser': 'scripts/smoke-web-deletion-live.sh',
    'deletion-review-browser': 'scripts/smoke-web-deletion.sh',
    'admin-browser': 'scripts/check-web-admin-suspend-browser.cjs',
    'admin-live': 'scripts/smoke-web-admin-live.sh',
    'signup-browser': 'scripts/smoke-web-signup-live.sh',
  };
  const isolated = new Set(['isolated-deletion', 'deletion-browser']);
  for (const [scenario, expected] of Object.entries(cases)) {
    const { result, commands } = run(scenario);
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(tests(commands), expected);
    assert.deepEqual(commands.filter(item => item.command === 'cargo' && item.args.includes('--lib'))
      .map(item => item.args[item.args.indexOf('--lib') + 1]), libraries[scenario] || []);
    assert.deepEqual(commands.filter(item => ['bash', 'node'].includes(item.command)
      && item.args[0]?.startsWith('scripts/')).map(item => item.args[0]),
    browsers[scenario] ? [browsers[scenario]] : []);
    for (const item of commands.filter(item => ['cargo', 'idctl', 'bash', 'node'].includes(item.command))) {
      for (const key of ['CARGO_TARGET_DIR', 'RUSTFLAGS', 'LLVM_PROFILE_FILE', 'RUSTUP_TOOLCHAIN']) {
        assert.equal(item.env[key], env[key], `scenario changed instrumentation: ${key}`);
      }
      assert.equal(item.env.YDB_ENDPOINT, isolated.has(scenario) ? 'grpc://127.0.0.1:2137' : env.YDB_ENDPOINT);
      if (isolated.has(scenario)) assert.equal(item.env.ID_DISPOSABLE_YDB, 'true');
    }
    if (isolated.has(scenario)) assert.deepEqual(commands.at(-1).args, ['stop', ownedContainer]);
    if (scenario === 'isolated-deletion') {
      assert.deepEqual(commands.at(-1).args, ['stop', ownedContainer]);
      const admin = commands.find(item => item.args.includes('admin_http_ydb'));
      for (const gate of ['ID_AUTH_ADMIN_READ_ENABLED', 'ID_AUTH_ADMIN_SUSPEND_ENABLED', 'ID_AUTH_ADMIN_CLIENT_REDIRECTS_ENABLED']) {
        assert.equal(admin.env[gate], 'true');
      }
      assert.equal(admin.env.ID_EXPORT_TEST_REAL_S3, 'false');
    }
    if (scenario === 'password-change') {
      assert.equal(commands.find(item => item.args.includes('password_change_http_ydb')).env.ID_AUTH_PASSWORD_CHANGE_PILOT_ENABLED, 'true');
    }
    if (scenario === 'email-verification') {
      const verify = commands.find(item => item.args.includes('email_verify_http_ydb'));
      for (const gate of ['ID_AUTH_FORM_TOKEN_ENABLED', 'ID_AUTH_EMAIL_VERIFY_PILOT_ENABLED',
        'ID_AUTH_EMAIL_RESEND_ENABLED', 'ID_AUTH_SIGNUP_PILOT_ENABLED']) assert.equal(verify.env[gate], 'true');
      assert.equal(verify.env.CSRF_TRUSTED_ORIGINS, 'http://localhost:5175');
      assert.equal(verify.env.ID_EMAIL_VERIFY_HMAC_KEY, '08'.repeat(32));
    }
  }
  const instrumented = run('email-change', { ID_RUST_BIN_DIR: directory });
  assert.equal(instrumented.result.status, 0);
  assert.deepEqual(instrumented.commands.filter(item => item.command === 'idctl').map(item => item.args),
    [['email-change-schema'], ['email-change-schema'], ['security-mail-schema']]);
  assert.equal(instrumented.commands.some(item => item.command === 'cargo' && item.args[0] === 'run'), false);
  const failed = run('isolated-deletion', { FAIL_TEST: 'legacy_unbound_deletion_ydb', FAIL_CLEANUP: 'true' });
  assert.equal(failed.result.status, 37, 'cleanup must preserve the primary test failure');
  assert.deepEqual(tests(failed.commands), ['legacy_unbound_deletion_ydb']);
  assert.deepEqual(failed.commands.at(-1).args, ['stop', ownedContainer]);
  assert.equal(run('isolated-deletion', { FAIL_CLEANUP: 'true' }).result.status, 1, 'cleanup failure must fail a successful suite');
  const creation = run('isolated-deletion', { FAIL_CREATE: 'true' });
  assert.equal(creation.result.status, 42);
  assert.equal(creation.commands.some(item => item.args[0] === 'stop'), false, 'failed creation must not stop another container');
  const remote = run('isolated-deletion', { YDB_ENDPOINT: 'grpcs://example.invalid:2135' });
  assert.equal(remote.result.status, 1);
  assert.deepEqual(remote.commands, [], 'nonlocal input must fail before commands');
  const browserFailure = run('deletion-browser', { FAIL_SCRIPT: browsers['deletion-browser'], FAIL_CLEANUP: 'true' });
  assert.equal(browserFailure.result.status, 39, 'owned-container cleanup must preserve the browser failure');
  assert.deepEqual(browserFailure.commands.at(-1).args, ['stop', ownedContainer]);
  const remaining = ['password-change', 'email-verification', 'recovery-browser', 'deletion-browser',
    'deletion-review-browser', 'admin-browser', 'admin-live', 'signup-browser'];
  const replay = run('remaining-schema');
  assert.equal(replay.result.status, 0, replay.result.stderr);
  assert.deepEqual(replay.commands.filter(item => item.command === 'bash' && item.args[0] === script)
    .map(item => item.args[1]), remaining);
  assert.deepEqual(tests(replay.commands), remaining.flatMap(name => cases[name]));
  const recovery = replay.commands.find(item => item.args[0] === browsers['recovery-browser']);
  assert.equal(recovery.env.ID_AUTH_PASSWORD_CHANGE_PILOT_ENABLED, undefined, 'case flags leaked into a sibling process');
  assert.equal(recovery.env.ID_AUTH_SIGNUP_PILOT_ENABLED, undefined, 'case flags leaked into a sibling process');
  const signup = replay.commands.find(item => item.args[0] === browsers['signup-browser']);
  assert.equal(signup.env.YDB_ENDPOINT, env.YDB_ENDPOINT, 'disposable endpoint leaked into a later case');
  const replayFailure = run('remaining-schema', { FAIL_TEST: 'password_change_http_ydb' });
  assert.equal(replayFailure.result.status, 37);
  assert.deepEqual(tests(replayFailure.commands), ['password_change_http_ydb'], 'replay must stop on a scenario failure');

  const repository = path.resolve(path.dirname(script), '../..');
  const ci = fs.readFileSync(path.join(repository, '.github/workflows/ci-cd.yml'), 'utf8');
  const schema = ci.split('\n  ydb-schema-check:\n')[1].split('\n  terraform-check:\n')[0];
  const pilot = fs.readFileSync(path.join(repository, '.github/workflows/rust-pilot.yml'), 'utf8');
  const invocations = text => [...text.matchAll(/run-rust-security-scenarios\.sh ([a-z-]+)/g)].map(match => match[1]);
  assert.deepEqual(new Set(invocations(schema)), new Set(Object.keys(cases)), 'schema commands drifted from the shared scenario inventory');
  assert.deepEqual(new Set(invocations(pilot)), new Set(['password-reset', 'email-change', 'export-escrow', 'isolated-deletion', 'remaining-schema']));
  assert.deepEqual(new Set([...invocations(pilot).filter(name => name !== 'remaining-schema'), ...remaining]),
    new Set(invocations(schema)), 'coverage must replay every shared required schema case');
  // Remaining inline schema checks are already part of ordinary rust-pilot.
  // A newly added required test/browser command must gain measurement wiring too.
  const rustTests = text => [...text.matchAll(/cargo test[^\n]*?--(?:test|lib) ([a-zA-Z0-9_:]+)/g)]
    .map(match => match[1]);
  for (const name of rustTests(schema)) {
    assert(rustTests(pilot).includes(name), `required inline Rust scenario is not measured: ${name}`);
  }
  const browserScripts = text => [...text.matchAll(/(?:bash|node) (?:services\/id-rust\/)?(scripts\/[^\s]+\.(?:sh|cjs))/g)]
    .map(match => match[1]);
  for (const name of browserScripts(schema)) {
    assert(browserScripts(pilot).includes(name), `required inline browser scenario is not measured: ${name}`);
  }
  console.log('PASS: shared scenario commands, local DB isolation, instrumentation inheritance and owned-container cleanup');
} finally {
  fs.rmSync(directory, { recursive: true, force: true });
}
