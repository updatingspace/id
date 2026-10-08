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
`, { mode: 0o700 });
  for (const name of ['cargo', 'docker', 'idctl']) fs.symlinkSync(fake, path.join(directory, name));
  const env = {
    ...process.env, PATH: `${directory}:${process.env.PATH}`, SCENARIO_LOG: log,
    YDB_ENDPOINT: 'grpc://localhost:2136', YDB_DATABASE: '/local', YDB_CREDENTIALS_MODE: 'anonymous',
    DJANGO_DEBUG: 'true', ID_RUST_BIN_DIR: '',
    CARGO_TARGET_DIR: '/synthetic/instrumented-target', RUSTFLAGS: '-Zcoverage-options=branch -C instrument-coverage',
    LLVM_PROFILE_FILE: '/synthetic/rust-%p-%m.profraw', RUSTUP_TOOLCHAIN: 'synthetic-pinned-nightly',
    FAIL_TEST: '', FAIL_CLEANUP: '', FAIL_CREATE: '',
  };
  function run(scenario, overrides = {}) {
    fs.writeFileSync(log, '');
    const result = spawnSync('bash', [script, scenario], { env: { ...env, ...overrides }, encoding: 'utf8' });
    assert.ifError(result.error);
    const commands = fs.readFileSync(log, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse);
    return { result, commands };
  }
  function tests(commands) {
    return commands.filter(item => item.command === 'cargo' && item.args.includes('--test'))
      .map(item => item.args[item.args.indexOf('--test') + 1]);
  }
  const cases = {
    'password-reset': ['password_reset_http_ydb'],
    'email-change': ['email_change_ydb', 'email_cancel_http_ydb'],
    'export-escrow': ['data_export_escrow_ydb'],
    'isolated-deletion': ['legacy_unbound_deletion_ydb', 'legacy_cutover_reset_ydb', 'data_export_delete_flow_ydb', 'admin_http_ydb'],
  };
  for (const [scenario, expected] of Object.entries(cases)) {
    const { result, commands } = run(scenario);
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(tests(commands), expected);
    for (const item of commands.filter(item => item.command === 'cargo')) {
      for (const key of ['CARGO_TARGET_DIR', 'RUSTFLAGS', 'LLVM_PROFILE_FILE', 'RUSTUP_TOOLCHAIN']) {
        assert.equal(item.env[key], env[key], `scenario changed instrumentation: ${key}`);
      }
      assert.equal(item.env.YDB_ENDPOINT, scenario === 'isolated-deletion' ? 'grpc://127.0.0.1:2137' : env.YDB_ENDPOINT);
      if (scenario === 'isolated-deletion') assert.equal(item.env.ID_DISPOSABLE_YDB, 'true');
    }
    if (scenario === 'isolated-deletion') {
      assert.deepEqual(commands.at(-1).args, ['stop', ownedContainer]);
      const admin = commands.find(item => item.args.includes('admin_http_ydb'));
      for (const gate of ['ID_AUTH_ADMIN_READ_ENABLED', 'ID_AUTH_ADMIN_SUSPEND_ENABLED', 'ID_AUTH_ADMIN_CLIENT_REDIRECTS_ENABLED']) {
        assert.equal(admin.env[gate], 'true');
      }
      assert.equal(admin.env.ID_EXPORT_TEST_REAL_S3, 'false');
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
  console.log('PASS: shared scenario commands, local DB isolation, instrumentation inheritance and owned-container cleanup');
} finally {
  fs.rmSync(directory, { recursive: true, force: true });
}
