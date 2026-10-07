#!/usr/bin/env node
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const temporary = mkdtempSync(join(tmpdir(), 'id-deletion-gate-'));
const ids = {
  api: `bba${'a'.repeat(17)}`,
  jobs: `bba${'b'.repeat(17)}`,
  gateway: `d5${'c'.repeat(18)}`,
};
const build = 'd'.repeat(40);

const fakeYc = `#!/usr/bin/env node
const ids = ${JSON.stringify(ids)};
const build = ${JSON.stringify(build)};
const scenario = process.env.MOCK_SCENARIO;
const args = process.argv.slice(2);
const respond = value => process.stdout.write(JSON.stringify(value));
if (args.includes('revision') && args.includes('list')) {
  const role = args[args.indexOf('--container-id') + 1] === ids.api ? 'api' : 'jobs';
  const enabled = scenario === 'enabled' || scenario === 'wrong-key' || scenario === 'wrong-timer'
    || scenario === role + '-only';
  respond([{ status: 'ACTIVE', image: { environment: {
    BUILD_ID: build,
    ...(role === 'api' ? {
      ID_AUTH_DELETION_ROLLOUT_ENABLED: enabled ? 'true' : 'false',
      ID_EXPORT_DELAYED_ROLLOUT_ENABLED: 'true',
    } : {
      ID_DELETION_JOBS_ROLLOUT_ENABLED: enabled ? 'true' : 'false',
      ID_EXPORT_ESCROW_JOBS_ROLLOUT_ENABLED: 'true', ID_JOBS_HTTP_ENABLED: 'true',
    }),
  } }, secrets: role === 'api' && enabled ? [{
    environment_variable: 'ID_DELETION_OPERATION_KEY', id: 'secret', version_id: 'version',
    key: scenario === 'wrong-key' ? 'ID_EXPORT_OPERATION_KEY' : 'ID_DELETION_OPERATION_KEY',
  }] : [] }]);
} else if (args.includes('trigger') && args.includes('list')) {
  respond(['disabled', 'api-only', 'jobs-only', 'route-only'].includes(scenario) ? [] : [{
    name: 'updspace-id-rust-deletion-recovery', status: 'ACTIVE', rule: { timer: {
      invoke_container_with_retry: {
        container_id: ids.jobs, service_account_id: 'scheduler',
        path: scenario === 'wrong-timer' ? '/internal/jobs/wrong' : '/internal/jobs/recover-deletion',
      },
    } },
  }]);
} else if (args.includes('api-gateway') && args.includes('get-spec')) {
  const route = ['enabled', 'wrong-key', 'wrong-timer', 'route-only'].includes(scenario);
  respond({ openapi_spec: route ? 'paths:\\n  /api/v1/auth/account/deletions:\\n    post:\\n      x-yc-apigateway-integration:\\n        container_id: ' + ids.api + '\\n' : 'paths:\\n  /health:\\n    get:\\n' });
} else process.exit(2);
`;

try {
  const executable = join(temporary, 'yc');
  writeFileSync(executable, fakeYc);
  chmodSync(executable, 0o755);
  const run = (scenario, expectedBuild = build) => spawnSync(process.execPath,
    [join(here, 'check-yc-account-deletion.mjs'), '--if-enabled'], {
      encoding: 'utf8',
      env: { ...process.env, PATH: `${temporary}${delimiter}${process.env.PATH}`,
        RUST_MUTATIONS_CONTAINER_ID: ids.api, RUST_JOBS_CONTAINER_ID: ids.jobs,
        ID_GATEWAY_ID: ids.gateway, EXPECTED_BUILD_ID: expectedBuild,
        MOCK_SCENARIO: scenario },
    });
  const disabled = run('disabled', '');
  assert.equal(disabled.status, 0, JSON.stringify({ stdout: disabled.stdout, stderr: disabled.stderr, error: disabled.error?.message }));
  assert.equal(disabled.stdout.trim(), 'disabled');
  for (const [scenario, expected] of [
    ['api-only', /jobs: ID_DELETION_JOBS_ROLLOUT_ENABLED is not true/],
    ['jobs-only', /api: ID_AUTH_DELETION_ROLLOUT_ENABLED is not true/],
    ['route-only', /deletion recovery timer is not uniquely active/],
    ['wrong-key', /versioned ID_DELETION_OPERATION_KEY binding is required/],
    ['wrong-timer', /timer does not target private Rust jobs/],
  ]) {
    const result = run(scenario);
    assert.equal(result.status, 1, `${scenario}: ${result.stderr}`);
    assert.match(result.stderr, expected);
  }
  const enabled = run('enabled');
  assert.equal(enabled.status, 0, enabled.stderr);
  assert.equal(enabled.stdout.trim(), 'enabled');
  console.log('PASS: deletion gate skips disabled, rejects partial, accepts aligned revisions');
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
