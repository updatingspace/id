#!/usr/bin/env node
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const temporary = mkdtempSync(join(tmpdir(), 'id-delayed-gate-'));
const ids = {
  api: `bba${'a'.repeat(17)}`,
  web: `bba${'b'.repeat(17)}`,
  jobs: `bba${'c'.repeat(17)}`,
  gateway: `d5${'d'.repeat(18)}`,
};
const build = 'e'.repeat(40);

const fakeYc = `#!/usr/bin/env node
const ids = ${JSON.stringify(ids)};
const build = ${JSON.stringify(build)};
const scenario = process.env.MOCK_SCENARIO;
const args = process.argv.slice(2);
const response = (value) => process.stdout.write(JSON.stringify(value));
if (args.includes('revision') && args.includes('list')) {
  const role = Object.keys(ids).find(key => ids[key] === args[args.indexOf('--container-id') + 1]);
  if (!role || role === 'gateway') process.exit(2);
  const enabled = scenario === 'enabled' || (scenario === 'partial' && role === 'api');
  const environment = role === 'api' ? {
    BUILD_ID: build, ID_EXPORT_API_ROLLOUT_ENABLED: 'true', ID_RUST_EARLY_ROLLOUT_ENABLED: 'true',
    ID_EXPORT_DELAYED_ROLLOUT_ENABLED: enabled ? 'true' : 'false', ID_EXPORT_S3_BUCKET_NAME: 'test-bucket',
  } : role === 'web' ? {
    BUILD_ID: build, ID_WEB_EXPORTS_ENABLED: 'true', ID_WEB_EXPORT_REDEEM_ENABLED: enabled ? 'true' : 'false',
  } : {
    BUILD_ID: build, ID_EXPORT_JOBS_ENABLED: 'true', ID_JOBS_HTTP_ENABLED: 'true',
    ID_EXPORT_ESCROW_JOBS_ROLLOUT_ENABLED: enabled ? 'true' : 'false',
    ID_EXPORT_ESCROW_MAIL_ROLLOUT_ENABLED: enabled ? 'true' : 'false',
    ID_EXPORT_S3_BUCKET_NAME: 'test-bucket', ID_EXPORT_PUBLIC_ORIGIN: 'https://id.updspace.com',
  };
  response([{ status: 'ACTIVE', image: { environment }, secrets: enabled ? [{
    environment_variable: 'ID_EXPORT_ESCROW_KEY', id: 'secret', version_id: 'version', key: 'ID_EXPORT_ESCROW_KEY',
  }] : [] }]);
} else if (args.includes('trigger') && args.includes('list')) {
  if (scenario === 'disabled') process.exit(3);
  response([{ name: 'updspace-id-rust-export-recovery', status: 'ACTIVE', rule: {
    timer: { invoke_container_with_retry: { container_id: ids.jobs, path: '/internal/jobs/recover-export' } },
  } }]);
} else if (args.includes('api-gateway') && args.includes('get-spec')) {
  if (scenario === 'disabled') process.exit(3);
  const api = [
    ['/api/v1/auth/data/exports', 'post'], ['/api/v1/auth/data/exports/{id}', 'get'],
    ['/api/v1/auth/data/exports/{id}', 'delete'], ['/api/v1/auth/data/exports/{id}/download', 'get'],
    ['/api/v1/auth/data/exports/{id}/redeem', 'post'], ['/api/v1/auth/data/exports/{id}/cancel', 'post'],
  ];
  const web = [['/data/export', 'get'], ['/data/export/cancel', 'get'], ['/_id/{file+}', 'get']];
  const operations = [...api.map(([path, method]) => [path, method, ids.api]),
    ...web.map(([path, method]) => [path, method, ids.web])];
  const paths = [...new Set(operations.map(([path]) => path))];
  const spec = 'paths:\\n' + paths.map(path =>
    '  ' + path + ':\\n' + operations.filter(([candidate]) => candidate === path).map(([, method, id]) =>
      '    ' + method + ':\\n      x-yc-apigateway-integration:\\n        container_id: ' + id + '\\n').join('')).join('');
  response({ openapi_spec: spec });
} else process.exit(2);
`;

try {
  const executable = join(temporary, 'yc');
  writeFileSync(executable, fakeYc);
  chmodSync(executable, 0o755);
  const run = (scenario, expectedBuild) => spawnSync(process.execPath,
    [join(here, 'check-yc-delayed-export.mjs'), '--if-enabled'], {
      encoding: 'utf8',
      env: { ...process.env, PATH: `${temporary}${delimiter}${process.env.PATH}`,
        RUST_MUTATIONS_CONTAINER_ID: ids.api, RUST_WEB_CONTAINER_ID: ids.web,
        RUST_JOBS_CONTAINER_ID: ids.jobs, ID_GATEWAY_ID: ids.gateway,
        MOCK_SCENARIO: scenario, EXPECTED_BUILD_ID: expectedBuild },
    });
  const disabled = run('disabled', '');
  assert.equal(disabled.status, 0, JSON.stringify({ stdout: disabled.stdout, stderr: disabled.stderr,
    error: disabled.error?.message, signal: disabled.signal }));
  assert.equal(disabled.stdout.trim(), 'disabled');
  const partial = run('partial', build);
  assert.equal(partial.status, 1);
  assert.match(partial.stderr, /web: ID_WEB_EXPORT_REDEEM_ENABLED is not true/);
  assert.match(partial.stderr, /jobs: ID_EXPORT_ESCROW_JOBS_ROLLOUT_ENABLED is not true/);
  const enabled = run('enabled', build);
  assert.equal(enabled.status, 0, JSON.stringify({ stdout: enabled.stdout, stderr: enabled.stderr }));
  assert.equal(enabled.stdout.trim(), 'enabled');
  console.log('PASS: delayed export gate skips disabled, rejects partial, accepts aligned revisions');
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
