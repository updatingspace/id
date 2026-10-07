#!/usr/bin/env node
// Exercise the production rollback helpers against a disposable YC CLI double.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, chmodSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const scratch = mkdtempSync(join(tmpdir(), 'id-rust-rollback-'));
const statePath = join(scratch, 'yc-state.json');
const manifestPath = join(scratch, 'revisions.json');
const oldDigest = `sha256:${'a'.repeat(64)}`;
const newDigest = `sha256:${'b'.repeat(64)}`;
const oldBuild = '1'.repeat(40);
const newBuild = '2'.repeat(40);
const names = ['api', 'sessions', 'mutations', 'web', 'jobs'];
const ids = names.map((_, index) => `bba${String.fromCharCode(97 + index).repeat(17)}`);
const revisions = ids.map((id, index) => ({
  id: `bba${String.fromCharCode(102 + index).repeat(17)}`,
  container_id: id,
  created_at: '2026-10-01T00:00:00Z',
  status: 'ACTIVE',
  image: { image_url: 'cr.yandex/registry/updatingspace-id-api:old', image_digest: oldDigest,
    environment: { BUILD_ID: oldBuild, ID_EXPORT_DELAYED_ROLLOUT_ENABLED: 'false' } },
  resources: { memory: '536870912', cores: '1', core_fraction: '100' },
  execution_timeout: '60s', concurrency: '4', service_account_id: 'operator-sa',
  runtime: { http: {} }, connectivity: { network_id: 'enp-test-network' },
  metadata_options: { gce_http_endpoint: 'ENABLED' },
  log_options: { log_group_id: 'e23-test-log-group' },
  secrets: [{ id: 'e6' + 'a'.repeat(18), version_id: 'e6' + 'b'.repeat(18),
    key: 'ID_EXPORT_OPERATION_KEY', environment_variable: 'ID_EXPORT_OPERATION_KEY' }],
}));
const writeState = (value) => writeFileSync(statePath, JSON.stringify(value));
const readState = () => JSON.parse(readFileSync(statePath, 'utf8'));
writeState({ revisions, next: 1 });
writeFileSync(join(scratch, 'yc'), String.raw`#!/usr/bin/env node
const fs = require('node:fs');
const statePath = process.env.ID_FAKE_YC_STATE;
const state = JSON.parse(fs.readFileSync(statePath, 'utf8'));
const args = process.argv.slice(2);
if (args.slice(0, 3).join(' ') !== 'serverless container revision') process.exit(3);
const command = args[3];
const value = name => args[args.indexOf(name) + 1];
if (command === 'list') {
  console.log(JSON.stringify(state.revisions.filter(row => row.container_id === value('--container-id'))));
} else if (command === 'get') {
  const row = state.revisions.find(item => item.id === args[4]);
  if (!row) process.exit(4);
  console.log(JSON.stringify(row));
} else if (command === 'deploy') {
  const containerId = value('--container-id');
  const image = value('--image');
  const environment = Object.fromEntries(value('--environment').split(',').map(entry => {
    const split = entry.indexOf('=');
    return [entry.slice(0, split), entry.slice(split + 1)];
  }));
  const secrets = [];
  for (let i = 0; i < args.length; i++) if (args[i] === '--secret') {
    secrets.push(Object.fromEntries(args[i + 1].split(',').map(entry => {
      const split = entry.indexOf('=');
      const key = entry.slice(0, split).replaceAll('-', '_');
      return [key, entry.slice(split + 1)];
    })));
  }
  for (const row of state.revisions) if (row.container_id === containerId) row.status = 'OBSOLETE';
  const row = {
    id: 'bba' + String(state.next++).padStart(17, '0'), container_id: containerId,
    created_at: new Date().toISOString(), status: 'ACTIVE',
    description: value('--description'),
    image: { image_url: image, image_digest: image.split('@')[1], environment },
    secrets, runtime: { http: {} }, resources: { memory: value('--memory'),
      cores: value('--cores'), core_fraction: value('--core-fraction') },
    execution_timeout: value('--execution-timeout'), concurrency: value('--concurrency'),
    service_account_id: value('--service-account-id'),
    connectivity: { network_id: value('--network-id') },
    log_options: { log_group_id: value('--log-group-id') },
  };
  state.revisions.push(row);
  fs.writeFileSync(statePath, JSON.stringify(state));
  console.log(JSON.stringify(row));
} else process.exit(5);
`);
chmodSync(join(scratch, 'yc'), 0o700);

const env = { ...process.env, PATH: `${scratch}:${process.env.PATH}`, ID_FAKE_YC_STATE: statePath,
  DEPLOY_SHA: newBuild, REGISTRY_ID: 'registry',
  API_DIGEST: newDigest, WEB_DIGEST: newDigest, JOBS_DIGEST: newDigest,
  RUST_API_CONTAINER_ID: ids[0], RUST_SESSIONS_CONTAINER_ID: ids[1],
  RUST_MUTATIONS_CONTAINER_ID: ids[2], RUST_WEB_CONTAINER_ID: ids[3], RUST_JOBS_CONTAINER_ID: ids[4] };
function run(args, success = true) {
  const result = spawnSync(process.execPath, args, { cwd: new URL('../..', import.meta.url).pathname,
    env, encoding: 'utf8' });
  assert.equal(result.status === 0, success, `${args.join(' ')}\n${result.stdout}\n${result.stderr}`);
  return result;
}
try {
  const ambiguous = readState();
  ambiguous.revisions.push({ ...structuredClone(ambiguous.revisions[0]), id: `bba${'z'.repeat(17)}` });
  writeState(ambiguous);
  run(['scripts/ci/check-yc-rust-rollout.mjs'], false);
  run(['scripts/ci/rollback-yc-rust-revisions.mjs', 'capture', manifestPath], false);
  writeState({ revisions, next: 1 });
  run(['scripts/ci/check-yc-rust-rollout.mjs']);
  run(['scripts/ci/rollback-yc-rust-revisions.mjs', 'capture', manifestPath]);
  const rotation = ['scripts/ci/deploy-yc-rust-revision.mjs', ids[0], revisions[0].id,
    `cr.yandex/registry/updatingspace-id-api@${oldDigest}`,
    '--replace-secret-version', `${'e6' + 'a'.repeat(18)}:${'e6' + 'b'.repeat(18)}:${'e6' + 'c'.repeat(18)}`];
  run([...rotation, '--apply']);
  const rotated = readState().revisions.findLast(row => row.container_id === ids[0] && row.status === 'ACTIVE');
  assert.equal(rotated.secrets[0].version_id, 'e6' + 'c'.repeat(18));
  run([...rotation, '--apply'], false);
  writeState({ revisions, next: 1 });
  for (const [index, id] of ids.entries()) {
    const imageName = index === 3 ? 'web' : index === 4 ? 'jobs' : 'api';
    const args = ['scripts/ci/deploy-yc-rust-revision.mjs', id, revisions[index].id,
      `cr.yandex/registry/updatingspace-id-${imageName}@${newDigest}`,
      '--set-env', `BUILD_ID=${newBuild}`, '--set-env', 'ID_EXPORT_DELAYED_ROLLOUT_ENABLED=true'];
    if ([0, 2, 4].includes(index)) args.push('--add-secret',
      `${'e6' + 'c'.repeat(18)}:${'e6' + 'd'.repeat(18)}:ID_EXPORT_ESCROW_KEY:ID_EXPORT_ESCROW_KEY`);
    run([...args, '--apply']);
  }
  const deployed = readState();
  run(['scripts/ci/check-yc-rust-rollout.mjs', '--deployed']);
  for (const [index, id] of ids.entries()) {
    const active = deployed.revisions.findLast(row => row.container_id === id && row.status === 'ACTIVE');
    assert.equal(active.image.environment.ID_EXPORT_DELAYED_ROLLOUT_ENABLED, 'true');
    assert.equal(active.image.environment.BUILD_ID, newBuild);
    assert.equal(active.secrets.some(secret => secret.environment_variable === 'ID_EXPORT_ESCROW_KEY'),
      [0, 2, 4].includes(index));
  }
  const wrongImage = readState();
  wrongImage.revisions.findLast(row => row.container_id === ids[3] && row.status === 'ACTIVE')
    .image.image_url = `cr.yandex/registry/updatingspace-id-api@${newDigest}`;
  writeState(wrongImage);
  run(['scripts/ci/check-yc-rust-rollout.mjs', '--deployed'], false);
  writeState(deployed);
  run(['scripts/ci/rollback-yc-rust-revisions.mjs', 'rollback', manifestPath]);
  const restored = readState();
  for (const [index, id] of ids.entries()) {
    const active = restored.revisions.filter(row => row.container_id === id && row.status === 'ACTIVE');
    assert.equal(active.length, 1);
    assert.equal(active[0].image.image_digest, oldDigest);
    assert.deepEqual(active[0].image.environment, revisions[index].image.environment);
    assert.deepEqual(active[0].secrets, revisions[index].secrets);
    assert.deepEqual(active[0].connectivity, revisions[index].connectivity);
    assert.deepEqual(active[0].log_options, revisions[index].log_options);
  }
  writeState(deployed);
  const outsider = readState();
  const api = outsider.revisions.findLast(row => row.container_id === ids[0] && row.status === 'ACTIVE');
  api.image.image_digest = `sha256:${'c'.repeat(64)}`;
  writeState(outsider);
  run(['scripts/ci/rollback-yc-rust-revisions.mjs', 'rollback', manifestPath], false);
  assert.deepEqual(readState(), outsider, 'preflight must not partially restore other containers');
  console.log('PASS: rollback restores prior image, flags and secret bindings; unrelated revisions are refused');
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
