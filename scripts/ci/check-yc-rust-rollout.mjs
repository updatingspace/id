#!/usr/bin/env node
// Read-only preflight and post-deployment proof for all five Rust revisions.
import { execFileSync } from 'node:child_process';

const digest = (value) => /^sha256:[0-9a-f]{64}$/.test(value ?? '');
const container = (value) => /^bba[a-z0-9]{17}$/.test(value ?? '');
const registry = process.env.REGISTRY_ID;
const buildId = process.env.DEPLOY_SHA;
const logGroupId = process.env.ID_LOG_GROUP_ID;
const deployed = process.argv[2] === '--deployed';
if (process.argv.length > (deployed ? 3 : 2)) {
  throw new Error('usage: check-yc-rust-rollout.mjs [--deployed]');
}
const services = [
  ['api', process.env.RUST_API_CONTAINER_ID, 'api', process.env.API_DIGEST],
  ['sessions', process.env.RUST_SESSIONS_CONTAINER_ID, 'api', process.env.API_DIGEST],
  ['mutations', process.env.RUST_MUTATIONS_CONTAINER_ID, 'api', process.env.API_DIGEST],
  ['web', process.env.RUST_WEB_CONTAINER_ID, 'web', process.env.WEB_DIGEST],
  ['jobs', process.env.RUST_JOBS_CONTAINER_ID, 'jobs', process.env.JOBS_DIGEST],
];
if (!/^[a-z0-9]+$/.test(registry ?? '') || !/^[0-9a-f]{40}$/.test(buildId ?? '') ||
    (logGroupId !== undefined && !/^e23[a-z0-9]{17}$/.test(logGroupId)) ||
    services.some(([, id, , imageDigest]) => !container(id) || !digest(imageDigest)) ||
    new Set(services.map(([, id]) => id)).size !== services.length) {
  throw new Error('rollout preflight requires five distinct container IDs, three image digests, registry ID and tested SHA');
}

for (const [name, id, imageName, imageDigest] of services) {
  const revisions = JSON.parse(execFileSync('yc', [
    'serverless', 'container', 'revision', 'list', '--container-id', id, '--format', 'json',
  ], { encoding: 'utf8', maxBuffer: 4 * 1024 * 1024 }));
  const active = revisions.filter((revision) => revision.status === 'ACTIVE');
  if (active.length !== 1) throw new Error(`${name}: expected one active revision, found ${active.length}`);
  const image = `cr.yandex/${registry}/updatingspace-id-${imageName}@${imageDigest}`;
  if (deployed) {
    const actual = active[0].image;
    const repository = `cr.yandex/${registry}/updatingspace-id-${imageName}`;
    if (actual?.image_digest !== imageDigest ||
        !new RegExp(`^${repository.replaceAll('.', '\\.')}(:[A-Za-z0-9._-]+|@sha256:[0-9a-f]{64})$`).test(actual.image_url ?? '') ||
        actual.environment?.BUILD_ID !== buildId ||
        (logGroupId && active[0].log_options?.log_group_id !== logGroupId)) {
      throw new Error(`${name}: active Rust image, tested SHA or log group differs from deployment`);
    }
    console.log(`${name}: active tested Rust image verified`);
    continue;
  }
  const output = execFileSync('node', [
    'scripts/ci/deploy-yc-rust-revision.mjs', id, active[0].id, image,
    '--set-env', `BUILD_ID=${buildId}`,
    ...(logGroupId ? ['--log-group-id', logGroupId] : []),
  ], { encoding: 'utf8', maxBuffer: 4 * 1024 * 1024 });
  const plan = JSON.parse(output);
  if (plan.apply !== false || plan.container_id !== id || plan.source_revision !== active[0].id ||
      plan.target_image !== image || !plan.environment_keys.includes('BUILD_ID') ||
      (logGroupId && plan.log_group_id !== logGroupId)) {
    throw new Error(`${name}: dry-run revision plan differs from the tested deployment`);
  }
  console.log(`${name}: active revision and clone configuration ready`);
}
