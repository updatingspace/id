#!/usr/bin/env node
// Read-only preflight: prove that every serving Rust revision can be cloned
// with the exact image digest and build ID selected by this deployment.
import { execFileSync } from 'node:child_process';

const digest = (value) => /^sha256:[0-9a-f]{64}$/.test(value ?? '');
const container = (value) => /^bba[a-z0-9]{17}$/.test(value ?? '');
const registry = process.env.REGISTRY_ID;
const buildId = process.env.DEPLOY_SHA;
const services = [
  ['api', process.env.RUST_API_CONTAINER_ID, 'api', process.env.API_DIGEST],
  ['sessions', process.env.RUST_SESSIONS_CONTAINER_ID, 'api', process.env.API_DIGEST],
  ['mutations', process.env.RUST_MUTATIONS_CONTAINER_ID, 'api', process.env.API_DIGEST],
  ['web', process.env.RUST_WEB_CONTAINER_ID, 'web', process.env.WEB_DIGEST],
  ['jobs', process.env.RUST_JOBS_CONTAINER_ID, 'jobs', process.env.JOBS_DIGEST],
];
if (!/^[a-z0-9]+$/.test(registry ?? '') || !/^[0-9a-f]{40}$/.test(buildId ?? '') ||
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
  const output = execFileSync('node', [
    'scripts/ci/deploy-yc-rust-revision.mjs', id, active[0].id, image,
    '--set-env', `BUILD_ID=${buildId}`,
  ], { encoding: 'utf8', maxBuffer: 4 * 1024 * 1024 });
  const plan = JSON.parse(output);
  if (plan.apply !== false || plan.container_id !== id || plan.source_revision !== active[0].id ||
      plan.target_image !== image || !plan.environment_keys.includes('BUILD_ID')) {
    throw new Error(`${name}: dry-run revision plan differs from the tested deployment`);
  }
  console.log(`${name}: active revision and clone configuration ready`);
}
