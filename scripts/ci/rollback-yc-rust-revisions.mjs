#!/usr/bin/env node
// Capture non-secret revision identities; restore only images deployed by this run.
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, chmodSync } from 'node:fs';

const [mode, manifestPath] = process.argv.slice(2);
const services = [
  ['api', process.env.RUST_API_CONTAINER_ID, process.env.API_DIGEST],
  ['sessions', process.env.RUST_SESSIONS_CONTAINER_ID, process.env.API_DIGEST],
  ['mutations', process.env.RUST_MUTATIONS_CONTAINER_ID, process.env.API_DIGEST],
  ['web', process.env.RUST_WEB_CONTAINER_ID, process.env.WEB_DIGEST],
  ['jobs', process.env.RUST_JOBS_CONTAINER_ID, process.env.JOBS_DIGEST],
];
if (!['capture', 'rollback'].includes(mode) || !manifestPath ||
    services.some(([, id, digest]) => !/^bba[a-z0-9]{17}$/.test(id ?? '') || !/^sha256:[0-9a-f]{64}$/.test(digest ?? ''))) {
  throw new Error('usage: rollback-yc-rust-revisions.mjs capture|rollback MANIFEST with container IDs and image digests in environment');
}

function yc(args) {
  return JSON.parse(execFileSync('yc', args, {
    encoding: 'utf8',
    maxBuffer: 4 * 1024 * 1024,
    env: { ...process.env, YC_CLI_INITIALIZATION_SILENCE: 'true' },
  }));
}
function active(containerId) {
  const revisions = yc(['serverless', 'container', 'revision', 'list', '--container-id', containerId, '--format', 'json']);
  const latest = revisions.filter((revision) => revision.status === 'ACTIVE')
    .sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at))[0];
  if (!latest) throw new Error(`no active revision for ${containerId}`);
  return yc(['serverless', 'container', 'revision', 'get', latest.id, '--format', 'json']);
}

if (mode === 'capture') {
  const manifest = services.map(([name, id, deployedDigest]) => {
    const revision = active(id);
    const imageUrl = revision.image?.image_url;
    const imageDigest = revision.image?.image_digest;
    if (revision.container_id !== id || !/^cr\.yandex\/[a-z0-9]+\/[a-z0-9-]+(?::[A-Za-z0-9._-]+|@sha256:[0-9a-f]{64})$/.test(imageUrl ?? '') ||
        !/^sha256:[0-9a-f]{64}$/.test(imageDigest ?? '')) {
      throw new Error(`cannot capture active ${name} revision`);
    }
    return { name, id, imageUrl, imageDigest, buildId: revision.image.environment?.BUILD_ID ?? '', deployedDigest };
  });
  writeFileSync(manifestPath, JSON.stringify(manifest), { mode: 0o600 });
  chmodSync(manifestPath, 0o600);
  console.log('Captured previous Rust revision identities.');
} else {
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  for (const previous of manifest.reverse()) {
    const current = active(previous.id);
    if (current.image.image_digest === previous.imageDigest) continue;
    if (current.image.image_digest !== previous.deployedDigest) {
      throw new Error(`refusing rollback of ${previous.name}: image changed outside this deployment`);
    }
    const repository = previous.imageUrl.match(/^(.+?)(?::[^:@]+|@sha256:[0-9a-f]{64})$/u)?.[1];
    if (!repository) throw new Error(`invalid previous ${previous.name} image URL`);
    const image = `${repository}@${previous.imageDigest}`;
    const args = [
      'scripts/ci/deploy-yc-rust-revision.mjs',
      previous.id,
      current.id,
      image,
      '--set-env',
      `BUILD_ID=${previous.buildId}`,
      '--apply',
    ];
    execFileSync('node', args, { stdio: 'inherit' });
    console.log(`Restored previous ${previous.name} image digest.`);
  }
}
