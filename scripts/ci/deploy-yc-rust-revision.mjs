#!/usr/bin/env node
// Clone a verified Serverless Container revision without dropping its environment,
// secret bindings, limits, network, or service account. An inactive captured
// revision may be restored only while the expected new revision is still active.
// No secret values are printed.
import { execFileSync } from 'node:child_process';

function die(message) {
  console.error(message);
  process.exit(1);
}

const [containerId, sourceId, image, ...options] = process.argv.slice(2);
if (!/^bba[a-z0-9]{17}$/.test(containerId ?? '') ||
    !/^bba[a-z0-9]{17}$/.test(sourceId ?? '') ||
    !/^cr\.yandex\/[a-z0-9]+\/[a-z0-9-]+@sha256:[0-9a-f]{64}$/.test(image ?? '')) {
  die('usage: deploy-yc-rust-revision.mjs CONTAINER_ID SOURCE_REVISION IMAGE@sha256:DIGEST [--expect-active-revision REVISION_ID] [--set-env NAME=VALUE]... [--add-secret ID:VERSION:KEY:ENV] [--apply]');
}

let apply = false;
let expectedActiveId = sourceId;
let restoring = false;
const overrides = new Map();
const addedSecrets = [];
for (let i = 0; i < options.length; i++) {
  const option = options[i];
  if (option === '--apply') {
    apply = true;
  } else if (option === '--expect-active-revision') {
    const id = options[++i];
    if (restoring || !/^bba[a-z0-9]{17}$/.test(id ?? '')) die('invalid or duplicate --expect-active-revision');
    expectedActiveId = id;
    restoring = true;
  } else if (option === '--set-env') {
    const entry = options[++i] ?? '';
    const split = entry.indexOf('=');
    const name = entry.slice(0, split);
    const value = entry.slice(split + 1);
    if (split < 0 || !/^[A-Z][A-Z0-9_]*$/.test(name) || overrides.has(name) || /[,\r\n]/.test(value)) {
      die('invalid or duplicate --set-env entry');
    }
    overrides.set(name, value);
  } else if (option === '--add-secret') {
    const entry = options[++i] ?? '';
    const [id, versionId, key, environmentVariable, extra] = entry.split(':');
    if (extra !== undefined || !/^[a-z0-9]{20}$/.test(id ?? '') ||
        !/^[a-z0-9]{20}$/.test(versionId ?? '') ||
        !/^[A-Z][A-Z0-9_]*$/.test(key ?? '') ||
        !/^[A-Z][A-Z0-9_]*$/.test(environmentVariable ?? '')) {
      die('invalid --add-secret entry');
    }
    addedSecrets.push({ id, version_id: versionId, key, environment_variable: environmentVariable });
  } else {
    die(`unknown option: ${option}`);
  }
}
if (restoring && (overrides.size || addedSecrets.length)) {
  die('restoring a captured revision cannot override environment or secret bindings');
}

function yc(args) {
  return execFileSync('yc', args, {
    encoding: 'utf8',
    maxBuffer: 4 * 1024 * 1024,
    env: { ...process.env, YC_CLI_INITIALIZATION_SILENCE: 'true' },
  });
}

const revisions = JSON.parse(yc(['serverless', 'container', 'revision', 'list', '--container-id', containerId, '--format', 'json']));
const activeRevisions = revisions.filter((revision) => revision.status === 'ACTIVE');
if (activeRevisions.length !== 1) die(`expected one active revision, found ${activeRevisions.length}`);
const latest = activeRevisions[0];
if (latest?.id !== expectedActiveId) die(`active revision changed: expected ${expectedActiveId}, found ${latest?.id ?? 'none'}`);
const source = JSON.parse(yc(['serverless', 'container', 'revision', 'get', sourceId, '--format', 'json']));
if (source.container_id !== containerId || !source.runtime?.http || (!restoring && source.status !== 'ACTIVE')) {
  die('source revision does not match the expected HTTP container');
}
if (restoring && source.image?.image_digest !== image.split('@')[1]) {
  die('restore image digest differs from the captured source revision');
}
const environment = { ...source.image.environment, ...Object.fromEntries(overrides) };
for (const [name, value] of Object.entries(environment)) {
  if (!/^[A-Z][A-Z0-9_]*$/.test(name) || typeof value !== 'string' || /[,\r\n]/.test(value)) {
    die(`cannot safely encode environment variable ${name}`);
  }
}
const secrets = [...(source.secrets ?? []), ...addedSecrets];
const names = secrets.map((secret) => secret.environment_variable);
if (new Set(names).size !== names.length || names.some((name) => name in environment)) {
  die('duplicate secret binding or collision with environment');
}
const args = [
  'serverless', 'container', 'revision', 'deploy', '--container-id', containerId,
  '--image', image,
  '--memory', `${source.resources.memory}B`,
  '--cores', source.resources.cores,
  '--core-fraction', source.resources.core_fraction,
  '--execution-timeout', source.execution_timeout,
  '--concurrency', source.concurrency,
  '--service-account-id', source.service_account_id,
  '--runtime', 'http',
  '--environment', Object.entries(environment).map(([name, value]) => `${name}=${value}`).join(','),
  '--description', `Rust revision from ${sourceId}; ${image.slice(image.indexOf('@') + 1)}`,
  '--format', 'json',
];
for (const secret of secrets) {
  args.push('--secret', `id=${secret.id},version-id=${secret.version_id},key=${secret.key},environment-variable=${secret.environment_variable}`);
}
if (source.connectivity?.network_id) args.push('--network-id', source.connectivity.network_id);
if (source.metadata_options?.gce_http_endpoint) {
  args.push('--metadata-options', `gce-http-endpoint=${source.metadata_options.gce_http_endpoint.toLowerCase()}`);
}
if (source.metadata_options?.aws_v1_http_endpoint) {
  args.push('--metadata-options', `aws-v1-http-endpoint=${source.metadata_options.aws_v1_http_endpoint.toLowerCase()}`);
}
if (source.log_options?.folder_id) args.push('--log-folder-id', source.log_options.folder_id);
else if (source.log_options?.log_group_id) args.push('--log-group-id', source.log_options.log_group_id);
else if (source.log_options?.disabled) args.push('--no-logging');

console.log(JSON.stringify({
  container_id: containerId,
  source_revision: sourceId,
  expected_active_revision: expectedActiveId,
  target_image: image,
  environment_keys: Object.keys(environment).sort(),
  secret_environment_keys: names.sort(),
  apply,
}));
if (!apply) process.exit(0);
const deployed = JSON.parse(yc(args));
if (deployed.container_id !== containerId || deployed.image?.image_digest !== image.split('@')[1]) {
  die('deployment returned an unexpected container or image digest');
}
console.log(JSON.stringify({ revision_id: deployed.id, status: deployed.status, image_digest: deployed.image.image_digest }));
