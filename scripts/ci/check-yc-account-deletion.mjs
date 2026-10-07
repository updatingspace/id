#!/usr/bin/env node
// Read-only gate for the public deletion API and private recovery job.
import { execFileSync } from 'node:child_process';

const apiId = process.env.RUST_MUTATIONS_CONTAINER_ID;
const jobsId = process.env.RUST_JOBS_CONTAINER_ID;
const gatewayId = process.env.ID_GATEWAY_ID;
const expectedBuild = process.env.EXPECTED_BUILD_ID;
const conditional = process.argv[2] === '--if-enabled';
if (process.argv.length > (conditional ? 3 : 2)) {
  throw new Error('usage: check-yc-account-deletion.mjs [--if-enabled]');
}

const issues = [];
function yc(...args) {
  return JSON.parse(execFileSync('yc', [...args, '--format', 'json'], {
    encoding: 'utf8', maxBuffer: 4 * 1024 * 1024,
    env: { ...process.env, YC_CLI_INITIALIZATION_SILENCE: 'true' },
  }));
}
function active(role, id) {
  if (!/^bba[a-z0-9]{17}$/.test(id ?? '')) {
    issues.push(`${role}: container ID is missing or malformed`);
    return null;
  }
  const revisions = yc('serverless', 'container', 'revision', 'list', '--container-id', id);
  const current = revisions.filter(row => row.status === 'ACTIVE');
  if (current.length !== 1) {
    issues.push(`${role}: expected one active revision, found ${current.length}`);
    return null;
  }
  return current[0];
}
function routeContainer(spec, path, method) {
  const lines = spec.split(/\r?\n/);
  const start = lines.indexOf(`  ${path}:`);
  if (start < 0) return null;
  const end = lines.findIndex((line, index) => index > start && /^  \/[^\n]*:$/.test(line));
  const pathLines = lines.slice(start + 1, end < 0 ? undefined : end);
  const methodStart = pathLines.indexOf(`    ${method}:`);
  if (methodStart < 0) return null;
  const methodEnd = pathLines.findIndex((line, index) => index > methodStart && /^    [a-z-]+:$/.test(line));
  return pathLines.slice(methodStart + 1, methodEnd < 0 ? undefined : methodEnd)
    .find(line => line.startsWith('        container_id: '))?.slice('        container_id: '.length) ?? null;
}

try {
  const api = active('api', apiId);
  const jobs = active('jobs', jobsId);
  const triggers = yc('serverless', 'trigger', 'list');
  if (!/^d5[a-z0-9]{18}$/.test(gatewayId ?? '')) {
    issues.push('Gateway ID is missing or malformed');
  }
  const spec = /^d5[a-z0-9]{18}$/.test(gatewayId ?? '')
    ? yc('serverless', 'api-gateway', 'get-spec', '--id', gatewayId).openapi_spec
    : '';
  const route = typeof spec === 'string'
    ? routeContainer(spec, '/api/v1/auth/account/deletions', 'post') : null;
  const timer = triggers.filter(row => row.name === 'updspace-id-rust-deletion-recovery' && row.status === 'ACTIVE');
  const enabled = [
    api?.image?.environment?.ID_AUTH_DELETION_ROLLOUT_ENABLED,
    jobs?.image?.environment?.ID_DELETION_JOBS_ROLLOUT_ENABLED,
  ].includes('true') || route !== null || timer.length > 0;
  if (conditional && !enabled && issues.length === 0) {
    console.log('disabled');
    process.exit(0);
  }

  if (!/^[0-9a-f]{40}$/.test(expectedBuild ?? '')) issues.push('EXPECTED_BUILD_ID must be the tested commit SHA');
  for (const [role, revision, name] of [
    ['api', api, 'ID_AUTH_DELETION_ROLLOUT_ENABLED'],
    ['api', api, 'ID_EXPORT_DELAYED_ROLLOUT_ENABLED'],
    ['jobs', jobs, 'ID_DELETION_JOBS_ROLLOUT_ENABLED'],
    ['jobs', jobs, 'ID_EXPORT_ESCROW_JOBS_ROLLOUT_ENABLED'],
    ['jobs', jobs, 'ID_JOBS_HTTP_ENABLED'],
  ]) {
    if (revision?.image?.environment?.[name] !== 'true') issues.push(`${role}: ${name} is not true`);
  }
  for (const [role, revision] of [['api', api], ['jobs', jobs]]) {
    if (revision?.image?.environment?.BUILD_ID !== expectedBuild) issues.push(`${role}: BUILD_ID differs from tested revision`);
  }
  const bindings = (api?.secrets ?? []).filter(item => item.environment_variable === 'ID_DELETION_OPERATION_KEY');
  if (bindings.length !== 1 || !bindings[0].id || !bindings[0].version_id ||
      bindings[0].key !== 'ID_DELETION_OPERATION_KEY') {
    issues.push('api: exactly one versioned ID_DELETION_OPERATION_KEY binding is required');
  }
  if (route !== apiId) issues.push('Gateway: POST /api/v1/auth/account/deletions must target Rust mutations API');
  if (typeof spec !== 'string' || spec.includes('  /internal/jobs/recover-deletion:')) {
    issues.push('Gateway: private deletion recovery route must not be public');
  }
  if (timer.length !== 1) {
    issues.push('deletion recovery timer is not uniquely active');
  } else {
    const target = timer[0].rule?.timer?.invoke_container_with_retry;
    if (target?.container_id !== jobsId || target?.path !== '/internal/jobs/recover-deletion' ||
        !target?.service_account_id) {
      issues.push('deletion recovery timer does not target private Rust jobs');
    }
  }
} catch (error) {
  issues.push(`YC read failed: ${error instanceof Error ? error.message.split('\n')[0] : 'unknown error'}`);
}

if (issues.length) {
  for (const issue of issues) console.error(`NOT READY: ${issue}`);
  process.exitCode = 1;
} else {
  console.log(conditional ? 'enabled' : 'Deletion API, operation key, private recovery timer and jobs are aligned. Run end-to-end checks before traffic.');
}
