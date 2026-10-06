#!/usr/bin/env node
// Read-only gate for enabling delayed export. Never print secret values or IDs.
import { execFileSync } from 'node:child_process';

const containerIds = {
  api: process.env.RUST_MUTATIONS_CONTAINER_ID,
  web: process.env.RUST_WEB_CONTAINER_ID,
  jobs: process.env.RUST_JOBS_CONTAINER_ID,
};
const expectedBuild = process.env.EXPECTED_BUILD_ID;
const origin = process.env.ID_EXPORT_PUBLIC_ORIGIN ?? 'https://id.updspace.com';
const issues = [];
if (!/^[0-9a-f]{40}$/.test(expectedBuild ?? '')) {
  issues.push('EXPECTED_BUILD_ID must be the tested 40-character commit SHA');
}

function yc(...args) {
  return JSON.parse(execFileSync('yc', [...args, '--format', 'json'], {
    encoding: 'utf8', maxBuffer: 4 * 1024 * 1024,
    env: { ...process.env, YC_CLI_INITIALIZATION_SILENCE: 'true' },
  }));
}

function activeRevision(role, id) {
  if (!/^bba[a-z0-9]{17}$/.test(id ?? '')) {
    issues.push(`${role}: container ID is missing or malformed`);
    return null;
  }
  const revisions = yc('serverless', 'container', 'revision', 'list', '--container-id', id);
  const active = revisions.filter(row => row.status === 'ACTIVE');
  if (active.length !== 1) {
    issues.push(`${role}: expected one active revision, found ${active.length}`);
    return null;
  }
  return active[0];
}

function flag(role, revision, name) {
  if (revision?.image?.environment?.[name] !== 'true') issues.push(`${role}: ${name} is not true`);
}

function escrowBinding(role, revision) {
  const bindings = (revision?.secrets ?? []).filter(item => item.environment_variable === 'ID_EXPORT_ESCROW_KEY');
  if (bindings.length !== 1 || !bindings[0].id || !bindings[0].version_id || !bindings[0].key) {
    issues.push(`${role}: exactly one versioned ID_EXPORT_ESCROW_KEY binding is required`);
    return null;
  }
  return bindings[0];
}

try {
  const api = activeRevision('api', containerIds.api);
  const web = activeRevision('web', containerIds.web);
  const jobs = activeRevision('jobs', containerIds.jobs);
  for (const name of ['ID_EXPORT_API_ROLLOUT_ENABLED', 'ID_EXPORT_DELAYED_ROLLOUT_ENABLED', 'ID_RUST_EARLY_ROLLOUT_ENABLED']) flag('api', api, name);
  for (const name of ['ID_WEB_EXPORTS_ENABLED', 'ID_WEB_EXPORT_REDEEM_ENABLED']) flag('web', web, name);
  for (const name of ['ID_EXPORT_JOBS_ENABLED', 'ID_EXPORT_ESCROW_JOBS_ROLLOUT_ENABLED', 'ID_EXPORT_ESCROW_MAIL_ROLLOUT_ENABLED', 'ID_JOBS_HTTP_ENABLED']) flag('jobs', jobs, name);
  const apiKey = escrowBinding('api', api);
  const jobsKey = escrowBinding('jobs', jobs);
  if (apiKey && jobsKey && ['id', 'version_id', 'key'].some(name => apiKey[name] !== jobsKey[name])) {
    issues.push('api/jobs: escrow key bindings differ');
  }
  const apiBucket = api?.image?.environment?.ID_EXPORT_S3_BUCKET_NAME;
  const jobsBucket = jobs?.image?.environment?.ID_EXPORT_S3_BUCKET_NAME;
  if (!apiBucket || apiBucket !== jobsBucket) issues.push('api/jobs: private export bucket differs or is unset');
  if (jobs?.image?.environment?.ID_EXPORT_PUBLIC_ORIGIN !== origin) issues.push('jobs: public export origin differs');
  if (/^[0-9a-f]{40}$/.test(expectedBuild ?? '')) {
    for (const [role, revision] of Object.entries({ api, web, jobs })) {
      if (revision?.image?.environment?.BUILD_ID !== expectedBuild) issues.push(`${role}: BUILD_ID differs from tested revision`);
    }
  }
  const triggers = yc('serverless', 'trigger', 'list');
  const timer = triggers.filter(row => row.name === 'updspace-id-rust-export-recovery' && row.status === 'ACTIVE');
  if (timer.length !== 1) issues.push('export recovery timer is not uniquely active');
  else {
    const target = timer[0].rule?.timer?.invoke_container_with_retry;
    if (target?.container_id !== containerIds.jobs || target?.path !== '/internal/jobs/recover-export') {
      issues.push('export recovery timer does not target Rust jobs export recovery');
    }
  }
} catch (error) {
  issues.push(`YC read failed: ${error instanceof Error ? error.message.split('\n')[0] : 'unknown error'}`);
}

if (issues.length) {
  for (const issue of issues) console.error(`NOT READY: ${issue}`);
  process.exitCode = 1;
} else {
  console.log('Delayed export revisions, escrow key, bucket and timer are aligned. Run end-to-end checks before traffic.');
}
