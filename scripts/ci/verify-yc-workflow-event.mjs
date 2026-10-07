#!/usr/bin/env node
// Trust GitHub's successful workflow_run event for this exact checked-out SHA.
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

const fail = (reason) => {
  console.error(`Deployment revision verification failed: ${reason}`);
  process.exit(1);
};

if (process.env.GITHUB_EVENT_NAME !== 'workflow_run') fail('expected a completed CI workflow event');
const sha = process.env.DEPLOY_SHA;
if (!/^[0-9a-f]{40}$/.test(sha ?? '')) fail('DEPLOY_SHA must be a full commit SHA');
const repository = process.env.GITHUB_REPOSITORY;
if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository ?? '')) fail('invalid repository');

let event;
try {
  event = JSON.parse(readFileSync(process.env.GITHUB_EVENT_PATH, 'utf8'));
} catch {
  fail('workflow event payload is missing or invalid');
}
const run = event.workflow_run;
if (!run || run.head_repository?.full_name !== repository ||
    run.head_sha !== sha || run.event !== 'push' ||
    !['main', 'master'].includes(run.head_branch) ||
    run.status !== 'completed' || run.conclusion !== 'success' ||
    run.path?.split('@')[0] !== '.github/workflows/ci-cd.yml' ||
    !Number.isSafeInteger(run.id) || run.id <= 0) {
  fail('event is not a successful push CI run for this repository and SHA on main/master');
}

const checkout = execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
if (checkout !== sha) fail('checked-out source differs from tested SHA');
console.log(`Verified successful CI workflow event ${run.id} for ${sha}.`);
