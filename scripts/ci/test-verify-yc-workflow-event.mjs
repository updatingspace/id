#!/usr/bin/env node
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const sha = execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
const directory = mkdtempSync(join(tmpdir(), 'id-workflow-event-'));
const eventPath = join(directory, 'event.json');
const valid = {
  workflow_run: {
    id: 10,
    head_repository: { full_name: 'updatingspace/id' },
    head_sha: sha,
    head_branch: 'main',
    event: 'push',
    status: 'completed',
    conclusion: 'success',
    path: '.github/workflows/ci-cd.yml@refs/heads/main',
  },
};

const check = (event, overrides = {}) => {
  writeFileSync(eventPath, JSON.stringify(event));
  return spawnSync(process.execPath, ['scripts/ci/verify-yc-workflow-event.mjs'], {
    encoding: 'utf8',
    env: {
      ...process.env,
      GITHUB_EVENT_NAME: 'workflow_run',
      GITHUB_REPOSITORY: 'updatingspace/id',
      GITHUB_EVENT_PATH: eventPath,
      DEPLOY_SHA: sha,
      ...overrides,
    },
  });
};

try {
  assert.equal(check(valid).status, 0);
  for (const field of ['head_sha', 'head_branch', 'event', 'status', 'conclusion', 'path', 'id']) {
    const bad = structuredClone(valid);
    bad.workflow_run[field] = field === 'id' ? 0 : 'invalid';
    assert.equal(check(bad).status, 1, field);
  }
  const wrongRepo = structuredClone(valid);
  wrongRepo.workflow_run.head_repository.full_name = 'other/id';
  assert.equal(check(wrongRepo).status, 1);
  assert.equal(check(valid, { DEPLOY_SHA: 'a'.repeat(40) }).status, 1);
  assert.equal(check(valid, { GITHUB_EVENT_NAME: 'workflow_dispatch' }).status, 1);
  console.log('PASS: deployment requires a successful CI event for the checked-out SHA');
} finally {
  rmSync(directory, { recursive: true, force: true });
}
