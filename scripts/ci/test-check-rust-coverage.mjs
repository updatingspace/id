#!/usr/bin/env node
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { checkCoverage, checkChildProfiles } from './check-rust-coverage.mjs';

const temporary = mkdtempSync(join(tmpdir(), 'id-coverage-check-'));
try {
  for (const name of ['critical.rs', 'support.rs']) writeFileSync(join(temporary, name), '// fixture\n');
  const profile = { version: 1, name: 'gate regression',
    thresholds: { lines: 85, branches: 80, critical_lines: 100, critical_branches: 100 },
    groups: [{ name: 'critical', critical: true, files: ['critical.rs'] },
      { name: 'support', critical: false, files: ['support.rs'] }] };
  const file = (name, lines, branches) => ({ filename: join(temporary, name), summary: {
    lines: { count: 100, covered: lines, percent: 100 },
    branches: { count: 100, covered: branches, percent: 100 },
    regions: { count: 100, covered: 100, percent: 100 } } });
  const report = { type: 'llvm.coverage.json.export', version: '3.1.0',
    data: [{ files: [file('critical.rs', 100, 100), file('support.rs', 70, 60)] }] };
  assert.equal(checkCoverage(report, profile, temporary).passed, true); // exactly 85/80
  const changed = change => { const copy = structuredClone(report); change(copy); return copy; };
  assert.equal(checkCoverage(changed(r => r.data[0].files[1].summary.branches.covered = 59), profile, temporary).passed, false);
  assert.equal(checkCoverage(changed(r => r.data[0].files[0].summary.lines.covered = 99), profile, temporary).passed, false);
  assert.equal(checkCoverage(changed(r => r.data[0].files[0].summary.branches.covered = 99), profile, temporary).passed, false);
  assert.throws(() => checkCoverage(changed(r => r.data[0].files.shift()), profile, temporary), /coverage file is missing/);
  assert.throws(() => checkCoverage(changed(r => delete r.data[0].files[0].summary.branches), profile, temporary), /missing or invalid branches/);
  assert.throws(() => checkCoverage(changed(r => r.data[0].files.forEach(f => f.summary.branches = { count: 0, covered: 0 })), profile, temporary), /no aggregate branches/);
  assert.throws(() => checkCoverage(changed(r => r.version = 'unknown'), profile, temporary), /unsupported LLVM JSON/);
  assert.throws(() => checkCoverage(changed(r => r.data[0].files.push(r.data[0].files[0])), profile, temporary), /duplicate LLVM file/);
  assert.throws(() => checkCoverage(report, { ...profile, thresholds: { ...profile.thresholds, branches: 79 } }, temporary), /retain branches=80/);
  const receipts = join(temporary, 'children');
  mkdirSync(receipts);
  const pattern = join(temporary, 'id-api-child-%p-%m.profraw');
  writeFileSync(join(receipts, 'api.started'), `id-api\n123\n${pattern}\n`);
  assert.throws(() => checkChildProfiles(receipts, ['id-api']), /did not complete/);
  const raw = join(temporary, 'id-api-child-123-456.profraw');
  writeFileSync(join(receipts, 'api.completed'), `${raw}\n`);
  assert.throws(() => checkChildProfiles(receipts, ['id-api']), /missing child profile/);
  writeFileSync(raw, 'synthetic profile presence');
  assert.equal(checkChildProfiles(receipts, ['id-api']).completed, 1);
  assert.throws(() => checkChildProfiles(receipts, ['id-api', 'id-web']), /no completed id-web/);
  for (const [binary, pid] of [['id-web', 124], ['idctl', 125]]) {
    const raw = join(temporary, `${binary}-child-${pid}-456.profraw`);
    writeFileSync(raw, 'synthetic profile presence');
    writeFileSync(join(receipts, `${binary}.started`), `${binary}\n${pid}\n${join(temporary, `${binary}-child-%p-%m.profraw`)}\n`);
    writeFileSync(join(receipts, `${binary}.completed`), `${raw}\n`);
  }
  const reportPath = join(temporary, 'llvm.json');
  const profilePath = join(temporary, 'profile.json');
  const resultPath = join(temporary, 'result.json');
  writeFileSync(reportPath, JSON.stringify(report));
  writeFileSync(profilePath, JSON.stringify(profile));
  for (const status of [undefined, 'false', 'true']) {
    const env = { ...process.env };
    delete env.ID_COVERAGE_TESTS_SUCCEEDED;
    if (status !== undefined) env.ID_COVERAGE_TESTS_SUCCEEDED = status;
    const run = spawnSync(process.execPath, [fileURLToPath(new URL('./check-rust-coverage.mjs', import.meta.url)),
      reportPath, profilePath, temporary, receipts, resultPath], { env, encoding: 'utf8' });
    assert.ifError(run.error);
    const result = JSON.parse(readFileSync(resultPath, 'utf8'));
    const complete = status === 'true';
    assert.equal(run.status, complete ? 0 : 1);
    assert.equal(result.passed, complete);
    assert.equal(result.scenario_completed, complete);
    assert.equal(run.stdout.includes('Coverage PASS'), complete, JSON.stringify({ stdout: run.stdout, stderr: run.stderr }));
    assert.equal(result.failures.some(message => message.includes('scenario did not complete')), !complete);
  }
  console.log('PASS: exact 85/80 and critical 100/100; missing branches/files/profiles and rounded percentages cannot pass');
  console.log('PASS: incomplete scenarios cannot publish PASS in JSON or stdout, even at passing percentages');
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
