#!/usr/bin/env node
import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { isAbsolute, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const requiredThresholds = { lines: 85, branches: 80, critical_lines: 100, critical_branches: 100 };
const ensure = (condition, message) => { if (!condition) throw new Error(message); };

// Use integer counts, not rounded percentages or LLVM regions (which are not branches).
function metric(summary, kind, file) {
  const value = summary?.[kind];
  ensure(value && Number.isSafeInteger(value.count) && Number.isSafeInteger(value.covered)
    && value.count >= 0 && value.covered >= 0 && value.covered <= value.count,
  `${file}: missing or invalid ${kind} counts`);
  return { count: value.count, covered: value.covered };
}

export function checkCoverage(report, profile, root) {
  ensure(profile.version === 1 && Array.isArray(profile.groups) && profile.groups.length > 0,
    'unsupported or empty coverage profile');
  for (const [key, threshold] of Object.entries(requiredThresholds)) {
    ensure(profile.thresholds?.[key] === threshold, `profile must retain ${key}=${threshold}`);
  }
  ensure(report.type === 'llvm.coverage.json.export' && report.version === '3.1.0'
    && report.data?.length === 1 && Array.isArray(report.data[0].files),
  'unsupported LLVM JSON schema (expected 3.1.0 with one merged data set)');
  const files = new Map();
  for (const file of report.data[0].files) {
    ensure(typeof file.filename === 'string', 'LLVM file omitted filename');
    const path = resolve(root, file.filename);
    ensure(!files.has(path), `duplicate LLVM file: ${file.filename}`);
    files.set(path, file);
  }
  const expected = new Set();
  const rows = [];
  const failures = [];
  const totals = { lines: { count: 0, covered: 0 }, branches: { count: 0, covered: 0 } };
  let criticalFiles = 0;
  for (const group of profile.groups) {
    ensure(typeof group.name === 'string' && typeof group.critical === 'boolean'
      && Array.isArray(group.files) && group.files.length > 0, 'invalid profile group');
    for (const path of group.files) {
      ensure(typeof path === 'string' && path.endsWith('.rs') && !isAbsolute(path)
        && !path.split('/').includes('..') && !expected.has(path), `invalid/duplicate profile path: ${path}`);
      expected.add(path);
      const absolute = resolve(root, path);
      ensure(existsSync(absolute) && statSync(absolute).isFile(), `profile source is missing: ${path}`);
      const file = files.get(absolute);
      ensure(file, `coverage file is missing: ${path}`);
      const row = { path, critical: group.critical, group: group.name,
        lines: metric(file.summary, 'lines', path), branches: metric(file.summary, 'branches', path) };
      ensure(row.lines.count > 0, `${path}: no executable lines measured`);
      rows.push(row);
      if (group.critical) criticalFiles++;
      for (const kind of ['lines', 'branches']) {
        totals[kind].count += row[kind].count;
        totals[kind].covered += row[kind].covered;
        ensure(Number.isSafeInteger(totals[kind].count), 'coverage count overflow');
        if (group.critical) {
          // Zero is not a measured 100%. Review genuinely branchless critical files explicitly.
          if (row[kind].count === 0) failures.push(`${path}: no ${kind} measured for critical file`);
          else if (row[kind].covered !== row[kind].count) {
            failures.push(`${path}: critical ${kind} ${row[kind].covered}/${row[kind].count}, requires 100%`);
          }
        }
      }
    }
  }
  ensure(criticalFiles > 0, 'profile omitted all critical files');
  for (const kind of ['lines', 'branches']) {
    ensure(totals[kind].count > 0, `no aggregate ${kind} measured; instrumentation is incomplete`);
    if (BigInt(totals[kind].covered) * 100n < BigInt(requiredThresholds[kind]) * BigInt(totals[kind].count)) {
      failures.push(`aggregate ${kind} ${totals[kind].covered}/${totals[kind].count}, requires ${requiredThresholds[kind]}%`);
    }
  }
  return { passed: failures.length === 0, profile: profile.name, thresholds: requiredThresholds,
    totals, files: rows, failures };
}

// A SIGTERM harness must actually let each server exit and flush its own profile.
// Shell cleanup often ignores wait failures, so report-time receipt validation is mandatory.
export function checkChildProfiles(directory, required = ['id-api', 'id-web', 'idctl']) {
  const names = readdirSync(directory);
  const seen = new Set();
  const started = names.filter(name => name.endsWith('.started'));
  ensure(started.length > 0, 'no instrumented child process receipts');
  for (const name of started) {
    const receipt = resolve(directory, name);
    const [binary, pid, pattern] = readFileSync(receipt, 'utf8').trim().split('\n');
    ensure(binary && /^\d+$/.test(pid) && pattern, `invalid child receipt: ${name}`);
    const completed = resolve(directory, name.replace(/\.started$/, '.completed'));
    ensure(existsSync(completed), `${binary}/${pid}: child did not complete profile recording`);
    const profiles = readFileSync(completed, 'utf8').trim().split('\n');
    ensure(profiles.length > 0, `${binary}/${pid}: no child profiles`);
    for (const profile of profiles) {
      ensure(profile.startsWith(pattern.replace('%p', pid).split('%m')[0])
        && existsSync(profile) && statSync(profile).size > 0, `${binary}/${pid}: missing child profile`);
    }
    seen.add(binary);
  }
  for (const binary of required) ensure(seen.has(binary), `no completed ${binary} child profile`);
  return { completed: started.length, binaries: [...seen].sort() };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const [reportPath, profilePath, sourceRoot, receipts, outputPath] = process.argv.slice(2);
    ensure(reportPath && profilePath && sourceRoot && receipts && outputPath,
      'usage: check-rust-coverage.mjs report.json profile.json source-root child-receipts result.json');
    const result = checkCoverage(JSON.parse(readFileSync(reportPath, 'utf8')),
      JSON.parse(readFileSync(profilePath, 'utf8')), resolve(sourceRoot));
    result.children = checkChildProfiles(receipts);
    result.scenario_completed = process.env.ID_COVERAGE_TESTS_SUCCEEDED === 'true';
    if (!result.scenario_completed) {
      result.passed = false;
      result.failures.push('integration scenario did not complete successfully; measurement is partial');
    }
    writeFileSync(outputPath, `${JSON.stringify(result, null, 2)}\n`);
    for (const kind of ['lines', 'branches']) {
      console.log(`${kind}: ${result.totals[kind].covered}/${result.totals[kind].count}`);
    }
    for (const failure of result.failures) console.error(failure);
    console.log(`Coverage ${result.passed ? 'PASS' : 'FAIL'}: ${result.files.length} files; ${result.children.completed} completed children`);
    if (!result.passed) process.exitCode = 1;
  } catch (error) {
    console.error(`Coverage FAIL: ${error.message}`);
    process.exitCode = 1;
  }
}
