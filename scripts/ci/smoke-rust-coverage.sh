#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$script_dir/../.." && pwd)"
probe="$(mktemp -d "$repo/.coverage-smoke.XXXXXX")"
trap 'rm -rf "$probe"' EXIT
mkdir "$probe/src" "$probe/tests" "$probe/coverage"
cat >"$probe/Cargo.toml" <<'TOML'
[workspace]
[package]
name = "coverage-probe"
version = "0.0.0"
edition = "2024"
[[bin]]
name = "id-api"
path = "src/main.rs"
[lints.rust]
unexpected_cfgs = { level = "deny", check-cfg = ["cfg(coverage_nightly)"] }
TOML
cat >"$probe/src/lib.rs" <<'RS'
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]
pub fn choose(value: &str) -> u8 {
    if value == "yes" {
        1
    } else {
        0
    }
}
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    #[test]
    fn excluded_test_body() {
        assert_eq!(super::choose("yes"), 1);
    }
}
RS
# Dependency-free Unix process to exercise the harness's real SIGTERM + wait.
# This is only an instrumentation probe; actual API/web shutdown receipts are
# separately mandatory when the existing application scenarios run in CI.
cat >"$probe/src/main.rs" <<'RS'
use std::sync::atomic::{AtomicBool, Ordering};
static STOP: AtomicBool = AtomicBool::new(false);
extern "C" fn terminate(_: i32) { STOP.store(true, Ordering::SeqCst); }
unsafe extern "C" { fn signal(number: i32, handler: extern "C" fn(i32)) -> usize; }
fn main() {
    let once = std::env::args().any(|arg| arg == "once");
    println!("{}", coverage_probe::choose(if once { "no" } else { "yes" }));
    if once { return; }
    unsafe { signal(15, terminate); }
    println!("ready");
    while !STOP.load(Ordering::SeqCst) { std::thread::sleep(std::time::Duration::from_millis(5)); }
}
RS
cat >"$probe/tests/child.rs" <<'RS'
#[test]
fn cargo_bin_exe_child_flushes_its_own_profile() {
    let child = std::process::Command::new(env!("CARGO_BIN_EXE_id-api"))
        .arg("once").stdout(std::process::Stdio::piped()).spawn().unwrap();
    let pid = child.id();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"0\n");
    let pattern = std::env::var("LLVM_PROFILE_FILE").unwrap();
    let directory = std::path::Path::new(&pattern).parent().unwrap();
    assert!(std::fs::read_dir(directory).unwrap().any(|entry| {
        let entry = entry.unwrap();
        entry.file_name().to_string_lossy().contains(&format!("-{pid}-"))
            && entry.metadata().unwrap().len() > 0
    }), "CARGO_BIN_EXE child did not flush its own profile after exit");
}
RS
cat >"$probe/coverage/security-profile.json" <<'JSON'
{"version":1,"name":"real branch probe","thresholds":{"lines":85,"branches":80,"critical_lines":100,"critical_branches":100},"groups":[{"name":"decision","critical":true,"files":["src/lib.rs"]}]}
JSON
cd "$probe"
cargo generate-lockfile --offline
GITHUB_ENV="$probe/github.env" bash "$script_dir/rust-coverage.sh" prepare "$probe" "$probe/measurement"
node --input-type=module - "$probe/github.env" <<'JS'
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { spawnSync } from 'node:child_process';
const recorded = Object.fromEntries(fs.readFileSync(process.argv[2], 'utf8').trim().split('\n')
  .map(line => { const at = line.indexOf('='); return [line.slice(0, at), line.slice(at + 1)]; }));
assert.match(recorded.RUSTFLAGS, /coverage-options=branch/);
assert.match(recorded.__CARGO_LLVM_COV_RUSTC_WRAPPER_RUSTFLAGS, /instrument-coverage/);
assert.match(recorded.LLVM_PROFILE_FILE, /%p-%m\.profraw$/);
// Simulate the next Actions step, using the recorded environment instead of
// shell state inherited from prepare. Preserve the encoded wrapper flags.
const nextStep = spawnSync('cargo', ['build', '--locked', '--offline'], {
  env: { ...process.env, ...recorded }, stdio: 'inherit' });
assert.equal(nextStep.status, 0, 'instrumented build in the next Actions step');
JS
source "$probe/measurement/coverage.env"
node --input-type=module - "$ID_RUST_BIN_DIR/id-api" <<'JS'
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
const child = spawn(process.argv[2], [], { stdio: ['ignore', 'pipe', 'inherit'] });
let output = '';
const limit = setTimeout(() => child.kill('SIGKILL'), 10000);
child.stdout.on('data', data => { output += data; if (output.includes('ready\n')) child.kill('SIGTERM'); });
const code = await new Promise(resolve => child.once('exit', resolve));
clearTimeout(limit);
assert.equal(code, 0, `SIGTERM harness exit: ${code}`);
assert.match(output, /ready/);
JS
cargo llvm-cov report --json --output-path "$probe/one-side.json"
node --input-type=module - "$script_dir/check-rust-coverage.mjs" "$probe" <<'JS'
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { pathToFileURL } from 'node:url';
const { checkCoverage, checkChildProfiles } = await import(pathToFileURL(process.argv[2]));
const root = process.argv[3];
const result = checkCoverage(JSON.parse(fs.readFileSync(`${root}/one-side.json`)),
  JSON.parse(fs.readFileSync(`${root}/coverage/security-profile.json`)), root);
assert.equal(result.passed, false, 'single branch must fail critical 100%');
assert.equal(result.totals.branches.count, 2);
assert.equal(result.totals.branches.covered, 1);
assert.equal(checkChildProfiles(`${root}/measurement/children`, ['id-api']).completed, 1);
JS
cargo test --locked --offline --lib --test child
cargo llvm-cov report --json --output-path "$probe/both-sides.json"
node --input-type=module - "$script_dir/check-rust-coverage.mjs" "$probe" <<'JS'
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { pathToFileURL } from 'node:url';
const { checkCoverage } = await import(pathToFileURL(process.argv[2]));
const root = process.argv[3];
const before = JSON.parse(fs.readFileSync(`${root}/one-side.json`));
const after = JSON.parse(fs.readFileSync(`${root}/both-sides.json`));
const profile = JSON.parse(fs.readFileSync(`${root}/coverage/security-profile.json`));
const result = checkCoverage(after, profile, root);
assert.equal(result.passed, true, JSON.stringify(result.failures));
assert.equal(result.totals.branches.count, 2);
assert.equal(result.totals.branches.covered, 2);
assert.equal(result.totals.lines.count, checkCoverage(before, profile, root).totals.lines.count,
  'test-only code must not inflate the production denominator');
console.log('PASS: real LLVM branches 1/2 fails, 2/2 passes; SIGTERM + wait server profile and CARGO_BIN_EXE child profile recorded; test code excluded');
JS
