#!/usr/bin/env node
// Fail deployment if the ID Gateway sends traffic to a container outside the
// set captured, updated and rolled back by this workflow.
const names = [
  'RUST_API_CONTAINER_ID',
  'RUST_SESSIONS_CONTAINER_ID',
  'RUST_MUTATIONS_CONTAINER_ID',
  'RUST_WEB_CONTAINER_ID',
];
const expected = new Set(names.map(name => process.env[name]));
if (expected.size !== names.length || [...expected].some(id => !/^bba[a-z0-9]{17}$/.test(id ?? ''))) {
  throw new Error('four distinct Rust Gateway container IDs are required');
}

let spec = '';
for await (const chunk of process.stdin) {
  spec += chunk;
  if (spec.length > 4 * 1024 * 1024) throw new Error('Gateway specification is too large');
}
const routed = [...spec.matchAll(/^[ \t]*container_id:[ \t]*([^\s#]+)/gm)].map(match => match[1]);
const actual = new Set(routed);
if (!routed.length || [...actual].some(id => !expected.has(id)) || [...expected].some(id => !actual.has(id))) {
  throw new Error('Gateway routes do not match the four captured Rust containers');
}
function targetFor(path, method) {
  const lines = spec.split(/\r?\n/);
  const start = lines.indexOf(`  ${path}:`);
  if (start < 0) return null;
  const end = lines.findIndex((line, index) => index > start && /^  \/[^\n]*:$/.test(line));
  const route = lines.slice(start + 1, end < 0 ? undefined : end);
  const operationStart = route.indexOf(`    ${method}:`);
  if (operationStart < 0) return null;
  const operationEnd = route.findIndex((line, index) => index > operationStart && /^    [a-z-]+:$/.test(line));
  const operation = route.slice(operationStart + 1, operationEnd < 0 ? undefined : operationEnd);
  return operation.find(line => line.startsWith('        container_id: '))?.slice('        container_id: '.length) ?? null;
}
for (const action of ['begin', 'complete']) {
  const path = `/api/v1/auth/passkeys/${action}`;
  if (targetFor(path, 'post') !== process.env.RUST_API_CONTAINER_ID) {
    throw new Error(`POST ${path} must target the main Rust API container`);
  }
}
console.log(`Verified ${routed.length} Gateway container integrations across four Rust containers.`);
