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
console.log(`Verified ${routed.length} Gateway container integrations across four Rust containers.`);
