#!/usr/bin/env node
// Replace only the retired React Object Storage routes in a captured YC spec.
// The input is kept unchanged for rollback; this command never calls YC.
import { readFileSync, writeFileSync } from 'node:fs';

const [beforePath, afterPath] = process.argv.slice(2);
const webId = process.env.RUST_WEB_CONTAINER_ID;
const expectedIds = new Set([
  process.env.RUST_API_CONTAINER_ID,
  process.env.RUST_SESSIONS_CONTAINER_ID,
  process.env.RUST_MUTATIONS_CONTAINER_ID,
  webId,
]);
if (!beforePath || !afterPath || expectedIds.size !== 4 ||
    [...expectedIds].some(id => !/^bba[a-z0-9]{17}$/.test(id ?? ''))) {
  throw new Error('usage: set four distinct Rust container IDs, then pass before.yaml after.yaml');
}

const before = readFileSync(beforePath, 'utf8');
if (before.length > 4 * 1024 * 1024 || !before.startsWith('openapi:')) {
  throw new Error('invalid Gateway spec');
}
const lines = before.split('\n');
const positions = lines.flatMap((line, index) => /^  (\/[^:]*):\s*$/.test(line) ? [index] : []);
if (!positions.length) throw new Error('Gateway has no paths');
const prefix = lines.slice(0, positions[0]);
const blocks = positions.map((start, index) => {
  const end = positions[index + 1] ?? lines.length;
  const path = lines[start].match(/^  (\/[^:]*):\s*$/)?.[1];
  return { path, lines: lines.slice(start, end) };
});
const byPath = new Map(blocks.map(block => [block.path, block]));
if (byPath.size !== blocks.length) throw new Error('duplicate Gateway paths');
const legacy = byPath.get('/legacy/account');
const assets = byPath.get('/assets/{file+}');
const fallback = byPath.get('/{file+}');
const root = byPath.get('/');
if (![legacy, assets, fallback, root].every(Boolean)) {
  throw new Error('expected React fallback and Topcoat root routes are missing');
}
const blockText = block => block.lines.join('\n');
const oldObjectRoutes = blocks.filter(block => blockText(block).includes('type: object_storage')).map(block => block.path);
if (oldObjectRoutes.join(',') !== ['/legacy/account', '/assets/{file+}', '/{file+}'].join(',')) {
  throw new Error(`unexpected Object Storage routes: ${oldObjectRoutes.join(',')}`);
}
if (!blockText(fallback).includes('error_object:') || !blockText(fallback).includes('statusCode: 200')) {
  throw new Error('React fallback shape changed');
}
const rootText = blockText(root);
if (!rootText.includes(`container_id: ${webId}`) || !rootText.includes('type: serverless_containers')) {
  throw new Error('Gateway root is not served by the expected Topcoat container');
}
const serviceAccount = rootText.match(/^        service_account_id:\s*([a-z0-9]+)\s*$/m)?.[1];
if (!serviceAccount) throw new Error('Topcoat Gateway service account is missing');
const replacement = [
  '  /{file+}:',
  '    get:',
  '      parameters:',
  '      - name: file',
  '        in: path',
  '        required: true',
  '        explode: false',
  '        style: simple',
  '        schema:',
  '          type: string',
  "          default: '-'",
  '      x-yc-apigateway-integration:',
  '        type: serverless_containers',
  `        container_id: ${webId}`,
  `        service_account_id: ${serviceAccount}`,
];
const afterBlocks = blocks.flatMap(block => {
  if (block.path === '/legacy/account' || block.path === '/assets/{file+}') return [];
  return [block.path === '/{file+}' ? replacement : block.lines];
});
const after = [...prefix, ...afterBlocks.flat()].join('\n');
if (after.includes('type: object_storage') || after.includes('error_object:') || after.includes('/legacy/account:')) {
  throw new Error('React integration remains after transformation');
}
const ids = [...after.matchAll(/^\s*container_id:\s*([^\s#]+)/gm)].map(match => match[1]);
if (ids.length !== 121 || [...new Set(ids)].some(id => !expectedIds.has(id)) ||
    [...expectedIds].some(id => !ids.includes(id))) {
  throw new Error('transformed Gateway has unexpected container integrations');
}
writeFileSync(afterPath, after, { mode: 0o600, flag: 'wx' });
console.log(`Prepared ${blocks.length - 2} Gateway paths and ${ids.length} Rust integrations; saved original separately.`);
