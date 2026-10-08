#!/usr/bin/env node
// Deployment runners cannot reliably reach the production YDB query endpoint.
// The operator applies these additive schemas with idctl and records the exact
// source digest. Any schema or command change invalidates the receipt.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

const root = new URL('../..', import.meta.url);
const commands = [
  'cache-schema', 'password-mail-schema', 'security-mail-schema',
  'password-reset-schema', 'email-verify-schema', 'magic-link-schema',
  'email-change-schema', 'data-export-schema', 'data-export-escrow-schema',
  'data-export-mail-schema', 'passkey-index', 'provider-indexes',
];
const files = [
  'services/id-rust/crates/id-runtime/src/bin/idctl.rs',
  ...[
    'cache_store', 'password_mail', 'security_mail', 'password_reset',
    'email_verify', 'magic_link_request', 'email_change',
    'data_export_operation', 'data_export_escrow', 'data_export_mail',
    'passkey_index', 'legacy_schema',
  ].map((name) => `services/id-rust/crates/id-runtime/src/${name}.rs`),
].sort();

const hash = createHash('sha256');
for (const file of files) {
  hash.update(file).update('\0').update(readFileSync(new URL(file, root))).update('\0');
}
const digest = `sha256:${hash.digest('hex')}`;
if (process.argv[2] === '--print-digest') {
  console.log(digest);
  process.exit(0);
}
if (process.argv.length !== 2) throw new Error('unexpected arguments');

const receipt = JSON.parse(readFileSync(new URL('docs/rust-migration/production-ydb-schema-receipt.json', root)));
if (receipt.source_digest !== digest ||
    receipt.database_id !== process.env.YDB_DATABASE_ID ||
    !/^[a-z0-9]{20}$/.test(receipt.database_id ?? '') ||
    !Array.isArray(receipt.commands) ||
    receipt.commands.length !== commands.length ||
    receipt.commands.some((name, index) => name !== commands[index]) ||
    !Number.isFinite(Date.parse(receipt.verified_at))) {
  throw new Error('production YDB schema receipt is missing, stale, or for another database');
}
console.log(JSON.stringify({ database_id: receipt.database_id, source_digest: digest, schemas: commands.length }));
