// Verify that the operator smoke checks S3 listing as well as PUT/GET/DELETE.
// All objects and credentials are synthetic and remain on loopback.
const assert = require('node:assert/strict');
const http = require('node:http');
const { spawn } = require('node:child_process');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const binary = path.join(process.env.ID_RUST_BIN_DIR || path.join(root, 'target/debug'), 'idctl');
const objects = new Map();
let denyList = false;
let lists = 0;

const server = http.createServer(async (request, response) => {
  const url = new URL(request.url, 'http://127.0.0.1');
  const prefix = '/private-exports/';
  if (request.method === 'GET' && url.pathname === '/private-exports') {
    lists += 1;
    if (denyList) { response.writeHead(403); response.end(); return; }
    assert.equal(url.searchParams.get('list-type'), '2');
    assert.equal(url.searchParams.get('max-keys'), '25');
    const selected = url.searchParams.get('prefix');
    assert.match(selected || '', /^exports\/escrow\/[a-f0-9]{32}\/$/);
    const contents = [...objects.keys()].filter(key => key.startsWith(selected))
      .map(key => `<Contents><Key>${key}</Key></Contents>`).join('');
    response.writeHead(200, { 'Content-Type': 'application/xml' });
    response.end(`<ListBucketResult><Name>private-exports</Name><Prefix>${selected}</Prefix><IsTruncated>false</IsTruncated>${contents}</ListBucketResult>`);
    return;
  }
  if (!url.pathname.startsWith(prefix)) { response.writeHead(404); response.end(); return; }
  const key = url.pathname.slice(prefix.length);
  if (request.method === 'PUT') {
    let body = Buffer.alloc(0);
    for await (const chunk of request) body = Buffer.concat([body, chunk]);
    objects.set(key, body);
    response.writeHead(200); response.end(); return;
  }
  if (request.method === 'GET') {
    const body = objects.get(key);
    response.writeHead(body ? 200 : 404);
    response.end(body); return;
  }
  if (request.method === 'DELETE') {
    objects.delete(key);
    response.writeHead(204); response.end(); return;
  }
  response.writeHead(405); response.end();
});

function run(port) {
  return new Promise((resolve, reject) => {
    const child = spawn(binary, ['data-export-storage-smoke'], {
      env: { ...process.env, S3_ENDPOINT_URL: `http://127.0.0.1:${port}/`,
        ID_EXPORT_S3_BUCKET_NAME: 'private-exports', S3_REGION: 'ru-central1',
        S3_ACCESS_KEY_ID: 'synthetic-key', S3_SECRET_ACCESS_KEY: 'synthetic-secret' },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', chunk => { stdout += chunk.toString(); });
    child.stderr.on('data', chunk => { stderr += chunk.toString(); });
    child.on('error', reject);
    child.on('exit', code => resolve({ code, stdout, stderr }));
  });
}

async function main() {
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const port = server.address().port;
    const passed = await run(port);
    assert.equal(passed.code, 0, passed.stderr);
    assert.deepEqual(JSON.parse(passed.stdout), {
      data_export_storage: 'pass', prefixes: 2, escrow_listing: 'pass',
    });
    assert.equal(lists, 2, 'smoke must list before and after escrow deletion');
    assert.equal(objects.size, 0);

    denyList = true;
    const rejected = await run(port);
    assert.notEqual(rejected.code, 0, 'smoke passed without ListBucket permission');
    assert.equal(objects.size, 0, 'smoke left synthetic objects after denied listing');
    console.log('PASS: idctl storage smoke verifies exact escrow listing and fails closed');
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
}

main().catch(error => { console.error(error); process.exitCode = 1; });
