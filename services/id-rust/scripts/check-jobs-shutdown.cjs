// Exercise the actual jobs process, HTTP server and OS signals; no jobs are queued.
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const { once } = require('node:events');
const net = require('node:net');
const path = require('node:path');
const { setTimeout: delay } = require('node:timers/promises');

async function main() {
  assert.match(process.env.YDB_ENDPOINT || '', /^grpc:\/\/(localhost|127\.0\.0\.1):2136$/);
  assert.equal(process.env.YDB_DATABASE, '/local');
  assert.equal(process.env.YDB_CREDENTIALS_MODE, 'anonymous');
  for (const signal of ['SIGTERM', 'SIGINT']) {
    const reservation = net.createServer();
    reservation.listen(0, '127.0.0.1');
    await once(reservation, 'listening');
    const port = reservation.address().port;
    await new Promise(resolve => reservation.close(resolve));
    const inherited = Object.fromEntries(Object.entries(process.env).filter(([key]) =>
      /^(PATH|YDB_ENDPOINT|YDB_DATABASE|YDB_CREDENTIALS_MODE|ID_COVERAGE_.+|CARGO_LLVM_COV_TARGET_DIR|LLVM_PROFILE_FILE)$/.test(key)));
    const child = spawn(path.join(process.env.ID_RUST_BIN_DIR || path.join(__dirname, '../target/debug'), 'id-jobs'), ['--serve'], {
      env: { ...inherited, DJANGO_DEBUG: 'true', ID_JOBS_HTTP_ENABLED: 'true', PORT: String(port),
        EMAIL_HOST: '127.0.0.1', EMAIL_PORT: '9', EMAIL_USE_TLS: 'false', DEFAULT_FROM_EMAIL: 'synthetic@example.invalid' },
      stdio: ['ignore', 'ignore', 'pipe'],
    });
    let diagnostic = '';
    child.stderr.on('data', data => { diagnostic = (diagnostic + data).slice(-4096); });
    let socket;
    try {
      let ready = false;
      for (let attempt = 0; attempt < 100; attempt++) {
        assert.equal(child.exitCode, null, `jobs exited during startup: ${diagnostic}`);
        try { ready = (await fetch(`http://127.0.0.1:${port}/healthz`, { signal: AbortSignal.timeout(500) })).ok; } catch {}
        if (ready) break;
        await delay(50);
      }
      assert.ok(ready, `jobs did not become ready: ${diagnostic}`);
      socket = net.connect(port, '127.0.0.1');
      await once(socket, 'connect', { signal: AbortSignal.timeout(5000) });
      let wire = '';
      socket.on('data', data => { wire += data.toString(); });
      socket.write(`POST /internal/jobs/mail HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 2\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n`);
      for (let attempt = 0; attempt < 100 && !wire.includes('\r\n\r\n'); attempt++) await delay(20);
      assert.match(wire, /^HTTP\/1\.1 100 Continue\r\n/i, 'handler must be waiting for the request body before the signal');
      assert.ok(child.kill(signal));
      let listenerClosed = false;
      for (let attempt = 0; attempt < 100; attempt++) {
        assert.equal(child.exitCode, null, `${signal}: process exited before draining the request`);
        assert.equal(child.signalCode, null, `${signal}: process was terminated before draining the request`);
        listenerClosed = await new Promise((resolve, reject) => {
          const probe = net.connect(port, '127.0.0.1');
          probe.once('connect', () => { probe.destroy(); resolve(false); });
          probe.once('error', error => {
            if (error.code === 'ECONNREFUSED') resolve(true);
            // The listener can close during this TCP handshake. Probe again
            // until refusal confirms closure; the in-flight request is separate.
            else if (error.code === 'ECONNRESET') resolve(false);
            else reject(new Error(`${signal}: listener probe failed`, { cause: error }));
          });
        });
        if (listenerClosed) break;
        await delay(20);
      }
      assert.ok(listenerClosed, `${signal}: server kept accepting new connections`);
      const ended = once(socket, 'end', { signal: AbortSignal.timeout(5000) });
      socket.write('{}');
      await ended;
      assert.match(wire, /HTTP\/1\.1 400 Bad Request/i, 'in-flight request must receive its real handler response');
      assert.ok(wire.includes('invalid trigger JSON'));
      if (child.exitCode === null && child.signalCode === null) await once(child, 'exit', { signal: AbortSignal.timeout(5000) });
      assert.equal(child.exitCode, 0, `${signal}: expected successful process exit, got ${diagnostic}`);
      assert.equal(child.signalCode, null);
      console.log(`PASS: ${signal} closes listener, drains in-flight HTTP request and exits successfully`);
    } finally {
      socket?.destroy();
      if (child.exitCode === null && child.signalCode === null) {
        child.kill('SIGKILL');
        await once(child, 'exit');
      }
    }
  }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
