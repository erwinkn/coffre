// A call's connection closed by a time on workerd (`HyperdrivePool.end(by)`, T170): what it had not written yet is
// never sent, a write stuck under backpressure included, and the connection goes once the call's request ends.
// workerd's own `close()` waits for every write to go (reviews r2 and r3 of #438), so the driver aborts the socket's
// streams first (platform.workerd.ts, `destroy`); the TCP connection itself workerd closes with the request, which for
// a use's call is right after (cloudflare.ts: the pool's `end` is the last thing it waits for).
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createServer as createHttpServer } from 'node:http';
import { connect, createServer, type Socket } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as sleep } from 'node:timers/promises';

import { unstable_dev } from 'wrangler';

import { ENGINE, VAULT_URL } from './database.ts';

const skip = ENGINE === 'postgres' ? false : 'Postgres only: workerd';

/** What the statement carries: more than the kernel's buffers on both sides hold. */
const BYTES = 32 * 1024 * 1024;

test("closed by its time, a call's connection sends nothing it had not written, its statement stuck behind a server that reads nothing, and goes with its request (T170)", { skip, timeout: 120_000 }, async () => {
  const target = new URL(VAULT_URL);
  let client = null as Socket | null;
  let afterPause = 0;
  let paused = false;
  let closed = false;
  const proxy = createServer((socket) => {
    client = socket;
    const upstream = connect(Number(target.port), target.hostname);
    socket.on('data', (chunk) => {
      if (paused) afterPause += chunk.length;
      else upstream.write(chunk);
    });
    upstream.on('data', (chunk) => socket.write(chunk));
    socket.on('close', () => {
      closed = true;
      upstream.destroy();
    });
    socket.on('error', () => {});
    upstream.on('error', () => socket.destroy());
  });
  const control = createHttpServer((request, response) => {
    if (request.url === '/pause') {
      paused = true;
      client?.pause();
      return void response.end('paused');
    }
    // The pool has let go, the Worker's request still under way: read again. What the socket still held unsent would
    // come now; dropped, nothing does but what the kernel had.
    client?.resume();
    void sleep(1_000).then(() => response.end(JSON.stringify({ afterPause })));
  });
  await Promise.all([new Promise<void>((resolve) => proxy.listen(0, '127.0.0.1', resolve)), new Promise<void>((resolve) => control.listen(0, '127.0.0.1', resolve))]);
  const port = (server: { address(): unknown }) => (server.address() as { port: number }).port;
  const database = new URL(VAULT_URL);
  database.host = `127.0.0.1:${port(proxy)}`;
  const dir = mkdtempSync(join(tmpdir(), 'coffre-socket-worker-'));
  writeFileSync(join(dir, 'wrangler.json'), JSON.stringify({
    name: 'coffre-socket-workers-test',
    compatibility_date: '2026-08-06',
    compatibility_flags: ['nodejs_compat'],
    vars: { DATABASE: database.toString(), CONTROL: `http://127.0.0.1:${port(control)}`, BYTES: String(BYTES) },
  }));
  process.env.WRANGLER_BUILD_CONDITIONS = 'coffre:source,workerd,worker,browser';
  const worker = await unstable_dev(fileURLToPath(new URL('./workers/socket-worker.ts', import.meta.url)), {
    config: join(dir, 'wrangler.json'),
    local: true, ip: '127.0.0.1', port: 0, inspectorPort: 0, persist: false, logLevel: 'error',
    experimental: { disableExperimentalWarning: true, disableDevRegistry: true },
  });
  try {
    const answer = (await (await worker.fetch('/', { signal: AbortSignal.timeout(60_000) })).json()) as { query: string; past: number; read: { afterPause: number } };
    assert.equal(answer.query, 'failed', 'the statement under way failed');
    assert.ok(answer.past < 1_000, `the pool let go ${answer.past} ms past its time`);
    assert.ok(answer.read.afterPause < BYTES / 2, `${answer.read.afterPause} bytes of the statement's ${BYTES} came after the server stopped reading`);
    // The request done, its connection goes with it.
    for (let tries = 0; !closed && tries < 100; tries += 1) await sleep(20);
    assert.ok(closed, 'the connection outlived its request');
  } finally {
    await worker.stop();
    rmSync(dir, { recursive: true, force: true });
    proxy.close();
    control.close();
    client?.destroy();
  }
});
