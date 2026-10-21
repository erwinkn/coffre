// The Postgres tunnel on Workers, in workerd: each WebSocket in the Durable
// Object its path and handle name, its session the same `tunnel()` as on
// Node. Queries, through `cloudflare:sockets` and through a VPC Network
// binding; a cancel request that reaches the same object; a revoked handle
// whose session the object's recheck ends; and credit flow: a large result
// sent no faster than the app takes it, so a slow app holds the object to
// a window of it, not the whole result. Postgres only: the database is
// the suite's own.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createServer, type AddressInfo, type Server, type Socket } from 'node:net';
import { once } from 'node:events';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import pg from 'pg';
import { unstable_dev, type Unstable_DevWorker } from 'wrangler';
import { WebSocket } from 'ws';

import { TEST_RUNTIME_DATABASE_URL } from './db/connections.ts';
import { TEST_ENGINE } from './db/engine.ts';

const skip = TEST_ENGINE !== 'postgres' ? 'the tunnel reaches a Postgres database' : false;
const HANDLE = `coffre_use_${'h'.repeat(43)}`;
const REVOKED = `coffre_use_${'r'.repeat(43)}`;
const NAME = 'coffre-tunnel-workers-test';
/** The object's window, cloudflare-sockets.ts's `WINDOW`: what it sends that the app has not counted. */
const WINDOW = 1024 * 1024;

let dir: string;
let worker: Unstable_DevWorker;
let at: string;
const listeners: Server[] = [];

before(async () => {
  if (skip) return;
  dir = mkdtempSync(join(tmpdir(), 'coffre-tunnel-worker-'));
  writeFileSync(
    join(dir, 'wrangler.json'),
    JSON.stringify({
      name: NAME,
      compatibility_date: '2026-08-06',
      compatibility_flags: ['nodejs_compat'],
      vars: { DATABASE_URL: TEST_RUNTIME_DATABASE_URL },
      durable_objects: { bindings: [{ name: 'SOCKETS', class_name: 'CoffreSockets' }] },
      migrations: [{ tag: 'sockets', new_sqlite_classes: ['CoffreSockets'] }],
    }),
  );
  // Bundled from the packages' sources, as the tests read them.
  process.env.WRANGLER_BUILD_CONDITIONS = 'coffre:source,workerd,worker,browser';
  worker = await unstable_dev(fileURLToPath(new URL('./workers/tunnel-worker.ts', import.meta.url)), {
    config: join(dir, 'wrangler.json'),
    local: true, ip: '127.0.0.1', port: 0, inspectorPort: 0, persist: false, logLevel: 'error',
    experimental: { disableExperimentalWarning: true, disableDevRegistry: true },
  });
  at = `ws://${worker.address}:${worker.port}`;
}, { timeout: 120_000 });

after(async () => {
  for (const listener of listeners) listener.close();
  await worker?.stop();
  if (dir !== undefined) rmSync(dir, { recursive: true, force: true });
});

/**
 * `coffre run`'s listener as it speaks to a Workers coffre (packages/cli/src/tunnels.ts):
 * the flow header, and each side's count of what it took.
 */
async function listen(tunnel: string, handle = HANDLE): Promise<number> {
  const listener = createServer((socket: Socket) => {
    socket.pause();
    const ws = new WebSocket(`${at}/use/market/dev/${tunnel}`, { headers: { authorization: `Bearer ${handle}`, 'coffre-tunnel-flow': 'credit' } });
    let uncounted = 0;
    let taken = 0;
    ws.on('open', () => socket.resume());
    socket.on('data', (chunk: Buffer) => {
      uncounted += chunk.length;
      ws.send(chunk);
      if (uncounted >= WINDOW) socket.pause();
    });
    ws.on('message', (data: Buffer, binary: boolean) => {
      if (!binary) {
        uncounted -= Number(data.toString());
        if (uncounted < WINDOW) socket.resume();
        return;
      }
      socket.write(data, () => {
        taken += data.length;
        if (taken >= 64 * 1024) {
          ws.send(String(taken));
          taken = 0;
        }
      });
    });
    ws.on('close', () => socket.destroy());
    ws.on('error', () => socket.destroy());
    socket.on('close', () => ws.close());
    socket.on('error', () => ws.terminate());
  });
  listener.listen(0, '127.0.0.1');
  await once(listener, 'listening');
  listeners.push(listener);
  return (listener.address() as AddressInfo).port;
}

const appClient = (port: number, handle = HANDLE) => new pg.Client({ connectionString: `postgres://app:${handle}@127.0.0.1:${port}/app` });

test('queries through the object, over cloudflare:sockets and over a network binding to a private address', { skip, timeout: 60_000 }, async () => {
  for (const tunnel of ['db', 'replica']) {
    const client = appClient(await listen(tunnel));
    await client.connect();
    try {
      assert.deepEqual((await client.query('SELECT current_user AS who, $1::int + 1 AS two', [1])).rows, [{ who: 'coffre_runtime', two: 2 }], tunnel);
    } finally {
      await client.end();
    }
  }
});

test('a cancel request, on a connection of its own, reaches the session in the same object', { skip, timeout: 60_000 }, async () => {
  const port = await listen('db');
  const client = appClient(port);
  await client.connect();
  try {
    const sleeping = client.query('SELECT pg_sleep(30)');
    await new Promise((resolve) => setTimeout(resolve, 300));
    const started = Date.now();
    // pg sends it as psql does: a CancelRequest with the key it was given, on a new connection to the listener.
    const canceller = appClient(port) as unknown as { cancel(client: pg.Client, query: unknown): void };
    canceller.cancel(client, (client as unknown as { activeQuery: unknown }).activeQuery);
    await assert.rejects(sleeping, (error: { code?: string }) => error.code === '57014');
    assert.ok(Date.now() - started < 5000);
  } finally {
    await client.end();
  }
});

test("a revoked handle's session ends at the object's recheck", { skip, timeout: 60_000 }, async () => {
  const client = appClient(await listen('db', REVOKED), REVOKED);
  // The driver says the connection dropped, then ends.
  client.on('error', () => undefined);
  const ended = new Promise((resolve) => client.once('end', resolve));
  await client.connect();
  // Live, until the worker's stand-in refuses the handle, from its fourth use: its admission's, then a recheck each half second.
  assert.deepEqual((await client.query('SELECT 1 AS one')).rows, [{ one: 1 }]);
  const started = Date.now();
  await ended;
  assert.ok(Date.now() - started < 5000);
});

test('a WebSocket that does not ask for credit flow, or names no bearer, is refused before any object: an older CLI would let a large result fill one', { skip, timeout: 30_000 }, async () => {
  for (const [headers, status] of [[{ authorization: `Bearer ${HANDLE}` }, 426], [{ 'coffre-tunnel-flow': 'credit' }, 401]] as const) {
    const ws = new WebSocket(`${at}/use/market/dev/db`, { headers });
    ws.on('error', () => undefined);
    const [, response] = (await once(ws, 'unexpected-response')) as [unknown, { statusCode: number }];
    assert.equal(response.statusCode, status);
    ws.terminate();
  }
});

test('a client that ignores the window is ended: past two windows uncounted, or counting what it was never sent', { skip, timeout: 30_000 }, async () => {
  // The app itself, say, speaking WebSocket with its handle, and no listener in between; the database not reading yet.
  const flood = new WebSocket(`${at}/use/market/dev/db`, { headers: { authorization: `Bearer ${HANDLE}`, 'coffre-tunnel-flow': 'credit' } });
  await once(flood, 'open');
  const flooded = once(flood, 'close');
  // A startup that claims a long first message, so the session waits for bytes that never make one; then 3 MiB more.
  const startup = Buffer.alloc(4);
  startup.writeInt32BE(9_000);
  flood.send(startup);
  for (let sent = 0; sent < 3 * WINDOW; sent += 256 * 1024) flood.send(Buffer.alloc(256 * 1024));
  await flooded;

  const greedy = new WebSocket(`${at}/use/market/dev/db`, { headers: { authorization: `Bearer ${HANDLE}`, 'coffre-tunnel-flow': 'credit' } });
  await once(greedy, 'open');
  const ended = once(greedy, 'close');
  // Nothing was sent to it yet: a count of anything opens the window past what it took.
  greedy.send('1000000');
  await ended;
});

test("a large result goes no faster than the app counts it: uncounted, the object holds back all but a window", { skip, timeout: 120_000 }, async () => {
  const ws = new WebSocket(`${at}/use/market/dev/db`, { headers: { authorization: `Bearer ${HANDLE}`, 'coffre-tunnel-flow': 'credit' } });
  // The object says it paces, with a count of nothing, before any byte.
  const [first, binary] = (await once(ws, 'message')) as [Buffer, boolean];
  assert.deepEqual([first.toString(), binary], ['0', false]);
  let received = 0;
  let counting = false;
  let tail = Buffer.alloc(0);
  const ready = () => tail.length >= 6 && tail.subarray(-6).equals(Buffer.from([0x5a, 0, 0, 0, 5, 0x49]));
  let readied: () => void = () => {};
  ws.on('message', (data: Buffer, binary: boolean) => {
    if (!binary) return;
    received += data.length;
    tail = Buffer.concat([tail, data]).subarray(-6);
    if (counting) ws.send(String(data.length));
    if (ready()) readied();
  });
  const idle = () => new Promise<void>((resolve) => (readied = resolve));
  // The startup, as a driver sends it, and the handle as the password.
  const params = Buffer.from('user\0app\0database\0app\0\0');
  const startup = Buffer.alloc(8);
  startup.writeInt32BE(8 + params.length, 0);
  startup.writeInt32BE(196608, 4);
  const message = (type: string, body: Buffer) => {
    const head = Buffer.alloc(5);
    head.write(type, 0);
    head.writeInt32BE(body.length + 4, 1);
    return Buffer.concat([head, body]);
  };
  counting = true;
  let login = idle();
  ws.send(Buffer.concat([startup, params]));
  await new Promise((resolve) => setTimeout(resolve, 200));
  ws.send(message('p', Buffer.from(`${HANDLE}\0`)));
  await login;

  // 64 MB of rows, and the app counts nothing: the object sends a window, and holds the rest in the database's socket.
  counting = false;
  received = 0;
  const done = idle();
  ws.send(message('Q', Buffer.from(`SELECT repeat('x', 1000) FROM generate_series(1, 64000)\0`)));
  await new Promise((resolve) => setTimeout(resolve, 2000));
  const held = received;
  assert.ok(held <= WINDOW + 128 * 1024, `the object sent ${held} bytes the app had not counted`);
  assert.ok(held >= WINDOW / 2, `the object sent only ${held} bytes before it waited`);

  // The app counts it all: the rest comes.
  counting = true;
  ws.send(String(held));
  await done;
  assert.ok(received > 64_000 * 1000, `the whole result came: ${received} bytes`);
  ws.close();
});
