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
import { once } from 'node:events';
import { createServer, type AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import pg from 'pg';
import { unstable_dev, type Unstable_DevWorker } from 'wrangler';
import { WebSocket } from 'ws';

import { TEST_RUNTIME_DATABASE_URL } from './db/connections.ts';
import { TEST_ENGINE } from './db/engine.ts';
import { tunnelListener, WINDOW } from './tunnel-listener.ts';

const skip = TEST_ENGINE !== 'postgres' ? 'the tunnel reaches a Postgres database' : false;
const HANDLE = `coffre_use_${'h'.repeat(43)}`;
const REVOKED = `coffre_use_${'r'.repeat(43)}`;
const NAME = 'coffre-tunnel-workers-test';

let dir: string;
let worker: Unstable_DevWorker;
let at: string;
/** workerd's inspector, for the heap the object's isolate holds. */
let inspector: number;
const listeners: { close(): void }[] = [];

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
  const free = createServer().listen(0, '127.0.0.1');
  await once(free, 'listening');
  inspector = (free.address() as AddressInfo).port;
  free.close();
  worker = await unstable_dev(fileURLToPath(new URL('./workers/tunnel-worker.ts', import.meta.url)), {
    config: join(dir, 'wrangler.json'),
    local: true, ip: '127.0.0.1', port: 0, inspectorPort: inspector, persist: false, logLevel: 'error',
    experimental: { disableExperimentalWarning: true, disableDevRegistry: true },
  });
  at = `ws://${worker.address}:${worker.port}`;
}, { timeout: 120_000 });

after(async () => {
  for (const listener of listeners) listener.close();
  await worker?.stop();
  if (dir !== undefined) rmSync(dir, { recursive: true, force: true });
});

/** A listener for `tunnel`, closed after the suite; its port. */
async function listen(tunnel: string, handle = HANDLE): Promise<number> {
  const { port, close } = await tunnelListener(`${at}/use/market/dev/${tunnel}`, handle);
  listeners.push({ close });
  return port;
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

test('an object holds 32 connections of a run at most, a burst of them included: the next is refused, until one ends', { skip, timeout: 60_000 }, async () => {
  // Another handle, so another object, empty: each connection admitted, and waiting at its startup.
  const many = `coffre_use_${'m'.repeat(43)}`;
  const open = async () => {
    const ws = new WebSocket(`${at}/use/market/dev/db`, { headers: { authorization: `Bearer ${many}`, 'coffre-tunnel-flow': 'credit' } });
    ws.on('error', () => undefined);
    const [event, answer] = (await Promise.race([once(ws, 'open').then(() => ['open']), once(ws, 'unexpected-response').then(([, response]) => ['refused', response])])) as [string, { statusCode: number }?];
    return { ws, event, status: answer?.statusCode };
  };
  // Forty at once, as a pool starts: 32 are admitted, however many were being admitted together, and the rest refused.
  const burst = await Promise.all(Array.from({ length: 40 }, open));
  assert.equal(burst.filter(({ event }) => event === 'open').length, 32);
  assert.ok(burst.filter(({ event }) => event === 'refused').every(({ status }) => status === 503));
  const held = burst.filter(({ event }) => event === 'open');
  const refused = await open();
  assert.deepEqual([refused.event, refused.status], ['refused', 503]);
  const closed = once(held[0]!.ws, 'close');
  held[0]!.ws.close();
  await closed;
  // The slot comes back once the object has seen the session end.
  let again = await open();
  for (let tries = 0; again.event !== 'open' && tries < 50; tries += 1) {
    await new Promise((resolve) => setTimeout(resolve, 50));
    again = await open();
  }
  assert.equal(again.event, 'open');
  for (const { ws } of [...burst, again]) ws.close();
});

test("a pool's 32 connections opened at once are all let in, though each admission reads the URL in turn", { skip, timeout: 90_000 }, async () => {
  // Half a second each, one after another: together, 16 s, past one admission's time to decide had they all started at once.
  const turns = `coffre_use_${'t'.repeat(43)}`;
  const open = async () => {
    const ws = new WebSocket(`${at}/use/market/dev/db`, { headers: { authorization: `Bearer ${turns}`, 'coffre-tunnel-flow': 'credit' } });
    ws.on('error', () => undefined);
    const [event, answer] = (await Promise.race([once(ws, 'open').then(() => ['open']), once(ws, 'unexpected-response').then(([, response]) => ['refused', response])])) as [string, { statusCode: number }?];
    return { ws, event, status: answer?.statusCode };
  };
  const burst = await Promise.all(Array.from({ length: 32 }, open));
  assert.deepEqual(burst.map(({ event, status }) => status ?? event).filter((outcome) => outcome !== 'open'), []);
  for (const { ws } of burst) ws.close();
  // In turn, in fact: one until the first was in, then four at most.
  const asked = new WebSocket(`${at}/use/market/dev/db`, { headers: { authorization: `Bearer coffre_use_${'g'.repeat(43)}`, 'coffre-tunnel-flow': 'credit' } });
  asked.on('error', () => undefined);
  const [, response] = (await once(asked, 'unexpected-response')) as [unknown, NodeJS.ReadableStream];
  let body = '';
  for await (const chunk of response) body += String(chunk);
  assert.deepEqual(JSON.parse(body), { cold: 1, warm: 4 });
});

test('an admission that takes 20 s, as under a burst of runs at once, is let in', { skip, timeout: 60_000 }, async () => {
  const loaded = `coffre_use_${'l'.repeat(43)}`;
  const ws = new WebSocket(`${at}/use/market/dev/db`, { headers: { authorization: `Bearer ${loaded}`, 'coffre-tunnel-flow': 'credit' } });
  ws.on('error', () => undefined);
  const [event] = (await Promise.race([once(ws, 'open').then(() => ['open']), once(ws, 'unexpected-response').then(([, response]) => ['refused', response])])) as [string];
  assert.equal(event, 'open');
  ws.close();
});

test("a connection refused at admission frees its slot: 33 refused, then one let in", { skip, timeout: 60_000 }, async () => {
  const refused = `coffre_use_${'f'.repeat(43)}`;
  const open = async () => {
    const ws = new WebSocket(`${at}/use/market/dev/db`, { headers: { authorization: `Bearer ${refused}`, 'coffre-tunnel-flow': 'credit' } });
    ws.on('error', () => undefined);
    const [event, answer] = (await Promise.race([once(ws, 'open').then(() => ['open']), once(ws, 'unexpected-response').then(([, response]) => ['refused', response])])) as [string, { statusCode: number }?];
    return { ws, event, status: answer?.statusCode };
  };
  // The stand-in refuses this handle 33 times, one after another: past 32, only a slot not given back would refuse with 503.
  for (let tries = 0; tries < 33; tries += 1) assert.equal((await open()).status, 401);
  const admitted = await open();
  assert.equal(admitted.event, 'open');
  admitted.ws.close();
});

test("a connection refused while its admission goes on holds its slot until the admission is done", { skip, timeout: 60_000 }, async () => {
  const slow = `coffre_use_${'s'.repeat(43)}`;
  const open = async () => {
    const ws = new WebSocket(`${at}/use/market/dev/db`, { headers: { authorization: `Bearer ${slow}`, 'coffre-tunnel-flow': 'credit' } });
    ws.on('error', () => undefined);
    const [, response] = (await once(ws, 'unexpected-response')) as [unknown, { statusCode: number; on(event: 'data', listener: (chunk: Buffer) => void): void }];
    let text = '';
    response.on('data', (chunk) => (text += chunk.toString()));
    await once(response as never, 'end');
    return text;
  };
  // Each is refused at once, its decision going on a second: 32 of them fill the object, and the next finds no slot.
  const refusals = await Promise.all(Array.from({ length: 32 }, open));
  assert.ok(refusals.every((text) => text === 'coffre took too long to decide'));
  assert.match(await open(), /this run holds 32 connections here already/);
  // Their decisions done, the slots come back.
  await new Promise((resolve) => setTimeout(resolve, 1200));
  assert.equal(await open(), 'coffre took too long to decide');
});

test('a client that ignores the window is ended: past two windows uncounted, or counting what it was never sent', { skip, timeout: 30_000 }, async () => {
  // The app itself, say, speaking WebSocket with its handle, and no listener in between, to a database that takes nothing:
  // a startup and the password, as a driver sends them, and the session waits on the database, reading no more of the app.
  const flood = new WebSocket(`${at}/use/market/dev/stall`, { headers: { authorization: `Bearer ${HANDLE}`, 'coffre-tunnel-flow': 'credit' } });
  await once(flood, 'open');
  const flooded = once(flood, 'close') as Promise<[number, Buffer]>;
  const params = Buffer.from('user\0app\0database\0app\0\0');
  const startup = Buffer.alloc(8);
  startup.writeInt32BE(8 + params.length, 0);
  startup.writeInt32BE(196608, 4);
  flood.send(Buffer.concat([startup, params]));
  const password = Buffer.from(`p\0\0\0\0${HANDLE}\0`);
  password.writeInt32BE(password.length - 1, 1);
  flood.send(password);
  await new Promise((resolve) => setTimeout(resolve, 300));
  // Then 3 MiB, which the session does not take.
  for (let sent = 0; sent < 3 * WINDOW; sent += 256 * 1024) flood.send(Buffer.alloc(256 * 1024));
  // Ended for the window, not for a startup it could not read: the policy's close, and its reason.
  const [code, reason] = await flooded;
  assert.deepEqual([code, reason.toString()], [1008, 'past its window']);

  const greedy = new WebSocket(`${at}/use/market/dev/db`, { headers: { authorization: `Bearer ${HANDLE}`, 'coffre-tunnel-flow': 'credit' } });
  await once(greedy, 'open');
  const ended = once(greedy, 'close') as Promise<[number, Buffer]>;
  // Nothing was sent to it yet but the first count's: a count of anything opens the window past what it took.
  greedy.send('1000000');
  const [greedyCode, greedyReason] = await ended;
  assert.deepEqual([greedyCode, greedyReason.toString()], [1008, 'a count of bytes it was not sent']);
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

/** The JavaScript heap workerd's isolate holds once garbage is collected, in bytes, through its inspector. */
async function heapUsed(): Promise<number> {
  const [target] = (await (await fetch(`http://127.0.0.1:${inspector}/json`)).json()) as { webSocketDebuggerUrl: string }[];
  const cdp = new WebSocket(target!.webSocketDebuggerUrl);
  await once(cdp, 'open');
  let id = 0;
  const call = (method: string) =>
    new Promise<{ result?: { usedSize: number } }>((resolve) => {
      const mine = ++id;
      cdp.on('message', (data: Buffer) => {
        const answer = JSON.parse(data.toString()) as { id?: number; result?: { usedSize: number } };
        if (answer.id === mine) resolve(answer);
      });
      cdp.send(JSON.stringify({ id: mine, method }));
    });
  try {
    await call('HeapProfiler.collectGarbage');
    return (await call('Runtime.getHeapUsage')).result!.usedSize;
  } finally {
    cdp.close();
  }
}

test("a long result streamed through the object leaves its heap as it was: each chunk is let go once sent", { skip, timeout: 180_000 }, async () => {
  const ws = new WebSocket(`${at}/use/market/dev/db`, { headers: { authorization: `Bearer ${HANDLE}`, 'coffre-tunnel-flow': 'credit' } });
  await once(ws, 'message');
  let received = 0;
  let tail = Buffer.alloc(0);
  let reached: { at: number; then: () => void } | null = null;
  let readied: () => void = () => {};
  ws.on('message', (data: Buffer, binary: boolean) => {
    if (!binary) return;
    received += data.length;
    ws.send(String(data.length));
    tail = Buffer.concat([tail, data]).subarray(-6);
    if (tail.length === 6 && tail.equals(Buffer.from([0x5a, 0, 0, 0, 5, 0x49]))) readied();
    if (reached !== null && received >= reached.at) reached.then();
  });
  const idle = () => new Promise<void>((resolve) => (readied = resolve));
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
  const login = idle();
  ws.send(Buffer.concat([startup, params]));
  await new Promise((resolve) => setTimeout(resolve, 200));
  ws.send(message('p', Buffer.from(`${HANDLE}\0`)));
  await login;
  // 1.2 GB of rows, counted as they come; the heap read at 200 MB and again at 1 GB, the session still open, so that what
  // the other objects of this isolate did before is in both.
  const done = idle();
  const at200 = new Promise<void>((resolve) => (reached = { at: 200e6, then: resolve }));
  ws.send(message('Q', Buffer.from(`SELECT repeat('x', 1000) FROM generate_series(1, 1200000)\0`)));
  await at200;
  reached = null;
  const before = await heapUsed();
  const at1000 = new Promise<void>((resolve) => (reached = { at: 1000e6, then: resolve }));
  await at1000;
  reached = null;
  const during = await heapUsed();
  await done;
  ws.close();
  assert.ok(during - before < 8 * 1024 * 1024, `the object's heap grew ${Math.round((during - before) / 1024)} KiB over 800 MB`);
});
