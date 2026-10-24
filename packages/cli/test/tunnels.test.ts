// `coffre run`'s tunnel listener against a stand-in coffre: credit flow
// with a coffre that answers the upgrade with it (Workers), each side
// sending no more than a window the other has not counted, and none with
// one that does not (Node); and the keepalive that keeps an idle
// connection's WebSocket, and its Durable Object, alive.
import test, { after, mock } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createServer, type Server } from 'node:http';
import { connect, type AddressInfo, type Socket } from 'node:net';

import { WebSocketServer, type WebSocket } from 'ws';

import { listen } from '../src/tunnels.ts';

const HANDLE = `coffre_use_${'h'.repeat(43)}`;
/** The listener's window and how often it counts back, tunnels.ts's. */
const WINDOW = 1024 * 1024;
const COUNT_EVERY = 128 * 1024;

const servers: Server[] = [];
after(() => servers.forEach((server) => server.close()));

/**
 * A stand-in coffre: each WebSocket the listener opens, with whether it
 * asked for credit flow; paced if `credit`, which it says with a first `0`;
 * deaf to pings, the network gone, if `deaf`.
 */
async function coffre(credit: boolean, { deaf = false } = {}): Promise<{ url: string; next: () => Promise<{ ws: WebSocket; asked: boolean }> }> {
  const http = createServer();
  const sockets = new WebSocketServer({ server: http, autoPong: !deaf });
  const opened: { ws: WebSocket; asked: boolean }[] = [];
  let waiting: (() => void) | null = null;
  sockets.on('connection', (ws, request) => {
    assert.equal(request.headers.authorization, `Bearer ${HANDLE}`);
    if (credit) ws.send('0');
    opened.push({ ws, asked: request.headers['coffre-tunnel-flow'] === 'credit' });
    waiting?.();
  });
  http.listen(0, '127.0.0.1');
  await once(http, 'listening');
  servers.push(http);
  return {
    url: `ws://127.0.0.1:${(http.address() as AddressInfo).port}/use/market/dev/db`,
    next: async () => {
      while (opened.length === 0) await new Promise<void>((resolve) => (waiting = resolve));
      return opened.shift()!;
    },
  };
}

/** The app's connection to the listener. */
async function app(url: string): Promise<Socket> {
  const { port } = new URL(url);
  const socket = connect({ host: '127.0.0.1', port: Number(port) });
  await once(socket, 'connect');
  return socket;
}

const settle = () => new Promise((resolve) => setTimeout(resolve, 300));

test("with a coffre that paces it, the app's bytes go no further than a window coffre has not counted", async () => {
  const stand = await coffre(true);
  const { url, close } = await listen({ key: 'DATABASE_URL', url: stand.url }, HANDLE);
  const socket = await app(url);
  const { ws, asked } = await stand.next();
  assert.ok(asked);
  let received = 0;
  ws.on('message', (data: Buffer, binary: boolean) => binary && (received += data.length));
  // 4 MiB from the app, which coffre does not count: a window of it reaches coffre, the rest waits in the app's socket.
  socket.write(Buffer.alloc(4 * WINDOW));
  await settle();
  assert.ok(received >= WINDOW && received <= WINDOW + 128 * 1024, `${received} bytes reached coffre uncounted`);
  // Counted, the rest comes.
  ws.on('message', (data: Buffer, binary: boolean) => binary && ws.send(String(data.length)));
  ws.send(String(received));
  for (let tries = 0; received < 4 * WINDOW && tries < 50; tries += 1) await settle();
  assert.equal(received, 4 * WINDOW);
  socket.destroy();
  close();
});

test("the listener counts back what the app took, so that coffre sends on", async () => {
  const stand = await coffre(true);
  const { url, close } = await listen({ key: 'DATABASE_URL', url: stand.url }, HANDLE);
  const socket = await app(url);
  const { ws } = await stand.next();
  const counts: number[] = [];
  ws.on('message', (data: Buffer, binary: boolean) => !binary && counts.push(Number(data.toString())));
  let read = 0;
  socket.on('data', (chunk: Buffer) => (read += chunk.length));
  for (let sent = 0; sent < 2 * WINDOW; sent += 64 * 1024) ws.send(Buffer.alloc(64 * 1024));
  for (let tries = 0; read < 2 * WINDOW && tries < 50; tries += 1) await settle();
  await settle();
  const counted = counts.reduce((sum, count) => sum + count, 0);
  assert.equal(read, 2 * WINDOW);
  assert.ok(counted <= read && read - counted < COUNT_EVERY, `${counted} of ${read} bytes counted`);
  assert.ok(counts.every((count) => count >= COUNT_EVERY), 'counted in steps, not per message');
  socket.destroy();
  close();
});

test('with a coffre that does not pace it (Node), the listener holds nothing back for want of a count, and counts back all the same', async () => {
  const stand = await coffre(false);
  const { url, close } = await listen({ key: 'DATABASE_URL', url: stand.url }, HANDLE);
  const socket = await app(url);
  const { ws } = await stand.next();
  let received = 0;
  const texts: string[] = [];
  ws.on('message', (data: Buffer, binary: boolean) => (binary ? (received += data.length) : texts.push(data.toString())));
  // Until coffre's first message, the listener cannot tell it from one that paces: the app is held to the window.
  socket.write(Buffer.alloc(4 * WINDOW));
  await settle();
  assert.ok(received >= WINDOW && received <= WINDOW + 128 * 1024, `${received} bytes reached coffre before it said anything`);
  // Its first message is a byte, as a database's answer is: coffre on Node paces nothing, and the rest comes.
  ws.send(Buffer.from('N'));
  for (let tries = 0; received < 4 * WINDOW && tries < 50; tries += 1) await settle();
  assert.equal(received, 4 * WINDOW);
  // Its counts go to a coffre that ignores them: none waits on a header a proxy could drop.
  ws.send(Buffer.alloc(COUNT_EVERY * 2));
  await settle();
  assert.deepEqual(texts, [String(COUNT_EVERY * 2 + 1)]);
  socket.destroy();
  close();
});

test('an idle connection says it is there each interval (30 seconds), a message that reaches coffre', async () => {
  const stand = await coffre(true);
  const { url, close } = await listen({ key: 'DATABASE_URL', url: stand.url }, HANDLE, { keepaliveMs: 200 });
  const socket = await app(url);
  const { ws } = await stand.next();
  const texts: string[] = [];
  ws.on('message', (data: Buffer, binary: boolean) => !binary && texts.push(data.toString()));
  await new Promise((resolve) => setTimeout(resolve, 700));
  // Each ping answered before the next: the connection stays, and says it is there each time.
  assert.ok(texts.length >= 2 && texts.every((text) => text === '0'), `${JSON.stringify(texts)}`);
  assert.equal(socket.destroyed, false);
  socket.destroy();
  close();
});

test('an app that stops reading for a while keeps its connection: the listener still hears the pongs', async () => {
  const stand = await coffre(true);
  const { url, close } = await listen({ key: 'DATABASE_URL', url: stand.url }, HANDLE, { keepaliveMs: 200 });
  const socket = await app(url);
  const { ws } = await stand.next();
  // coffre as it paces: never more than a window the listener has not counted.
  const total = 32 * WINDOW;
  let sent = 0;
  let uncounted = 0;
  const send = () => {
    while (sent < total && uncounted < WINDOW) {
      ws.send(Buffer.alloc(64 * 1024));
      sent += 64 * 1024;
      uncounted += 64 * 1024;
    }
  };
  ws.on('message', (data: Buffer, binary: boolean) => {
    if (binary) return;
    uncounted -= Number(data.toString());
    send();
  });
  send();
  // A psql in its pager, or a slow consumer: the app reads nothing for five intervals.
  socket.pause();
  await new Promise((resolve) => setTimeout(resolve, 1000));
  assert.equal(ws.readyState, ws.OPEN, 'the listener ended a connection whose app stopped reading');
  let read = 0;
  socket.on('data', (chunk: Buffer) => (read += chunk.length));
  socket.resume();
  for (let tries = 0; read < total && tries < 50; tries += 1) await settle();
  assert.equal(read, total);
  socket.destroy();
  close();
});

test('a connection whose ping goes unanswered until the next is gone: the app sees it close', async () => {
  const stand = await coffre(true, { deaf: true });
  const { url, close } = await listen({ key: 'DATABASE_URL', url: stand.url }, HANDLE, { keepaliveMs: 200 });
  const socket = await app(url);
  await stand.next();
  const started = Date.now();
  await once(socket, 'close');
  // A ping at the first interval, unanswered at the second.
  assert.ok(Date.now() - started < 1000);
  close();
});

test("once the app has closed, the listener's WebSocket closes at once, however much coffre was still sending", async () => {
  const stand = await coffre(true);
  const { url, close } = await listen({ key: 'DATABASE_URL', url: stand.url }, HANDLE);
  const socket = await app(url);
  const { ws } = await stand.next();
  // coffre's bytes still come, for an app that is gone: writing them to its socket must not pause the WebSocket,
  // or coffre's answer to the listener's close waits unread until ws's close timeout, 30 seconds.
  socket.destroy();
  const closed = once(ws, 'close');
  const sending = setInterval(() => ws.readyState === ws.OPEN && ws.send(Buffer.alloc(64 * 1024)), 1);
  try {
    const started = Date.now();
    await Promise.race([closed, new Promise((resolve) => setTimeout(resolve, 3000))]);
    assert.ok(Date.now() - started < 3000, "the listener's WebSocket is still open");
  } finally {
    clearInterval(sending);
    ws.terminate();
    close();
  }
});

test("a count that is none, or for bytes coffre was never sent, ends the connection", async () => {
  for (const said of ['soon', '5']) {
    const stand = await coffre(true);
    const { url, close } = await listen({ key: 'DATABASE_URL', url: stand.url }, HANDLE);
    const socket = await app(url);
    const { ws } = await stand.next();
    const closed = once(socket, 'close');
    // Nothing was sent to coffre yet: no count but 0 is one.
    ws.send(said);
    await closed;
    close();
  }
});

test('a refused tunnel says why, once for each reason in the run, however many connections the app retries', async () => {
  const http = createServer();
  let refusals = 0;
  http.on('upgrade', (_, socket) => {
    // The same status for two reasons: the cap, twice, then the migration door.
    refusals += 1;
    const body = JSON.stringify({ error: 'credential_proxy', message: refusals <= 2 ? 'this run holds 32 connections here already' : "coffre's database lacks this version's migrations" });
    socket.end(`HTTP/1.1 503 Service Unavailable\r\ncontent-type: application/json\r\ncontent-length: ${body.length}\r\nconnection: close\r\n\r\n${body}`);
  });
  http.listen(0, '127.0.0.1');
  await once(http, 'listening');
  servers.push(http);
  const { url, close } = await listen({ key: 'DATABASE_URL', url: `ws://127.0.0.1:${(http.address() as AddressInfo).port}/use/market/dev/db` }, HANDLE);
  const written: string[] = [];
  const stderr = mock.method(process.stderr, 'write', (text: string) => (written.push(text), true));
  try {
    for (let tries = 0; tries < 3; tries += 1) {
      const socket = await app(url);
      await once(socket, 'close');
    }
  } finally {
    stderr.mock.restore();
    close();
  }
  assert.deepEqual(written, [
    'coffre: the tunnel for DATABASE_URL was refused (503): this run holds 32 connections here already\n',
    "coffre: the tunnel for DATABASE_URL was refused (503): coffre's database lacks this version's migrations\n",
  ]);
});
