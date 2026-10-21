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

/** A stand-in coffre: each WebSocket the listener opens, with whether it asked for credit flow; paced if `credit`, which it says with a first `0`. */
async function coffre(credit: boolean): Promise<{ url: string; next: () => Promise<{ ws: WebSocket; asked: boolean }> }> {
  const http = createServer();
  const sockets = new WebSocketServer({ server: http });
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
  socket.write(Buffer.alloc(4 * WINDOW));
  for (let tries = 0; received < 4 * WINDOW && tries < 50; tries += 1) await settle();
  assert.equal(received, 4 * WINDOW);
  // Its counts go to a coffre that ignores them: none waits on a header a proxy could drop.
  ws.send(Buffer.alloc(COUNT_EVERY * 2));
  await settle();
  assert.deepEqual(texts, [String(COUNT_EVERY * 2)]);
  socket.destroy();
  close();
});

test('an idle connection says it is there every 30 seconds, a message that reaches coffre', async () => {
  const stand = await coffre(true);
  const { url, close } = await listen({ key: 'DATABASE_URL', url: stand.url }, HANDLE);
  mock.timers.enable({ apis: ['setInterval'] });
  try {
    const socket = await app(url);
    const { ws } = await stand.next();
    const texts: string[] = [];
    ws.on('message', (data: Buffer, binary: boolean) => !binary && texts.push(data.toString()));
    mock.timers.tick(29_000);
    await settle();
    assert.deepEqual(texts, []);
    mock.timers.tick(1_000);
    await settle();
    assert.deepEqual(texts, ['0']);
    mock.timers.tick(60_000);
    await settle();
    assert.deepEqual(texts, ['0', '0', '0']);
    socket.destroy();
  } finally {
    mock.timers.reset();
    close();
  }
});
