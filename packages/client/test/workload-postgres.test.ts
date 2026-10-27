import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';

import { oidc, workload } from '../src/workload.ts';
import { connect, type TunnelSocket } from '../src/workload-postgres.ts';

/** A session that a fake coffre signs in: the exchange answers, nothing else is asked. */
async function session() {
  const fetch = async (url: string | URL | Request) => {
    assert.match(String(url), /\/api\/auth\/workload$/);
    const now = Date.now();
    const body = { token: 'session-token', expiresAt: new Date(now + 600_000).toISOString(), notAfter: new Date(now + 3_600_000).toISOString(), places: ['market/prod'] };
    return new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } });
  };
  return workload({ url: 'https://coffre.test', service: 'api-prod', proof: oidc(() => 'id-token'), fetch, log: () => undefined });
}

/** A WebSocket that opens and closes when the test says so. */
class Socket implements TunnelSocket {
  static made: Socket[] = [];
  binaryType = 'blob';
  readyState = 0;
  bufferedAmount = 0;
  readonly sent: unknown[] = [];
  readonly #listeners = new Map<string, ((event: object) => void)[]>();
  constructor() {
    Socket.made.push(this);
  }
  addEventListener(type: string, listener: (event: object) => void) {
    this.#listeners.set(type, [...(this.#listeners.get(type) ?? []), listener]);
  }
  fire(type: 'open' | 'close') {
    this.readyState = type === 'open' ? 1 : 3;
    for (const listener of this.#listeners.get(type) ?? []) listener({});
  }
  send(data: unknown) {
    this.sent.push(data);
  }
  /** Closing waits for coffre's side, which `fire('close')` plays. */
  close() {
    this.readyState = 2;
  }
}

async function opened() {
  for (let tries = 0; Socket.made.length === 0; tries += 1) {
    assert.ok(tries < 100, 'no WebSocket was made');
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  return Socket.made.pop()!;
}

test("a tunnel's stream says where it is as a socket does: opening, open, ended by the app, closed", async () => {
  const coffre = await session();
  try {
    const stream = connect(coffre, 'db', { WebSocket: Socket as never });
    assert.equal(stream.readyState, 'opening');
    const socket = await opened();
    assert.equal(stream.readyState, 'opening', 'until the WebSocket opens');
    socket.fire('open');
    assert.equal(stream.readyState, 'open');
    // The app says goodbye (postgres.js ends only an open socket): its side ends, the WebSocket closes.
    stream.end(Buffer.from('X'));
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(stream.readyState, 'readOnly');
    assert.equal(socket.readyState, 2, 'the WebSocket is closing');
    // coffre closes its side: the stream closes, and says so, which postgres.js's end() waits for.
    const closed = once(stream, 'close');
    socket.fire('close');
    await closed;
    assert.equal(stream.readyState, 'closed');
  } finally {
    await coffre.close().catch(() => undefined);
  }
});

test('a stream destroyed before its WebSocket opens is closed', async () => {
  const coffre = await session();
  try {
    const stream = connect(coffre, 'db', { WebSocket: Socket as never });
    stream.destroy();
    assert.equal(stream.readyState, 'closed');
  } finally {
    await coffre.close().catch(() => undefined);
  }
});
