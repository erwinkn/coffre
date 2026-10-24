// The local end of the credential proxy's database tunnel
// (docs/design/credential-proxy.md, "Postgres through a tunnel"): a listener
// on 127.0.0.1 for the app `coffre run` starts, which carries each of its
// connections over a WebSocket to coffre, with the run's handle. It holds no
// value and reads no byte: coffre logs in to the database, and the app's
// password, the handle, is checked there. For a workload, `coffre serve`'s
// or `coffre run --service`'s (docs/design/workload-access.md, section 9.3),
// each upgrade is signed by the session's key instead, DPoP, and the app's
// password is empty: the sidecar's boundary is the pod.
import { createServer, type Socket } from 'node:net';

import { upgradeHeaders, upgradeRefused, type Workload } from '@coffre/client/workload';
import { WebSocket } from 'ws';

/** A tunnel the plan names: the key the app reads its database's URL from, and coffre's end of it. */
export type Tunnel = { key: string; url: string };

/** How much one side may hold for the other before it stops reading: a few COPY chunks. */
const HIGH_WATER = 1024 * 1024;

/**
 * Credit flow, asked for in a header (on Workers, whose WebSockets have no
 * back-pressure: packages/server/src/cloudflare-sockets.ts): each side
 * counts back what it took, in text messages, each the bytes taken from
 * binary messages since its last, and sends at most `WINDOW` bytes the
 * other has not counted. coffre's first message says whether it paces: a
 * count, `0`, before any byte, or a byte, from a coffre on Node, which
 * reads its socket only as fast as it writes and ignores the counts. Until
 * it says, the listener holds the app to the window; it counts back
 * whatever coffre it reaches.
 */
const FLOW = 'coffre-tunnel-flow';
const WINDOW = 1024 * 1024;
/** How much the app takes before the listener counts it back: well under the window. */
const COUNT_EVERY = 128 * 1024;
/**
 * How often an open connection says it is there, idle or not: a count,
 * which reaches coffre's end, so that a psql left at its prompt outlives
 * Cloudflare's idle timeout (100 seconds), and keeps its Durable Object;
 * and a ping, whose pong must come before the next, or the connection is
 * gone, as when a laptop's network changes without a word.
 */
const KEEPALIVE_MS = 30_000;
/**
 * How long coffre has to answer the upgrade: a coffre that does not is gone,
 * and both ends close, rather than wait forever on it. Longer than coffre's
 * own 15 s wait for a turn and 45 s to admit (cloudflare-sockets.ts,
 * socket-admission.ts), so that its refusal for taking too long is the one said.
 */
const HANDSHAKE_MS = 70_000;

/**
 * A listener, on a port of its own (or at `address`, a sidecar's), for as
 * long as the run lasts; and the URL the app connects with. Its connections
 * are a person's run's, by `handle`, or a workload's, signed by its session.
 * `keepaliveMs` and `handshakeMs` are for tests.
 */
export async function listen(
  tunnel: Tunnel,
  as: string | Workload,
  { keepaliveMs = KEEPALIVE_MS, handshakeMs = HANDSHAKE_MS, address = { host: '127.0.0.1', port: 0 } } = {},
): Promise<{ url: string; close: () => void }> {
  const sockets = new Set<Socket>();
  /** The refusals said already, by status and reason: once each for the run, however many connections a pool retries. */
  const said = new Set<string>();
  const server = createServer((socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    const ws = new WebSocket(tunnel.url, { headers: { ...(typeof as === 'string' ? { authorization: `Bearer ${as}` } : {}), [FLOW]: 'credit' }, handshakeTimeout: handshakeMs, finishRequest: signed(as, tunnel.url) });
    carry(socket, ws, keepaliveMs);
    ws.on('unexpected-response', (request, response) => {
      // A workload's refusal carries the gate's newest nonce: the next connection signs with it.
      if (typeof as !== 'string') upgradeRefused(as, { get: (name) => (typeof response.headers[name] === 'string' ? (response.headers[name] as string) : null) });
      // coffre's refusal, said once for each reason: the app sees its connection close, and a driver may retry it at once.
      let body = '';
      response.setEncoding('utf8');
      response.on('data', (chunk: string) => (body = (body + chunk).slice(0, 1000)));
      response.on('end', () => {
        let message = body.trim();
        try {
          message = (JSON.parse(body) as { message?: string }).message ?? message;
        } catch {}
        const refusal = `(${response.statusCode})${message === '' ? '' : `: ${message}`}`;
        if (!said.has(refusal)) {
          said.add(refusal);
          process.stderr.write(`coffre: the tunnel for ${tunnel.key} was refused ${refusal}\n`);
        }
        request.destroy();
        socket.destroy();
      });
    });
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(address.port, address.host, () => resolve());
  });
  // A listener keeps no run alive: the run ends with its command.
  server.unref();
  const { port } = server.address() as { port: number };
  return {
    // The database's user and name are coffre's to set, from the real URL; the app's, `app`, are filler.
    url: `postgres://app${typeof as === 'string' ? `:${encodeURIComponent(as)}` : ''}@${address.host.includes(':') ? `[${address.host}]` : address.host}:${port}/app?sslmode=disable`,
    close: () => {
      for (const socket of sockets) socket.destroy();
      server.close();
    },
  };
}

/**
 * One app connection, carried over its WebSocket to coffre: each side reads
 * only as fast as the other takes, by credit with a coffre that paces, and
 * the keepalive. Exported for its properties (tunnel-properties.test.ts).
 */
export function carry(socket: Socket, ws: WebSocket, keepaliveMs: number): void {
  // Nothing read from the app until coffre's end is open: then each side reads only as fast as the other takes.
  socket.pause();
  /** Whether coffre paces: unknown until its first message says. */
  let pacing: boolean | null = null;
  /** Bytes sent that coffre has not counted, and bytes the app took that the listener has not. */
  let uncounted = 0;
  let taken = 0;
  /** Bytes coffre sent that the listener has not counted back: a coffre that paces keeps them under a window. */
  let owed = 0;
  let answered = true;
  const held = () => ws.bufferedAmount >= HIGH_WATER || (pacing !== false && uncounted >= WINDOW);
  const count = () => {
    if (ws.readyState !== WebSocket.OPEN) return;
    ws.send(String(taken), () => undefined);
    owed -= taken;
    taken = 0;
  };
  ws.on('open', () => socket.resume());
  ws.on('pong', () => (answered = true));
  const keepalive = setInterval(() => {
    if (ws.readyState !== WebSocket.OPEN) return;
    // A WebSocket paused for its app reads no pong: its silence says nothing of the network.
    if (!answered && !ws.isPaused) return ws.terminate();
    answered = false;
    ws.ping();
    count();
  }, keepaliveMs);
  keepalive.unref();
  socket.on('data', (chunk: Buffer) => {
    uncounted += chunk.length;
    ws.send(chunk, { binary: true }, () => {
      if (!held()) socket.resume();
    });
    if (held()) socket.pause();
  });
  ws.on('message', (data: Buffer, binary: boolean) => {
    if (!binary) {
      // coffre's count of what it took, the first saying that it paces: one that is no count of bytes it was sent ends the connection.
      const text = data.toString();
      const counted = Number(text);
      if (pacing === false || !/^\d{1,10}$/.test(text) || counted > uncounted) return ws.terminate();
      pacing = true;
      uncounted -= counted;
      if (!held()) socket.resume();
      return;
    }
    if (pacing === null) {
      // A byte first: coffre paces nothing, and the app is held to the window no longer.
      pacing = false;
      if (!held()) socket.resume();
    }
    // A coffre that said it paces and sends past two windows uncounted is held to it, as the object holds the listener.
    owed += data.length;
    if (pacing === true && owed > 2 * WINDOW) return ws.terminate();
    // Nothing for an app that has gone: a write there fails, and would pause the WebSocket with coffre's answer to its close unread.
    if (socket.destroyed) return;
    const flushed = socket.write(data, () => {
      taken += data.length;
      if (taken >= COUNT_EVERY) count();
    });
    // Paced, coffre sends no more than a window the app has not taken: the WebSocket need not wait for the app, and goes
    // on reading pongs and counts while it reads nothing (a psql in its pager). A coffre that does not pace (Node) waits.
    if (!flushed && pacing === false) ws.pause();
  });
  socket.on('drain', () => ws.resume());
  ws.on('close', () => {
    clearInterval(keepalive);
    socket.destroy();
  });
  ws.on('error', () => socket.destroy());
  socket.on('close', () => {
    clearInterval(keepalive);
    ws.close();
  });
  socket.on('error', () => ws.terminate());
}
