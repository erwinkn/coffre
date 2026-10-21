// The local end of the credential proxy's database tunnel
// (docs/design/credential-proxy.md, "Postgres through a tunnel"): a listener
// on 127.0.0.1 for the app `coffre run` starts, which carries each of its
// connections over a WebSocket to coffre, with the run's handle. It holds no
// value and reads no byte: coffre logs in to the database, and the app's
// password, the handle, is checked there.
import { createServer, type Socket } from 'node:net';

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

/** A listener, on a port of its own, for as long as the run lasts; and the URL the app connects with. `keepaliveMs` is for tests. */
export async function listen(tunnel: Tunnel, handle: string, { keepaliveMs = KEEPALIVE_MS } = {}): Promise<{ url: string; close: () => void }> {
  const sockets = new Set<Socket>();
  /** The refusals said already, by status: once each for the run, however many connections a pool retries. */
  const said = new Set<number>();
  const server = createServer((socket) => {
    sockets.add(socket);
    // Nothing read from the app until coffre's end is open: then each side reads only as fast as the other takes.
    socket.pause();
    // A coffre that does not answer the upgrade in time is gone: both ends close, rather than wait forever on it.
    const ws = new WebSocket(tunnel.url, { headers: { authorization: `Bearer ${handle}`, [FLOW]: 'credit' }, handshakeTimeout: 15_000 });
    /** Whether coffre paces: unknown until its first message says. */
    let pacing: boolean | null = null;
    /** Bytes sent that coffre has not counted, and bytes the app took that the listener has not. */
    let uncounted = 0;
    let taken = 0;
    let answered = true;
    const held = () => ws.bufferedAmount >= HIGH_WATER || (pacing !== false && uncounted >= WINDOW);
    const count = () => {
      if (ws.readyState !== WebSocket.OPEN) return;
      ws.send(String(taken), () => undefined);
      taken = 0;
    };
    ws.on('open', () => socket.resume());
    ws.on('pong', () => (answered = true));
    const keepalive = setInterval(() => {
      if (ws.readyState !== WebSocket.OPEN) return;
      if (!answered) return ws.terminate();
      answered = false;
      ws.ping();
      count();
    }, keepaliveMs);
    keepalive.unref();
    ws.on('unexpected-response', (request, response) => {
      // coffre's refusal, said once per status: the app sees its connection close, and a driver may retry it at once.
      let body = '';
      response.setEncoding('utf8');
      response.on('data', (chunk: string) => (body = (body + chunk).slice(0, 1000)));
      response.on('end', () => {
        if (!said.has(response.statusCode ?? 0)) {
          said.add(response.statusCode ?? 0);
          let message = body.trim();
          try {
            message = (JSON.parse(body) as { message?: string }).message ?? message;
          } catch {}
          process.stderr.write(`coffre: the tunnel for ${tunnel.key} was refused (${response.statusCode})${message === '' ? '' : `: ${message}`}\n`);
        }
        request.destroy();
        socket.destroy();
      });
    });
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
      const flushed = socket.write(data, () => {
        taken += data.length;
        if (taken >= COUNT_EVERY) count();
      });
      if (!flushed) ws.pause();
    });
    socket.on('drain', () => ws.resume());
    ws.on('close', () => {
      clearInterval(keepalive);
      socket.destroy();
    });
    ws.on('error', () => socket.destroy());
    socket.on('close', () => {
      sockets.delete(socket);
      clearInterval(keepalive);
      ws.close();
    });
    socket.on('error', () => ws.terminate());
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve());
  });
  // A listener keeps no run alive: the run ends with its command.
  server.unref();
  const { port } = server.address() as { port: number };
  return {
    // The database's user and name are coffre's to set, from the real URL; the app's, `app`, are filler.
    url: `postgres://app:${encodeURIComponent(handle)}@127.0.0.1:${port}/app?sslmode=disable`,
    close: () => {
      for (const socket of sockets) socket.destroy();
      server.close();
    },
  };
}
