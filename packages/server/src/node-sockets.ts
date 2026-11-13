// A plugin's WebSockets on Node (`routes.socket`, in plugins.ts): the
// server's `upgrade` event, answered with the plugin's refusal or its
// session, and TCP out for that session, TLS once its protocol says so.
// Node only: `node:net` and `node:tls` stay out of the Workers build.
import type { IncomingMessage } from 'node:http';
import { connect as tcp, type LookupFunction, type Socket as NetSocket } from 'node:net';
import { connect as tls } from 'node:tls';
import type { Duplex } from 'node:stream';

import { WebSocketServer, type WebSocket } from 'ws';
import { BODY_READ_WHOLE_BYTES } from '@coffre/core/memory';

import type { Connect, Pipe, Socket } from './plugins.ts';
import type { CoffreRuntime } from './runtime.ts';
import { admitSocket } from './socket-admission.ts';
import { literalRefusal, publicLookup } from './workloads/node-transport.ts';

/**
 * A message is held whole until it has all come, as a body read whole is, and no larger (`@coffre/core/memory`). A
 * tunnel's clients send 64 KiB a message at most: `@coffre/client`'s frames, and what the CLI's socket reads at once.
 */
const sockets = new WebSocketServer({ noServer: true, maxPayload: BODY_READ_WHOLE_BYTES });

/** What frames an HTTP answer, which the refusal writer says itself. */
const FRAMING = new Set(['connection', 'content-length', 'transfer-encoding', 'keep-alive', 'upgrade']);

/**
 * One `upgrade` of the server's: the plugin under the path decides, and
 * a path no plugin takes for a socket is a 404. The request reaches the
 * plugin as a `Request` with its headers and no body, as a WebSocket's
 * handshake has none.
 */
export async function upgrade(runtime: CoffreRuntime, incoming: IncomingMessage, socket: Duplex, head: Buffer): Promise<void> {
  // Node lets go of the socket's errors before it hands an upgrade over: one reset while the plugin decides would crash the process.
  const ignore = () => socket.destroy();
  socket.on('error', ignore);
  // A peer that leaves while the plugin decides takes its socket with it.
  socket.once('end', ignore);
  const headers = new Headers();
  for (const [name, value] of Object.entries(incoming.headers)) if (typeof value === 'string') headers.set(name, value);
  const request = new Request(new URL(incoming.url ?? '/', runtime.publicUrl), { headers });
  const answer = await admitSocket(request, runtime, incoming.socket.remoteAddress ?? null);
  if (socket.destroyed) return;
  if (answer instanceof Response) {
    // The plugin's refusal: its status and headers (`coffre-proxy`, `www-authenticate`), framed for this one answer, and no
    // body, which no WebSocket client reads and a plugin's stream could hold the socket with.
    void answer.body?.cancel().catch(() => undefined);
    const headers = [...answer.headers].filter(([name]) => !FRAMING.has(name)).map(([name, value]) => `${name}: ${value}\r\n`).join('');
    // Then gone, once said or a second on: a peer that keeps its side open keeps nothing of the server's.
    const gone = setTimeout(() => socket.destroy(), 1000);
    gone.unref();
    socket.once('close', () => clearTimeout(gone));
    socket.end(`HTTP/1.1 ${answer.status} ${answer.statusText || 'Refused'}\r\n${headers}content-length: 0\r\nconnection: close\r\n\r\n`, 'latin1', () => socket.destroy());
    return;
  }
  const session = answer;
  if (socket.destroyed) return;
  socket.off('end', ignore);
  sockets.handleUpgrade(incoming, socket, head, (ws) => {
    socket.off('error', ignore);
    void session(fromWebSocket(ws), connect).catch(() => undefined).finally(() => ws.terminate());
  });
}

/** A WebSocket's binary messages as a byte stream, each way, paused while the stream's reader is behind; nothing delivered once it ends. */
function fromWebSocket(ws: WebSocket): Pipe {
  const closed = new Promise<void>((resolve) => ws.once('close', () => resolve()));
  let done = false;
  let stop = () => {};
  const readable = new ReadableStream<Uint8Array>({
    start(controller) {
      const finish = (end: () => void) => {
        if (done) return;
        done = true;
        ws.off('message', deliver);
        try {
          end();
        } catch {}
      };
      // Frames `ws` still drains while it terminates find the stream ended, and are dropped.
      const deliver = (data: Buffer, binary: boolean) => {
        if (!binary || done || data.length === 0) return;
        controller.enqueue(new Uint8Array(data));
        if ((controller.desiredSize ?? 1) <= 0) ws.pause();
      };
      ws.on('message', deliver);
      ws.on('close', () => finish(() => controller.close()));
      ws.on('error', (error) => finish(() => controller.error(error)));
      stop = () => finish(() => undefined);
    },
    pull: () => ws.resume(),
    cancel: () => {
      stop();
      ws.terminate();
    },
  }, { highWaterMark: 8 });
  const writable = new WritableStream<Uint8Array>({
    write: (chunk) => new Promise<void>((resolve, reject) => ws.send(chunk, { binary: true }, (error) => (error ? reject(error) : resolve()))),
    close: () => ws.close(),
    abort: () => ws.terminate(),
  });
  return { readable, writable, close: () => ws.terminate(), closed };
}

/** TCP out, on Node: a socket, which `startTls` hands over to TLS as it stands, nothing read beyond what was asked. */
const connect: Connect = (host, port, signal) => dial({ host, port }, signal);

/**
 * TCP out to a host an Owner typed, a UI tunnel's database (docs/design/proxy-ui.md, section 5): its name resolved
 * through `lookup` as the connection opens, which refuses a name with any answer that is not public, so a name that
 * resolves to `10.0.1.5` gets no SYN, however it resolved a moment before; an address written as one, which Node
 * dials without asking a resolver, is checked as written. TLS, once Postgres says it will, still checks the
 * certificate against the name.
 *
 *   db.acme.example:5432, resolving to 34.117.1.2       dialled
 *   db.attacker.example:5432, resolving to 10.0.1.5     refused before the SYN: ENOTPUBLIC
 *   [::ffff:a00:105]:5432                               refused: 10.0.1.5, written as IPv6
 */
export function publicConnect(lookup: LookupFunction = publicLookup): Connect {
  return (host, port, signal) => {
    const refused = literalRefusal(host);
    if (refused !== null) return Promise.reject(refused);
    return dial({ host: host.replace(/^\[|\]$/g, ''), port, lookup }, signal);
  };
}

function dial(options: { host: string; port: number; lookup?: LookupFunction }, signal: AbortSignal | undefined): Promise<Socket> {
  return new Promise<Socket>((resolve, reject) => {
    if (signal?.aborted) return reject(new Error('the session ended'));
    const socket = tcp(options);
    const abort = () => {
      socket.destroy();
      reject(new Error('the session ended'));
    };
    signal?.addEventListener('abort', abort, { once: true });
    socket.once('error', reject);
    socket.once('connect', () => {
      socket.off('error', reject);
      signal?.removeEventListener('abort', abort);
      resolve(fromNetSocket(socket));
    });
  });
}

function fromNetSocket(socket: NetSocket | ReturnType<typeof tls>): Socket {
  // Each event's own arguments.
  type Listener = (...args: any[]) => void;
  const listeners: [string, Listener][] = [];
  // Once the stream ended, by either side: no chunk is delivered to it.
  let done = false;
  const on = (event: string, listener: Listener) => {
    listeners.push([event, listener]);
    socket.on(event, listener);
  };
  const readable = new ReadableStream<Uint8Array>(
    {
      start(controller) {
        on('data', (chunk: Buffer) => {
          if (done) return;
          controller.enqueue(new Uint8Array(chunk));
          if ((controller.desiredSize ?? 1) <= 0) socket.pause();
        });
        on('end', () => {
          done = true;
          try {
            controller.close();
          } catch {}
        });
        on('error', (error: Error) => {
          done = true;
          try {
            controller.error(error);
          } catch {}
        });
      },
      pull: () => void socket.resume(),
      cancel: () => {
        done = true;
        socket.destroy();
      },
    },
    { highWaterMark: 8 },
  );
  const writable = new WritableStream<Uint8Array>({
    write: (chunk) => new Promise<void>((resolve, reject) => socket.write(chunk, (error) => (error ? reject(error) : resolve()))),
    close: () => void socket.end(),
    abort: () => void socket.destroy(),
  });
  const closed = new Promise<void>((resolve) => socket.once('close', () => resolve()));
  return {
    readable,
    writable,
    closed,
    close: () => void socket.destroy(),
    startTls: (servername) =>
      new Promise<Pipe>((resolve, reject) => {
        // Nothing more comes before the handshake: the streams above let go, and TLS takes the socket as it is.
        for (const [event, listener] of listeners) socket.off(event, listener);
        socket.pause();
        const secure = tls({ socket: socket as NetSocket, servername });
        secure.once('error', reject);
        secure.once('secureConnect', () => {
          secure.off('error', reject);
          resolve(fromNetSocket(secure));
        });
      }),
  };
}
