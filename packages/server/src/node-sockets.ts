// A plugin's WebSockets on Node (`routes.socket`, in plugins.ts): the
// server's `upgrade` event, answered with the plugin's refusal or its
// session, and TCP out for that session, TLS once its protocol says so.
// Node only: `node:net` and `node:tls` stay out of the Workers build.
import type { IncomingMessage } from 'node:http';
import { connect as tcp, type Socket as NetSocket } from 'node:net';
import { connect as tls } from 'node:tls';
import type { Duplex } from 'node:stream';

import { WebSocketServer, type WebSocket } from 'ws';

import { schemaReady } from './app.ts';
import { pluginSocket, type Connect, type Pipe, type Socket } from './plugins.ts';
import type { CoffreRuntime } from './runtime.ts';

const sockets = new WebSocketServer({ noServer: true, maxPayload: 16 * 1024 * 1024 });

/** How long a plugin has to admit a WebSocket or refuse it. */
const ADMISSION_MS = 15_000;

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
  let answer: Response | Awaited<NonNullable<ReturnType<typeof pluginSocket>>>;
  let late: ReturnType<typeof setTimeout> | undefined;
  try {
    // The migration door, as `respond` keeps it for every other request; and a plugin that has not decided in time has refused.
    const decided = (async () =>
      !(await schemaReady(runtime))
        ? new Response("coffre's database lacks this version's migrations", { status: 503 })
        : ((await pluginSocket(request, runtime, incoming.socket.remoteAddress ?? null)) ?? new Response('no WebSocket here', { status: 404 })))();
    answer = await Promise.race([decided, new Promise<Response>((resolve) => (late = setTimeout(() => resolve(new Response('coffre took too long to decide', { status: 503 })), ADMISSION_MS)))]);
  } catch {
    answer = new Response('the plugin failed', { status: 500 });
  } finally {
    clearTimeout(late);
  }
  if (socket.destroyed) return;
  if (answer instanceof Response) {
    // The plugin's refusal as it said it, its headers included (`coffre-proxy`, `www-authenticate`), framed for this one answer.
    const body = Buffer.from(await answer.arrayBuffer());
    const headers = [...answer.headers].filter(([name]) => !FRAMING.has(name)).map(([name, value]) => `${name}: ${value}\r\n`).join('');
    // Then gone, once said or a second on: a peer that keeps its side open keeps nothing of the server's.
    const gone = setTimeout(() => socket.destroy(), 1000);
    gone.unref();
    socket.once('close', () => clearTimeout(gone));
    socket.end(`HTTP/1.1 ${answer.status} ${answer.statusText || 'Refused'}\r\n${headers}content-length: ${body.length}\r\nconnection: close\r\n\r\n${body.toString('latin1')}`, 'latin1', () => socket.destroy());
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

/** A WebSocket's binary messages as a byte stream, each way, paused while the stream's reader is behind. */
function fromWebSocket(ws: WebSocket): Pipe {
  const closed = new Promise<void>((resolve) => ws.once('close', () => resolve()));
  const readable = new ReadableStream<Uint8Array>({
    start(controller) {
      ws.on('message', (data: Buffer, binary: boolean) => {
        if (!binary) return;
        controller.enqueue(new Uint8Array(data));
        if ((controller.desiredSize ?? 1) <= 0) ws.pause();
      });
      ws.on('close', () => {
        try {
          controller.close();
        } catch {}
      });
      ws.on('error', (error) => controller.error(error));
    },
    pull: () => ws.resume(),
    cancel: () => ws.terminate(),
  }, { highWaterMark: 8 });
  const writable = new WritableStream<Uint8Array>({
    write: (chunk) => new Promise<void>((resolve, reject) => ws.send(chunk, { binary: true }, (error) => (error ? reject(error) : resolve()))),
    close: () => ws.close(),
    abort: () => ws.terminate(),
  });
  return { readable, writable, close: () => ws.terminate(), closed };
}

/** TCP out, on Node: a socket, which `startTls` hands over to TLS as it stands, nothing read beyond what was asked. */
const connect: Connect = (host, port, signal) =>
  new Promise<Socket>((resolve, reject) => {
    if (signal?.aborted) return reject(new Error('the session ended'));
    const socket = tcp({ host, port });
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

function fromNetSocket(socket: NetSocket | ReturnType<typeof tls>): Socket {
  // Each event's own arguments.
  type Listener = (...args: any[]) => void;
  const listeners: [string, Listener][] = [];
  const on = (event: string, listener: Listener) => {
    listeners.push([event, listener]);
    socket.on(event, listener);
  };
  const readable = new ReadableStream<Uint8Array>(
    {
      start(controller) {
        on('data', (chunk: Buffer) => {
          controller.enqueue(new Uint8Array(chunk));
          if ((controller.desiredSize ?? 1) <= 0) socket.pause();
        });
        on('end', () => {
          try {
            controller.close();
          } catch {}
        });
        on('error', (error: Error) => {
          try {
            controller.error(error);
          } catch {}
        });
      },
      pull: () => void socket.resume(),
      cancel: () => void socket.destroy(),
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
