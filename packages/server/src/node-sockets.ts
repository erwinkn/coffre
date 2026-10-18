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

/**
 * One `upgrade` of the server's: the plugin under the path decides, and
 * a path no plugin takes for a socket is a 404. The request reaches the
 * plugin as a `Request` with its headers and no body, as a WebSocket's
 * handshake has none.
 */
export async function upgrade(runtime: CoffreRuntime, incoming: IncomingMessage, socket: Duplex, head: Buffer): Promise<void> {
  const headers = new Headers();
  for (const [name, value] of Object.entries(incoming.headers)) if (typeof value === 'string') headers.set(name, value);
  const request = new Request(new URL(incoming.url ?? '/', runtime.publicUrl), { headers });
  let answer: Response | Awaited<NonNullable<ReturnType<typeof pluginSocket>>>;
  try {
    // The migration door, as `respond` keeps it for every other request.
    answer = !(await schemaReady(runtime))
      ? new Response("coffre's database lacks this version's migrations", { status: 503 })
      : ((await pluginSocket(request, runtime, incoming.socket.remoteAddress ?? null)) ?? new Response('no WebSocket here', { status: 404 }));
  } catch {
    answer = new Response('the plugin failed', { status: 500 });
  }
  if (answer instanceof Response) {
    const body = Buffer.from(await answer.arrayBuffer());
    socket.end(`HTTP/1.1 ${answer.status} ${answer.statusText || 'Refused'}\r\ncontent-type: ${answer.headers.get('content-type') ?? 'text/plain'}\r\ncontent-length: ${body.length}\r\nconnection: close\r\n\r\n${body.toString('latin1')}`, 'latin1');
    return;
  }
  const session = answer;
  sockets.handleUpgrade(incoming, socket, head, (ws) => {
    void session(fromWebSocket(ws), connect).catch(() => undefined).finally(() => ws.terminate());
  });
}

/** A WebSocket's binary messages as a byte stream, each way. */
function fromWebSocket(ws: WebSocket): Pipe {
  const readable = new ReadableStream<Uint8Array>({
    start(controller) {
      ws.on('message', (data: Buffer, binary: boolean) => {
        if (binary) controller.enqueue(new Uint8Array(data));
      });
      ws.on('close', () => {
        try {
          controller.close();
        } catch {}
      });
      ws.on('error', (error) => controller.error(error));
    },
    cancel: () => ws.terminate(),
  });
  const writable = new WritableStream<Uint8Array>({
    write: (chunk) => new Promise<void>((resolve, reject) => ws.send(chunk, { binary: true }, (error) => (error ? reject(error) : resolve()))),
    close: () => ws.close(),
    abort: () => ws.terminate(),
  });
  return { readable, writable, close: () => ws.terminate() };
}

/** TCP out, on Node: a socket, which `startTls` hands over to TLS as it stands, nothing read beyond what was asked. */
const connect: Connect = (host, port) =>
  new Promise<Socket>((resolve, reject) => {
    const socket = tcp({ host, port });
    socket.once('error', reject);
    socket.once('connect', () => {
      socket.off('error', reject);
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
  return {
    readable,
    writable,
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
