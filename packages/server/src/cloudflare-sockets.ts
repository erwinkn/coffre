// A plugin's WebSockets on Workers (`routes.socket`, in plugins.ts): the
// credential proxy's database tunnel. A Worker's invocation is no place for
// a connection that lasts an hour, and a Postgres cancel request comes on a
// connection of its own, which could land in any isolate. So the Worker
// only routes: each WebSocket goes to a Durable Object named by its path and
// its bearer, which is one `coffre run`'s connections to one database, its
// cancel requests among them. There the plugin admits it, as on Node, and
// its session runs, with TCP out through `cloudflare:sockets`.
//
// The object holds what one run's connections share, and nothing an
// instance decides: access, the vault and the log stay where every request
// reaches them, through the plugin's context.
import { cloudflareSourceIp } from './auth.ts';
import type { Connect, Pipe, Socket } from './plugins.ts';
import type { CoffreRuntime } from './runtime.ts';
import { admitSocket } from './socket-admission.ts';

/** The Durable Object binding the deployment hands coffre: `sockets: env.SOCKETS`. */
export type SocketsNamespace = {
  idFromName(name: string): unknown;
  get(id: unknown): { fetch(request: Request): Promise<Response> };
};

/** What the object is given by the runtime: its `waitUntil`, for the database's closing. */
type ObjectState = { waitUntil(promise: Promise<unknown>): void };

/**
 * A WebSocket a plugin takes, sent to its object: one per path and bearer,
 * which the name is a digest of, so that the bearer, a handle, names no
 * object anyone can read.
 */
export async function forwardSocket(request: Request, sockets: SocketsNamespace): Promise<Response> {
  const { pathname } = new URL(request.url);
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`${pathname}\n${request.headers.get('authorization') ?? ''}`));
  const name = [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
  return sockets.get(sockets.idFromName(name)).fetch(request);
}

/** How long the object's database client stays open once idle: a check's queries share it, and a session holds none between checks. */
export const IDLE_DATABASE_MS = 1_000;

/**
 * The Durable Object class the deployment exports, `export const
 * CoffreSockets = coffre.Sockets`. `runtime` makes coffre for the object,
 * once: its database client opens with a query and closes once idle.
 */
export function socketsObject<Env>(runtime: (env: Env, state: ObjectState) => CoffreRuntime) {
  return class CoffreSockets {
    readonly #state: ObjectState;
    readonly #env: Env;
    #runtime: CoffreRuntime | undefined;
    constructor(state: ObjectState, env: Env) {
      this.#state = state;
      this.#env = env;
    }
    async fetch(request: Request): Promise<Response> {
      this.#runtime ??= runtime(this.#env, this.#state);
      const answer = await admitSocket(request, this.#runtime, cloudflareSourceIp(request));
      if (answer instanceof Response) return answer;
      const pair = new (globalThis as unknown as { WebSocketPair: new () => Record<0 | 1, WorkersWebSocket> }).WebSocketPair();
      const server = pair[1];
      server.accept();
      // Binary messages as bytes: at the deployments' compatibility date a Workers WebSocket gives a Blob, as the standard says.
      server.binaryType = 'arraybuffer';
      const client = fromWebSocket(server);
      this.#state.waitUntil(answer(client, connect).catch(() => undefined).finally(client.close));
      return new Response(null, { status: 101, webSocket: pair[0] } as ResponseInit);
    }
  };
}

/** A Workers WebSocket, as far as a pipe needs it. */
type WorkersWebSocket = {
  accept(): void;
  binaryType: 'blob' | 'arraybuffer';
  send(data: Uint8Array): void;
  close(code?: number, reason?: string): void;
  addEventListener(type: 'message', listener: (event: { data: ArrayBuffer | string }) => void): void;
  addEventListener(type: 'close' | 'error', listener: () => void): void;
};

/**
 * A WebSocket's binary messages as a byte stream, each way. Workers give a
 * server-side WebSocket no flow control: what the app sends is queued here
 * as it comes, and what the database sends is handed to the socket at once.
 */
function fromWebSocket(ws: WorkersWebSocket): Pipe {
  let ended!: () => void;
  const closed = new Promise<void>((resolve) => (ended = resolve));
  let done = false;
  let controller!: ReadableStreamDefaultController<Uint8Array>;
  const end = () => {
    if (done) return;
    done = true;
    try {
      controller.close();
    } catch {}
    try {
      ws.close(1000);
    } catch {}
    ended();
  };
  const readable = new ReadableStream<Uint8Array>({
    start(made) {
      controller = made;
      ws.addEventListener('message', (event) => {
        if (done || typeof event.data === 'string' || event.data.byteLength === 0) return;
        controller.enqueue(new Uint8Array(event.data));
      });
      ws.addEventListener('close', end);
      ws.addEventListener('error', end);
    },
    cancel: end,
  });
  const writable = new WritableStream<Uint8Array>({
    write: (chunk) => {
      if (done) throw new Error('the WebSocket closed');
      ws.send(chunk);
    },
    close: end,
    abort: end,
  });
  return { readable, writable, close: end, closed };
}

/** A `cloudflare:sockets` socket, as far as a pipe needs it. */
type WorkersSocket = {
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
  opened: Promise<unknown>;
  closed: Promise<void>;
  close(): Promise<void>;
  startTls(): WorkersSocket;
};

const pipeOf = (socket: WorkersSocket): Pipe => ({
  readable: socket.readable,
  writable: socket.writable,
  close: () => void socket.close().catch(() => undefined),
  closed: socket.closed.then(
    () => undefined,
    () => undefined,
  ),
});

/**
 * TCP out, on Workers: `connect()` with STARTTLS, which `startTls` turns to
 * TLS once Postgres has said it will, the certificate checked against the
 * host dialled, the database's; workerd refuses a name of the caller's
 * (`expectedServerHostname`), so `servername` is that host already. Imported when first used, so that Node, where
 * tests load this module, never resolves `cloudflare:sockets`.
 */
const connect: Connect = async (host, port, signal) => {
  if (signal?.aborted) throw new Error('the session ended');
  const { connect: tcp } = (await import('cloudflare:sockets' as string)) as { connect: (address: { hostname: string; port: number }, options: { secureTransport: 'starttls' }) => WorkersSocket };
  const socket = tcp({ hostname: host, port }, { secureTransport: 'starttls' });
  const abort = () => void socket.close().catch(() => undefined);
  signal?.addEventListener('abort', abort, { once: true });
  try {
    await socket.opened;
  } finally {
    signal?.removeEventListener('abort', abort);
  }
  if (signal?.aborted) throw new Error('the session ended');
  return {
    ...pipeOf(socket),
    startTls: async () => {
      const secure = socket.startTls();
      await secure.opened;
      return pipeOf(secure);
    },
  } satisfies Socket;
};
