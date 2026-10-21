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
import type { Connect, Pipe, SocketSession } from './plugins.ts';
import { workersSocket, type WorkersSocket } from './workers-socket.ts';

/** The Durable Object binding the deployment hands coffre: `sockets: env.SOCKETS`. */
export type SocketsNamespace = {
  idFromName(name: string): unknown;
  get(id: unknown): { fetch(request: Request): Promise<Response> };
};

/** What the object is given by the runtime: its `waitUntil`, for the database's closing. */
type ObjectState = { waitUntil(promise: Promise<unknown>): void };

/** A WebSocket's admission: the plugin's refusal, or its session (`admitSocket`). */
export type Admit = (request: Request, sourceIp: string | null) => Promise<Response | SocketSession>;

/**
 * How a plugin's WebSocket carries its bytes on Workers, its client saying
 * it will with a header, `coffre-tunnel-flow: credit`. A Workers WebSocket
 * has no back-pressure, either way: what one side sends faster than the
 * other takes waits in the object's memory, 128 MB, a large `SELECT *`
 * included. So each side counts back what it took, in text messages, each
 * the bytes taken from binary messages since its last, and sends at most
 * `WINDOW` bytes the other has not counted; `0` counts nothing. The object
 * says it paces so with a first `0`, before any byte, and ends a client
 * that sends past its window or counts what it was never sent: a peer that
 * ignores the window could otherwise fill the object. The client's `0`
 * every 30 seconds keeps an idle connection alive (`coffre run`'s
 * listener, packages/cli/src/tunnels.ts).
 */
export const FLOW = 'coffre-tunnel-flow';
/** What either side may send that the other has not counted back. */
const WINDOW = 1024 * 1024;
/** What the object takes from a client before it ends it: a window, and the message that crossed it. */
const MOST_HELD = 2 * WINDOW;
/** How much the object takes before it counts it back: well under the window, so that neither side waits on the other. */
const COUNT_EVERY = 128 * 1024;

/**
 * A WebSocket a plugin takes, sent to its object: one per path and bearer,
 * which the name is a digest of, so that the bearer, a handle, names no
 * object anyone can read.
 */
export async function forwardSocket(request: Request, sockets: SocketsNamespace): Promise<Response> {
  const refused = refusal(request);
  if (refused !== null) return refused;
  const { pathname } = new URL(request.url);
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`${pathname}\n${request.headers.get('authorization') ?? ''}`));
  const name = [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
  return sockets.get(sockets.idFromName(name)).fetch(request);
}

/**
 * A WebSocket no object is made for: one whose client paces nothing, which
 * a coffre before 0.11 is, or that carries no bearer, which names its object.
 */
function refusal(request: Request): Response | null {
  if (request.headers.get(FLOW) !== 'credit') {
    return new Response(`this coffre's WebSockets pace their bytes (${FLOW}: credit), as coffre 0.11 and later do: update the CLI`, { status: 426 });
  }
  if (!/^Bearer\s+\S+$/i.test(request.headers.get('authorization') ?? '')) return new Response('send a bearer token', { status: 401 });
  return null;
}

/**
 * How long the object's database client stays open once idle: a check's
 * queries share it, its vault calls between them included (ten seconds at
 * most, `RECHECK_DEADLINE_MS`), and a session holds none between checks.
 */
export const IDLE_DATABASE_MS = 10_000;

/**
 * The Durable Object class the deployment exports, `export const
 * CoffreSockets = coffre.Sockets`. `admission` makes, once for the object,
 * what admits its WebSockets: coffre's, whose database client opens with a
 * query and closes once idle.
 */
export function socketsObject<Env>(admission: (env: Env, state: ObjectState) => Admit) {
  return class CoffreSockets {
    readonly #state: ObjectState;
    readonly #env: Env;
    #admit: Admit | undefined;
    constructor(state: ObjectState, env: Env) {
      this.#state = state;
      this.#env = env;
    }
    async fetch(request: Request): Promise<Response> {
      // The Worker refuses these first (`refusal`); an object asked otherwise refuses them too.
      const refused = refusal(request);
      if (refused !== null) return refused;
      this.#admit ??= admission(this.#env, this.#state);
      const answer = await this.#admit(request, cloudflareSourceIp(request));
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
  send(data: Uint8Array | string): void;
  close(code?: number, reason?: string): void;
  addEventListener(type: 'message', listener: (event: { data: ArrayBuffer | string }) => void): void;
  addEventListener(type: 'close' | 'error', listener: () => void): void;
};

/**
 * A WebSocket's binary messages as a byte stream, each way, paced by
 * credit (`FLOW`): what the app sent waits here until the session takes it,
 * a window at most, and what the session sends waits for the app's count
 * once a window of it is uncounted, so the session stops reading the
 * database until then.
 */
function fromWebSocket(ws: WorkersWebSocket): Pipe {
  let ended!: () => void;
  const closed = new Promise<void>((resolve) => (ended = resolve));
  let done = false;
  /** What the app sent that the session has not taken, and its bytes. */
  const queue: Uint8Array[] = [];
  let queued = 0;
  /** Bytes the session took, not yet counted back to the app. */
  let taken = 0;
  /** Bytes sent to the app that it has not counted back. */
  let uncounted = 0;
  /** The reader waiting for a message, and the writer for the app's count. */
  let arrived: (() => void) | null = null;
  let counted: (() => void) | null = null;
  const wake = () => {
    arrived?.();
    counted?.();
    arrived = counted = null;
  };
  const end = () => {
    if (done) return;
    done = true;
    try {
      ws.close(1000);
    } catch {}
    wake();
    ended();
  };
  ws.addEventListener('message', ({ data }) => {
    if (done) return;
    if (typeof data === 'string') {
      // The app's count of what it took: a count that is no count ends the connection, as a broken frame would.
      // So is one for more than it was sent: it would open the window past what the app took.
      const count = Number(data);
      if (!/^\d{1,10}$/.test(data) || count > uncounted) return end();
      uncounted -= count;
      wake();
      return;
    }
    if (data.byteLength === 0) return;
    // Past its window, uncounted: a client that ignores it is ended, never queued for.
    if (queued + taken + data.byteLength > MOST_HELD) return end();
    queue.push(new Uint8Array(data));
    queued += data.byteLength;
    wake();
  });
  ws.addEventListener('close', end);
  ws.addEventListener('error', end);
  // That the object paces: the client holds itself to the window from here.
  ws.send('0');
  const readable = new ReadableStream<Uint8Array>(
    {
      async pull(controller) {
        while (queue.length === 0 && !done) await new Promise<void>((resolve) => (arrived = resolve));
        const chunk = queue.shift();
        if (chunk === undefined) return controller.close();
        queued -= chunk.length;
        controller.enqueue(chunk);
        taken += chunk.length;
        if (taken < COUNT_EVERY) return;
        try {
          ws.send(String(taken));
          taken = 0;
        } catch {
          end();
        }
      },
      cancel: end,
    },
    // Nothing read ahead: a message is taken when the session asks for it, and counted then.
    { highWaterMark: 0 },
  );
  const writable = new WritableStream<Uint8Array>({
    async write(chunk) {
      while (uncounted >= WINDOW && !done) await new Promise<void>((resolve) => (counted = resolve));
      if (done) throw new Error('the WebSocket closed');
      ws.send(chunk);
      uncounted += chunk.length;
    },
    close: end,
    abort: end,
  });
  return { readable, writable, close: end, closed };
}

/**
 * TCP out, on Workers: `connect()` with STARTTLS, which `startTls` turns to
 * TLS once Postgres has said it will. Imported when first used, so that
 * Node, where tests load this module, never resolves `cloudflare:sockets`.
 */
const connect: Connect = async (host, port, signal) => {
  if (signal?.aborted) throw new Error('the session ended');
  const { connect: tcp } = (await import('cloudflare:sockets' as string)) as { connect: (address: { hostname: string; port: number }, options: { secureTransport: 'starttls' }) => WorkersSocket };
  return workersSocket(tcp({ hostname: host, port }, { secureTransport: 'starttls' }), signal);
};
