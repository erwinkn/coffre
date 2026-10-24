// A plugin's WebSockets on Workers (`routes.socket`, in plugins.ts): the
// credential proxy's database tunnel. A Worker's invocation is no place for
// a connection that lasts an hour, and a Postgres cancel request comes on a
// connection of its own, which could land in any isolate. So the Worker
// only routes: each WebSocket goes to a Durable Object named by its path and
// its bearer, which is one `coffre run`'s connections to one database, its
// cancel requests among them; or by its path and its workload's session, the
// token of `Authorization: DPoP`, which names that one session. There the plugin admits it, as on Node, and
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

/** A WebSocket's admission: the plugin's refusal, or its session (`admitSocket`), and the decision itself told to `hold`, if it outlasts the answer. */
export type Admit = (request: Request, sourceIp: string | null, hold: (deciding: Promise<unknown>) => void) => Promise<Response | SocketSession>;

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
/**
 * The sessions one object holds at once: a pool of a few dozen, each at
 * most three windows of the object's 128 MB (one out, two in).
 */
const MOST_SESSIONS = 32;
/**
 * The longest a refused connection holds its slot while its admission
 * goes on, past its refusal: a database or vault that never answers would
 * otherwise keep it forever. An admission holds no window.
 */
const MOST_DECIDING_MS = 60_000;
/** How much the object takes before it counts it back: well under the window, so that neither side waits on the other. */
const COUNT_EVERY = 128 * 1024;
/**
 * The admissions an object runs at once, the rest waiting their turn in
 * the order they came: one until a connection is in, which leaves the run's
 * database URL in the cache for the rest, then a few. A pool's burst of 32
 * made together each read the URL from the vault and wrote two entries in
 * the log, all on the object's one database client, and past 16 or so ran
 * into their time to decide together.
 */
const ADMITTING = 4;
/**
 * How long a connection waits for the first admission before the object
 * stops waiting for it to fill the cache, and admits a few at once all the
 * same: an admission that never ends holds up no other for good.
 */
const MOST_WAITING_MS = 15_000;

/**
 * A WebSocket a plugin takes, sent to its object: one per path and bearer,
 * or per path and workload session, which the name is a digest of, so that
 * the bearer, a handle, names no object anyone can read. A session's token
 * names one session for its whole life, renewals included, so its object is
 * the session's (docs/design/workload-access.md, section 7.1) with nothing
 * to look up before it; its proof is checked there, as the plugin admits it.
 */
export async function forwardSocket(request: Request, sockets: SocketsNamespace): Promise<Response> {
  const refused = refusal(request);
  if (refused !== null) return refused;
  // As admission reads them: the scheme and the token alone, and the path's segments decoded, so one run's spellings of them name one object.
  const [, scheme, token] = CREDENTIAL.exec(request.headers.get('authorization')!)!;
  const segments = new URL(request.url).pathname.split('/').map((segment) => {
    try {
      return decodeURIComponent(segment);
    } catch {
      return segment;
    }
  });
  // A handle's names are as they always were; a session's are apart, by its scheme.
  const named = scheme!.toLowerCase() === 'bearer' ? `${JSON.stringify(segments)}\n${token}` : `${JSON.stringify(segments)}\ndpop\n${token}`;
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(named));
  const name = [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
  return sockets.get(sockets.idFromName(name)).fetch(request);
}

/** What names a socket's object: a bearer, a handle, or a workload's session, `Authorization: DPoP <token>`. */
const CREDENTIAL = /^(Bearer|DPoP)\s+(\S+)$/i;

/**
 * A WebSocket no object is made for: one whose client paces nothing, which
 * a coffre before 0.11 is, or that carries no bearer or session, which names its object.
 */
function refusal(request: Request): Response | null {
  if (request.headers.get(FLOW) !== 'credit') {
    return new Response(`this coffre's WebSockets pace their bytes (${FLOW}: credit), as coffre 0.11 and later do: update the CLI`, { status: 426 });
  }
  if (!CREDENTIAL.test(request.headers.get('authorization') ?? '')) return new Response('send a bearer token, or a workload\'s session with its proof', { status: 401 });
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
    /** The sessions open in the object, which it holds to `MOST_SESSIONS`. */
    #open = 0;
    /** Admissions under way, those waiting their turn, and whether one has let a connection in yet, or waited `MOST_WAITING_MS` for it. */
    #admitting = 0;
    readonly #waiting: (() => void)[] = [];
    #warm = false;
    #stalled = false;
    constructor(state: ObjectState, env: Env) {
      this.#state = state;
      this.#env = env;
    }
    async fetch(request: Request): Promise<Response> {
      // The Worker refuses these first (`refusal`); an object asked otherwise refuses them too.
      const refused = refusal(request);
      if (refused !== null) return refused;
      if (this.#open >= MOST_SESSIONS) {
        return new Response(`this run holds ${MOST_SESSIONS} connections here already, each up to three windows of the object's memory: close some, or make the pool smaller`, { status: 503 });
      }
      // The slot is taken now, before admission waits: a burst of connections counts every one still being admitted. A
      // refusal frees it once the decision is done, past a refusal for taking too long included.
      this.#open += 1;
      let session: Promise<void> | undefined;
      let deciding: Promise<unknown> = Promise.resolve();
      // Its time to decide starts with its turn (socket-admission.ts), not with the burst it came in.
      await this.#turn();
      try {
        this.#admit ??= admission(this.#env, this.#state);
        const answer = await this.#admit(request, cloudflareSourceIp(request), (decided) => (deciding = decided));
        if (answer instanceof Response) return answer;
        this.#warm = true;
        const pair = new (globalThis as unknown as { WebSocketPair: new () => Record<0 | 1, WorkersWebSocket> }).WebSocketPair();
        const server = pair[1];
        server.accept();
        // Binary messages as bytes: at the deployments' compatibility date a Workers WebSocket gives a Blob, as the standard says.
        server.binaryType = 'arraybuffer';
        const client = fromWebSocket(server);
        // A session that throws before it is under way, as one that fails after, closes its client and frees the slot.
        session = Promise.resolve()
          .then(() => answer(client, connect))
          .catch(() => undefined)
          .finally(() => {
            this.#open -= 1;
            client.close();
          });
        this.#state.waitUntil(session);
        return new Response(null, { status: 101, webSocket: pair[0] } as ResponseInit);
      } finally {
        // Its turn to the next, however its admission ended.
        this.#next();
        // Refused, or failed before its session began: the slot is free again once nothing decides for it, a minute at most.
        if (session === undefined) {
          let late: ReturnType<typeof setTimeout> | undefined;
          const free = () => {
            clearTimeout(late);
            this.#open -= 1;
          };
          void Promise.race([deciding, new Promise<void>((resolve) => (late = setTimeout(resolve, MOST_DECIDING_MS)))]).then(free, free);
        }
      }
    }
    /** How many admissions the object runs at once: one, until a connection is in or the first has taken too long. */
    #allowed(): number {
      return this.#warm || this.#stalled ? ADMITTING : 1;
    }
    /** A turn to admit: at once while fewer than the object allows are under way, else in the order they came. */
    async #turn(): Promise<void> {
      if (this.#admitting < this.#allowed()) {
        this.#admitting += 1;
        return;
      }
      let late: ReturnType<typeof setTimeout> | undefined;
      let given!: () => void;
      const turn = new Promise<void>((resolve) => (given = resolve));
      this.#waiting.push(given);
      const waited = await Promise.race([turn.then(() => false), new Promise<boolean>((resolve) => (late = setTimeout(() => resolve(true), MOST_WAITING_MS)))]);
      clearTimeout(late);
      if (!waited) return;
      // The first admission is taking long: a few go at once from here, in order, each turn counted as it is given.
      this.#stalled = true;
      this.#give();
      await turn;
    }
    /** An admission done: its turn to the next in line. */
    #next(): void {
      this.#admitting -= 1;
      this.#give();
    }
    /** Turns to those waiting, in order, as many as the object now allows. */
    #give(): void {
      while (this.#waiting.length > 0 && this.#admitting < this.#allowed()) {
        this.#admitting += 1;
        this.#waiting.shift()!();
      }
    }
  };
}

/** A Workers WebSocket, as far as a pipe needs it. */
export type WorkersWebSocket = {
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
 * database until then. Exported for its properties (tunnel-properties.test.ts).
 */
export function fromWebSocket(ws: WorkersWebSocket): Pipe {
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
  /**
   * Ends the pipe, closing the WebSocket with `code` and `reason`, or not at
   * all when the client already did (null): workerd answers its close
   * itself, and a close after it fails out of reach.
   */
  const end = (code: number | null = 1000, reason?: string) => {
    if (done) return;
    done = true;
    if (code !== null) {
      try {
        ws.close(code, reason);
      } catch {}
    }
    wake();
    ended();
  };
  ws.addEventListener('message', ({ data }) => {
    if (done) return;
    if (typeof data === 'string') {
      // The app's count of what it took: a count that is no count ends the connection, as a broken frame would.
      // So is one for more than it was sent: it would open the window past what the app took.
      const count = Number(data);
      if (!/^\d{1,10}$/.test(data) || count > uncounted) return end(1008, 'a count of bytes it was not sent');
      uncounted -= count;
      wake();
      return;
    }
    if (data.byteLength === 0) return;
    // Past its window, uncounted: a client that ignores it is ended, never queued for.
    if (queued + taken + data.byteLength > MOST_HELD) return end(1008, 'past its window');
    queue.push(new Uint8Array(data));
    queued += data.byteLength;
    wake();
  });
  ws.addEventListener('close', () => end(null));
  ws.addEventListener('error', () => end(null));
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
      cancel: () => end(),
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
    close: () => end(),
    abort: () => end(),
  });
  return { readable, writable, close: () => end(), closed };
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
