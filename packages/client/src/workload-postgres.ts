/**
 * Postgres from a workload, through coffre's tunnel (docs/design/workload-access.md,
 * section 9.1): a stream node-postgres takes as its socket, carried over the
 * tunnel's WebSocket and signed by the session. No listener, no password,
 * and no database URL in the app: coffre logs in to the database.
 *
 *   import pg from 'pg';
 *   import { connect } from '@coffre/client/workload/postgres';
 *
 *   const pool = new pg.Pool({ stream: () => connect(coffre, 'db') });
 *
 * The WebSocket is the runtime's own (`globalThis.WebSocket`: Node 22 and
 * later, Deno, Bun), which takes the upgrade's headers; on Node 20, pass the
 * `ws` package's: `connect(coffre, 'db', { WebSocket })`.
 *
 * The bytes go by credit, as `coffre run`'s listener sends them
 * (packages/cli/src/tunnels.ts): each side counts back what it took, in
 * text messages, and sends at most a window the other has not counted, so a
 * large result waits in coffre's Durable Object no more than a window. A
 * coffre on Node says so with a byte before any count, and paces nothing.
 */
import { Buffer } from 'node:buffer';
import { Duplex } from 'node:stream';

import { upgradeHeaders, upgradeRefused, type Workload } from './workload.ts';

/**
 * What the stream uses of a WebSocket: the WHATWG API's, which Node's,
 * Deno's, Bun's and the `ws` package's all have; and `pause` and `resume`,
 * which only the `ws` package's has, and which hold back a coffre that does
 * not pace while the app reads nothing.
 */
export type TunnelSocket = {
  binaryType: string;
  readonly readyState: number;
  readonly bufferedAmount: number;
  send(data: Uint8Array | string): void;
  close(): void;
  addEventListener(type: 'open' | 'close' | 'error' | 'message', listener: (event: object) => void): void;
  pause?(): void;
  resume?(): void;
  /** The `ws` package's: ends the connection at once, a paused one included, which reads no closing handshake. */
  terminate?(): void;
};

/** A WebSocket class that takes the upgrade's headers, as all of those do. */
export type WebSocketClass = new (url: string, options: { headers: Record<string, string> }) => TunnelSocket;

const FLOW = 'coffre-tunnel-flow';
/** What either side may send that the other has not counted back. */
const WINDOW = 1024 * 1024;
/** How much the app takes before the stream counts it back: well under the window. */
const COUNT_EVERY = 128 * 1024;
/** How much the stream sends before it waits for the WebSocket to send it: a few COPY chunks. */
const HIGH_WATER = 1024 * 1024;
/** The most one message carries: a large query is sent in frames, each within the credit left. */
const FRAME = 64 * 1024;
/** How often an open connection says it is there, so that an idle one outlives Cloudflare's 100-second timeout. */
const KEEPALIVE_MS = 30_000;

/**
 * A stream to the database behind the tunnel `name`, which node-postgres
 * connects, writes and ends as it would a socket.
 */
export function connect(coffre: Workload, name: string, options: { WebSocket?: WebSocketClass } = {}): TunnelStream {
  const WebSocketImpl = options.WebSocket ?? (globalThis as unknown as { WebSocket?: WebSocketClass }).WebSocket;
  if (WebSocketImpl === undefined) throw new Error("this runtime has no WebSocket of its own (Node 20): connect(coffre, name, { WebSocket }) with the ws package's");
  return new TunnelStream(coffre, tunnelUrl(coffre, name), WebSocketImpl);
}

/**
 * The WebSocket URL of the tunnel `name`: always under its environment,
 * `/use/<project>/<env>/<name>`, which coffre's tunnel route requires,
 * where `url(name)` shortens a single place's to `/use/<name>`.
 */
export function tunnelUrl(coffre: Workload, name: string): string {
  const url = new URL(coffre.url(name));
  if (coffre.places.length === 1) url.pathname = `/use/${[...coffre.places[0]!.split('/'), name].map(encodeURIComponent).join('/')}`;
  return url.href.replace(/^http/, 'ws');
}

export class TunnelStream extends Duplex {
  #ws: TunnelSocket | null = null;
  /** Whether coffre paces: unknown until its first message says. */
  #pacing: boolean | null = null;
  /** Bytes sent that coffre has not counted; bytes the app took that this has not counted back; bytes coffre sent that it has not. */
  #uncounted = 0;
  #taken = 0;
  #owed = 0;
  /** Bytes pushed while the app was not reading: counted back once it reads, so coffre waits for it. */
  #held = 0;
  /** A write waiting for room: credit from coffre, or the WebSocket's own buffer to empty. */
  #waiting: (() => void) | null = null;
  #keepalive: ReturnType<typeof setInterval> | undefined;
  /** Whether coffre took the upgrade. */
  #opened = false;

  constructor(coffre: Workload, url: string, WebSocketImpl: WebSocketClass) {
    super();
    void upgradeHeaders(coffre, url).then(
      (headers) => {
        // Ended or destroyed while it was signed: no connection is opened for it.
        if (this.destroyed || this.writableEnded) return void (this.destroyed || this.destroy());
        const ws = new WebSocketImpl(url, { headers: { ...headers, [FLOW]: 'credit' } });
        ws.binaryType = 'arraybuffer';
        this.#ws = ws;
        ws.addEventListener('open', () => {
          this.#opened = true;
          this.emit('connect');
          this.emit('ready');
          this.#keepalive = setInterval(() => this.#count(), KEEPALIVE_MS);
          (this.#keepalive as { unref?: () => void }).unref?.();
          this.#release();
        });
        ws.addEventListener('message', (event) => this.#message((event as { data: ArrayBuffer | string }).data));
        ws.addEventListener('close', () => {
          clearInterval(this.#keepalive);
          this.push(null);
          this.destroy();
        });
        ws.addEventListener('error', () => {
          // Refused before it opened, perhaps for its nonce, which this WebSocket does not show: the next one asks for the newest.
          if (ws.readyState !== 1 && !this.#opened) upgradeRefused(coffre);
          this.destroy(new Error(`the tunnel to ${url} was refused or cut`));
        });
      },
      (error: unknown) => this.destroy(error as Error),
    );
  }

  /** node-postgres connects its stream itself; this one is connecting already, and says so with `connect`. */
  connect(): this {
    return this;
  }
  setNoDelay(): this {
    return this;
  }
  setKeepAlive(): this {
    return this;
  }
  ref(): this {
    return this;
  }
  unref(): this {
    return this;
  }

  #open(): boolean {
    return this.#ws !== null && this.#ws.readyState === 1;
  }

  #full(): boolean {
    return !this.#open() || this.#ws!.bufferedAmount >= HIGH_WATER || (this.#pacing !== false && this.#uncounted >= WINDOW);
  }

  /** Let a waiting write go, once there is room: the WebSocket's own buffer is polled, as it has no event for emptying. */
  #release(): void {
    if (this.#waiting === null) return;
    if (!this.#full()) {
      const go = this.#waiting;
      this.#waiting = null;
      go();
      return;
    }
    if (this.#open() && this.#ws!.bufferedAmount >= HIGH_WATER) setTimeout(() => this.#release(), 10);
  }

  #count(): void {
    if (!this.#open()) return;
    this.#ws!.send(String(this.#taken));
    this.#owed -= this.#taken;
    this.#taken = 0;
  }

  #message(data: ArrayBuffer | string): void {
    if (typeof data === 'string') {
      // coffre's count of what it took, the first saying that it paces: one that is no count of bytes it was sent ends the connection.
      const counted = Number(data);
      if (this.#pacing === false || !/^\d{1,10}$/.test(data) || counted > this.#uncounted) {
        this.destroy(new Error('the tunnel broke its flow'));
        return;
      }
      this.#pacing = true;
      this.#uncounted -= counted;
      this.#release();
      return;
    }
    if (this.#pacing === null) {
      // A byte first: coffre paces nothing, and the app is held to the window no longer.
      this.#pacing = false;
      this.#release();
    }
    this.#owed += data.byteLength;
    if (this.#pacing === true && this.#owed > 2 * WINDOW) {
      this.destroy(new Error('the tunnel sent past its window'));
      return;
    }
    if (this.push(Buffer.from(data))) this.#took(data.byteLength);
    else {
      this.#held += data.byteLength;
      // A coffre that paces waits for the count; one that does not is held back where the WebSocket can pause.
      if (this.#pacing === false) this.#ws!.pause?.();
    }
  }

  #took(bytes: number): void {
    this.#taken += bytes;
    if (this.#taken >= COUNT_EVERY) this.#count();
  }

  override _read(): void {
    // The app reads again: what it was holding is taken now, and counted back.
    const held = this.#held;
    this.#held = 0;
    if (held > 0) this.#took(held);
    if (this.#pacing === false) this.#ws?.resume?.();
  }

  override _write(chunk: Buffer, _encoding: BufferEncoding, callback: (error?: Error | null) => void): void {
    // In frames, each sent within the window coffre has left: a query larger than the window waits for its counts between them.
    let offset = 0;
    const next = () => {
      while (offset < chunk.length) {
        if (this.#full()) {
          if (this.#ws !== null && this.#ws.readyState > 1) return callback(new Error('the tunnel is closed'));
          this.#waiting = next;
          return this.#release();
        }
        const frame = chunk.subarray(offset, offset + FRAME);
        offset += frame.length;
        this.#uncounted += frame.length;
        this.#ws!.send(frame);
      }
      callback();
    };
    next();
  }

  override _final(callback: (error?: Error | null) => void): void {
    this.#ws?.close();
    callback();
  }

  override _destroy(error: Error | null, callback: (error?: Error | null) => void): void {
    clearInterval(this.#keepalive);
    if (this.#ws !== null && this.#ws.readyState <= 1) {
      if (this.#ws.terminate !== undefined) this.#ws.terminate();
      else this.#ws.close();
    }
    // Writes that waited for room end with the stream.
    this.#waiting = null;
    callback(error);
  }
}
