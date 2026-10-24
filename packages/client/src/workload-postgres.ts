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

import { upgradeHeaders, type Workload } from './workload.ts';

/** A WebSocket class as the WHATWG API has one, taking the upgrade's headers as Node's, Deno's, Bun's and the `ws` package's do. */
export type WebSocketClass = new (url: string, options: { headers: Record<string, string> }) => WebSocket;

const FLOW = 'coffre-tunnel-flow';
/** What either side may send that the other has not counted back. */
const WINDOW = 1024 * 1024;
/** How much the app takes before the stream counts it back: well under the window. */
const COUNT_EVERY = 128 * 1024;
/** How much the stream sends before it waits for the WebSocket to send it: a few COPY chunks. */
const HIGH_WATER = 1024 * 1024;
/** How often an open connection says it is there, so that an idle one outlives Cloudflare's 100-second timeout. */
const KEEPALIVE_MS = 30_000;

/**
 * A stream to the database behind the tunnel `name`, which node-postgres
 * connects, writes and ends as it would a socket.
 */
export function connect(coffre: Workload, name: string, options: { WebSocket?: WebSocketClass } = {}): TunnelStream {
  const WebSocketImpl = options.WebSocket ?? (globalThis as unknown as { WebSocket?: WebSocketClass }).WebSocket;
  if (WebSocketImpl === undefined) throw new Error("this runtime has no WebSocket of its own (Node 20): connect(coffre, name, { WebSocket }) with the ws package's");
  return new TunnelStream(coffre, coffre.url(name).replace(/^http/, 'ws'), WebSocketImpl);
}

export class TunnelStream extends Duplex {
  #ws: WebSocket | null = null;
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

  constructor(coffre: Workload, url: string, WebSocketImpl: WebSocketClass) {
    super();
    void upgradeHeaders(coffre, url).then(
      (headers) => {
        if (this.destroyed) return;
        const ws = new WebSocketImpl(url, { headers: { ...headers, [FLOW]: 'credit' } });
        ws.binaryType = 'arraybuffer';
        this.#ws = ws;
        ws.addEventListener('open', () => {
          this.emit('connect');
          this.emit('ready');
          this.#keepalive = setInterval(() => this.#count(), KEEPALIVE_MS);
          (this.#keepalive as { unref?: () => void }).unref?.();
          this.#release();
        });
        ws.addEventListener('message', (event) => this.#message(event.data as ArrayBuffer | string));
        ws.addEventListener('close', () => {
          clearInterval(this.#keepalive);
          this.push(null);
          this.destroy();
        });
        ws.addEventListener('error', () => this.destroy(new Error(`the tunnel to ${url} was refused or cut`)));
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
    else this.#held += data.byteLength;
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
  }

  override _write(chunk: Buffer, _encoding: BufferEncoding, callback: (error?: Error | null) => void): void {
    const send = () => {
      if (!this.#open()) return callback(new Error('the tunnel is closed'));
      this.#uncounted += chunk.length;
      this.#ws!.send(chunk);
      if (!this.#full()) return callback();
      this.#waiting = () => callback();
      this.#release();
    };
    if (this.#full()) {
      this.#waiting = send;
      this.#release();
    } else send();
  }

  override _final(callback: (error?: Error | null) => void): void {
    this.#ws?.close();
    callback();
  }

  override _destroy(error: Error | null, callback: (error?: Error | null) => void): void {
    clearInterval(this.#keepalive);
    if (this.#ws !== null && this.#ws.readyState <= 1) this.#ws.close();
    // Writes that waited for room end with the stream.
    this.#waiting = null;
    callback(error);
  }
}
