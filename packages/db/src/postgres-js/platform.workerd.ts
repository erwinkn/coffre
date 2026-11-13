// The driver on workerd (platform.ts): TCP through `cloudflare:sockets`,
// shaped as the Node socket the connection expects, and WebCrypto, whose
// hashes are all asynchronous. Upstream's `cf/polyfills.js`, as it was.
import { Buffer } from 'node:buffer';
import { EventEmitter } from 'node:events';

import type { Address, Platform, Socket } from './platform.ts';

/** A socket of `cloudflare:sockets`, what of it this uses. */
interface RawSocket {
  readonly readable: ReadableStream<Uint8Array>;
  readonly writable: WritableStream<Uint8Array>;
  readonly closed: Promise<void>;
  close(): Promise<void>;
  startTls(options: { servername?: string }): RawSocket;
}

type Connect = (address: string, options: { secureTransport?: 'starttls' }) => RawSocket;

const v4Seg = '(?:[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])';
const v4Str = `(${v4Seg}[.]){3}${v4Seg}`;
const IPv4Reg = new RegExp(`^${v4Str}$`);

const v6Seg = '(?:[0-9a-fA-F]{1,4})';
const IPv6Reg = new RegExp(
  '^(' +
  `(?:${v6Seg}:){7}(?:${v6Seg}|:)|` +
  `(?:${v6Seg}:){6}(?:${v4Str}|:${v6Seg}|:)|` +
  `(?:${v6Seg}:){5}(?::${v4Str}|(:${v6Seg}){1,2}|:)|` +
  `(?:${v6Seg}:){4}(?:(:${v6Seg}){0,1}:${v4Str}|(:${v6Seg}){1,3}|:)|` +
  `(?:${v6Seg}:){3}(?:(:${v6Seg}){0,2}:${v4Str}|(:${v6Seg}){1,4}|:)|` +
  `(?:${v6Seg}:){2}(?:(:${v6Seg}){0,3}:${v4Str}|(:${v6Seg}){1,5}|:)|` +
  `(?:${v6Seg}:){1}(?:(:${v6Seg}){0,4}:${v4Str}|(:${v6Seg}){1,6}|:)|` +
  `(?::((?::${v6Seg}){0,5}:${v4Str}|(?::${v6Seg}){1,7}|:))` +
  ')(%[0-9a-zA-Z-.:]{1,})?$',
);

/**
 * A `cloudflare:sockets` socket as an event emitter: `connect` once it can
 * write, `data` for each chunk read, `error` then `close` when it fails.
 * With TLS to follow, it reads one chunk alone, the server's answer to the
 * SSLRequest, so that the reader is free for `startTls`.
 */
export class WorkerdSocket extends EventEmitter {
  readyState = 'open';
  raw: RawSocket | null = null;
  /** Destroyed before `connect` made its socket: closed as soon as it has. */
  destroyed = false;
  writer: WritableStreamDefaultWriter<Uint8Array> | null = null;
  reader: ReadableStreamDefaultReader<Uint8Array> | null = null;

  async connect(port: number, host: string, tls: boolean): Promise<void> {
    try {
      this.readyState = 'opening';
      const { connect } = (await import('cloudflare:sockets' as string)) as { connect: Connect };
      const raw = (this.raw = connect(host + ':' + port, tls ? { secureTransport: 'starttls' } : {}));
      if (this.destroyed) return this.abort();
      raw.closed.then(
        () => {
          if (this.readyState !== 'upgrade') return this.close();
          this.readyState = 'open';
          this.emit('secureConnect');
        },
        (error: unknown) => this.error(error),
      );
      this.writer = raw.writable.getWriter();
      this.reader = raw.readable.getReader();

      void (tls ? this.readFirst() : this.read());
      void this.writer.ready.then(() => {
        this.readyState = 'open';
        this.emit('connect');
      });
    } catch (error) {
      this.error(error);
    }
  }

  /** Upgraded to TLS, the same emitter: `secureConnect` once the plain socket under it closes. */
  upgrade(servername: string | undefined): this {
    this.writer!.releaseLock();
    this.reader!.releaseLock();
    this.readyState = 'upgrading';
    // Upstream's option, which workerd reads as `expectedServerHostname`: the name is not checked here.
    const raw = (this.raw = this.raw!.startTls({ servername }));
    raw.closed.then(
      () => this.close(),
      (error: unknown) => this.error(error),
    );
    this.writer = raw.writable.getWriter();
    this.reader = raw.readable.getReader();
    void this.writer.ready.then(() => {
      void this.read();
      this.readyState = 'upgrade';
    });
    return this;
  }

  write(data: Uint8Array, callback?: () => void): boolean {
    this.writer!.write(data).then(callback, (error: unknown) => this.error(error));
    return true;
  }

  end(data?: Uint8Array): unknown {
    return data ? this.write(data, () => void this.raw!.close()) : this.raw!.close();
  }

  /**
   * Closed at once, as Node's `destroy`, whatever it is still writing or opening: its writes aborted and its reads
   * cancelled, so that nothing buffered is sent, then the raw socket closed, which on its own waits until the socket
   * has opened and every write has gone (workerd's `Socket::close`). Upstream ended it, which waits for a write stuck
   * under backpressure too (reviews r2 and r3 of #438). Its TCP connection workerd closes with the request, whose I/O
   * it is: locally, not before (packages/vault/test/workers-socket.test.ts). Before `connect` has made the raw socket,
   * it is made only to be closed. Says `close` once, a task later, as Node's does.
   */
  destroy(): void {
    if (this.destroyed) return;
    this.destroyed = true;
    if (this.raw !== null) this.abort();
    setTimeout(() => this.close(), 0);
  }

  /** The raw socket's streams torn down, then the socket closed (`destroy`). */
  abort(): void {
    const raw = this.raw!;
    void (this.writer ?? raw.writable).abort().catch(() => {});
    void (this.reader ?? raw.readable).cancel().catch(() => {});
    void raw.close().catch(() => {});
  }

  async read(): Promise<void> {
    try {
      for (;;) {
        const { done, value } = await this.reader!.read();
        if (done) return;
        this.emit('data', Buffer.from(value));
      }
    } catch (error) {
      this.error(error);
    }
  }

  /** The server's answer to the SSLRequest; failed, or the socket closed or destroyed first, said as any read's end. */
  async readFirst(): Promise<void> {
    try {
      const { done, value } = await this.reader!.read();
      if (done) return this.close();
      this.emit('data', Buffer.from(value));
    } catch (error) {
      this.error(error);
    }
  }

  close(): void {
    if (this.readyState === 'closed') return;
    this.readyState = 'closed';
    this.emit('close');
  }

  /** Said once: past `close` (a `destroy`'s, whose aborted streams fail what was under way), nothing more. */
  error(error: unknown): void {
    if (this.readyState === 'closed' || this.destroyed) return;
    this.emit('error', error);
    this.close();
  }
}

export const tcp: Platform['tcp'] = (to: Address, connected: () => void) => {
  if ('path' in to) throw new Error('a Unix socket cannot be reached from workerd');
  const socket = new WorkerdSocket();
  socket.once('connect', connected);
  void socket.connect(to.port, to.host, to.tls);
  return socket as Socket;
};

export const startTls: Platform['startTls'] = (socket, { servername }) => (socket as WorkerdSocket).upgrade(servername) as Socket;

export const isIP: Platform['isIP'] = (host) => (IPv4Reg.test(host) ? 4 : IPv6Reg.test(host) ? 6 : 0);

// A microtask, as upstream's polyfill: once the writes of this turn are buffered, they go together.
let ids = 1;
const tasks = new Set<number>();

export const setImmediate: Platform['setImmediate'] = (fn) => {
  const id = ids++;
  tasks.add(id);
  queueMicrotask(() => {
    if (tasks.has(id)) {
      fn();
      tasks.delete(id);
    }
  });
  return id;
};

export const clearImmediate: Platform['clearImmediate'] = (handle) => {
  tasks.delete(handle as number);
};

export const nextTask: Platform['nextTask'] = (fn) => setTimeout(fn, 0);
export const cancelTask: Platform['cancelTask'] = (handle) => clearTimeout(handle as ReturnType<typeof setTimeout>);

export const now: Platform['now'] = () => performance.now();

export const randomBytes: Platform['randomBytes'] = (length) => crypto.getRandomValues(Buffer.alloc(length));

const encoder = new TextEncoder();

/** `x`, as WebCrypto types the bytes it takes: a Buffer's memory is never shared. */
const own = (x: Uint8Array) => x as Uint8Array<ArrayBuffer>;

export const pbkdf2: Platform['pbkdf2'] = async (password, salt, iterations, length) =>
  Buffer.from(
    await crypto.subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-256', salt: own(salt), iterations },
      await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']),
      length * 8,
    ),
  );

export const hmac: Platform['hmac'] = async (key, text) =>
  Buffer.from(await crypto.subtle.sign('HMAC', await crypto.subtle.importKey('raw', own(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']), encoder.encode(text)));

export const sha256: Platform['sha256'] = async (data) => Buffer.from(await crypto.subtle.digest('SHA-256', own(data)));

// workerd's WebCrypto has MD5, which the standard leaves out.
export const md5: Platform['md5'] = async (data) =>
  Buffer.from(await crypto.subtle.digest('MD5', typeof data === 'string' ? encoder.encode(data) : own(data))).toString('hex');
