// What the driver needs of where it runs, and nothing else: a TCP socket, its
// TLS upgrade, a few hashes, and a timer. Two modules give it, with exactly
// these exports: platform.node.ts (Node's own modules) and platform.workerd.ts
// (`cloudflare:sockets` and WebCrypto). `@coffre/db`'s `#postgres/platform`
// import picks one where the package runs: workerd, as wrangler and Vite
// resolve it for a Worker, or Node, the default. The driver imports
// `#postgres/platform` alone; this file holds the types both satisfy.
import type { Buffer } from 'node:buffer';
import type { ConnectionOptions } from 'node:tls';

/**
 * What the connection speaks Postgres on: a TCP socket, a TLS one, or a
 * stream the caller made (`socket`, a tunnel's). A Node `Duplex` is one.
 */
export interface Socket {
  /** Node's states for a socket; a stream that has none never says it is open, so no Terminate is written to it. */
  readonly readyState?: string;
  on(event: 'data', listener: (chunk: Buffer) => void): unknown;
  on(event: 'error', listener: (error: Error) => void): unknown;
  on(event: 'close', listener: (hadError?: boolean) => void): unknown;
  on(event: 'connect' | 'secureConnect' | 'drain', listener: () => void): unknown;
  once(event: 'data', listener: (chunk: Buffer) => void): unknown;
  once(event: 'close', listener: () => void): unknown;
  removeListener(event: 'data', listener: (chunk: Buffer) => void): unknown;
  removeListener(event: 'connect', listener: () => void): unknown;
  removeAllListeners(): unknown;
  write(data: Uint8Array, callback?: () => void): boolean;
  /** Write `data`, the last, and close. */
  end(data: Uint8Array): unknown;
  destroy(): unknown;
  setKeepAlive?(enable: boolean, delay: number): unknown;
}

/** Where a socket connects: a host and port, TLS to follow or not (workerd asks so up front), or a Unix socket's path. */
export type Address = { readonly host: string; readonly port: number; readonly tls: boolean } | { readonly path: string };

/** The caller's TLS options, as Node's `tls.connect` takes them; workerd reads `servername` alone. */
export type TlsOptions = Omit<ConnectionOptions, 'socket'>;

/** What `#postgres/platform` exports, from either module. */
export interface Platform {
  /** A TCP socket to `to`, connecting: `connected` is called once it is, heard before it starts; or it says `error` and `close`. */
  tcp(to: Address, connected: () => void): Socket;
  /** `socket`, now speaking TLS: it says `secureConnect` once the handshake is done. */
  startTls(socket: Socket, options: TlsOptions): Socket;
  /** 4 or 6 for an IP address, 0 for a name. */
  isIP(host: string): number;
  /** Run `fn` once what is running now is done, before any timer; and cancel it. */
  setImmediate(fn: () => void): unknown;
  clearImmediate(handle: unknown): void;
  /**
   * Run `fn` in a task of its own, once every microtask asked before it has run, and cancel it: what a transaction
   * waits for before it sends the statements its work asked together (`begin`, index.ts). Node's `setImmediate`;
   * a timer of 0 on workerd, whose `setImmediate` here is a microtask.
   */
  nextTask(fn: () => void): unknown;
  cancelTask(handle: unknown): void;
  /** Milliseconds, monotonic. */
  now(): number;
  randomBytes(length: number): Buffer;
  /** PBKDF2 with HMAC-SHA-256, as SCRAM-SHA-256 salts a password. */
  pbkdf2(password: string, salt: Buffer, iterations: number, length: number): Promise<Buffer>;
  hmac(key: Uint8Array, text: string): Promise<Buffer>;
  sha256(data: Uint8Array): Promise<Buffer>;
  /** MD5, in hex. */
  md5(data: string | Uint8Array): Promise<string>;
}
