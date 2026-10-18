/**
 * Postgres through the credential proxy's tunnel (docs/design/credential-proxy.md,
 * "Postgres through a tunnel"): coffre speaks Postgres's startup to the
 * app as a server, takes the handle as its password, logs in to the real
 * database itself with the real password, then pipes bytes both ways. The
 * app's driver is unchanged: `DATABASE_URL=postgres://app:<handle>@127.0.0.1:<port>/app`,
 * the port a listener of `coffre run`'s that carries each connection here
 * over a WebSocket. WebCrypto and web streams only, so it runs on Workers
 * and Node alike.
 */
import type { Connect, Pipe, Socket } from '../plugins.ts';

/** The real database, from its URL in the environment: `postgres://user:password@host:port/database?sslmode=require`. */
export type Database = { host: string; port: number; user: string; password: string; database: string; tls: 'require' | 'disable' };

const SSL_REQUEST = 80877103;
const GSS_REQUEST = 80877104;
const CANCEL_REQUEST = 80877102;
const PROTOCOL_3 = 196608;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** Parse a `DATABASE_URL`; TLS unless `sslmode=disable`, which only a local database should say. */
export function database(url: string): Database {
  const parsed = new URL(url);
  if (parsed.protocol !== 'postgres:' && parsed.protocol !== 'postgresql:') throw new Error('a Postgres URL starts postgres://');
  return {
    host: parsed.hostname.replace(/^\[|\]$/g, ''),
    port: Number(parsed.port || 5432),
    user: decodeURIComponent(parsed.username),
    password: decodeURIComponent(parsed.password),
    database: decodeURIComponent(parsed.pathname.slice(1)) || decodeURIComponent(parsed.username),
    tls: parsed.searchParams.get('sslmode') === 'disable' ? 'disable' : 'require',
  };
}

/** Reads exact lengths from a stream, keeping what came beyond them. */
class Reader {
  #reader: ReadableStreamDefaultReader<Uint8Array>;
  #held = new Uint8Array(0);
  constructor(stream: ReadableStream<Uint8Array>) {
    this.#reader = stream.getReader();
  }
  async take(length: number): Promise<Uint8Array> {
    while (this.#held.length < length) {
      const { done, value } = await this.#reader.read();
      if (done) throw new Error('the connection closed');
      this.#held = concat(this.#held, value);
    }
    const out = this.#held.slice(0, length);
    this.#held = this.#held.slice(length);
    return out;
  }
  /** One backend or frontend message: its type byte and its body. */
  async message(): Promise<{ type: string; body: Uint8Array }> {
    const head = await this.take(5);
    const length = view(head).getInt32(1);
    return { type: String.fromCharCode(head[0]!), body: await this.take(length - 4) };
  }
  /** What is left: what was read beyond the last message, then the rest of the stream. */
  rest(): ReadableStream<Uint8Array> {
    const held = this.#held;
    const reader = this.#reader;
    return new ReadableStream({
      start(controller) {
        if (held.length > 0) controller.enqueue(held);
      },
      async pull(controller) {
        const { done, value } = await reader.read();
        if (done) controller.close();
        else controller.enqueue(value);
      },
      cancel: (reason) => reader.cancel(reason),
    });
  }
  release(): void {
    this.#reader.releaseLock();
  }
}

/** Writes whole messages to a stream. */
class Writer {
  #writer: WritableStreamDefaultWriter<Uint8Array>;
  constructor(stream: WritableStream<Uint8Array>) {
    this.#writer = stream.getWriter();
  }
  write(bytes: Uint8Array): Promise<void> {
    return this.#writer.write(bytes);
  }
  message(type: string, body: Uint8Array): Promise<void> {
    const out = new Uint8Array(5 + body.length);
    out[0] = type.charCodeAt(0);
    view(out).setInt32(1, body.length + 4);
    out.set(body, 5);
    return this.write(out);
  }
  release(): void {
    this.#writer.releaseLock();
  }
}

const view = (bytes: Uint8Array) => new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
const concat = (...parts: Uint8Array[]) => {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
};
const int32 = (value: number) => {
  const out = new Uint8Array(4);
  view(out).setInt32(0, value);
  return out;
};
const cstring = (text: string) => concat(encoder.encode(text), new Uint8Array([0]));

/** An ErrorResponse, as a server sends one: severity, SQLSTATE and message. */
function errorResponse(code: string, message: string): Uint8Array {
  const fields = concat(encoder.encode('S'), cstring('FATAL'), encoder.encode('V'), cstring('FATAL'), encoder.encode('C'), cstring(code), encoder.encode('M'), cstring(message), new Uint8Array([0]));
  const out = new Uint8Array(5 + fields.length);
  out[0] = 'E'.charCodeAt(0);
  view(out).setInt32(1, fields.length + 4);
  out.set(fields, 5);
  return out;
}

/** The parameters of a StartupMessage's body, after its protocol number. */
function parameters(body: Uint8Array): Map<string, string> {
  const parts = decoder.decode(body).split('\0');
  const out = new Map<string, string>();
  for (let i = 0; i + 1 < parts.length; i += 2) if (parts[i] !== '') out.set(parts[i]!, parts[i + 1]!);
  return out;
}

/** What a session needs from coffre: the handle checked and the database's URL opened, and the handle checked again later. */
export type TunnelSession = {
  /** The handle this tunnel was opened with, which the app must give as its password. */
  handle: string;
  /** The real database. */
  database: Database;
  /** Whether the handle still stands: asked every `recheckMs`, the session ended when it does not. */
  stands(): Promise<boolean>;
  recheckMs: number;
  connect: Connect;
};

/**
 * One connection of the app's, from its first byte to its last. A cancel
 * request is forwarded to the database as it is: its process id and secret
 * key are the database's own, which the app saw in BackendKeyData.
 */
export async function tunnel(client: Pipe, session: TunnelSession): Promise<void> {
  const from = new Reader(client.readable);
  const to = new Writer(client.writable);
  let upstream: Socket | Pipe | null = null;
  let timer: ReturnType<typeof setInterval> | undefined;
  const end = () => {
    clearInterval(timer);
    try {
      client.close();
    } catch {}
    try {
      upstream?.close();
    } catch {}
  };
  try {
    // The startup: SSL and GSS refused (the hop to the listener is local), a cancel forwarded, or the real StartupMessage.
    let startup: Map<string, string> | null = null;
    while (startup === null) {
      const length = view(await from.take(4)).getInt32(0);
      if (length < 8 || length > 10_000) throw new Error('not a Postgres startup');
      const body = await from.take(length - 4);
      const code = view(body).getInt32(0);
      if (code === SSL_REQUEST || code === GSS_REQUEST) {
        await to.write(encoder.encode('N'));
        continue;
      }
      if (code === CANCEL_REQUEST) {
        const socket = await session.connect(session.database.host, session.database.port);
        const writer = new Writer(socket.writable);
        await writer.write(concat(int32(16), body));
        writer.release();
        socket.close();
        end();
        return;
      }
      if (code !== PROTOCOL_3) {
        await to.write(errorResponse('0A000', 'coffre tunnels protocol 3.0 only'));
        end();
        return;
      }
      startup = parameters(body.slice(4));
    }
    // The app logs in with the handle as its password, which only who holds it knows: any process on the machine reaches the listener.
    await to.message('R', int32(3));
    const password = await from.message();
    if (password.type !== 'p' || decoder.decode(password.body).replace(/\0$/, '') !== session.handle) {
      await to.write(errorResponse('28P01', 'coffre: the password is the handle `coffre run` gave your app, in DATABASE_URL'));
      end();
      return;
    }

    // The real database, logged in to with the real password.
    const db = session.database;
    let socket: Socket | Pipe = await session.connect(db.host, db.port);
    upstream = socket;
    if (db.tls === 'require') {
      const plain = socket as Socket;
      const writer = new Writer(plain.writable);
      await writer.write(concat(int32(8), int32(SSL_REQUEST)));
      writer.release();
      const reader = new Reader(plain.readable);
      const answer = await reader.take(1);
      reader.release();
      if (answer[0] !== 'S'.charCodeAt(0)) throw new Error(`${db.host} does not take TLS, which the tunnel requires: sslmode=disable for a local database`);
      socket = await plain.startTls(db.host);
      upstream = socket;
    }
    const up = new Writer(socket.writable);
    const down = new Reader(socket.readable);
    // The app's own parameters (application_name, client_encoding, …), but who and where are the real database's.
    startup.set('user', db.user);
    startup.set('database', db.database);
    const fields = [...startup].flatMap(([name, value]) => [cstring(name), cstring(value)]);
    const body = concat(int32(PROTOCOL_3), ...fields, new Uint8Array([0]));
    await up.write(concat(int32(body.length + 4), body));
    await authenticate(up, down, db);

    // Logged in: from AuthenticationOk on, bytes both ways, until either side ends or the handle no longer stands.
    await to.message('R', int32(0));
    up.release();
    to.release();
    timer = setInterval(() => {
      void session.stands().then((stands) => {
        if (!stands) end();
      }, () => end());
    }, session.recheckMs);
    const rest = down.rest();
    const clientRest = from.rest();
    await Promise.race([
      rest.pipeTo(client.writable).catch(() => undefined),
      clientRest.pipeTo(socket.writable).catch(() => undefined),
    ]);
  } catch (error) {
    try {
      await to.write(errorResponse('08006', `coffre: ${error instanceof Error ? error.message : 'the tunnel failed'}`));
    } catch {}
  } finally {
    end();
  }
}

/** Log in to the database as it asks: SCRAM-SHA-256, or a cleartext password. MD5 is refused: WebCrypto has none. */
async function authenticate(up: Writer, down: Reader, db: Database): Promise<void> {
  let scram: Scram | null = null;
  for (;;) {
    const { type, body } = await down.message();
    if (type === 'E') throw new Error(`the database refused the login: ${fieldsOf(body).get('M') ?? 'no reason given'}`);
    if (type !== 'R') throw new Error(`the database sent ${type} before the login ended`);
    const code = view(body).getInt32(0);
    if (code === 0) return;
    if (code === 3) await up.message('p', cstring(db.password));
    else if (code === 10) {
      const mechanisms = decoder.decode(body.slice(4)).split('\0');
      if (!mechanisms.includes('SCRAM-SHA-256')) throw new Error(`the database offers ${mechanisms.filter(Boolean).join(', ')}, and the tunnel speaks SCRAM-SHA-256`);
      scram = await Scram.start(db.password);
      const first = encoder.encode(scram.clientFirst);
      await up.message('p', concat(cstring('SCRAM-SHA-256'), int32(first.length), first));
    } else if (code === 11 && scram !== null) await up.message('p', encoder.encode(await scram.clientFinal(decoder.decode(body.slice(4)))));
    else if (code === 12 && scram !== null) {
      if (!(await scram.verify(decoder.decode(body.slice(4))))) throw new Error("the database's SCRAM signature does not verify: it is not the database the URL names");
    } else throw new Error(code === 5 ? 'the database asks for MD5, which the tunnel does not speak: set password_encryption to scram-sha-256' : `the database asks for authentication ${code}`);
  }
}

function fieldsOf(body: Uint8Array): Map<string, string> {
  const out = new Map<string, string>();
  for (const field of decoder.decode(body).split('\0')) if (field.length > 1) out.set(field[0]!, field.slice(1));
  return out;
}

const base64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes));
const unbase64 = (text: string) => Uint8Array.from(atob(text), (char) => char.charCodeAt(0));
async function hmac(key: Uint8Array<ArrayBuffer>, data: string): Promise<Uint8Array<ArrayBuffer>> {
  const imported = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', imported, encoder.encode(data)));
}

/** SCRAM-SHA-256 (RFC 5802, RFC 7677), the client's side, as Postgres runs it: no channel binding, the user name left empty. */
class Scram {
  readonly clientFirst: string;
  #bare: string;
  #password: string;
  #serverKey: Uint8Array<ArrayBuffer> | null = null;
  #authMessage = '';
  private constructor(password: string, nonce: string) {
    this.#password = password;
    this.#bare = `n=,r=${nonce}`;
    this.clientFirst = `n,,${this.#bare}`;
  }
  static async start(password: string): Promise<Scram> {
    return new Scram(password, base64(crypto.getRandomValues(new Uint8Array(18))));
  }
  async clientFinal(serverFirst: string): Promise<string> {
    const fields = new Map(serverFirst.split(',').map((part) => [part[0], part.slice(2)] as const));
    const nonce = fields.get('r')!;
    if (!nonce.startsWith(this.#bare.slice('n=,r='.length))) throw new Error("the database's SCRAM nonce is not ours");
    const salt = unbase64(fields.get('s')!);
    const iterations = Number(fields.get('i'));
    const key = await crypto.subtle.importKey('raw', encoder.encode(this.#password.normalize('NFKC')), 'PBKDF2', false, ['deriveBits']);
    const salted = new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, key, 256));
    const clientKey = await hmac(salted, 'Client Key');
    const storedKey = new Uint8Array(await crypto.subtle.digest('SHA-256', clientKey));
    const withoutProof = `c=biws,r=${nonce}`;
    this.#authMessage = `${this.#bare},${serverFirst},${withoutProof}`;
    const signature = await hmac(storedKey, this.#authMessage);
    const proof = clientKey.map((byte, i) => byte ^ signature[i]!);
    this.#serverKey = await hmac(salted, 'Server Key');
    return `${withoutProof},p=${base64(proof)}`;
  }
  async verify(serverFinal: string): Promise<boolean> {
    const expected = base64(await hmac(this.#serverKey!, this.#authMessage));
    return serverFinal.startsWith('v=') && serverFinal.slice(2) === expected;
  }
}
