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
  // As an http URL reads it, which is how it is dialled: 127.1, 2130706433 and 0x7f000001 are all 127.0.0.1.
  const canonical = new URL(`http://${parsed.host}`).hostname;
  return {
    host: canonical.replace(/^\[|\]$/g, ''),
    port: Number(parsed.port || 5432),
    user: decodeURIComponent(parsed.username),
    password: decodeURIComponent(parsed.password),
    database: decodeURIComponent(parsed.pathname.slice(1)) || decodeURIComponent(parsed.username),
    tls: parsed.searchParams.get('sslmode') === 'disable' ? 'disable' : 'require',
  };
}

/** Reads exact lengths from a stream, keeping what came beyond them: the chunks as they came, each copied out once. */
class Reader {
  #reader: ReadableStreamDefaultReader<Uint8Array>;
  #chunks: Uint8Array[] = [];
  /** How far into the first chunk was taken. */
  #offset = 0;
  #size = 0;
  constructor(stream: ReadableStream<Uint8Array>) {
    this.#reader = stream.getReader();
  }
  async take(length: number): Promise<Uint8Array> {
    while (this.#size < length) {
      const { done, value } = await this.#reader.read();
      if (done) throw new Error('the connection closed');
      // An empty chunk adds nothing: kept, it would only grow the queue.
      if (value.length === 0) continue;
      this.#chunks.push(value);
      this.#size += value.length;
    }
    const out = new Uint8Array(length);
    let at = 0;
    while (at < length) {
      const chunk = this.#chunks[0]!;
      const part = Math.min(length - at, chunk.length - this.#offset);
      out.set(chunk.subarray(this.#offset, this.#offset + part), at);
      at += part;
      this.#offset += part;
      if (this.#offset === chunk.length) {
        this.#chunks.shift();
        this.#offset = 0;
      }
    }
    this.#size -= length;
    return out;
  }
  /** One backend or frontend message: its type byte and its body, `max` bytes at most, refused before it is read. */
  async message(max: number): Promise<{ type: string; body: Uint8Array }> {
    const head = await this.take(5);
    const length = view(head).getInt32(1);
    if (length < 4 || length - 4 > max) throw new Error('a message longer than this step of the startup takes');
    return { type: String.fromCharCode(head[0]!), body: await this.take(length - 4) };
  }
  /** How many bytes it read beyond what was taken. */
  get held(): number {
    return this.#size;
  }
  /** What is left: what was read beyond the last message, then the rest of the stream. */
  rest(): ReadableStream<Uint8Array> {
    const held = this.#chunks.map((chunk, i) => (i === 0 ? chunk.subarray(this.#offset) : chunk));
    const reader = this.#reader;
    return new ReadableStream({
      start(controller) {
        for (const chunk of held) if (chunk.length > 0) controller.enqueue(chunk);
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
  /** Which tunnel of the handle's this is, and so how it dials, `<handle>\0<project>/<env>\0<tunnel>`: a cancel reaches its own tunnel's sessions only. */
  group: string;
  /** The real database. */
  database: Database;
  /** Whether the session may log in, asked just before it does; afterwards, `watch`'s checks decide. */
  stands(): Promise<boolean>;
  /** Told how to end this session, which the checks of its handle's sessions end when they fail. Returns its undoing. */
  watch(end: () => void): () => void;
  connect: Connect;
};

/** How long a connection may take to log in, from its first byte to the database's AuthenticationOk. */
const STARTUP_MS = 30_000;
/** The longest message the startup takes from the app: a password is a handle, and parameters are few. */
const MAX_STARTUP = 10_000;
/** The longest message the database's login sends: a SASL exchange, an error. */
const MAX_LOGIN = 65_536;
/** How long a cancel request waits for the database to close its connection, which says the request arrived. */
const CANCEL_MS = 5_000;

/**
 * The cancel keys the app was given, by key, for the sessions logged in
 * now: each the database's own, which the app never sees, and the handle
 * that may use it. A cancel request names one of these or reaches nothing.
 * In this process only (on Workers, this isolate, which several objects may
 * share): a key outlives no session.
 */
const cancels = new Map<string, { processId: number; secret: number; group: string; database: Database }>();

/**
 * One connection of the app's, from its first byte to its last. A cancel
 * request names the key the app was given for one of this handle's live
 * sessions, and is forwarded to that session's database with its own key;
 * any other reaches nothing.
 */
export async function tunnel(client: Pipe, session: TunnelSession): Promise<void> {
  const from = new Reader(client.readable);
  const to = new Writer(client.writable);
  let upstream: Socket | Pipe | null = null;
  let key: string | null = null;
  let ended = false;
  // A dial still under way when the session ends is given up, not left to the system's timeout.
  const dialing = new AbortController();
  /** The outbound socket, owned from the moment TCP is made, through TLS: closed at once if the session ended meanwhile. */
  const own = (pipe: Pipe) => {
    upstream = pipe;
    if (ended) pipe.close();
  };
  const end = () => {
    ended = true;
    unwatch();
    dialing.abort();
    if (key !== null) cancels.delete(key);
    for (const pipe of [client, upstream]) {
      try {
        pipe?.close();
      } catch {}
    }
  };
  // From the first byte: its handle's checks failing, the app gone, or the login too slow, and the session ends.
  const deadline = setTimeout(end, STARTUP_MS);
  const unwatch = session.watch(end);
  void client.closed.then(end, end);
  /** A step of the startup, which an ended session does not wait for: its work, left behind, fails unheard (a dial given up). */
  const step = <T,>(work: Promise<T>): Promise<T> =>
    ended
      ? (work.catch(() => undefined), Promise.reject(new Error('the session ended')))
      : Promise.race([work, client.closed.then(() => Promise.reject(new Error('the app went away')))]);
  try {
    // The startup: SSL and GSS refused (the hop to the listener is local), a cancel forwarded, or the real StartupMessage.
    let startup: Map<string, string> | null = null;
    // SSL, then GSS, as a driver asks: no more than one of each before the real startup.
    let negotiations = 0;
    while (startup === null) {
      const length = view(await step(from.take(4))).getInt32(0);
      if (length < 8 || length > MAX_STARTUP) throw new Error('not a Postgres startup');
      const body = await step(from.take(length - 4));
      const code = view(body).getInt32(0);
      if (code === SSL_REQUEST || code === GSS_REQUEST) {
        if (++negotiations > 2) throw new Error('a startup asks for encryption once each');
        await to.write(encoder.encode('N'));
        continue;
      }
      if (code === CANCEL_REQUEST) {
        if (body.length !== 12) throw new Error('not a cancel request');
        await step(cancel(session, `${view(body).getInt32(4)}:${view(body).getInt32(8)}`, own, dialing.signal));
        return;
      }
      if (code !== PROTOCOL_3) {
        await to.write(errorResponse('0A000', 'coffre tunnels protocol 3.0 only'));
        return;
      }
      startup = parameters(body.slice(4));
    }
    // The app logs in with the handle as its password, which only who holds it knows: any process on the machine reaches the listener.
    await to.message('R', int32(3));
    const password = await step(from.message(MAX_STARTUP));
    if (password.type !== 'p' || decoder.decode(password.body).replace(/\0$/, '') !== session.handle) {
      await to.write(errorResponse('28P01', 'coffre: the password is the handle `coffre run` gave your app, in DATABASE_URL'));
      return;
    }
    // Asked again now, whatever the last check said: a connection held at the prompt logs in only while its handle stands.
    if (!(await step(session.stands()))) {
      await to.write(errorResponse('28P01', 'coffre: the handle ended: run the app with `coffre run` again'));
      return;
    }

    // The real database, logged in to with the real password.
    const db = session.database;
    const socket = await step(open(session, db, own, dialing.signal));
    const up = new Writer(socket.writable);
    const down = new Reader(socket.readable);
    // The app's own parameters (application_name, client_encoding, …), but who and where are the real database's.
    startup.set('user', db.user);
    startup.set('database', db.database);
    const fields = [...startup].flatMap(([name, value]) => [cstring(name), cstring(value)]);
    const body = concat(int32(PROTOCOL_3), ...fields, new Uint8Array([0]));
    await up.write(concat(int32(body.length + 4), body));
    await step(authenticate(up, down, db));

    // Logged in: what the database says until it is ready, its cancel key swapped for one of coffre's, then bytes both ways.
    await to.message('R', int32(0));
    for (;;) {
      const { type, body: said } = await step(down.message(MAX_LOGIN));
      if (type === 'K' && said.length === 8) {
        const mine = { processId: view(said).getInt32(0), secret: view(said).getInt32(4) };
        const given = crypto.getRandomValues(new Int32Array(2));
        key = `${given[0]}:${given[1]}`;
        cancels.set(key, { ...mine, group: session.group, database: db });
        await to.message('K', concat(int32(given[0]!), int32(given[1]!)));
        continue;
      }
      await to.message(type, said);
      if (type === 'E') return;
      if (type === 'Z') break;
    }
    clearTimeout(deadline);
    up.release();
    to.release();
    await Promise.race([
      relay(down.rest(), client.writable).catch(() => undefined),
      relay(from.rest(), socket.writable).catch(() => undefined),
      client.closed,
    ]);
  } catch (error) {
    try {
      if (!ended) await to.write(errorResponse('08006', `coffre: ${error instanceof Error ? error.message : 'the tunnel failed'}`));
    } catch {}
  } finally {
    clearTimeout(deadline);
    end();
  }
}

/**
 * Bytes from one side to the other, each chunk written before the next is
 * read, so that each side reads only as fast as the other takes. Not
 * `pipeTo`: on Workers, piping into a stream of JavaScript's own, as the
 * WebSocket's (cloudflare-sockets.ts) is, keeps a promise for every chunk
 * until the pipe ends, and a session that streamed some 4.7 GB from the
 * database outgrew the object's 128 MB.
 */
async function relay(from: ReadableStream<Uint8Array>, to: WritableStream<Uint8Array>): Promise<void> {
  const reader = from.getReader();
  const writer = to.getWriter();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) return writer.close();
    await writer.write(value);
  }
}

/**
 * A connection to the database: TLS first, unless the URL says
 * `sslmode=disable`, the server's one byte read alone. `own` is told of
 * each socket as it is made, TCP's then TLS's, so that whoever ends the
 * session closes what is open, however far this got.
 */
async function open(session: TunnelSession, db: Database, own: (pipe: Pipe) => void, signal: AbortSignal): Promise<Socket | Pipe> {
  const socket = await session.connect(db.host, db.port, signal);
  own(socket);
  if (db.tls === 'disable') return socket;
  const writer = new Writer(socket.writable);
  await writer.write(concat(int32(8), int32(SSL_REQUEST)));
  writer.release();
  const reader = new Reader(socket.readable);
  const answer = await reader.take(1);
  // Anything past the one byte came in plaintext, before TLS: a server that sends it is no Postgres, or someone between.
  const extra = reader.held;
  reader.release();
  if (answer[0] !== 'S'.charCodeAt(0)) {
    socket.close();
    throw new Error(`${db.host} does not take TLS, which the tunnel requires: sslmode=disable for a local database`);
  }
  if (extra > 0) {
    socket.close();
    throw new Error(`${db.host} sent bytes before TLS began`);
  }
  const secure = await socket.startTls(db.host);
  own(secure);
  return secure;
}

/** A cancel request of the app's: the key it was given, for a session of the same handle and tunnel; to its database, with its own key. */
async function cancel(session: TunnelSession, given: string, own: (pipe: Pipe) => void, signal: AbortSignal): Promise<void> {
  const target = cancels.get(given);
  // The same handle and tunnel: a cancel goes out the way its session's connection did, through its tunnel's network.
  if (target === undefined || target.group !== session.group) return;
  const socket = await open(session, target.database, own, signal);
  const writer = new Writer(socket.writable);
  await writer.write(concat(int32(16), int32(CANCEL_REQUEST), int32(target.processId), int32(target.secret)));
  writer.release();
  // The database closes the connection once it has the request, and libpq waits for that: closing first can lose it. A VPC
  // Network binding's socket is open before its connector has dialed the database, and closed then, it sends nothing.
  const reader = socket.readable.getReader();
  let late: ReturnType<typeof setTimeout> | undefined;
  await Promise.race([
    (async () => {
      while (!(await reader.read()).done);
    })(),
    new Promise<void>((resolve) => (late = setTimeout(resolve, CANCEL_MS))),
  ]).catch(() => undefined);
  clearTimeout(late);
  socket.close();
}

/** Log in to the database as it asks: SCRAM-SHA-256, or a cleartext password. MD5 is refused: WebCrypto has none. */
async function authenticate(up: Writer, down: Reader, db: Database): Promise<void> {
  let scram: Scram | null = null;
  let verified = false;
  for (;;) {
    const { type, body } = await down.message(MAX_LOGIN);
    if (type === 'E') throw new Error(`the database refused the login: ${fieldsOf(body).get('M') ?? 'no reason given'}`);
    if (type !== 'R') throw new Error(`the database sent ${type} before the login ended`);
    const code = view(body).getInt32(0);
    // SCRAM ends with the server's signature, verified, or it did not end: a server that skips it proved nothing.
    if (code === 0) {
      if (scram !== null && !verified) throw new Error("the database ended SCRAM without proving it knows the password: it is not the database the URL names");
      return;
    }
    if (code === 3) await up.message('p', cstring(db.password));
    else if (code === 10) {
      const mechanisms = decoder.decode(body.slice(4)).split('\0');
      if (!mechanisms.includes('SCRAM-SHA-256')) throw new Error(`the database offers ${mechanisms.filter(Boolean).join(', ')}, and the tunnel speaks SCRAM-SHA-256`);
      scram = await Scram.start(db.password);
      const first = encoder.encode(scram.clientFirst);
      await up.message('p', concat(cstring('SCRAM-SHA-256'), int32(first.length), first));
    } else if (code === 11 && scram !== null && !scram.answered) await up.message('p', encoder.encode(await scram.clientFinal(decoder.decode(body.slice(4)))));
    else if (code === 12 && scram !== null && scram.answered && !verified) {
      if (!(await scram.verify(decoder.decode(body.slice(4))))) throw new Error("the database's SCRAM signature does not verify: it is not the database the URL names");
      verified = true;
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

/** The most PBKDF2 iterations the tunnel computes for one login: well past any real database's (Postgres's default is 4096). */
const MAX_ITERATIONS = 100_000;

/** SCRAM-SHA-256 (RFC 5802, RFC 7677), the client's side, as Postgres runs it: no channel binding, the user name left empty. */
class Scram {
  readonly clientFirst: string;
  #bare: string;
  #password: string;
  #serverKey: Uint8Array<ArrayBuffer> | null = null;
  /** Whether the client's final message went out: the server's own comes after it, once. */
  get answered(): boolean {
    return this.#serverKey !== null;
  }
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
    // A count no database needs is a server spending the tunnel's time (RFC 5802, section 9): 4096 is Postgres's default.
    if (!Number.isInteger(iterations) || iterations < 1 || iterations > MAX_ITERATIONS) throw new Error(`the database asks for ${fields.get('i')} SCRAM iterations, past the ${MAX_ITERATIONS} the tunnel computes`);
    const key = await crypto.subtle.importKey('raw', encoder.encode(saslprep(this.#password)), 'PBKDF2', false, ['deriveBits']);
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

/**
 * SASLprep (RFC 4013), as Postgres runs it on a SCRAM password: non-ASCII
 * spaces made spaces, what maps to nothing dropped, NFKC; and the password
 * as it is when nothing is left, or the result holds a prohibited or an
 * unassigned character, or mixes right-to-left with left-to-right
 * letters, which is Postgres's own fallback (src/common/saslprep.c). One
 * difference stays: Postgres judges "unassigned" by Unicode 3.2 and this
 * by the runtime's Unicode, so a password with a character assigned since
 * (an emoji) is prepared here and taken as it is there. That matters only
 * when preparing changes it, which for such passwords is rare.
 */
export function saslprep(password: string): string {
  const mapped = password
    .replace(/[\u00A0\u1680\u2000-\u200B\u202F\u205F\u3000]/g, ' ')
    .replace(/[\u00AD\u034F\u1806\u180B-\u180D\u200C-\u200D\u2060\uFE00-\uFE0F\uFEFF]/g, '')
    .normalize('NFKC');
  // Controls, private use, non-characters, surrogates, and the bidirectional and tagging marks: C.2 to C.9.
  const prohibited = /[\u0000-\u001F\u007F-\u009F\u06DD\u070F\u180E\u200E\u200F\u2028-\u202E\u2FF0-\u2FFB\u2060-\u2063\u206A-\u206F\uE000-\uF8FF\uFDD0-\uFDEF\uFFF9-\uFFFF\u{1D173}-\u{1D17A}\u{E0001}\u{E0020}-\u{E007F}\u{F0000}-\u{10FFFF}\u{1FFFE}\u{1FFFF}\u{2FFFE}\u{2FFFF}]|\p{Cs}/u;
  // Nothing left, or a character Unicode leaves unassigned: Postgres's own fallback, the password as it is.
  if (mapped === '' || prohibited.test(mapped) || /\p{Cn}/u.test(mapped)) return password;
  // Bidirectional text: right-to-left letters only, no left-to-right one, the first and the last right-to-left.
  // Right-to-left letters (RandALCat), by script and as letters, never a digit, which is no letter's direction.
  const rtl = /(?=[\p{Script=Hebrew}\p{Script=Arabic}\p{Script=Syriac}\p{Script=Thaana}\p{Script=Nko}])\p{L}/u;
  const chars = [...mapped];
  if (chars.some((char) => rtl.test(char))) {
    if (chars.some((char) => /\p{L}/u.test(char) && !rtl.test(char)) || !rtl.test(chars[0]!) || !rtl.test(chars.at(-1)!)) return password;
  }
  return mapped;
}
