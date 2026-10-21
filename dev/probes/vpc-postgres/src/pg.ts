// Just enough of Postgres's wire protocol to log in and run two fixed
// queries: SSLRequest, StartupMessage, SCRAM-SHA-256 (WebCrypto), simple
// query, Terminate. Plaintext only: a VPC Network socket cannot start TLS.

/** What the probe needs of a socket: Workers' `Socket`, from `connect()` or a VPC Network binding. */
export interface ProbeSocket {
  readonly readable: ReadableStream<Uint8Array>;
  readonly writable: WritableStream<Uint8Array>;
  readonly opened?: Promise<unknown>;
  close(): Promise<void>;
}

export type Dial = (address: string) => ProbeSocket | Promise<ProbeSocket>;

export interface Target {
  host: string;
  port: string;
  database: string;
  user: string;
  password: string;
}

export type Stage = 'durable-object' | 'config' | 'dial' | 'ssl-request' | 'startup' | 'auth' | 'query' | 'hold';

export interface Report {
  ok: boolean;
  stage?: Stage;
  error?: string;
  dialMs?: number;
  /** The server's one-byte answer to SSLRequest: S (it would take TLS) or N. */
  sslRequest?: string;
  sslRequestMs?: number;
  /** After an S, the probe dials again and starts in plaintext, as a client that never asks does. */
  redialedPlaintext?: boolean;
  authOffered?: string[];
  loginOk?: boolean;
  loginMs?: number;
  serverVersion?: string;
  select1?: string | null;
  session?: Record<string, string | null>;
  afterHold?: { seconds: number; select1: string | null; ms: number };
  totalMs?: number;
}

/** The only SQL the probe runs. */
const SELECT_1 = 'select 1';
const SESSION = 'select current_user, inet_server_addr(), (select ssl from pg_stat_ssl where pid = pg_backend_pid())';

const STAGE_TIMEOUT_MS = 15_000;
const MAX_MESSAGE = 1 << 20;
/** Both fixed queries return one row; more is a server misbehaving. */
const MAX_ROWS = 16;
/** Postgres's default is 4096; a count far past it is a server spending our CPU (RFC 5802, section 9). */
const MAX_ITERATIONS = 100_000;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** Dial, log in and query; every failure comes back as the stage it happened in and a message, never thrown. */
export async function probe(dial: Dial, target: Target, holdSeconds: number): Promise<Report> {
  const report: Report = { ok: false };
  const started = Date.now();
  let stage: Stage = 'query';
  let connection: Connection | undefined;
  try {
    connection = await login(dial, target, report);
    report.select1 = await selectOne(connection);
    report.session = (await query(connection, SESSION))[0];

    if (holdSeconds > 0) {
      stage = 'hold';
      await sleep(holdSeconds);
      const at = Date.now();
      const select1 = await selectOne(connection);
      report.afterHold = { seconds: holdSeconds, select1, ms: Date.now() - at };
    }
    report.ok = true;
  } catch (error) {
    report.stage = error instanceof StageFailure ? error.stage : stage;
    report.error = describe(error);
  } finally {
    await connection?.close(true);
  }
  // The verdict first, so a failure reads at the top.
  const { ok, stage: failed, error, ...rest } = report;
  return { ok, stage: failed, error, ...rest, totalMs: Date.now() - started };
}

/** A failure, and the stage of the login it happened in. */
export class StageFailure extends Error {
  readonly stage: Stage;
  constructor(stage: Stage, cause: unknown) {
    super(describe(cause));
    this.stage = stage;
  }
}

/** Dial and log in, filling the report's dial and login fields. A failure is thrown as a StageFailure, its socket closed. */
export async function login(dial: Dial, target: Target, report: Report): Promise<Connection> {
  let stage: Stage = 'config';
  let connection: Connection | undefined;
  try {
    const port = /^\d{1,5}$/.test(target.port) ? Number(target.port) : 0;
    if (!target.host || port < 1 || port > 65535 || !target.database || !target.user || !target.password) {
      throw new Error('PG_HOST, PG_PORT, PG_DATABASE, PG_USER and the DEBUG_RO_PASSWORD secret must all be set');
    }
    const address = `${target.host}:${target.port}`;
    const open = async (): Promise<Connection> => {
      const at = Date.now();
      const dialing = Promise.resolve(dial(address));
      let socket: ProbeSocket;
      try {
        socket = await within(dialing);
      } catch (error) {
        // A socket that arrives after the timeout is closed, not left open on the tunnel.
        void dialing.then((late) => late.close()).catch(() => {});
        throw error;
      }
      try {
        await within(socket.opened ?? Promise.resolve());
      } catch (error) {
        await within(socket.close()).catch(() => {});
        throw error;
      }
      report.dialMs = Date.now() - at;
      return new Connection(socket);
    };

    stage = 'dial';
    connection = await open();

    stage = 'ssl-request';
    const asked = Date.now();
    connection.stage();
    await connection.write(int32s(8, 80877103));
    const answer = decoder.decode(await connection.read(1));
    report.sslRequest = answer;
    report.sslRequestMs = Date.now() - asked;
    if (answer === 'S') {
      await connection.close(false);
      connection = undefined;
      stage = 'dial';
      connection = await open();
      report.redialedPlaintext = true;
    } else if (answer !== 'N') {
      throw new Error(`the server answered SSLRequest with ${JSON.stringify(answer)}, neither S nor N`);
    }

    stage = 'startup';
    const loginStarted = Date.now();
    connection.stage();
    await connection.write(startup(target));

    stage = 'auth';
    await authenticate(connection, target.password, report);
    report.serverVersion = await untilReady(connection);
    report.loginOk = true;
    report.loginMs = Date.now() - loginStarted;
    return connection;
  } catch (error) {
    await connection?.close(true);
    throw new StageFailure(stage, error);
  }
}

/** `select 1` on a logged-in connection. */
export async function selectOne(connection: Connection): Promise<string | null> {
  return (await query(connection, SELECT_1))[0]?.['?column?'] ?? null;
}

export function sleep(seconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, seconds * 1000));
}

/** An error's message alone, bounded: never a stack. */
export function describe(error: unknown): string {
  return (error instanceof Error ? error.message : String(error)).slice(0, 500);
}

export class Connection {
  readonly #socket: ProbeSocket;
  readonly #reader: ReadableStreamDefaultReader<Uint8Array>;
  readonly #writer: WritableStreamDefaultWriter<Uint8Array>;
  #buffer = new Uint8Array(0);
  /** When the current stage gives up: one deadline for all its reads and writes, however many messages the server sends. */
  #deadline = Date.now() + STAGE_TIMEOUT_MS;

  constructor(socket: ProbeSocket) {
    this.#socket = socket;
    this.#reader = socket.readable.getReader();
    this.#writer = socket.writable.getWriter();
  }

  /** Start a stage: STAGE_TIMEOUT_MS from now. */
  stage(): void {
    this.#deadline = Date.now() + STAGE_TIMEOUT_MS;
  }

  write(bytes: Uint8Array): Promise<void> {
    return within(this.#writer.write(bytes), this.#deadline);
  }

  read(length: number): Promise<Uint8Array> {
    return within(this.#fill(length), this.#deadline);
  }

  async #fill(length: number): Promise<Uint8Array> {
    while (this.#buffer.length < length) {
      const { value, done } = await this.#reader.read();
      if (done) throw new Error('the server closed the connection');
      this.#buffer = concat(this.#buffer, value);
    }
    const out = this.#buffer.slice(0, length);
    this.#buffer = this.#buffer.slice(length);
    return out;
  }

  /** The next message, its one-byte type and its body; an ErrorResponse is thrown as its fields. */
  async message(): Promise<{ type: string; body: Uint8Array }> {
    const head = await this.read(5);
    const length = new DataView(head.buffer, head.byteOffset, 5).getInt32(1);
    if (length < 4 || length > MAX_MESSAGE) throw new Error(`the server sent a message of ${length} bytes`);
    const body = await this.read(length - 4);
    const type = String.fromCharCode(head[0]!);
    if (type === 'E') throw new Error(`the server says: ${serverError(body)}`);
    return { type, body };
  }

  async close(terminate: boolean): Promise<void> {
    if (terminate) await within(this.#writer.write(message('X'))).catch(() => {});
    await within(this.#socket.close()).catch(() => {});
  }
}

function startup(target: Target): Uint8Array {
  const params = ['user', target.user, 'database', target.database, 'application_name', 'vpc-postgres-probe'];
  const body = concat(int32s(196608), ...params.map(cstring), new Uint8Array([0]));
  return concat(int32s(body.length + 4), body);
}

/** Log in with SCRAM-SHA-256 and verify the server's signature; any other method is reported, never answered. */
async function authenticate(connection: Connection, password: string, report: Report): Promise<void> {
  let scram: Scram | undefined;
  let verified = false;
  for (;;) {
    const { type, body } = await connection.message();
    if (type !== 'R') throw new Error(`expected an authentication request, got message ${JSON.stringify(type)}`);
    const code = new DataView(body.buffer, body.byteOffset).getInt32(0);
    if (code === 0) {
      if (!verified) throw new Error('the server ended authentication without proving it knows the password');
      return;
    }
    if (code === 10) {
      const mechanisms = decoder.decode(body.slice(4)).split('\0').filter(Boolean);
      report.authOffered = mechanisms;
      if (!mechanisms.includes('SCRAM-SHA-256')) throw new Error(`the server offers ${mechanisms.join(', ')}, not SCRAM-SHA-256`);
      scram = new Scram(password);
      const first = encoder.encode(scram.clientFirst);
      await connection.write(message('p', cstring('SCRAM-SHA-256'), int32s(first.length), first));
    } else if (code === 11 && scram && !scram.answered) {
      await connection.write(message('p', encoder.encode(await scram.clientFinal(decoder.decode(body.slice(4))))));
    } else if (code === 12 && scram?.answered && !verified) {
      if (!(await scram.verify(decoder.decode(body.slice(4))))) throw new Error("the server's SCRAM signature does not verify");
      verified = true;
    } else {
      const method = { 3: 'cleartext password', 5: 'MD5' }[code] ?? `authentication code ${code}`;
      report.authOffered = [method];
      throw new Error(`the server asks for ${method}; the probe only answers SCRAM-SHA-256 and sent no password`);
    }
  }
}

/** Read past ParameterStatus and BackendKeyData to ReadyForQuery; returns server_version. */
async function untilReady(connection: Connection): Promise<string | undefined> {
  let version: string | undefined;
  for (;;) {
    const { type, body } = await connection.message();
    if (type === 'Z') return version;
    if (type === 'S') {
      const [name, value] = decoder.decode(body).split('\0');
      if (name === 'server_version') version = value;
    }
  }
}

/** A simple query's rows, each column by name, as text. */
async function query(connection: Connection, sql: string): Promise<Record<string, string | null>[]> {
  connection.stage();
  await connection.write(message('Q', cstring(sql)));
  let columns: string[] = [];
  const rows: Record<string, string | null>[] = [];
  for (;;) {
    const { type, body } = await connection.message();
    const view = new DataView(body.buffer, body.byteOffset, body.byteLength);
    if (type === 'T') {
      columns = [];
      let at = 2;
      for (let i = 0; i < view.getInt16(0); i++) {
        const end = body.indexOf(0, at);
        if (end === -1) throw new Error('the server sent a malformed RowDescription');
        columns.push(decoder.decode(body.slice(at, end)));
        at = end + 1 + 18;
      }
    } else if (type === 'D') {
      const row: Record<string, string | null> = {};
      let at = 2;
      for (let i = 0; i < view.getInt16(0); i++) {
        const length = view.getInt32(at);
        at += 4;
        row[columns[i] ?? String(i)] = length < 0 ? null : decoder.decode(body.slice(at, at + length));
        at += Math.max(length, 0);
      }
      rows.push(row);
      if (rows.length > MAX_ROWS) throw new Error(`the server sent more than ${MAX_ROWS} rows`);
    } else if (type === 'Z') {
      return rows;
    }
  }
}

/** SCRAM-SHA-256 (RFC 5802, RFC 7677), the client's side as Postgres runs it: no channel binding, the user name left empty. */
class Scram {
  readonly clientFirst: string;
  answered = false;
  readonly #bare: string;
  readonly #password: string;
  #authMessage = '';
  #serverKey: Uint8Array | undefined;

  constructor(password: string) {
    this.#password = password;
    this.#bare = `n=,r=${base64(crypto.getRandomValues(new Uint8Array(18)))}`;
    this.clientFirst = `n,,${this.#bare}`;
  }

  async clientFinal(serverFirst: string): Promise<string> {
    const fields = new Map(serverFirst.split(',').map((part) => [part[0], part.slice(2)] as const));
    const nonce = fields.get('r') ?? '';
    if (!nonce.startsWith(this.#bare.slice('n=,r='.length))) throw new Error("the server's SCRAM nonce does not extend ours");
    const iterations = Number(fields.get('i'));
    if (!Number.isInteger(iterations) || iterations < 1 || iterations > MAX_ITERATIONS) {
      throw new Error(`the server asks for ${fields.get('i')} SCRAM iterations, past the ${MAX_ITERATIONS} the probe computes`);
    }
    // SASLprep is left out: it changes nothing in an ASCII password, which the README asks for.
    const key = await crypto.subtle.importKey('raw', encoder.encode(this.#password), 'PBKDF2', false, ['deriveBits']);
    const salt = unbase64(fields.get('s') ?? '');
    const salted = new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, key, 256));
    const clientKey = await hmac(salted, 'Client Key');
    const storedKey = new Uint8Array(await crypto.subtle.digest('SHA-256', clientKey));
    const withoutProof = `c=biws,r=${nonce}`;
    this.#authMessage = `${this.#bare},${serverFirst},${withoutProof}`;
    const signature = await hmac(storedKey, this.#authMessage);
    this.#serverKey = await hmac(salted, 'Server Key');
    this.answered = true;
    return `${withoutProof},p=${base64(clientKey.map((byte, i) => byte ^ signature[i]!))}`;
  }

  async verify(serverFinal: string): Promise<boolean> {
    return serverFinal === `v=${base64(await hmac(this.#serverKey!, this.#authMessage))}`;
  }
}

async function hmac(key: Uint8Array, data: string): Promise<Uint8Array> {
  const imported = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', imported, encoder.encode(data)));
}

/** ErrorResponse's severity, SQLSTATE and message; its other fields (detail, hint, position) are dropped. */
function serverError(body: Uint8Array): string {
  const fields = new Map<string, string>();
  let at = 0;
  while (at < body.length && body[at] !== 0) {
    const end = body.indexOf(0, at + 1);
    if (end === -1) break;
    fields.set(String.fromCharCode(body[at]!), decoder.decode(body.slice(at + 1, end)));
    at = end + 1;
  }
  return `${fields.get('V') ?? fields.get('S') ?? 'ERROR'} ${fields.get('C') ?? '?'}: ${fields.get('M') ?? ''}`;
}

/** The promise, or a rejection at the deadline: by default STAGE_TIMEOUT_MS from now. */
function within<T>(promise: Promise<T>, deadline = Date.now() + STAGE_TIMEOUT_MS): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | null = null;
  const timeout = new Promise<never>((_, reject) => {
    const fail = () => reject(new Error(`no answer within ${STAGE_TIMEOUT_MS / 1000} s`));
    timer = setTimeout(fail, Math.max(0, deadline - Date.now()));
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

function message(type: string, ...parts: Uint8Array[]): Uint8Array {
  const body = concat(...parts);
  return concat(encoder.encode(type), int32s(body.length + 4), body);
}

function int32s(...values: number[]): Uint8Array {
  const bytes = new Uint8Array(values.length * 4);
  values.forEach((value, i) => new DataView(bytes.buffer).setInt32(i * 4, value));
  return bytes;
}

function cstring(value: string): Uint8Array {
  return concat(encoder.encode(value), new Uint8Array([0]));
}

function concat(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}

function base64(bytes: Uint8Array): string {
  return btoa(Array.from(bytes, (byte) => String.fromCharCode(byte)).join(''));
}

function unbase64(text: string): Uint8Array {
  return Uint8Array.from(atob(text), (char) => char.charCodeAt(0));
}
