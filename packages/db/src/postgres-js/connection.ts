// One connection to Postgres: it opens (TLS, startup, authentication), sends
// the statements the pool hands it, pipelined, and reads their answers.
import { Buffer } from 'node:buffer';

import * as platform from '#postgres/platform';

import { b, N } from './bytes.ts';
import * as Errors from './errors.ts';
import { FIELDS, type Notice } from './errors.ts';
import type { Settings } from './index.ts';
import type { Socket, TlsOptions } from './platform.ts';
import type { Query } from './query.ts';
import { Queue } from './queue.ts';
import { Result, type Backend, type Column } from './result.ts';
import { inferType } from './types.ts';

/** A connection asked of the pool by `reserve()`: given the connection itself, rather than sent on it. */
export interface Reservation {
  reserve(connection: Connection): void;
  reject(error: unknown): void;
}

/** What waits for a connection: a statement, or a reservation. */
export type Waiting = Query | Reservation;

const isReservation = (waiting: Waiting): waiting is Reservation => 'reserve' in waiting;

/**
 * A connection held for one caller, a transaction or a `reserve()`, until it
 * gives it back (`release`): the pool sends it nothing else. `next` sends the
 * caller's next statement.
 */
export interface Reserved {
  next(): void;
}

export interface Connection {
  readonly id: number;
  /** The pool's queue it is in: open, busy, full, connecting, reserved, closed or ended. */
  queue: Queue<Connection>;
  readonly idleTimer: Timer;
  reserved: Reserved | null;
  /** What its transaction hears if it closes: `begin` fails. */
  onclose: ((error: Error) => void) | null;
  /** Open it, for `first`. */
  connect(first: Waiting): void;
  /** Send `query`; whether more may follow it now. */
  execute(query: Query): boolean;
  /** Close it once what it was sent has answered. */
  end(): Promise<void>;
  /** Given back by what held it: closed if it was asked to end meanwhile, or the pool's again. */
  release(): void;
  /** Close it now, failing what it was sent. */
  terminate(): void;
}

export interface Events {
  onopen(connection: Connection): void;
  onend(connection: Connection): void;
  onclose(connection: Connection, error: Error): void;
}

interface Timer {
  start(): void;
  cancel(): void;
}

let uid = 1;

const Sync = b.typed('S').end();
const Flush = b.typed('H').end();
const SSLRequest = b.untyped().inc(4).i32(80877103).end(0);
const ExecuteOnly = b.typed('E').str(N).i32(0).end();
const ExecuteUnnamed = Buffer.concat([ExecuteOnly, Sync]);
const BindNothing = b.typed('B').str(N).str(N).i16(0).i16(0).i16(0).end();
const DescribeUnnamed = b.typed('D').str('S').str(N).end();
const noop = () => {};

/** A connection, closed, in `queue`, the pool's queue of closed ones. */
export function createConnection(options: Settings, queue: Queue<Connection>, { onopen, onend, onclose }: Events): Connection {
  const { sslnegotiation, ssl, max, user, database, parsers, serializers, onnotice, max_pipeline, keep_alive, backoff } = options;

  const sent = new Queue<Query>();
  const id = uid++;
  const backend: Backend = { pid: null, secret: null };
  const idleTimer = timer(end, options.idle_timeout);
  const lifeTimer = timer(end, options.max_lifetime);
  const connectTimer = timer(connectTimedOut, options.connect_timeout);

  let socket: Socket | null = null;
  let errorResponse: Error | null = null;
  let result = new Result();
  let results: Result[] | null = null;
  let incoming: Buffer = Buffer.alloc(0);
  let incomings: Buffer[] | null = null;
  let closedTime = 0;
  let remaining = 0;
  let length = 0;
  let delay = 0;
  let rows = 0;
  let serverSignature: string | null = null;
  let nextWriteTimer: unknown = null;
  let terminated = false;
  let initial: Waiting | null = null;
  let ending: Promise<void> | null = null;
  let chunk: Buffer | null = null;
  let ended: (() => void) | null = null;
  let nonce: string | null = null;
  /** The statement answering now; those sent after it, pipelined, wait in `sent`. */
  let query: Query | null = null;

  const connection: Connection = {
    queue,
    idleTimer,
    reserved: null,
    onclose: null,
    connect(first) {
      initial = first;
      reconnect();
    },
    terminate,
    execute,
    end,
    release,
    id,
  };

  queue.push(connection);

  return connection;

  async function createSocket(): Promise<Socket | null> {
    let x: Socket;
    try {
      x = options.socket
        ? await options.socket()
        : platform.tcp(options.path ? { path: options.path } : { host: options.host, port: options.port, tls: ssl !== false }, ssl ? () => void secure().catch(openingFailed) : connected);
    } catch (e) {
      // Coffre: and closes, so that the pool can open it again, backing off as from a refused connection; upstream left
      // it opening for ever.
      error(e);
      void closed(true);
      return null;
    }
    x.on('error', error);
    x.on('close', closed);
    x.on('drain', drain);
    return x;
  }

  function execute(q: Query): boolean {
    if (terminated) {
      queryError(q, Errors.connection('CONNECTION_DESTROYED', options));
      return false;
    }

    let message: Buffer;
    try {
      build(q);
      message = toBuffer(q);
      // What is sent, once it can be: its BEGIN first, if it carries one, and its values as asked.
      if (typeof options.debug === 'function') {
        if (q.begin !== null) options.debug(id, q.begin, [], []);
        options.debug(id, q.text, q.args, q.statement!.types);
      }
    } catch (e) {
      // Coffre: a statement the client cannot write fails alone, and nothing of it is sent. On an idle connection it is
      // answered all the same, a lone Sync's ReadyForQuery, which goes on as any answer does; behind one answering, it
      // is dropped. Upstream failed the statement already answering there, and left this one waiting for an answer,
      // its transaction with it.
      queryError(q, e);
      if (query === null) {
        query = q;
        write(Sync);
      }
      return true;
    }
    if (query) sent.push(q);
    else query = q;
    // Nothing follows a statement that carries its transaction's BEGIN until Postgres has said whether it took.
    return write(message) && !q.describeFirst && q.begin === null && sent.length < max_pipeline;
  }

  function toBuffer(q: Query): Buffer {
    if (q.parameters.length >= 65534) throw Errors.generic('MAX_PARAMETERS_EXCEEDED', 'Max number of parameters (65534) exceeded');

    // Coffre: a transaction's BEGIN goes with its first statement, a round trip less, and under the same Sync, so that
    // a BEGIN that fails has Postgres skip the statement, which never runs outside the transaction: in one Query
    // message, whose statements stop at the first that fails, or as the extended protocol's Parse, Bind and Execute
    // ahead of the statement's. Upstream sent BEGIN alone and waited for it.
    if (q.options.simple) return b.typed('Q').str((q.begin === null ? '' : q.begin + ';\n') + q.statement!.string + N).end();
    const statement = q.describeFirst ? [Parse(q), DescribeUnnamed, Flush] : [Parse(q), DescribeUnnamed, bound(q)];
    return Buffer.concat(q.begin === null ? statement : [b.typed('P').str(N).str(q.begin + N).i16(0).end(), BindNothing, ExecuteOnly, ...statement]);
  }

  /** The statement's values, bound, and its execution: what follows its Parse once the values can be written. */
  function bound(q: Query): Buffer {
    return Buffer.concat([Bind(q.parameters, q.statement!.types), ExecuteUnnamed]);
  }

  function build(q: Query): void {
    const parameters: unknown[] = [];
    const types: number[] = [];
    for (const x of q.args) {
      if (x === undefined) throw Errors.generic('UNDEFINED_VALUE', 'Undefined values are not allowed');
      parameters.push(x);
      types.push(inferType(x));
    }

    q.parameters = parameters;
    // Coffre: an unnamed statement's plain values go with it, in one round trip (typedByServer, below).
    q.describeFirst = parameters.length > 0 && typedByServer(parameters, types);
    q.statement = { string: q.text, types, columns: null };
  }

  function write(x: Buffer): boolean {
    chunk = chunk ? Buffer.concat([chunk, x]) : Buffer.from(x);
    if (chunk.length >= 1024) return nextWrite();
    if (nextWriteTimer === null) nextWriteTimer = platform.setImmediate(nextWrite);
    return true;
  }

  function nextWrite(): boolean {
    const x = socket!.write(chunk!);
    if (nextWriteTimer !== null) platform.clearImmediate(nextWriteTimer);
    chunk = nextWriteTimer = null;
    return x;
  }

  function connectTimedOut(): void {
    errored(Errors.connection('CONNECT_TIMEOUT', options));
    socket!.destroy();
  }

  async function secure(): Promise<void> {
    if (sslnegotiation !== 'direct') {
      const at = socket!;
      write(SSLRequest);
      // The server's answer, S or N: TLS is tried either way, and fails against a server that said no.
      await new Promise<void>((resolve) => at.once('data', () => resolve()));
      // Coffre: unless the socket closed meanwhile (on workerd its answer and its close can come in either order): the
      // connection may be opening again, for another query.
      if (socket !== at) return;
    }

    const tls: TlsOptions = {
      // The host's name, for TLS's SNI; not an IP address's, nor a socket the caller made.
      servername: options.socket || options.path || platform.isIP(options.host) ? undefined : options.host,
    };
    if (sslnegotiation === 'direct') tls.ALPNProtocols = ['postgresql'];
    if (ssl) Object.assign(tls, ssl);

    const plain = socket!;
    plain.removeAllListeners();
    try {
      socket = platform.startTls(plain, tls);
    } catch (e) {
      // Coffre: TLS options it cannot load (a key, a password): the plain socket closes the connection, as openingFailed destroys it.
      plain.on('close', closed);
      throw e;
    }
    socket.on('secureConnect', connected);
    socket.on('error', error);
    socket.on('close', closed);
    socket.on('drain', drain);
  }

  function drain(): void {
    if (!query) onopen(connection);
  }

  function data(x: Buffer): void {
    if (incomings) {
      incomings.push(x);
      remaining -= x.length;
      if (remaining > 0) return;
    }

    incoming = incomings
      ? Buffer.concat(incomings, length - remaining)
      : incoming.length === 0
        ? x
        : Buffer.concat([incoming, x], incoming.length + x.length);

    while (incoming.length > 4) {
      length = incoming.readUInt32BE(1);
      if (length >= incoming.length) {
        remaining = length - incoming.length;
        incomings = [incoming];
        break;
      }

      try {
        handle(incoming.subarray(0, length + 1));
      } catch (e) {
        if (query?.describeFirst) write(Sync);
        errored(e);
      }
      incoming = incoming.subarray(length + 1);
      remaining = 0;
      incomings = null;
    }
  }

  async function connect(): Promise<void> {
    terminated = false;
    socket ??= await createSocket();
    if (!socket) return;

    connectTimer.start();

    // A socket of the pool's own is opening, heard from `tcp`; the caller's is open.
    if (options.socket) return ssl ? secure().catch(openingFailed) : connected();
  }

  function reconnect(): void {
    setTimeout(() => void connect(), closedTime ? Math.max(0, closedTime + delay - platform.now()) : 0);
  }

  function connected(): void {
    try {
      lifeTimer.start();
      socket!.on('data', data);
      if (keep_alive) socket!.setKeepAlive?.(true, 1000 * keep_alive);
      write(StartupMessage());
    } catch (err) {
      // Coffre: and closes; upstream left it opening until its connect_timeout, if any.
      openingFailed(err);
    }
  }

  function error(err: unknown): void {
    errored(err);
    while (sent.length) queryError(sent.shift()!, err);
  }

  function errored(err: unknown): void {
    if (query) queryError(query, err);
    if (initial) {
      queryError(initial, err);
      initial = null;
    }
  }

  function queryError(q: Waiting, err: unknown): void {
    if (isReservation(q)) return q.reject(err);

    const e = err && typeof err === 'object' ? err : new Error(String(err));
    if (!('query' in e) && !('parameters' in e)) {
      const debug = Boolean(options.debug);
      // Postgres refusing the BEGIN a statement carried refused the BEGIN: named as such.
      const begin = q.begin !== null && !q.began && e instanceof Errors.PostgresError;
      Object.defineProperties(e, {
        stack: { value: ('stack' in e ? String(e.stack) : '') + q.origin.replace(/.*\n/, '\n'), enumerable: debug },
        query: { value: begin ? q.begin : q.text, enumerable: debug },
        parameters: { value: begin ? [] : q.parameters, enumerable: debug },
        args: { value: q.args, enumerable: debug },
        types: { value: q.statement?.types, enumerable: debug },
      });
    }
    q.reject(e);
  }

  function end(): Promise<void> {
    if (ending) return ending;
    if (!connection.reserved) onend(connection);
    if (!connection.reserved && !initial && !query && sent.length === 0) {
      terminate();
      return new Promise((resolve) => (socket && socket.readyState !== 'closed' ? socket.once('close', () => resolve()) : resolve()));
    }
    return (ending = new Promise((resolve) => (ended = resolve)));
  }

  // Coffre: a held connection asked to end meanwhile (its lifetime, the client's end) closes once given back; upstream
  // closed a transaction's once Postgres said it was idle, and gave a reserve()'s back to the pool, its end() still
  // waiting, which a later end() waited on for ever.
  function release(): void {
    connection.reserved = null;
    if (ending) terminate();
    else onopen(connection);
  }

  function terminate(): void {
    terminated = true;
    if (query || initial || sent.length) error(Errors.connection('CONNECTION_DESTROYED', options));

    platform.clearImmediate(nextWriteTimer);
    if (socket) {
      socket.removeListener('data', data);
      socket.removeListener('connect', connected);
      if (socket.readyState === 'open') socket.end(b.typed('X').end());
    }
    if (ended) {
      ended();
      ending = ended = null;
    }
  }

  async function closed(hadError?: boolean): Promise<void> {
    incoming = Buffer.alloc(0);
    remaining = 0;
    incomings = null;
    platform.clearImmediate(nextWriteTimer);
    idleTimer.cancel();
    lifeTimer.cancel();
    connectTimer.cancel();

    socket?.removeAllListeners();
    socket = null;

    // Coffre: a connection closed while it opened, with no error said, fails the query that opened it, as
    // node-postgres's "Connection terminated unexpectedly" did, and is closed as any other. Upstream dialled again, at
    // once and for ever, the query never answered and end() waiting on it; its retry was for the next of several hosts,
    // which coffre never names.
    if (initial) errored(Errors.connection('CONNECTION_CLOSED', options));

    if (!hadError && (query || sent.length)) error(Errors.connection('CONNECTION_CLOSED', options));
    // Coffre: the query cut short has failed; upstream kept it as the connection's, so that end() waited for it to
    // answer, for ever, unless a later query opened the connection again. And an end() asked meanwhile, as the
    // connection opened or answered, is done: the connection it waited to close has.
    query = null;
    // Coffre: and with it what its answer had left half read, its error, its rows, its results, and what was still to
    // be written: upstream kept them, so the next query on the connection opened again failed with the dead one's
    // error, or answered its own rows after the dead one's count, holes first.
    errorResponse = null;
    rows = 0;
    result = new Result();
    results = null;
    chunk = null;
    nextWriteTimer = null;
    if (ended) {
      ended();
      ending = ended = null;
    }
    closedTime = platform.now();
    if (hadError) options.shared.retries++;
    delay = (typeof backoff === 'function' ? backoff(options.shared.retries) : backoff) * 1000;
    onclose(connection, Errors.connection('CONNECTION_CLOSED', options));
  }

  /* Handlers */
  function handle(x: Buffer): void {
    switch (x[0]) {
      case 68: return DataRow(x); // D
      case 83: return ParameterStatus(x); // S
      case 90: return ReadyForQuery(x); // Z
      case 67: return CommandComplete(x); // C
      case 50: return BindComplete(); // 2
      case 49: return; // 1, ParseComplete
      case 116: return ParameterDescription(x); // t
      case 84: return RowDescription(x); // T
      case 82: return authenticate(x); // R
      case 110: return NoData(); // n
      case 75: return BackendKeyData(x); // K
      case 69: return ErrorResponse(x); // E
      case 78: return NoticeResponse(x); // N
      case 73: return; // I, EmptyQueryResponse
      // No LISTEN is asked, but a NOTIFY to a channel listened on by hand would come: it is dropped.
      case 65: return; // A, NotificationResponse
      case 71: return CopyInResponse(); // G
      case 72: // H, CopyOutResponse
      case 87: return CopyOutResponse(); // W, CopyBothResponse
      case 100: return; // d, CopyData
      case 99: return; // c, CopyDone
      case 86: return errored(Errors.notSupported('FunctionCallResponse')); // V
      case 118: return errored(Errors.notSupported('NegotiateProtocolVersion')); // v
      default: console.error('Postgres.js : Unknown Message:', x[0]);
    }
  }

  function DataRow(x: Buffer): void {
    const q = query!;
    const columns = q.statement!.columns!;
    let index = 7;
    const row: unknown[] | Record<string, unknown> = q.arrays ? new Array(columns.length) : {};
    for (let i = 0; i < columns.length; i++) {
      const column = columns[i]!;
      const length = x.readInt32BE(index);
      index += 4;

      const value = length === -1
        ? null
        : column.parser === undefined
          ? x.toString('utf8', index, (index += length))
          : column.parser(x.toString('utf8', index, (index += length)));

      if (Array.isArray(row)) row[i] = value;
      else row[column.name] = value;
    }

    result[rows++] = row;
  }

  function ParameterStatus(x: Buffer): void {
    const [k, v] = x.toString('utf8', 5, x.length - 1).split(N);
    options.parameters[k!] = v!;
  }

  function ReadyForQuery(x: Buffer): void {
    if (query) {
      if (errorResponse) errored(errorResponse);
      else query.resolve(results || result);
    } else if (errorResponse) {
      errored(errorResponse);
    }

    query = results = errorResponse = null;
    result = new Result();
    connectTimer.cancel();

    if (initial) {
      // Open: what opened it goes now, a statement sent, a reservation given the connection.
      if (!isReservation(initial)) execute(initial);
      options.shared.retries = 0;
      // Coffre: a reserve() that opened the connection is given it now, itself, even as the client ends: asked before,
      // it is served, and its release closes the connection, which end() waits for. Upstream gave it after
      // fetch_types's own query, and without fetch_types never; and it gave the connection to the pool's first waiting,
      // which the reservation, taken from the queue to open this connection again after one closed, no longer was:
      // that reserve() waited for ever.
      const opened = initial;
      initial = null;
      if (opened !== null && isReservation(opened)) opened.reserve(connection);
      return;
    }

    if (sent.length) query = sent.shift()!;
    if (query) return; // Consider opening if able and sent.length < 50

    if (connection.reserved) {
      connection.reserved.next();
    } else if (ending) {
      terminate();
    } else {
      onopen(connection);
    }
  }

  function CommandComplete(x: Buffer): void {
    // The BEGIN sent ahead of the statement: its answer, not the statement's.
    if (query!.begin !== null && !query!.began) {
      query!.began = true;
      return;
    }
    rows = 0;

    for (let i = x.length - 1; i > 0; i--) {
      if (x[i] === 32 && (x[i + 1] ?? 58) < 58 && result.count === null) result.count = +x.toString('utf8', i + 1, x.length - 1);
      if (x[i - 1]! >= 65) {
        result.command = x.toString('utf8', 5, i);
        result.state = backend;
        break;
      }
    }

    if (result.command === 'BEGIN' && max !== 1 && !connection.reserved) {
      return errored(Errors.generic('UNSAFE_TRANSACTION', 'Only use sql.begin, sql.reserved or max: 1'));
    }

    if (query!.options.simple) return BindComplete();
  }

  function BindComplete(): void {
    if (!result.statement) result.statement = query!.statement;
    result.columns = query!.statement!.columns;
  }

  function ParameterDescription(x: Buffer): void {
    const q = query!;
    const types = q.statement!.types;
    const length = x.readUInt16BE(5);

    for (let i = 0; i < length; ++i) if (!types[i]) types[i] = x.readUInt32BE(7 + i * 4);

    if (q.describeFirst) {
      write(bound(q));
      q.describeFirst = false;
    }
  }

  function RowDescription(x: Buffer): void {
    const statement = query!.statement!;
    if (result.command) {
      results = results || [result];
      results.push((result = new Result()));
      result.count = null;
      statement.columns = null;
    }

    const length = x.readUInt16BE(5);
    let index = 7;
    let start: number;

    const columns: Column[] = (statement.columns = Array(length));

    for (let i = 0; i < length; ++i) {
      start = index;
      while (x[index++] !== 0);
      columns[i] = {
        name: x.toString('utf8', start, index - 1),
        parser: parsers[x.readUInt32BE(index + 6)],
        table: x.readUInt32BE(index),
        number: x.readUInt16BE(index + 4),
        type: x.readUInt32BE(index + 6),
      };
      index += 18;
    }

    result.statement = statement;
  }

  // Coffre: a step that finishes once its socket has closed (on workerd the hashes are WebCrypto's promises) writes
  // nothing and fails nothing: the connection may be opening again, on another socket, for another query.
  function authenticate(x: Buffer): void {
    const at = socket!;
    Authentication(x, at).catch((err: unknown) => {
      if (socket === at) openingFailed(err);
    });
  }

  async function Authentication(x: Buffer, at: Socket): Promise<void> {
    const type = x.readUInt32BE(5);
    switch (type) {
      case 0: return;
      case 3: return AuthenticationCleartextPassword();
      case 5: return AuthenticationMD5Password(x, at);
      case 10: return SASL();
      case 11: return SASLContinue(x, at);
      case 12: return SASLFinal(x);
      // Coffre: GSSAPI, SSPI, Kerberos: the connection fails, where upstream logged it and waited.
      default: throw Errors.generic('AUTH_TYPE_NOT_SUPPORTED', `Postgres asked for an authentication the client has not: type ${type}`);
    }
  }

  // Coffre: what the client failed to do to open the connection, its TLS (a key it cannot read) or its sign-in (a hash,
  // the server's message), fails what waits for the connection, and the connection closes. Upstream left the rejection
  // unhandled, which ends a Node process.
  function openingFailed(err: unknown): void {
    errored(err);
    socket?.destroy();
  }

  function AuthenticationCleartextPassword(): void {
    write(b.typed('p').str(options.pass).z(1).end());
  }

  async function AuthenticationMD5Password(x: Buffer, at: Socket): Promise<void> {
    const payload = 'md5' + (await platform.md5(Buffer.concat([Buffer.from(await platform.md5(options.pass + user)), x.subarray(9)])));
    if (socket !== at) return;
    write(b.typed('p').str(payload).z(1).end());
  }

  function SASL(): void {
    nonce = platform.randomBytes(18).toString('base64');
    b.typed('p').str('SCRAM-SHA-256' + N);
    const i = b.i;
    write(b.inc(4).str('n,,n=*,r=' + nonce).i32(b.i - i - 4, i).end());
  }

  async function SASLContinue(x: Buffer, at: Socket): Promise<void> {
    const res: Record<string, string> = {};
    for (const part of x.toString('utf8', 9).split(',')) res[part[0]!] = part.slice(2);

    const saltedPassword = await platform.pbkdf2(options.pass, Buffer.from(res.s!, 'base64'), parseInt(res.i!), 32);

    const clientKey = await platform.hmac(saltedPassword, 'Client Key');

    const auth = 'n=*,r=' + nonce + ','
      + 'r=' + res.r + ',s=' + res.s + ',i=' + res.i
      + ',c=biws,r=' + res.r;

    const signature = (await platform.hmac(await platform.hmac(saltedPassword, 'Server Key'), auth)).toString('base64');

    const payload = 'c=biws,r=' + res.r + ',p=' + xor(clientKey, await platform.hmac(await platform.sha256(clientKey), auth)).toString('base64');

    if (socket !== at) return;
    serverSignature = signature;
    write(b.typed('p').str(payload).end());
  }

  function SASLFinal(x: Buffer): void {
    if (x.toString('utf8', 9).split(N, 1)[0]!.slice(2) === serverSignature) return;
    errored(Errors.generic('SASL_SIGNATURE_MISMATCH', 'The server did not return the correct signature'));
    socket!.destroy();
  }

  function NoData(): void {
    result.statement = query!.statement;
    result.statement!.columns = [];
  }

  function BackendKeyData(x: Buffer): void {
    backend.pid = x.readUInt32BE(5);
    backend.secret = x.readUInt32BE(9);
  }

  function ErrorResponse(x: Buffer): void {
    if (query) {
      if (query.describeFirst) write(Sync);
      errorResponse = Errors.postgres(parseError(x));
    } else {
      errored(Errors.postgres(parseError(x)));
    }
  }

  // COPY: never asked by coffre, and refused if a statement asks for it. COPY FROM STDIN is failed, which ends it
  // (CopyFail; after the extended protocol's, a Sync), and the statement fails with Postgres's error, which names
  // this; COPY TO STDOUT's rows are dropped as they come, and the statement fails once Postgres is ready again.
  function CopyInResponse(): void {
    write(b.typed('f').str('COPY is not supported by this client' + N).end());
    if (!query?.options.simple) write(Sync);
  }

  function CopyOutResponse(): void {
    errorResponse ??= Errors.generic('COPY_NOT_SUPPORTED', 'COPY is not supported by this client');
  }

  function NoticeResponse(x: Buffer): void {
    if (onnotice) onnotice(parseError(x));
    else console.log(parseError(x));
  }

  /* Messages */
  function Bind(parameters: unknown[], types: number[]): Buffer {
    let prev: number;

    b.typed('B').str(N).str(N).i16(0).i16(parameters.length);

    parameters.forEach((x, i) => {
      if (x === null) return void b.i32(0xffffffff);

      const type = types[i]!;
      const serialize = serializers[type];
      parameters[i] = x = serialize ? serialize(x) : String(x);

      prev = b.i;
      b.inc(4).str(x as string).i32(b.i - prev - 4, prev);
    });

    b.i16(0);

    return b.end();
  }

  function Parse(q: Query): Buffer {
    const { string, types } = q.statement!;
    b.typed('P').str(N).str(string + N).i16(q.parameters.length);
    q.parameters.forEach((_, i) => b.i32(types[i] || 0));
    return b.end();
  }

  function StartupMessage(): Buffer {
    return b
      .untyped()
      .inc(4)
      .i16(3)
      .z(2)
      .str(
        Object.entries({ user, database, client_encoding: 'UTF8', ...options.connection })
          .filter(([, v]) => v)
          .map(([k, v]) => k + N + String(v))
          .join(N),
      )
      .z(2)
      .end(0);
  }
}

function parseError(x: Buffer): Notice {
  const error: Record<string, string> = {};
  let start = 5;
  for (let i = 5; i < x.length - 1; i++) {
    if (x[i] === 0) {
      error[FIELDS[x[start] as keyof typeof FIELDS]] = x.toString('utf8', start + 1, i);
      start = i + 1;
    }
  }
  return error;
}

function xor(a: Buffer, b: Buffer): Buffer {
  const length = Math.max(a.length, b.length);
  const buffer = Buffer.allocUnsafe(length);
  for (let i = 0; i < length; i++) buffer[i] = a[i]! ^ b[i]!;
  return buffer;
}

/** `fn`, `seconds` after each `start` unless cancelled; nothing at all for no seconds. */
function timer(fn: () => unknown, seconds: number | null | undefined | (() => number)): Timer {
  const s = typeof seconds === 'function' ? seconds() : seconds;
  if (!s) return { cancel: noop, start: noop };

  let handle: ReturnType<typeof setTimeout> | null = null;
  return {
    cancel() {
      if (handle) {
        clearTimeout(handle);
        handle = null;
      }
    },
    start() {
      if (handle) clearTimeout(handle);
      handle = setTimeout(() => {
        fn();
        handle = null;
      }, s * 1000);
    },
  };
}

/**
 * Whether an unnamed statement must learn its parameters' types before it
 * can send them. Strings, numbers and nulls go as text, typed by the server,
 * in the same flush as the statement, as libpq and node-postgres send them;
 * only an array or an object whose type is not known yet has a text that
 * depends on the type. porsager/postgres#1225
 */
function typedByServer(parameters: unknown[], types: number[]): boolean {
  return parameters.some((x, i) => !types[i] && x !== null && typeof x === 'object');
}
