// postgres.js, coffre's own: the pool, its statements and transactions. See
// README.md beside this file for where it comes from and how it differs.
import { createConnection, type Connection, type Reservation, type Reserved } from './connection.ts';
import * as Errors from './errors.ts';
import { PostgresError, type Notice } from './errors.ts';
import type { Socket, TlsOptions } from './platform.ts';
import { Query } from './query.ts';
import { Queue } from './queue.ts';
import type { Column } from './result.ts';
import { defaultTypes, type Parsers, type Serializers } from './types.ts';

export { PostgresError, Query };
export type { Column, Notice, Socket };

/** What a client is opened with. Nothing is read from the environment: what is not given is the default named. */
export interface Options {
  /** Default `localhost`. */
  host?: string;
  /** Default 5432. */
  port?: number;
  /** A Unix socket's path, in place of `host` and `port`. */
  path?: string | undefined;
  /** Default the server's: the user's name. */
  database?: string | undefined;
  user?: string;
  pass?: string;
  /** TLS, with Node's options for it; default none. */
  ssl?: false | TlsOptions;
  /** `direct`: TLS from the first byte, with no SSLRequest (Postgres 17). */
  sslnegotiation?: 'direct' | null | undefined;
  /** Connections at most. Default 10. */
  max?: number;
  /** Statements sent on a connection before the first has answered. Default 100. */
  max_pipeline?: number;
  /** Seconds a connection may be idle before it closes. Default none. */
  idle_timeout?: number | null | undefined;
  /** Seconds a connection may take to open. Default 30. */
  connect_timeout?: number | null | undefined;
  /** Seconds a connection may live, or a function that says how many. Default 30 to 60 minutes. */
  max_lifetime?: number | null | (() => number);
  /** Seconds before a closed connection is opened again, by how many in a row closed with an error. */
  backoff?: number | ((retries: number) => number);
  /** Seconds of TCP keep-alive. Default 60. */
  keep_alive?: number | null;
  /** True to keep where each statement was made, for its error's stack, and its text on its error; or a function told each statement. */
  debug?: boolean | ((connection: number, query: string, parameters: unknown[], types: number[]) => void);
  /** Run-time parameters sent as each connection starts. Default `application_name` postgres.js. */
  connection?: Record<string, string | number | boolean | undefined>;
  /** Each notice Postgres sends. Default: logged. */
  onnotice?: (notice: Notice) => void;
  /** Each connection's close, by its id. */
  onclose?: (connectionId: number) => void;
  /** The stream to speak Postgres on, made for each connection, rather than a TCP socket to `host`. */
  socket?: () => Socket | Promise<Socket>;
}

/** A client's options, every one settled, and what it keeps beside them: `parsers` and `serializers`, which it may change. */
export interface Settings {
  host: string;
  port: number;
  path: string | undefined;
  database: string | undefined;
  user: string;
  pass: string;
  ssl: false | TlsOptions;
  sslnegotiation: 'direct' | null | undefined;
  max: number;
  max_pipeline: number;
  idle_timeout: number | null | undefined;
  connect_timeout: number | null | undefined;
  max_lifetime: number | null | undefined | (() => number);
  backoff: number | ((retries: number) => number);
  keep_alive: number | null | undefined;
  debug: boolean | ((connection: number, query: string, parameters: unknown[], types: number[]) => void);
  connection: Record<string, string | number | boolean | undefined>;
  onnotice: ((notice: Notice) => void) | undefined;
  onclose: ((connectionId: number) => void) | undefined;
  socket: (() => Socket | Promise<Socket>) | undefined;
  parsers: Parsers;
  serializers: Serializers;
  /** The server's run-time parameters, as its ParameterStatus messages said them. */
  parameters: Record<string, string>;
  /** What the pool's connections share: how many in a row closed with an error, which backs off reopening. */
  shared: { retries: number };
}

/** A row, by its columns' names: whatever a hand-written statement selects, as upstream types it. */
export type Row = Record<string, any>;

/** What a statement's CommandComplete said, beside its rows. */
export interface ResultMeta {
  /** Rows inserted, updated, deleted or returned; null for a command that counts none. */
  readonly count: number | null;
  readonly command: string;
  /** The backend that ran it: its process id and secret key, what a CancelRequest names. */
  readonly state: { readonly pid: number; readonly secret: number };
  readonly columns: Column[] | null;
}

/** A statement's rows, with what Postgres said of it. */
export type RowList<T extends readonly unknown[]> = T & ResultMeta;

/** A statement, sent once awaited or `execute`d. */
export type PendingQuery<T extends readonly unknown[]> = Query<RowList<T>>;

/** A transaction's statements, and its savepoints. */
export interface TransactionSql {
  unsafe<T extends readonly unknown[] = Row[]>(query: string, parameters?: unknown[], options?: { simple?: boolean }): PendingQuery<T>;
  /** A savepoint, rolled back to if `fn` fails. */
  savepoint<T>(fn: (sql: TransactionSql) => T | Promise<T>): Promise<Settled<T>>;
}

/** A connection held until `release()`. */
export interface ReservedSql {
  unsafe<T extends readonly unknown[] = Row[]>(query: string, parameters?: unknown[], options?: { simple?: boolean }): PendingQuery<T>;
  release(): void;
}

/** A pool of connections to Postgres. */
export interface Sql {
  /**
   * A statement: with `parameters`, the extended protocol, one round trip;
   * without, the simple one, unless `simple: false`.
   */
  unsafe<T extends readonly unknown[] = Row[]>(query: string, parameters?: unknown[], options?: { simple?: boolean }): PendingQuery<T>;
  /**
   * A transaction, on a connection held for it: BEGIN (`options` after it,
   * `isolation level serializable` and the like), `fn`, then COMMIT, or
   * ROLLBACK if `fn` fails, or a statement of it did that `fn` did not wait for.
   */
  begin<T>(fn: (sql: TransactionSql) => T | Promise<T>): Promise<Settled<T>>;
  begin<T>(options: string, fn: (sql: TransactionSql) => T | Promise<T>): Promise<Settled<T>>;
  /** A connection of the pool, held for the caller until it releases it. */
  reserve(): Promise<ReservedSql>;
  /** Close every connection once what it was sent has answered; after `timeout` seconds, at once. */
  end(options?: { timeout?: number | null }): Promise<void>;
  readonly options: Settings;
}

/** What a transaction's work answers: an array of promises, each awaited. */
export type Settled<T> = T extends readonly unknown[] ? { -readonly [K in keyof T]: Awaited<T[K]> } : Awaited<T>;

/** A pool of connections, opened as statements ask for them. */
export default function postgres(given: Options): Sql {
  const options = settle(given);

  let ending: Promise<void> | null = null;

  const queries = new Queue<Query | Reservation>();
  const connecting = new Queue<Connection>();
  const reserved = new Queue<Connection>();
  const closed = new Queue<Connection>();
  const ended = new Queue<Connection>();
  const open = new Queue<Connection>();
  const busy = new Queue<Connection>();
  const full = new Queue<Connection>();

  const connections = Array.from({ length: options.max }, () => createConnection(options, closed, { onopen, onend, onclose }));

  return {
    unsafe: unsafeOn(pooled),
    begin,
    reserve,
    end,
    options,
  };

  /** `unsafe`, sending each statement through `handler`. */
  function unsafeOn(handler: (query: Query) => void): Sql['unsafe'] {
    return (text, args = [], { simple = args.length === 0 } = {}) => new Query(text, args, handler, { simple }, Boolean(options.debug)) as never;
  }

  /** A connection of the pool's own, held until given back: `reserve`'s, and a transaction's. */
  async function hold(): Promise<Connection> {
    // Coffre: an ending client opens no connection again (onclose, below), not one to reserve either.
    if (ending) throw Errors.connection('CONNECTION_ENDED', options);
    // Coffre: the connection idle the shortest (queue.ts, pop), as for a query below.
    const c = open.length
      ? open.pop()!
      : await new Promise<Connection>((resolve, reject) => {
        // Coffre: what a connection opens for, given it once open (connection.ts, ReadyForQuery), or what waits for
        // one, never both: upstream did both, and a reservation taken from the queue to open a connection lost its.
        const query: Reservation = { reserve: resolve, reject };
        if (closed.length) connect(closed.shift()!, query);
        else queries.push(query);
      });
    return move(c, reserved);
  }

  /** `c`, held, given back to the pool. */
  function giveBack(c: Connection): void {
    c.reserved = null;
    // Coffre: given back once the client is ending, the connection ends, which end() waits for; upstream gave it back.
    if (ending) c.terminate();
    else onopen(c);
  }

  async function reserve(): Promise<ReservedSql> {
    const queue = new Queue<Query>();
    const c = await hold();
    c.reserved = { next: () => (queue.length ? c.execute(queue.shift()!) : move(c, reserved)), untilReleased: true };

    return {
      unsafe: unsafeOn(onReserved),
      release: () => giveBack(c),
    };

    /** A statement on the connection held: sent, or queued until the connection can take more. */
    function onReserved(q: Query): void {
      if (c.queue === full) queue.push(q);
      else if (!c.execute(q)) move(c, full);
    }
  }

  async function begin<T>(...args: [fn: (sql: TransactionSql) => T | Promise<T>] | [options: string, fn: (sql: TransactionSql) => T | Promise<T>]): Promise<Settled<T>> {
    const [mode, fn] = args.length === 1 ? ['', args[0]] : args;
    const queries = new Queue<Query>();
    let savepoints = 0;
    /** The transaction's first statement, which carries its BEGIN (`toBuffer`, connection.ts), once asked. */
    let first: Query | null = null;
    /**
     * Why nothing more of the transaction is sent, which would run outside it: its BEGIN failed, its connection closed,
     * or it has ended, and its connection is the pool's again (what its work left running may still ask).
     */
    let stopped: Error | null = null;
    const stop = (error: Error) => {
      stopped ??= error;
      while (queries.length) queries.shift()!.reject(stopped);
    };

    // Coffre: the transaction holds its connection from its first statement, BEGIN with it, until it has ended, and
    // gives it back then. Upstream sent BEGIN alone, waited for it, and gave the connection back once Postgres said it
    // was idle, which a BEGIN that failed would also have said, its transaction still running.
    const c = await hold();
    const mine: Reserved = {
      next: () => {
        if (first !== null && !first.began) {
          stop(Errors.generic('TRANSACTION_NOT_BEGUN', 'The transaction did not begin, so its statements were not sent'));
          return void move(c, reserved);
        }
        // What waited for the BEGIN goes at once, as many as the connection pipelines; upstream sent one an answer.
        move(c, reserved);
        while (queries.length) if (!c.execute(queries.shift()!)) return void move(c, full);
      },
      untilReleased: true,
    };
    c.reserved = mine;
    try {
      return await Promise.race([
        scope(fn),
        new Promise<never>((_, reject) => (c.onclose = (error) => {
          stop(error);
          reject(error);
        })),
      ]);
    } finally {
      stop(Errors.generic('TRANSACTION_ENDED', 'The transaction has ended, so the statement was not sent'));
      c.onclose = null;
      // Closed meanwhile, the connection is the pool's again already.
      if (c.reserved === mine) giveBack(c);
    }

    async function scope<R>(fn: (sql: TransactionSql) => R | Promise<R>, name?: string): Promise<Settled<R>> {
      let uncaughtError: unknown;
      let result: Settled<R>;
      const sql: TransactionSql = {
        unsafe: unsafeOn(inTransaction),
        savepoint: (fn) => scope(fn, 's' + savepoints++),
      };
      // The transaction's own statements, sent as the simple protocol's, as a statement with no parameters is.
      const own = (text: string) => sql.unsafe(text);

      if (name) await own('savepoint ' + quote(name));
      try {
        result = await new Promise<Settled<R>>((resolve, reject) => {
          const x = fn(sql);
          Promise.resolve(Array.isArray(x) ? Promise.all(x) : x).then(resolve as (value: unknown) => void, reject);
        });

        if (uncaughtError) throw uncaughtError;
      } catch (e) {
        // A transaction that never began has nothing to roll back: none asked of it, or its BEGIN failed; nor one whose
        // connection closed, which Postgres rolled back.
        if (!name) await first?.catch(() => {});
        if (!stopped && (name || first?.began)) await own(name ? 'rollback to ' + quote(name) : 'rollback');
        throw (e instanceof PostgresError && e.code === '25P02' && uncaughtError) || e;
      }

      if (!name && first !== null) await own('commit');

      return result;

      /** A statement of the transaction's: one that fails and is not waited for fails the transaction all the same. */
      function inTransaction(q: Query): void {
        q.catch((e: unknown) => uncaughtError || (uncaughtError = e));
        if (stopped) return q.reject(stopped);
        if (first === null) {
          first = q;
          q.begin = 'begin ' + mode.replace(/[^a-z ]/gi, '');
        }
        // Nothing follows the BEGIN until Postgres has answered it, whatever execute says: a statement that failed to
        // be written, its BEGIN with it, has the next wait all the same, to be refused.
        if (c.queue === full) queries.push(q);
        else if (!c.execute(q) || q === first) move(c, full);
      }
    }
  }

  function move(c: Connection, queue: Queue<Connection>): Connection {
    c.queue.remove(c);
    queue.push(c);
    c.queue = queue;
    if (queue === open) c.idleTimer.start();
    else c.idleTimer.cancel();
    return c;
  }

  /** A statement of the pool's: sent on an open connection, one opened for it, a busy one, or queued for the first free. */
  function pooled(query: Query): void {
    if (ending) return query.reject(Errors.connection('CONNECTION_ENDED', options));

    // Coffre: the connection idle the shortest, as pg-pool takes it; upstream took the one idle the longest.
    if (open.length) return void go(open.pop()!, query);

    if (closed.length) return void connect(closed.shift()!, query);

    if (busy.length) go(busy.shift()!, query);
    else queries.push(query);
  }

  function go(c: Connection, query: Query): Connection {
    return c.execute(query) ? move(c, busy) : move(c, full);
  }

  async function end({ timeout = null }: { timeout?: number | null } = {}): Promise<void> {
    if (ending) return ending;

    // What is asked in this tick is still served, and waited for.
    await null;
    let timer: ReturnType<typeof setTimeout> | undefined;
    return (ending = Promise.race([
      new Promise<void>((resolve) => {
        if (timeout !== null) timer = setTimeout(() => void destroy(resolve), timeout * 1000);
      }),
      Promise.all(connections.map((c) => c.end())).then(() => undefined),
    ]).then(() => clearTimeout(timer)));
  }

  async function destroy(resolve: () => void): Promise<void> {
    await Promise.all(connections.map((c) => c.terminate()));
    while (queries.length) queries.shift()!.reject(Errors.connection('CONNECTION_DESTROYED', options));
    resolve();
  }

  function connect(c: Connection, query: Query | Reservation): Connection {
    move(c, connecting);
    c.connect(query);
    return c;
  }

  function onend(c: Connection): void {
    move(c, ended);
  }

  function onopen(c: Connection): void {
    if (queries.length === 0) return void move(c, open);

    let max = Math.ceil(queries.length / (connecting.length + 1));
    let ready = true;

    while (ready && queries.length && max-- > 0) {
      const query = queries.shift()!;
      if ('reserve' in query) return query.reserve(c);

      ready = c.execute(query);
    }

    if (ready) move(c, busy);
    else move(c, full);
  }

  function onclose(c: Connection, e: Error): void {
    move(c, closed);
    c.reserved = null;
    if (c.onclose) {
      c.onclose(e);
      c.onclose = null;
    }
    options.onclose?.(c.id);
    // Coffre: once the client is ending, what waits for a connection fails, as what it asks next does; upstream opened
    // the connection again for it, after end() had answered, and no end() could close that one.
    if (ending) {
      while (queries.length) queries.shift()!.reject(Errors.connection('CONNECTION_ENDED', options));
      return;
    }
    if (queries.length) connect(c, queries.shift()!);
  }
}

/** `options`, each one not given at its default. */
function settle(options: Options): Settings {
  return {
    host: options.host ?? 'localhost',
    port: options.port ?? 5432,
    path: options.path,
    database: options.database,
    user: options.user ?? '',
    pass: options.pass ?? '',
    ssl: options.ssl ?? false,
    sslnegotiation: options.sslnegotiation,
    max: options.max ?? 10,
    max_pipeline: options.max_pipeline ?? 100,
    idle_timeout: options.idle_timeout,
    connect_timeout: 'connect_timeout' in options ? options.connect_timeout : 30,
    max_lifetime: 'max_lifetime' in options ? options.max_lifetime : () => 60 * (30 + Math.random() * 30),
    backoff: options.backoff ?? ((retries) => (0.5 + Math.random() / 2) * Math.min(3 ** retries / 100, 20)),
    keep_alive: 'keep_alive' in options ? options.keep_alive : 60,
    debug: options.debug ?? false,
    connection: { application_name: 'postgres.js', ...options.connection },
    onnotice: options.onnotice,
    onclose: options.onclose,
    socket: options.socket,
    ...defaultTypes(),
    parameters: {},
    shared: { retries: 0 },
  };
}

/** `name` as an identifier, quoted. */
function quote(name: string): string {
  return '"' + name.replace(/"/g, '""').replace(/\./g, '"."') + '"';
}
