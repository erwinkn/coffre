import type { Client } from './database.ts';
import { postgresClient, textTypes, type PostgresClient } from './postgres.ts';

/** Postgres through a Hyperdrive binding: `postgres(env.HYPERDRIVE)`. */
export type PostgresDatabase = { readonly engine: 'postgres'; readonly hyperdrive: { readonly connectionString: string } };

/** Postgres through Hyperdrive, the one database a Worker runs on, the app's and the vault's. */
export function postgres(hyperdrive: { readonly connectionString: string }): PostgresDatabase {
  if (typeof hyperdrive?.connectionString !== 'string') {
    throw new Error('postgres() takes the Hyperdrive binding, e.g. postgres(env.HYPERDRIVE)');
  }
  return { engine: 'postgres', hyperdrive };
}

/** A statement asked of the pool, sent at its turn once awaited or `execute`d, as postgres.js sends one. */
type Statement = Promise<unknown> & { values(): Statement; execute(): Statement };

/**
 * postgres.js for one call on Workers, through Hyperdrive: one connection,
 * opened by the first query, which every query and transaction of the
 * call takes its turn on.
 *
 * Hyperdrive keeps the pool to the database; a Worker's connections belong
 * to the call that opened them, so each call opens its own. One, not one per
 * query: on Cloudflare, a call that opened several Hyperdrive connections at
 * once was now and then cancelled as hung, with nothing left pending, and
 * every connection costs a round trip before the query can be sent.
 *
 * The turns keep a transaction whole: statements go to the connection in
 * the order they are asked, each once the one before it has answered; a
 * transaction holds the connection from BEGIN until it ends, and a query
 * asked meanwhile waits until then, so nothing runs inside a transaction it
 * is not part of. So code inside a transaction must query through the
 * transaction: a query on the database there would wait for the transaction
 * to end, which waits for it. Neither the vault nor the server does.
 *
 * Closed by `end`, once what was asked has answered; asked again after, as
 * a call's background work may, it opens a connection again.
 */
export class HyperdrivePool implements Client {
  readonly #connectionString: string;
  /** How long the connection may sit idle before it closes, or undefined: closed by `end` alone. */
  readonly #closeIdleMs: number | undefined;
  /** The client, made by the first statement; null before it, and once `end` closed it. */
  #client: PostgresClient | null = null;
  /** The end of the last turn asked: the next one starts once it has. */
  #tail: Promise<unknown> = Promise.resolve();
  /** Turns asked and not done: waiting, or under way. */
  #busy = 0;
  /** What waits for every turn to be done: `end`. */
  readonly #idle: (() => void)[] = [];

  /**
   * `closeIdleMs`: for what outlives a call, a Durable Object, which queries
   * now and then: the connection closes once it has been idle that long,
   * and the next query connects again.
   */
  constructor(connectionString: string, options: { closeIdleMs?: number } = {}) {
    if (connectionString.trim().length === 0) {
      throw new Error('Hyperdrive returned an empty connection string');
    }
    this.#connectionString = connectionString;
    this.#closeIdleMs = options.closeIdleMs;
  }

  readonly unsafe = ((...args: Parameters<PostgresClient['unsafe']>) => {
    let values = false;
    let answer: Promise<unknown> | undefined;
    /** Its turn, asked once: the first `then`, `catch`, `finally` or `execute` asks it. */
    const asked = () =>
      (answer ??= this.#turn(() => {
        const query = this.#connected().unsafe(...args);
        return values ? query.values() : query;
      }));
    const statement = {
      values: () => {
        values = true;
        return statement;
      },
      execute: () => {
        void asked().catch(() => {});
        return statement;
      },
      then: (resolve?: (value: unknown) => unknown, reject?: (error: unknown) => unknown) => asked().then(resolve, reject),
      catch: (reject: (error: unknown) => unknown) => asked().catch(reject),
      finally: (done: () => void) => asked().finally(done),
      [Symbol.toStringTag]: 'Statement',
    } as Statement;
    return statement;
  }) as unknown as PostgresClient['unsafe'];

  /** A transaction: its turn lasts until it has committed or rolled back. */
  readonly begin = ((...args: unknown[]) =>
    this.#turn(() => (this.#connected().begin as (...beginArgs: unknown[]) => Promise<unknown>)(...args))) as PostgresClient['begin'];

  /** Close the connection once every turn asked is done: what a Worker hands `waitUntil` when the call is done. */
  async end(): Promise<void> {
    // A statement awaited just before reaches the pool a few promise steps later, through Drizzle's session: a task
    // later, every one has taken its turn, and none opens a connection that this would leave open.
    await new Promise((resolve) => setTimeout(resolve, 0));
    while (this.#busy > 0) {
      await new Promise<void>((resolve) => this.#idle.push(resolve));
    }
    const client = this.#client;
    this.#client = null;
    await client?.end().catch(() => {});
  }

  /** `go` once every turn asked before it is done. */
  #turn<T>(go: () => PromiseLike<T>): Promise<T> {
    this.#busy += 1;
    const answer = this.#tail.then(go);
    this.#tail = answer.then(
      () => this.#done(),
      () => this.#done(),
    );
    return answer;
  }

  /** One turn done: once none is left, what waits for the pool to be idle goes on. */
  #done(): void {
    this.#busy -= 1;
    if (this.#busy === 0) for (const resolve of this.#idle.splice(0)) resolve();
  }

  /** The call's client, made the first time. postgres.js opens its connection again when one is lost. */
  #connected(): PostgresClient {
    this.#client ??= textTypes(postgresClient(this.#connectionString, {
      max: 1,
      idle_timeout: this.#closeIdleMs === undefined ? undefined : this.#closeIdleMs / 1000,
      // No timer left to outlive the call: `end` closes the connection, or idling does.
      max_lifetime: null,
    }));
    return this.#client;
  }
}
