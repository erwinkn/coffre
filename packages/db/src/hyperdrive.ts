import pg from 'pg';

import type { PoolLike } from './database.ts';
import { postgresConnection } from './postgres.ts';

/** Postgres through a Hyperdrive binding: `postgres(env.HYPERDRIVE)`. */
export type PostgresDatabase = { readonly engine: 'postgres'; readonly hyperdrive: { readonly connectionString: string } };

/** Postgres through Hyperdrive, the one database a Worker runs on, the app's and the vault's. */
export function postgres(hyperdrive: { readonly connectionString: string }): PostgresDatabase {
  if (typeof hyperdrive?.connectionString !== 'string') {
    throw new Error('postgres() takes the Hyperdrive binding, e.g. postgres(env.HYPERDRIVE)');
  }
  return { engine: 'postgres', hyperdrive };
}

/**
 * node-postgres for one call on Workers, through Hyperdrive: one client,
 * connected on the first query, which every query and transaction of the
 * call takes its turn on.
 *
 * Hyperdrive keeps the pool to the database; a Worker's connections belong
 * to the call that opened them, so each call opens its own. One, not one per
 * query: on Cloudflare, a call that opened several Hyperdrive connections at
 * once was now and then cancelled as hung, with nothing left pending, and
 * every connection costs a round trip before the query can be sent.
 *
 * The turns keep a transaction whole: queries go to the client in the order
 * they are asked, a transaction holds it from BEGIN until it is released,
 * and a query asked meanwhile waits until then, so nothing runs inside a
 * transaction it is not part of. So code inside a transaction must query
 * through the transaction: a query on the database there would wait for the
 * transaction to end, which waits for it. Neither the vault nor the server
 * does.
 *
 * The class name must end in `Pool`: that is how Drizzle knows to check out
 * a client for each transaction.
 */
export class HyperdrivePool implements Exclude<PoolLike, pg.Pool> {
  readonly #connectionString: string;
  /** The client, connecting or connected; null before the first query, and once it has failed. */
  #client: Promise<pg.Client> | null = null;
  /** Whether a transaction holds the client. */
  #held = false;
  /** What waits for its turn, in the order it asked. */
  readonly #waiting: (() => void)[] = [];
  /** Queries and transactions asked and not done: waiting for the client, their turn, or an answer. */
  #busy = 0;
  /** What waits for the client to be idle: `end`. */
  readonly #idle: (() => void)[] = [];

  constructor(connectionString: string) {
    if (connectionString.trim().length === 0) {
      throw new Error('Hyperdrive returned an empty connection string');
    }
    this.#connectionString = connectionString;
  }

  readonly query: pg.Pool['query'] = (async (...args: unknown[]) => {
    this.#busy += 1;
    try {
      const client = await this.#connected();
      return await new Promise((resolve, reject) => {
        // Sent at its turn, at once: pg answers its queries in the order they are sent.
        this.#turn(() => (client.query as (...queryArgs: unknown[]) => Promise<unknown>)(...args).then(resolve, reject));
      });
    } finally {
      this.#done();
    }
  }) as pg.Pool['query'];

  /** The client, for a transaction: held from now until `release`. */
  async connect(): Promise<Pick<pg.PoolClient, 'query'> & { release: () => void }> {
    this.#busy += 1;
    let client: pg.Client;
    try {
      client = await this.#connected();
    } catch (error) {
      this.#done();
      throw error;
    }
    await new Promise<void>((resolve) =>
      this.#turn(() => {
        this.#held = true;
        resolve();
      }),
    );
    let released = false;
    return {
      query: client.query.bind(client) as pg.PoolClient['query'],
      release: () => {
        if (released) return;
        released = true;
        this.#held = false;
        this.#next();
        this.#done();
      },
    };
  }

  /** Close the client once nothing waits on it: what a Worker hands `waitUntil` when the call is done. */
  async end(): Promise<void> {
    while (this.#busy > 0) {
      await new Promise<void>((resolve) => this.#idle.push(resolve));
    }
    const client = this.#client;
    this.#client = null;
    if (client === null) return;
    await client.then((connected) => connected.end()).catch(() => {});
  }

  /** Run `go` now if nothing holds the client or waits before it, otherwise at its turn. */
  #turn(go: () => void): void {
    if (!this.#held && this.#waiting.length === 0) go();
    else this.#waiting.push(go);
  }

  /** Give the next turns: queries until one is a transaction, which holds the client. */
  #next(): void {
    while (!this.#held && this.#waiting.length > 0) this.#waiting.shift()!();
  }

  /** One query or transaction done: once none is left, what waits for the client to be idle goes on. */
  #done(): void {
    this.#busy -= 1;
    if (this.#busy === 0) for (const resolve of this.#idle.splice(0)) resolve();
  }

  /** The call's client, connecting it the first time. One that fails is dropped: the next query connects again. */
  #connected(): Promise<pg.Client> {
    if (this.#client !== null) return this.#client;
    const client = new pg.Client(postgresConnection(this.#connectionString));
    const connecting: Promise<pg.Client> = client.connect().then(() => client);
    const drop = () => {
      if (this.#client === connecting) this.#client = null;
    };
    // A connection lost between queries: pg fails what was waiting on it, and the next query connects again.
    client.on('error', drop);
    client.on('end', drop);
    connecting.catch(drop);
    this.#client = connecting;
    return connecting;
  }
}
