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
 * Request-scoped node-postgres adapter for Hyperdrive.
 *
 * Hyperdrive owns the durable origin pool. The Worker creates edge clients
 * only inside one invocation, which prevents I/O objects from leaking across
 * Worker request contexts while keeping the Pool shape Drizzle expects. The
 * class name must end in `Pool`: that is how Drizzle knows to check out a
 * client for each transaction.
 */
export class HyperdrivePool implements Exclude<PoolLike, pg.Pool> {
  readonly #connectionString: string;

  constructor(connectionString: string) {
    if (connectionString.trim().length === 0) {
      throw new Error('Hyperdrive returned an empty connection string');
    }
    this.#connectionString = connectionString;
  }

  readonly query: pg.Pool['query'] = (async (...args: unknown[]) => {
    const client = await this.#connectClient();
    try {
      return await (client.query as (...queryArgs: unknown[]) => Promise<unknown>)(...args);
    } finally {
      await client.end();
    }
  }) as pg.Pool['query'];

  async connect(): Promise<Pick<pg.PoolClient, 'query'> & { release: () => void }> {
    const client = await this.#connectClient();
    let released = false;
    return {
      query: client.query.bind(client) as pg.PoolClient['query'],
      release: () => {
        if (released) return;
        released = true;
        client.end().catch(() => {});
      },
    };
  }

  async #connectClient(): Promise<pg.Client> {
    const client = new pg.Client(postgresConnection(this.#connectionString));
    await client.connect();
    return client;
  }
}
