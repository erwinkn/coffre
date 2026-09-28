import pg from 'pg';

import type { PoolLike } from '../../../../packages/db/src/database.ts';

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
    const client = new pg.Client({ connectionString: this.#connectionString });
    await client.connect();
    return client;
  }
}
