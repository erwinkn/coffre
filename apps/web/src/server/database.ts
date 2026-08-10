import pg from 'pg';

export type DatabaseClient = Pick<pg.PoolClient, 'query'> & {
  release: () => void | Promise<void>;
};

export type Database = Pick<pg.Pool, 'query'> & {
  connect: () => Promise<DatabaseClient>;
};

/** Convert node-postgres timestamp values at the service boundary. */
export function toIsoTimestamp(value: string | Date): string {
  const timestamp = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(timestamp.getTime())) throw new Error('database returned an invalid timestamp');
  return timestamp.toISOString();
}

export function toNullableIsoTimestamp(value: string | Date | null): string | null {
  return value === null ? null : toIsoTimestamp(value);
}

/**
 * Request-scoped node-postgres adapter for Hyperdrive.
 *
 * Hyperdrive owns the durable origin pool. The Worker creates edge clients
 * only inside one invocation, which prevents I/O objects from leaking across
 * Worker request contexts while preserving the Pool-shaped contract used by
 * the service layer.
 */
export class HyperdriveDatabase implements Database {
  readonly #connectionString: string;

  constructor(connectionString: string) {
    if (connectionString.trim().length === 0) {
      throw new Error('Hyperdrive returned an empty connection string');
    }
    this.#connectionString = connectionString;
  }

  readonly query: Database['query'] = (async (...args: unknown[]) => {
    const client = await this.#connectClient();
    try {
      return await (client.query as (...queryArgs: unknown[]) => Promise<unknown>)(...args);
    } finally {
      await client.end();
    }
  }) as Database['query'];

  async connect(): Promise<DatabaseClient> {
    const client = await this.#connectClient();
    let released = false;

    return {
      query: client.query.bind(client),
      release: async () => {
        if (released) return;
        released = true;
        await client.end();
      },
    };
  }

  async #connectClient(): Promise<pg.Client> {
    const client = new pg.Client({ connectionString: this.#connectionString });
    await client.connect();
    return client;
  }
}
