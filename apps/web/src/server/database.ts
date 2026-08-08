import pg from 'pg';

export type DatabaseClient = Pick<pg.PoolClient, 'query' | 'release'>;

export type Database = Pick<pg.Pool, 'query'> & {
  connect: () => Promise<DatabaseClient>;
};

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
  #queryClient: pg.Client | undefined;
  #queryClientReady: Promise<pg.Client> | undefined;

  constructor(connectionString: string) {
    if (connectionString.trim().length === 0) {
      throw new Error('Hyperdrive returned an empty connection string');
    }
    this.#connectionString = connectionString;
  }

  readonly query: Database['query'] = (async (...args: unknown[]) => {
    const client = await this.#defaultClient();
    return (client.query as (...queryArgs: unknown[]) => Promise<unknown>)(...args);
  }) as Database['query'];

  async connect(): Promise<DatabaseClient> {
    const client = new pg.Client({ connectionString: this.#connectionString });
    await client.connect();

    return {
      query: client.query.bind(client),
      // Hyperdrive releases the edge client when the invocation finishes and
      // retains the origin connection in its own pool. Service code still
      // calls release() to delimit transaction ownership.
      release: () => {},
    };
  }

  async #defaultClient(): Promise<pg.Client> {
    this.#queryClient ??= new pg.Client({ connectionString: this.#connectionString });
    this.#queryClientReady ??= this.#queryClient.connect();
    await this.#queryClientReady;
    return this.#queryClient;
  }
}
