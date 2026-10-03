import pg from 'pg';

/** Bound broken connections and blocked SQL in tests, including the vault's pool. */
export function testPostgresPool(connectionString: string, allowExitOnIdle = false): pg.Pool {
  return new pg.Pool({
    connectionString,
    allowExitOnIdle,
    connectionTimeoutMillis: 5_000,
    query_timeout: 10_000,
    statement_timeout: 10_000,
  });
}
