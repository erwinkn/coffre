import pg from 'pg';

import { createDatabase, type Database } from './database.ts';
import { postgresConnection } from './postgres.ts';

export { postgresConnection } from './postgres.ts';

/**
 * Open a Postgres database from its URL, `postgres://…` or
 * `postgresql://…`, on a Node server: node-postgres. The Worker does not
 * come through here; it builds its database from the Hyperdrive pool with
 * createDatabase.
 */
export async function openDatabase(url: string): Promise<OpenDatabase> {
  checkDatabaseUrl(url);
  const pool = new pg.Pool(postgresConnection(url));
  return { db: createDatabase(pool), close: () => pool.end() };
}

export type OpenDatabase = { db: Database; close: () => Promise<void> };

/** Refuse a URL that names no Postgres database, before anything connects. */
export function checkDatabaseUrl(url: string): void {
  const scheme = url.slice(0, url.indexOf(':'));
  if (scheme === 'postgres' || scheme === 'postgresql') return;
  if (scheme === 'mysql') throw new Error('coffre supports Postgres; MySQL support was removed');
  throw new Error(`unsupported database URL scheme: ${scheme}:`);
}
