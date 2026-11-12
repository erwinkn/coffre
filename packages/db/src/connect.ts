import { createDatabase, type Database } from './database.ts';
import { postgresClient } from './postgres.ts';

export { postgresClient, postgresOptions, postgresSession, quoteIdentifier, quoteLiteral, SessionLost, type ClientOptions, type PostgresClient } from './postgres.ts';

/**
 * Open a Postgres database from its URL, `postgres://…` or
 * `postgresql://…`, on a Node server: postgres.js, a pool of up to 10
 * connections. The Worker does not come through here; it builds its
 * database from the Hyperdrive pool with createDatabase. `max`, for a pool
 * of its own beside another, as the vault's checkpointer has (T169).
 * `lockWaitMs`: each transaction's lock waits (`createDatabase`).
 */
export async function openDatabase(url: string, options: { max?: number; lockWaitMs?: number } = {}): Promise<OpenDatabase> {
  checkDatabaseUrl(url);
  // As node-postgres's pool was: 10 connections, each closed after 10 s idle.
  const client = postgresClient(url, { max: options.max ?? 10, idle_timeout: 10 });
  return { db: createDatabase(client, { lockWaitMs: options.lockWaitMs }), close: () => client.end(), cut: () => client.end({ timeout: 0 }) };
}

/** `close` once what was asked has answered; `cut` at once, what is in flight failing (T169). */
export type OpenDatabase = { db: Database; close: () => Promise<void>; cut: () => Promise<void> };

/** Refuse a URL that names no Postgres database, before anything connects. */
export function checkDatabaseUrl(url: string): void {
  const scheme = url.slice(0, url.indexOf(':'));
  if (scheme === 'postgres' || scheme === 'postgresql') return;
  if (scheme === 'mysql') throw new Error('coffre supports Postgres; MySQL support was removed');
  throw new Error(`unsupported database URL scheme: ${scheme}:`);
}
