// How many connections each of coffre's logins may hold open to Postgres,
// out of what the database lets in: one rule on both runtimes
// (docs/design/config.md, Q2 and Q3). `coffre setup` gives each Hyperdrive
// config its share; on Node, each process reads the same numbers as it starts
// and sizes its pools to it; the vault holds the reads waiting for the log's
// head to what its connections leave free. Nothing here is set by a deployment.
import { RUNTIME_STATEMENT_TIMEOUT_MS } from '@coffre/core/vault';
import { sql } from 'drizzle-orm';

import type { Queryable } from './database.ts';
import { engineOf, rowsOf } from './dialect.ts';

/** What the database lets in: `max_connections`, and the slots it reserves for superusers and `pg_use_reserved_connections`. */
export type Connections = { max: number; reserved: number };

/** coffre's runtime logins, each with a pool or a Hyperdrive config of its own: the app's, the vault's, and the vault's hot path's. */
export const LOGINS = 3;

/**
 * Connections the logins' shares leave free, for what connects outside them,
 * each counted at its most at once:
 *
 *   a deploy's migrations   2   `coffre migrate` holds one session (`postgresMigrator`); with Workers Builds both
 *                               Workers' builds run it, at once, the second waiting on its own session for the
 *                               first's lock (docs/deploy.md, "Workers Builds")
 *   a backup                2   `coffre backup`'s session, which holds the snapshot, and pg_dump reading in it
 *
 * An administrator's own session, a superuser's, takes a slot the database
 * reserves (`reserved`, counted apart); on a host whose administrator is no
 * superuser, it shares these.
 */
export const HELD_BACK = 2 + 2;

/** The vault checkpointer's pool on Node, a pool of its own beside the vault's, which it cuts once it stalls (T169). */
export const CHECKPOINTER_CONNECTIONS = 2;

/**
 * The vault's connections the reads waiting for the log's head leave free
 * (`headWaiters`): one for the writer that holds the head, which every waiter
 * waits on, so that it can commit and let them through; one for a call that
 * needs no head, so that the vault answers it meanwhile.
 */
export const LEFT_BESIDE_WAITERS = 2;

/** The fewest connections Hyperdrive takes per config, and the most its Free plan allows (Hyperdrive's limits). */
export const HYPERDRIVE_CONNECTIONS = { fewest: 5, most: 20 } as const;

/**
 * The smallest share coffre runs on: Hyperdrive's fewest for a config on
 * Workers, and on Node, the vault's, whose share holds the checkpointer's
 * pool and a request pool with one place in line for the head and the
 * connections the waiters leave free. Both are 5.
 */
export const FEWEST = Math.max(HYPERDRIVE_CONNECTIONS.fewest, CHECKPOINTER_CONNECTIONS + 1 + LEFT_BESIDE_WAITERS);

/** Each login's even share of what the database lets coffre's logins open, less what is held back. */
export function share({ max, reserved }: Connections): number {
  return Math.floor((max - reserved - HELD_BACK) / LOGINS);
}

/** The `max_connections` a database needs for coffre's logins each to have the fewest connections it runs on, `reserved` as it reserves. */
export function connectionsNeeded(reserved: number): number {
  return LOGINS * FEWEST + HELD_BACK + reserved;
}

/**
 * Each of a Node deployment's pools, out of the share each login has: the
 * app's process takes the app's, the vault's process the vault's and the hot
 * path's, the checkpointer's pool out of the vault's. Null below `FEWEST`.
 *
 *   max_connections 100, 3 reserved: share 31, app 31, hot path 31, vault 29, checkpointer 2
 *   max_connections 25, 3 reserved:  share 6,  app 6,  hot path 6,  vault 4,  checkpointer 2
 */
export function nodePools(connections: Connections): { app: number; hot: number; vault: number; checkpointer: number } | null {
  const each = share(connections);
  if (each < FEWEST) return null;
  return { app: each, hot: each, vault: each - CHECKPOINTER_CONNECTIONS, checkpointer: CHECKPOINTER_CONNECTIONS };
}

/**
 * The connections the vault answers requests on, as `coffre setup` sizes its
 * Hyperdrive config: the share, at most Free's most. On Node its pool is
 * the share less the checkpointer's (`nodePools`), which the vault is told.
 */
export function hyperdriveConnections(connections: Connections): number {
  return Math.min(share(connections), HYPERDRIVE_CONNECTIONS.most);
}

/** Why a database letting in `connections` is too small for coffre's logins: what it needs, and what to do. */
export function tooFewConnections(connections: Connections, { workers }: { workers: boolean }): string {
  const needs = workers
    ? `Hyperdrive takes at least ${FEWEST} for each of coffre's three configs, and setup keeps`
    : `coffre needs at least ${FEWEST} for each of its three logins' pools, and keeps`;
  return (
    `the database's max_connections is ${connections.max}, ${connections.reserved} of them reserved; ${needs} ${HELD_BACK} for migrations and backups: ` +
    `raise max_connections to ${connectionsNeeded(connections.reserved)} or more, or move to a larger plan`
  );
}

/**
 * The connections, and the statement timeout this login runs with, in
 * milliseconds (Postgres's 0 for none): one plain read, which a vault's or
 * an app's first reads ask beside theirs, adding no round trip (T206).
 * `reserved_connections` is Postgres 16's, and none before.
 */
export const DATABASE_FACTS = `SELECT current_setting('max_connections')::int AS max,
       current_setting('superuser_reserved_connections')::int
         + coalesce(current_setting('reserved_connections', true), '0')::int AS reserved,
       (SELECT setting::int FROM pg_settings WHERE name = 'statement_timeout') AS statement_ms,
       current_user AS login`;

export type DatabaseFacts = { connections: Connections; statementMs: number; login: string };

/** `DATABASE_FACTS`, read through `db`: null on SQLite, which has no connections to share and no statement timeout. */
export async function databaseFacts(db: Queryable): Promise<DatabaseFacts | null> {
  if (engineOf(db) !== 'postgres') return null;
  const [row] = await rowsOf<{ max: number; reserved: number; statement_ms: number; login: string }>(db, sql.raw(DATABASE_FACTS));
  return { connections: { max: Number(row!.max), reserved: Number(row!.reserved) }, statementMs: Number(row!.statement_ms), login: row!.login };
}

/**
 * What to log when a runtime login runs without the ceiling
 * (`RUNTIME_STATEMENT_TIMEOUT_MS`): none at all, or a longer one. Null when
 * it has it, or a shorter one of its administrator's.
 *
 *   coffre_runtime runs with no statement_timeout: a stuck statement holds its connection until it ends, or
 *   Hyperdrive gives up at 60 s. Have a login with CREATEROLE and ADMIN on it run ALTER ROLE coffre_runtime SET
 *   statement_timeout = '5s' (docs/deploy.md, "Statement timeouts").
 */
export function unboundedStatements({ statementMs, login }: Pick<DatabaseFacts, 'statementMs' | 'login'>): string | null {
  if (statementMs > 0 && statementMs <= RUNTIME_STATEMENT_TIMEOUT_MS) return null;
  const now = statementMs === 0 ? 'no statement_timeout' : `a statement_timeout of ${statementMs} ms`;
  return (
    `${login} runs with ${now}: a stuck statement holds its connection until it ends, or Hyperdrive gives up at 60 s. ` +
    `Have a login with CREATEROLE and ADMIN on it run ALTER ROLE ${quoteName(login)} SET statement_timeout = '${RUNTIME_STATEMENT_TIMEOUT_MS / 1000}s' ` +
    '(docs/deploy.md, "Statement timeouts")'
  );
}

function quoteName(name: string): string {
  return /^[a-z_][a-z0-9_$]*$/.test(name) ? name : `"${name.replaceAll('"', '""')}"`;
}

/** A Node process refused at its start: the database is too small for coffre's pools (`nodePools`). */
export class TooFewConnections extends Error {
  readonly connections: Connections;

  constructor(connections: Connections) {
    super(`coffre cannot start: ${tooFewConnections(connections, { workers: false })}`);
    this.name = 'TooFewConnections';
    this.connections = connections;
  }
}
