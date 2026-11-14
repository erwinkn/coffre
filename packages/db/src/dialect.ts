import { TOMBSTONE } from '@coffre/core/schemas';
import { sql, type SQL, type SQLWrapper } from 'drizzle-orm';

import { sentPrepared, type Queryable } from './database.ts';

/** Postgres's ways, in one place: the queries use these rather than spell them out. */

/**
 * The rows a hand-written query answers, as the driver gives them. Column
 * names are the query's own, unmapped.
 *
 * With `prepare`, for a read sent on every call with new values (a use's),
 * the statement goes prepared by name rather than unnamed, which Postgres
 * parses and plans again each time it runs. A name is its text's, the same
 * from every connection, so a pooler that keeps statements prepared on its
 * own connections to the database (Hyperdrive, and PgBouncer with
 * `max_prepared_statements`) has Postgres parse it once on each, and,
 * after its first five runs, plan it no more where the plan for any values
 * costs no more than the plans for each (Postgres's own choice, by default).
 * On Workers a call's connection is new, so the client sends the Parse each
 * time, with the rest, under the same Sync: no round trip more. Only for a
 * query whose text is one of a few: a pooler keeps a bounded number per
 * connection, so a text that varies by what was asked would push the others
 * out. A pooler that passes named statements through to whichever
 * connection it gives (PgBouncer in transaction mode without
 * `max_prepared_statements`) fails the second client's Parse there (42P05):
 * coffre connects to Postgres directly or through Hyperdrive. Not in a
 * transaction, whose statements go unnamed (`sentPrepared`, database.ts).
 */
export async function rowsOf<Row>(db: Queryable, query: SQL, { prepare = false }: { prepare?: boolean } = {}): Promise<Row[]> {
  const rows = async () => [...(await (db as unknown as { execute(query: SQL): Promise<Row[]> }).execute(query))];
  return prepare ? sentPrepared(rows) : rows();
}

/** A tombstone's slug, `@coffre/core/schemas`'s `isTombstone` in SQL. No LIKE wildcard is a `~`. */
export function tombstone(slug: SQLWrapper): SQL {
  return sql`${slug} LIKE ${`%${TOMBSTONE}%`}`;
}

/** A condition read as a boolean. */
export function truth(condition: SQL): SQL<boolean> {
  return condition.mapWith((value) => Number(value) === 1);
}

/** How many rows an insert, update or delete touched. */
export function changedRows(result: unknown): number {
  return (result as { count?: number | null }).count ?? 0;
}

/**
 * The network's codes for a server that is not there, postgres.js's for a
 * connection lost, cut short or never made, and Postgres's for one that will
 * not take the connection, or has none left (53300).
 */
const UNREACHABLE = new Set([
  'ECONNREFUSED', 'ECONNRESET', 'ETIMEDOUT', 'ENOTFOUND', 'EAI_AGAIN', 'EHOSTUNREACH', 'ENETUNREACH', 'EPIPE',
  'CONNECTION_CLOSED', 'CONNECTION_DESTROYED', 'CONNECTION_ENDED', 'CONNECT_TIMEOUT',
  '53300', '57P01', '57P02', '57P03',
]);

/** Hyperdrive's words for having no connection to give, beside Workers' for one lost. */
const UNREACHABLE_WORDS = /connection terminated|network connection lost|connect(ion)? timeout|open slot in the pool|acquire a connection from the pool|server connection attempt failed/i;

/**
 * Whether a query failed because the database could not be reached or
 * dropped the connection: an outage, not an answer. Postgres's connection
 * exceptions are class 08; postgres.js says so in codes of its own, Workers'
 * sockets in words, and so
 * does Hyperdrive when it has no connection to the database to give: every
 * one of its pool busy for 15 s ("Timed out while waiting for an open slot
 * in the pool", FATAL 58000; "Failed to acquire a connection from the
 * pool"), or none to be made ("Server connection attempt failed:
 * destination_unavailable").
 */
export function isUnreachable(error: unknown): boolean {
  for (let cause = error; typeof cause === 'object' && cause !== null; ) {
    const { code, message } = cause as { code?: unknown; message?: unknown };
    // Class 08 but its protocol violation (08P01), which is the client's bug: asked again, it fails again.
    if (typeof code === 'string' && (UNREACHABLE.has(code) || (/^08[0-9A-Z]{3}$/.test(code) && code !== '08P01'))) return true;
    // The words only of what said no code, or Hyperdrive's 58000, and never a message quoting a query and its
    // parameters (Drizzle's, the Node vault's carrying it): the driver's words are its cause's.
    if (typeof message === 'string' && (typeof code !== 'string' || code === '58000') && !message.includes('Failed query: ') && UNREACHABLE_WORDS.test(message)) return true;
    cause = (cause as { cause?: unknown }).cause;
  }
  return false;
}

/** Postgres's codes for a statement that gave up waiting: on a lock (55P03), or past its own bound (57014). */
const GAVE_UP = new Set(['55P03', '57014']);

/** Postgres's code for a statement that gave up waiting, when `error` or a cause of it is one. */
export function gaveUpCode(error: unknown): string | undefined {
  for (let cause = error; typeof cause === 'object' && cause !== null; cause = (cause as { cause?: unknown }).cause) {
    const { code } = cause as { code?: unknown };
    if (typeof code === 'string' && GAVE_UP.has(code)) return code;
  }
  return undefined;
}

/**
 * Whether a statement gave up waiting, on a lock or past its bound: the
 * database too busy to answer in time, or a transaction held too long,
 * which a bug may be (one held across a vault call waits on the vault's
 * decision, which waits on it).
 */
export function gaveUp(error: unknown): boolean {
  return gaveUpCode(error) !== undefined;
}

/**
 * Whether a query failed for want of the database, not for anything the
 * request asked: it could not be reached (`isUnreachable`), or a statement
 * gave up waiting (`gaveUp`). The same request may well succeed in a moment.
 */
export function isUnavailable(error: unknown): boolean {
  return isUnreachable(error) || gaveUp(error);
}

/** A consistent read of several statements that cannot write, such as verifying the chain. */
export const SNAPSHOT = { isolationLevel: 'repeatable read', accessMode: 'read only' } as const;

/**
 * The database clock as text, for canonicalTimestamp. Entries from several
 * servers order by it, so it is never an application server's.
 */
export function clock(db: Queryable): SQL<string> {
  return sql<string>`CURRENT_TIMESTAMP`;
}

/**
 * The database clock as milliseconds since the epoch, as the statement runs:
 * Postgres's `clock_timestamp()`, not `CURRENT_TIMESTAMP`, which is the
 * transaction's start and would date an entry that waited for the log's lock
 * before one written while it waited. Read it in a statement after the lock.
 */
export function clockMillis(db: Queryable): SQL<number> {
  return sql`(extract(epoch from clock_timestamp()) * 1000)::bigint`.mapWith(Number);
}

/**
 * Whether a timestamp column is still ahead of the database clock as the
 * statement runs: a condition, for a write that must not land once the
 * time it names has passed.
 */
export function ahead(db: Queryable, column: SQLWrapper): SQL {
  return sql`${column} > clock_timestamp()`;
}

/**
 * The migrator's own ledger, read by readiness to tell a database that is
 * up but not yet migrated from one that is ready. Drizzle keeps it in a
 * `drizzle` schema.
 */
export function migrationLedger(db: Queryable): SQL {
  return sql`${sql.identifier('drizzle')}.${sql.identifier('__drizzle_migrations')}`;
}

const TIMESTAMP =
  /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?(Z|[+-]\d{2}(?::?\d{2})?)?$/;

/**
 * The one rendering of a timestamp read as text: UTC, microseconds, `Z`.
 *
 * The audit chain covers occurred_at as text, so reading a row back has to
 * reproduce it byte for byte. Databases hand timestamps back in their own
 * shapes (`2026-09-27 12:34:56.1+02` from Postgres, ISO text from JavaScript),
 * and a Date would drop the microseconds, so every value goes through here
 * on the way in and out:
 *
 *   2026-09-27 12:34:56.1+02  ->  2026-09-27T10:34:56.100000Z
 *   2026-09-27T10:34:56.1Z   ->  2026-09-27T10:34:56.100000Z
 */
export function canonicalTimestamp(raw: string): string {
  const match = TIMESTAMP.exec(raw);
  if (match === null) throw new Error(`unexpected timestamp from the database: ${raw}`);
  const [, year, month, day, hour, minute, second, fraction = '', zone = 'Z'] = match;
  let offsetMinutes = 0;
  if (zone !== 'Z') {
    const sign = zone.startsWith('-') ? -1 : 1;
    const digits = zone.slice(1).replace(':', '');
    offsetMinutes = sign * (Number(digits.slice(0, 2)) * 60 + Number(digits.slice(2) || '0'));
  }
  const utc = new Date(
    Date.UTC(+year, +month - 1, +day, +hour, +minute, +second) - offsetMinutes * 60_000,
  );
  return `${utc.toISOString().slice(0, 19)}.${fraction.padEnd(6, '0')}Z`;
}
