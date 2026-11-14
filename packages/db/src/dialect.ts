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

/**
 * The network's codes for a server that is not there, postgres.js's for a
 * connection lost, cut short or never made, and Postgres's for one shutting
 * down or starting up. Out of connections (53300) is not one (`poolFull`).
 */
const UNREACHABLE = new Set([
  'ECONNREFUSED', 'ECONNRESET', 'ETIMEDOUT', 'ENOTFOUND', 'EAI_AGAIN', 'EHOSTUNREACH', 'ENETUNREACH', 'EPIPE',
  'CONNECTION_CLOSED', 'CONNECTION_DESTROYED', 'CONNECTION_ENDED', 'CONNECT_TIMEOUT',
  '57P01', '57P02', '57P03',
]);

/**
 * Workers' words for a connection lost, and Hyperdrive's for one it could
 * not make ("Server connection attempt failed: destination_unavailable";
 * local workerd's says only "connection attempt failed"), and Workers' for
 * a call it cancelled as hung ("… detected that your Worker's code had
 * hung"): the vault's, or its database's, that never answered.
 */
const UNREACHABLE_WORDS = /connection terminated|network connection lost|connect(ion)? timeout|connection attempt failed|code had hung/i;

/** Hyperdrive's words for a pool with no connection to give. */
const POOL_FULL_WORDS = /open slot in the pool|acquire a connection from the pool/i;

/** Whether `error` or a cause of it says so in `words`: only what said no code, or Hyperdrive's 58000. */
function says(error: unknown, words: RegExp): boolean {
  for (let cause = error; typeof cause === 'object' && cause !== null; cause = (cause as { cause?: unknown }).cause) {
    const { code, message } = cause as { code?: unknown; message?: unknown };
    // Never a message quoting a query and its parameters (Drizzle's, the Node vault's carrying it): the driver's
    // words are its cause's.
    if (typeof message === 'string' && (typeof code !== 'string' || code === '58000') && !message.includes('Failed query: ') && words.test(message)) return true;
  }
  return false;
}

/**
 * Whether a query failed because the database could not be reached or
 * dropped the connection: an outage, not an answer. Postgres's connection
 * exceptions are class 08; postgres.js says so in codes of its own, Workers'
 * sockets and Hyperdrive in words. A pool with no connection to give is not
 * one (`poolFull`).
 */
export function isUnreachable(error: unknown): boolean {
  for (let cause = error; typeof cause === 'object' && cause !== null; cause = (cause as { cause?: unknown }).cause) {
    const { code } = cause as { code?: unknown };
    // Class 08 but its protocol violation (08P01), which is the client's bug: asked again, it fails again.
    if (typeof code === 'string' && (UNREACHABLE.has(code) || (/^08[0-9A-Z]{3}$/.test(code) && code !== '08P01'))) return true;
  }
  return says(error, UNREACHABLE_WORDS);
}

/** Postgres's code for want of resources, which the vault's answer gives a pool with no connection to give. */
export const POOL_FULL = '53000';

/** Postgres's codes for no connection to give: `POOL_FULL`, and out of connections ("too many clients already"). */
const POOL_FULL_CODES = new Set([POOL_FULL, '53300']);

/**
 * Whether the pool had no connection to give: Hyperdrive's, every one busy
 * for 15 s ("Timed out while waiting for an open slot in the pool", FATAL
 * 58000; "Failed to acquire a connection from the pool"), Postgres's, out
 * of connections (53300, which Hyperdrive gives Workers past its own limit
 * too), or `POOL_FULL`.
 * The database busy, which whoever holds a credential can make it, as a
 * statement that gave up waiting: no outage (D238). Hyperdrive's docs give
 * "Failed to acquire" for a database it cannot connect to at all too, and
 * that is no outage either, until its connects fail in words of their own.
 */
export function poolFull(error: unknown): boolean {
  for (let cause = error; typeof cause === 'object' && cause !== null; cause = (cause as { cause?: unknown }).cause) {
    const { code } = cause as { code?: unknown };
    if (typeof code === 'string' && POOL_FULL_CODES.has(code)) return true;
  }
  return says(error, POOL_FULL_WORDS);
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
 * request asked: it could not be reached (`isUnreachable`), its pool had no
 * connection to give (`poolFull`), or a statement gave up waiting
 * (`gaveUp`). The same request may well succeed in a moment.
 */
export function isUnavailable(error: unknown): boolean {
  return isUnreachable(error) || poolFull(error) || gaveUp(error);
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

// What a log line says about an error: never a value a request sent or a
// row holds. Logged as it is, an error shows only its stack on Workers,
// without its message, and on Node all of what Postgres said. So each error
// is logged as a plain object: its name and message, Postgres's code and the
// names it gives (`table`, `constraint`, …), the same for its cause, and its
// stack's frames. Postgres's own words are left out, `message`, `detail`,
// `hint` and `where` alike: each may quote a value (`invalid input syntax
// for type uuid: "…"`, `Key (key)=(…) already exists`), and so are the
// parameters Drizzle's message quotes after its SQL.

/** The fields a Postgres error gives that name and never quote, each by the name a log line gives it. */
const POSTGRES_NAMES = [
  ['severity', 'severity'],
  ['code', 'code'],
  ['position', 'position'],
  ['schema_name', 'schema'],
  ['table_name', 'table'],
  ['column_name', 'column'],
  ['data type_name', 'dataType'],
  ['constraint_name', 'constraint'],
  ['routine', 'routine'],
] as const;

/** A SQLSTATE: its class, two characters, then three. Node's own codes (`EPIPE`) are none. */
const SQLSTATE = /^(?:[0-5][0-9A-Z]|F0|HV|P0|XX)[0-9A-Z]{3}$/;

/** How many causes deep a log line follows an error. */
const DEPTH = 4;

/** `error` as a log line says it: by Postgres's code and names alone, never its words or a query's parameters. */
export function logged(error: unknown, depth = 0): unknown {
  if (!(error instanceof Error)) return error;
  const fields = error as Error & Record<string, unknown>;
  // Postgres's, by its code, which an error rebuilt across a call keeps, when its severity is gone.
  const postgres = typeof fields.severity === 'string' || (typeof fields.code === 'string' && SQLSTATE.test(fields.code));
  // Drizzle's message ends with its parameters, read from its field or, past a call that kept only the words, from those.
  const message = postgres ? "Postgres's words are left out: they may quote a value" : error.message.split('\nparams: ')[0]!;
  const out: Record<string, unknown> = { name: error.name, message };
  for (const [field, name] of POSTGRES_NAMES) {
    if (fields[field] !== undefined) out[name] = fields[field];
  }
  if (error.cause !== undefined && depth < DEPTH) out.cause = logged(error.cause, depth + 1);
  if (depth === 0) {
    // What the words said, kept as a fixed word: 58000 is Hyperdrive's empty pool and many another failure.
    const failure = poolFull(error) ? 'pool full' : gaveUp(error) ? 'gave up waiting' : isUnreachable(error) ? 'unreachable' : undefined;
    if (failure !== undefined) out.failure = failure;
    const frames = framesOf(error);
    if (frames !== undefined) out.stack = frames;
  }
  return out;
}

/**
 * The stack's frames alone. It begins with the message, the parameters
 * with it, whose lines may look like frames (`\n    at …`): so the frames
 * are read past the message, and a stack that no longer holds it is left out.
 */
function framesOf(error: Error): string | undefined {
  const at = error.stack?.indexOf(error.message) ?? -1;
  if (at < 0) return undefined;
  return error.stack!.slice(at + error.message.length).split('\n').filter((line) => /^\s+at /.test(line)).join('\n');
}
