import { open, seal as sealValue, type Envelope } from '@coffre/core/envelope';
import { KekUnavailableError, type KekRegistry } from '@coffre/core/kek';
import type { Database } from '@coffre/db';
import { gaveUpCode } from '@coffre/db/dialect';
import { later, laterRows } from '@coffre/db/later';
import { bindings, environments, secrets, secretVersions } from '@coffre/db/schema';
import { sql, type SQL } from 'drizzle-orm';
import type { PgTable } from 'drizzle-orm/pg-core';

import { pending, type Entry, type Said } from './entry.ts';
import { fromWire, nameOf, seal, sealedBy, shapeOf, toWire, type Fresh, type Key, type Row, type Sealed, type Wire } from './rows.ts';
import { contextOf, natureOf } from './value.ts';

/**
 * A change: anything that writes (docs/design/0.16.md, "Operations"). Every
 * one runs the same way, in two database calls.
 *
 * 1. One read of the rows it depends on. A row whose MAC is not the vault's
 *    is not a row: no decision sees it.
 * 2. The decision, one function of those rows.
 * 3. One write, under the change lock: it reads the same rows again, and
 *    only if each still carries the MAC first read does it write the new
 *    rows and the log entry. Otherwise nothing is written, and the change
 *    starts again.
 *
 * The entry names every row the decision read, written or not, with its
 * MAC, and the signer holds each to its mirror: a row put back for the
 * decision and withdrawn after is found. A row the read looked for and did
 * not find has no name to give. So a decision takes nothing from a missing
 * row: with fewer rows it refuses, or allows less.
 *
 * One table is read that carries no MAC: the versions of values, for a
 * change that copies one (`Value`) or goes by one's label (`vouched`). A
 * version's encryption names what it is, so its row is held to that when it
 * is opened, before anything is written, and the write reads it again, as
 * any row, by a hash of all of it.
 *
 * So what an operation says is what it reads and how it decides. Reading
 * again, comparing, writing, sealing each row and logging what it replaced
 * are here, once.
 *
 * A value is the one thing a change writes that carries no MAC: a version's
 * encryption names what it is. The decision says what the version holds,
 * and the value is sealed here, after it and before the write, since
 * sealing draws a key and may call a key service, which no decision does.
 *
 * Nothing else writes what a MAC covers. A use moves a row's last-seen
 * columns on, one row a statement, and the signer's upkeep is changes like
 * any other. So under the lock, the rows a write compared are the rows it
 * writes over.
 */

/** The vault as it runs: its database, its keys (the first seals, each verifies), the keys values are wrapped under, its clock, and the signer's wake-up. */
export type Running = {
  db: Database;
  keys: readonly Key[];
  keks: KekRegistry;
  now(): number;
  /** Told the hash of each entry once it is committed. It does not hold the reply. */
  wake(hash: Buffer): void;
  /** What this instance logged refusing in the last minute, by who asked and what: a refusal is logged once in it. */
  refused: Map<string, { at: number }>;
};

/** A table a change reads: one whose rows carry the vault's MAC, or the versions of values, which carry none. */
export type Readable = Sealed | typeof secretVersions;

/**
 * Rows a decision depends on: those of `table` that `where` holds for, a
 * condition on its columns as Drizzle writes one (`eq(principals.id, id)`).
 * Each an index lookup, and few.
 */
export type Part<T extends Readable = Readable> = { table: T; where: SQL };

export function part<T extends Readable>(table: T, where: SQL | undefined): Part<T> {
  if (where === undefined) throw new Error('a part reads the rows a condition holds for, never a whole table by default');
  return { table, where };
}

export type Parts = Readonly<Record<string, Part>>;

/** What a read found, by part: the rows whose MAC is the vault's, and every version found. */
export type Seen<P extends Parts> = { [K in keyof P]: RowOf<P[K]['table']>[] };
/** A row of each table a part may read, one by one. */
type RowOf<T extends Readable> = T extends PgTable ? Row<T> : never;

/**
 * How many rows each part found whose MAC is not the vault's: written
 * behind it, and so no row of `Seen`. A decision that allows more for a
 * row that is not there reads this: a row it cannot trust is not a row
 * that is absent.
 */
export type Unsealed<P extends Parts> = { readonly [K in keyof P]: number };

/**
 * One row written. A row is put in place of the one read (`was`), which has
 * its key, or as a new one; or the row read is dropped. Within one change a
 * row is written once. Postgres checks a unique value as it writes each
 * row, in no set order, so a unique value one row gives up is taken by
 * another only if the first goes `first` (`aside`): every write that goes
 * first is made before any other.
 */
export type Write = { table: Sealed; row: object | null; was: object | null; first?: boolean };

export function put<T extends Sealed>(table: T, row: Fresh<T>, was: Row<T> | null = null): Write {
  return { table, row, was };
}

/** A row read, put back with what a change says of it: every other column as it was. */
export function amended<T extends Sealed>(table: T, was: Row<T>, changes: Partial<Fresh<T>>): Write {
  const { mac: _, ...kept } = was as Row<T> & { mac: unknown };
  return put(table, { ...kept, ...changes } as Fresh<T>, was);
}

/** A row read, put back with what a change says of it, before any other write: what it gives up, a key's name, another may then take. */
export function aside<T extends Sealed>(table: T, was: Row<T>, changes: Partial<Fresh<T>>): Write {
  return { ...amended(table, was, changes), first: true };
}

export function drop<T extends Sealed>(table: T, was: Row<T>): Write {
  return { table, row: null, was };
}

/**
 * A value a change writes: its version's row but for the encryption, and
 * its text, or the version it is a `copy` of (a restore), which the change
 * read: the engine opens that one as its row labels it, in the secret and
 * environment its row names, which the change read too, and the decision
 * never holds the value. One that does not open, relabelled or erased, or a
 * plain one whose copy in its row is not its value, refuses the change,
 * `unreadable`. A value is the current version of a secret the same change
 * writes, in an environment the change read or makes: those two rows say
 * what its encryption names, and nothing the operation says beside them. Its
 * nature is the one the secret's row says.
 */
export type Value = { version: Omit<Row<typeof secretVersions>, keyof Envelope> } & ({ text: Buffer; copy?: undefined } | { copy: Row<typeof secretVersions>; text?: undefined });

/** Why a change is not made. Nothing it asked is written. */
export type Refusal = { refused: string };

/**
 * A refusal's entry, as an operation says it: its own action, who asked,
 * and in `detail.refused` why not, which is what tells it from the entry
 * of a change that was made. Always among the entries that age out.
 */
export type Denied = Omit<Said, 'kept' | 'actor'> & { actor: string };

/**
 * What a decision writes. `once` is a proof the change spends, by the
 * SHA-256 of what was signed (`spent_id_tokens`, the one table a change
 * writes that carries no MAC and no decision reads): the change is made
 * only if that hash was never spent, and is refused `replayed` otherwise.
 * `used` is a trust binding the decision read, which the change is a use
 * of: its last use moves on to the entry's date, in the change's own
 * statement, so if and only if the change is made. No MAC covers that date
 * (rows.ts), so the row stays as every other change read it. `until` is
 * the instant, on the clock the decision was given (`at`), past which it
 * would not be made: a session renewed only while it has seconds left. A
 * write waits after its decision, for a connection and for the change lock,
 * and time changes no row. So the write is made only if its statement
 * starts within `until - at` of the read, by the database's clock at both
 * ends, which the vault's need not agree with; and otherwise the change
 * starts over, as behind a row that changed, and is decided at a later time.
 * `vouched` are versions the change read whose label its decision went by:
 * the engine opens each as its row labels it, as a copy's, before anything
 * is written, and one that does not open refuses the change, `unreadable`.
 */
export type Plan<A> = { writes: readonly Write[]; values?: readonly Value[]; vouched?: readonly Row<typeof secretVersions>[]; once?: Buffer; used?: Row<typeof bindings>; until?: number; entry: Said; answer: A };

export type Operation<P extends Parts, A, C = undefined> = {
  read: P;
  /**
   * What a decision needs that is neither a row nor the time, and cannot
   * be had in it: a signature held to keys the read found, which is
   * asynchronous where the vault runs. Between the read and the decision,
   * on the rows read, with no transaction open, and again each time the
   * change starts over. It reads nothing and writes nothing.
   */
  check?(seen: Seen<P>, unsealed: Unsealed<P>): Promise<C>;
  /** From the rows read, the time and what `check` found, and nothing else. `unsealed` counts, by part, the rows found that are not the vault's. */
  decide(seen: Seen<P>, at: number, unsealed: Unsealed<P>, checked: C): Plan<A> | Refusal;
  /**
   * What the log says of a refusal, from the same rows: who was refused
   * what, and why. Null for a caller who does not stand, who is told one
   * thing and logged nowhere.
   */
  denied?(seen: Seen<P>, at: number, refusal: Refusal): Denied | null;
};

/** A change read and decided, not yet written. */
export type Prepared<A> = { answer: A; statement: SQL; hash: Buffer };

/** A proof spent already: the one refusal a write makes, since no read sees the table of them. */
const REPLAYED: Refusal = { refused: 'replayed' };

/**
 * Only changes take it, each for its one write. Under it a write reads
 * what its decision read as of now: every change before it has committed,
 * and none runs beside it. `coffre` in ASCII, 0x636f66667265, in decimal:
 * Postgres reads a hex number from 16 on only.
 */
export const CHANGE_LOCK = 109330110509669;

/**
 * How often a change starts again before it answers busy. Each new start
 * means another change committed to the very rows this one read, so several
 * in a row is a crowd on those rows, not bad luck. Each start reads again
 * and dates its entry anew.
 */
const ATTEMPTS = 5;

/**
 * How long a write waits for a lock, in milliseconds: the change lock, then
 * any row it writes that another session holds. A write holds the change
 * lock for one statement, milliseconds, so two seconds behind it is a
 * holder that is stuck, or hundreds of changes queued. The change answers
 * busy then: every waiter holds a database connection, which uses need too.
 */
const LOCK_WAIT_MS = 2000;
/**
 * How long a write's statement runs, in milliseconds, once it has the
 * change lock, its waits for rows included. It is milliseconds of work, so
 * five seconds is a database that cannot keep up, and the write answers
 * busy. An entry is dated as its write is sent, so once its transaction has
 * a connection it commits within the two waits of its date, seven seconds,
 * well inside the minute the signer takes it in (`FRESH_MS` in signer.ts).
 * The wait for that connection comes before, and is the pool's to bound:
 * Hyperdrive's does, at 15 seconds; postgres.js's own, on Node, does not
 * (docs/design/0.16.md). An operation whose decision holds until a time
 * (`Plan.until`) leaves this much before what it must land ahead of: the
 * write's statement starts by then and ends within this, with its commit
 * right behind.
 */
export const WRITE_MS = 5000;

/**
 * The database had no turn for it in time: a wait that gave up, its cause,
 * or a change that started over too often. It carries Postgres's code for
 * the wait that ended, `lock_not_available` for a change that never had its
 * turn, and by it the app answers the outage it is, 503, and not a bug.
 * The code is its own, not only its cause's: an error crosses to the app
 * with its own fields, on Workers, and a cause may not (as `Overdue` and
 * `HeadBusy`).
 */
export class Busy extends Error {
  override readonly name = 'Busy';
  readonly code: string;
  constructor(message: string, code = '55P03', cause?: unknown) {
    super(message, { cause });
    this.code = code;
  }
}

/**
 * One statement in a transaction of its own that bounds its lock waits and
 * its run, and its rows. `first` is selected ahead of it, in a statement of
 * its own, which only its lock wait bounds: Postgres times a statement from
 * its start, by the bound in force then. One round trip: nothing is waited
 * for inside the transaction, so the driver sends BEGIN, the statements and
 * COMMIT together (`later` in @coffre/db). Postgres still runs them one
 * after the other, and skips the rest once one fails. Read committed, said here and not left to the
 * database's default: the statement sees the database as of when it starts,
 * after whatever `first` waited for.
 */
export async function bounded<Row>(db: Database, statement: SQL, { first, runMs = WRITE_MS }: { first?: SQL; runMs?: number } = {}): Promise<Row[]> {
  let rows!: Promise<Row[]>;
  await db
    .transaction(
      async (tx) => {
        // The bounds are set ahead of the wait they bound: a select list is worked out in order.
        later(tx, sql`SELECT set_config('lock_timeout', ${String(LOCK_WAIT_MS)}, true), set_config('statement_timeout', ${String(runMs)}, true)${first === undefined ? sql`` : sql`, ${first}`}`);
        rows = laterRows<Row>(tx, statement);
      },
      { isolationLevel: 'read committed' },
    )
    .catch((error: unknown) => {
      const code = gaveUpCode(error);
      throw code === undefined ? error : new Busy(`a statement waited ${LOCK_WAIT_MS} ms for a lock, or ran ${runMs} ms`, code, error);
    });
  // Read once the transaction has resolved: it committed.
  return rows;
}

const id = (name: string) => sql.identifier(name);
const list = (names: readonly { name: string }[], of?: string) => sql.join(names.map(({ name }) => (of === undefined ? id(name) : sql`${id(of)}.${id(name)}`)), sql`, `);

/**
 * Parts read in one statement: each part's rows whose MAC is the vault's,
 * `named` by table and key; `versions`, the rows of a table with no MAC
 * (a secret's versions), given unchecked: the engine opens one under its
 * label before a change copies it or goes by it (`Value`, `vouched`);
 * `tokens`, every row the statement found,
 * by its part and what it is read again by (`tokenOf`), the vault's or
 * not; and `readAt`, the database's clock as it read them, in
 * milliseconds (none when it found no row, of a part or beside one): a
 * number, which no session's settings read another way. `beside` rides in
 * the same statement and is no part: each a query of one jsonb column,
 * `row`, given back as read, with no token, since no write reads it again.
 * No MAC is checked on it here, so whoever asks for one holds it to its
 * own (the log's head, sealed as the signer seals it: caller.ts).
 */
export async function readParts<P extends Parts, B extends string = never>(
  vault: Pick<Running, 'db' | 'keys'>,
  read: P,
  beside?: Readonly<Record<B, SQL>>,
): Promise<{ seen: Seen<P>; unsealed: Unsealed<P>; named: Map<object, string>; versions: Set<object>; tokens: string[]; readAt: number | undefined; beside: Record<B, Wire[]> }> {
  const parts = Object.entries(read);
  if (parts.length === 0) throw new Error('a read names at least one part');
  const asides = Object.entries<SQL>(beside ?? {});
  if (asides.some(([name]) => Object.hasOwn(read, name))) throw new Error('what rides beside a read has a name no part has');
  const arms = [
    ...parts.map(([name, { table, where }]) => sql`SELECT ${sql.raw(`'${label(name)}'`)} AS part, to_jsonb(${table}) AS row, ${tokenOf(table)} AS token FROM ${table} WHERE ${where}`),
    // What rides beside is read once and never again: it has no token.
    ...asides.map(([name, query]) => sql`SELECT ${sql.raw(`'${label(name)}'`)} AS part, aside.row, NULL::text AS token FROM (${query}) aside`),
  ];
  // With the database's clock, so that no pooler answers the read from a cache (as a use's read, use.ts). Bounded as a
  // change's write is: a lock someone holds on a table it reads makes the call busy, and never holds it, nor the signer's upkeep.
  const found = await bounded<{ part: string; row: Wire; token: string | null; read_at: number }>(
    vault.db,
    sql`SELECT part, row, token, (extract(epoch FROM clock_timestamp()) * 1000)::float8 AS read_at FROM (${sql.join(arms, sql` UNION ALL `)}) parts`,
  );
  const aside = Object.fromEntries(asides.map(([name]) => [name, [] as Wire[]])) as Record<B, Wire[]>;
  const seen = Object.fromEntries(parts.map(([name]) => [name, [] as object[]]));
  const unsealed = Object.fromEntries(parts.map(([name]) => [name, 0]));
  /** Each row read, with its name. One that several parts found is one object each time. */
  const named = new Map<object, string>();
  /** Each version read, which carries no MAC. */
  const versions = new Set<object>();
  const tokens: string[] = [];
  for (const { part: name, row: wire, token } of found) {
    if (Object.hasOwn(aside, name)) {
      aside[name as B].push(wire);
      continue;
    }
    const { table } = read[name]!;
    tokens.push(`${name}:${token}`);
    if (!('mac' in table)) {
      const row = fromWire(table, wire);
      seen[name]!.push(row);
      versions.add(row);
      continue;
    }
    const row = fromWire(table, wire) as Row<Sealed> & { mac: Buffer };
    if (sealedBy(vault.keys, table, row) === undefined) {
      unsealed[name]! += 1;
      continue;
    }
    seen[name]!.push(row);
    named.set(row, nameOf(table, row));
  }
  return { seen: seen as Seen<P>, unsealed: unsealed as Unsealed<P>, named, versions, tokens, readAt: found[0] && Number(found[0].read_at), beside: aside };
}

/** What a row is read again by: its MAC, or a version's, which has none, a hash of all of it. */
const tokenOf = (table: Readable) => ('mac' in table ? sql`encode(${table}.mac, 'hex')` : sql`md5(to_jsonb(${table})::text)`);

/** A change's read and its decision. */
export async function prepare<P extends Parts, A, C = undefined>(vault: Running, operation: Operation<P, A, C>): Promise<Prepared<A> | (Refusal & { said?: Denied | null })> {
  const parts = Object.entries(operation.read);
  const { seen, unsealed, named: read, versions: copied, tokens, readAt } = await readParts(vault, operation.read);
  const checked = (operation.check === undefined ? undefined : await operation.check(seen, unsealed)) as C;
  // After the read, and the check: the entry's date is the decision's, and the write is sent next.
  const at = vault.now();
  const plan = operation.decide(seen, at, unsealed, checked);
  // Told before anything is sealed: a proof is spent by its hash's own bytes.
  if (!('refused' in plan) && plan.once !== undefined && !(Buffer.isBuffer(plan.once) && plan.once.length === 32)) throw new Error('a change spends a proof by the 32 bytes of its SHA-256');
  const refuse = (refusal: Refusal) => {
    // What the log says of it is the operation's to say, and never costs the refusal: one that cannot be said is not logged.
    let said: Denied | null | undefined;
    try {
      said = operation.denied?.(seen, at, refusal);
    } catch (error) {
      console.error('coffre: a refused change was not logged', error);
    }
    return { refused: refusal.refused, said };
  };
  if ('refused' in plan) return refuse(plan);

  const key = vault.keys[0]!;
  const rows: Entry['rows'][number][] = [];
  const written = new Map<string, { table: Sealed; first: boolean; inserts: Wire[]; updates: Wire[]; deletes: Wire[] }>();
  for (const { table, row, was, first = false } of plan.writes) {
    if (was !== null && !read.has(was)) throw new Error(`a change of ${shapeOf(table).name} replaces a row its decision did not read`);
    const name = nameOf(table, row ?? was!);
    if (row !== null && was !== null && nameOf(table, was) !== name) throw new Error(`a change of ${name} moves its key`);
    if (rows.some((other) => other.row === name)) throw new Error(`a change writes ${name} twice`);
    const mac = row === null ? null : seal(key, table, row);
    rows.push({ row: name, was: was === null ? null : (was as { mac: Buffer }).mac.toString('hex'), now: mac?.toString('hex') ?? null });
    const shape = shapeOf(table);
    const group = written.get(`${first} ${shape.name}`) ?? { table, first, inserts: [], updates: [], deletes: [] };
    written.set(`${first} ${shape.name}`, group);
    if (row === null) group.deletes.push(toWire(table, was!, shape.key));
    else (was === null ? group.inserts : group.updates).push({ ...toWire(table, row), mac: `\\x${mac!.toString('hex')}` });
  }
  // What it read and left, by the MAC it carried: the same twice.
  const { once, used, until } = plan;
  // The time a decision goes by is a row's, an expiry it read: a decision that read no row has none to hold until.
  if (until !== undefined && !(Number.isFinite(until) && until > at && Number.isFinite(readAt))) throw new Error('a change holds until a time after its decision, by a row it read');
  if (used !== undefined) {
    if (read.get(used) !== nameOf(bindings, used)) throw new Error('a change is a use of a binding its decision read');
    // Postgres writes a row once in a statement: which of two writes it kept would be anyone's guess.
    if (rows.some((other) => other.row === nameOf(bindings, used))) throw new Error(`a change that writes ${nameOf(bindings, used)} does not move its last use on too`);
  }
  for (const [row, name] of read) {
    const mac = (row as { mac: Buffer }).mac.toString('hex');
    if (!rows.some((other) => other.row === name)) rows.push({ row: name, was: mac, now: mac });
  }
  const versions: Wire[] = [];
  /** A row of `table` as this change leaves it, by its key: the one it writes, or else the one it read. None for a row it drops. */
  const rowOf = <T extends Sealed>(table: T, key: object): Fresh<T> | undefined => {
    const name = nameOf(table, key);
    const made = plan.writes.find((write) => write.table === table && nameOf(table, write.row ?? write.was!) === name);
    if (made !== undefined) return (made.row ?? undefined) as Fresh<T> | undefined;
    for (const [row, of] of read) if (of === name) return row as Fresh<T>;
    return undefined;
  };
  /** A version this change read, opened as its own rows say, as a use opens it: its secret's and its environment's, which this change read. Undefined for one that is not what it says. */
  const opened = async (copy: Row<typeof secretVersions>): Promise<Buffer | undefined> => {
    const of = copied.has(copy) ? rowOf(secrets, { id: copy.secretId }) : undefined;
    const where = of && rowOf(environments, { id: of.environmentId });
    if (of === undefined || where === undefined) throw new Error('a change opens a version it read, of a secret and in an environment it read');
    try {
      return await open(copy, contextOf(of, copy, where.owner), vault.keks);
    } catch (error) {
      // A key service that cannot answer is an outage. Anything else is a row that is not what it says: relabelled, moved, erased.
      if (error instanceof KekUnavailableError) throw error;
      return undefined;
    }
  };
  for (const row of plan.vouched ?? []) {
    const text = await opened(row);
    if (text === undefined) return refuse({ refused: 'unreadable' });
    text.fill(0);
  }
  for (const value of plan.values ?? []) {
    const { version, copy } = value;
    // Sealed under what its secret's row and its environment's say, as this change leaves them: a use opens it by the same rows.
    const held = plan.writes.find((write) => write.table === secrets && (write.row as { id?: string } | null)?.id === version.secretId)?.row as Fresh<typeof secrets> | undefined;
    const place = held && rowOf(environments, { id: held.environmentId });
    if (held === undefined || place === undefined || place.projectId !== held.projectId || held.currentVersion !== version.version || held.versions !== version.version) {
      throw new Error('a change writes a value as the current version of a secret it writes, in an environment of its project that it read');
    }
    // What the secret's row says of its value, which a change reads, is what the value is sealed as.
    if (held.nature !== natureOf(version)) throw new Error(`a value sealed as ${natureOf(version)} is the current version of a secret whose row says ${held.nature}`);
    let text = value.text;
    if (copy !== undefined) {
      text = await opened(copy);
      if (text === undefined) return refuse({ refused: 'unreadable' });
    }
    try {
      if (version.plaintext !== null && version.plaintext !== text!.toString('utf8')) {
        // A version's copy of its plain value is under no MAC: one that is not the value was written behind the vault.
        if (copy !== undefined) return refuse({ refused: 'unreadable' });
        throw new Error("a plain value's copy is the value");
      }
      versions.push(toWire(secretVersions, { ...version, ...(await sealValue(text!, contextOf(held, version, place.owner), vault.keks)) }));
    } finally {
      // A value opened here is the engine's own: nobody else holds it.
      if (copy !== undefined) text!.fill(0);
    }
  }
  // Dated now, as the write is sent: sealing a value, through a key service, takes as long as it takes.
  const dated = vault.now();
  const entry = pending(key, plan.entry, dated, rows);

  // The same rows, read again by the same conditions: one that changed, went or came since makes the lists differ.
  const again = sql.join(parts.map(([name, { table, where }]) => sql`SELECT ${sql.raw(`'${label(name)}:'`)} || ${tokenOf(table)} FROM ${table} WHERE ${where}`), sql` UNION ALL `);
  // And in time, for a decision that holds until one: counted from the read, which came before the decision, so never past it.
  const inTime = until === undefined ? sql`` : sql` AND extract(epoch FROM clock_timestamp()) * 1000 < ${readAt! + (until - at)}::float8`;
  const statements: SQL[] = [sql`same AS (SELECT (SELECT coalesce(array_agg(x ORDER BY x COLLATE "C"), '{}') FROM (${again}) seen (x)) = ${sql.param(tokens.sort())}::text[]${inTime} AS ok)`];
  // Spent only if the rows have not moved, so that a change that starts over does not find its own; and then everything
  // else is written only if it was not spent before: each write below selects from it, and so writes nothing without it.
  const when = sql`${new Date(dated).toISOString()}::timestamptz`;
  if (once !== undefined) statements.push(sql`spent AS (INSERT INTO spent_id_tokens (hash, spent_at) SELECT decode(${once.toString('hex')}, 'hex'), ${when} FROM same WHERE same.ok ON CONFLICT DO NOTHING RETURNING hash)`);
  const gates = once === undefined ? sql`same` : sql`same, spent`;
  const made = sql`${gates} WHERE same.ok`;
  // With everything else or not at all, as each write below. Never put back: a later date the row has stays.
  if (used !== undefined) statements.push(sql`used AS (UPDATE ${bindings} SET last_used_at = ${when} FROM ${made} AND ${bindings}.id = ${used.id} AND (${bindings}.last_used_at IS NULL OR ${bindings}.last_used_at < ${when}))`);
  const fromRows = (table: PgTable, wires: Wire[]) => sql`jsonb_populate_recordset(null::${table}, ${JSON.stringify(wires)}::jsonb) j, ${made}`;
  // The writes that go first, then the others, which each read how many rows those wrote: none of them can write a row
  // before every one of those has been written, so a unique value given up first is free for them.
  const firsts: string[] = [];
  const groups = [...written.values()].sort((a, b) => Number(b.first) - Number(a.first));
  for (const { table, first, inserts, updates, deletes } of groups) {
    const shape = shapeOf(table);
    const after = first || firsts.length === 0 ? made : sql`${gates}, (SELECT count(*) FROM (${sql.join(firsts.map((name) => sql`SELECT FROM ${sql.raw(name)}`), sql` UNION ALL `)}) f) firsts WHERE same.ok`;
    const from = (wires: Wire[]) => sql`jsonb_populate_recordset(null::${table}, ${JSON.stringify(wires)}::jsonb) j, ${after}`;
    const onKey = sql.join(shape.key.map(({ name }) => sql`${table}.${id(name)} = j.${id(name)}`), sql` AND `);
    const stored = shape.columns.filter((column) => !column.generated);
    // A row keeps its key, and what only says when it was last seen, which a use may have moved on since the read.
    const set = shape.columns.filter((column) => (column.sealed || column.name === 'mac') && !column.primary);
    const write = (statement: SQL) => {
      const name = `w${statements.length}`;
      if (first) firsts.push(name);
      statements.push(sql`${sql.raw(name)} AS (${statement}${first ? sql` RETURNING 1` : sql``})`);
    };
    if (inserts.length > 0) write(sql`INSERT INTO ${table} (${list(stored)}) SELECT ${list(stored, 'j')} FROM ${from(inserts)}`);
    if (updates.length > 0) write(sql`UPDATE ${table} SET (${list(set)}) = ROW(${list(set, 'j')}) FROM ${from(updates)} AND ${onKey}`);
    if (deletes.length > 0) write(sql`DELETE FROM ${table} USING ${from(deletes)} AND ${onKey}`);
  }
  // In the statement that writes its secret's row: the two are there together, or neither.
  if (versions.length > 0) {
    const stored = shapeOf(secretVersions).columns.filter((column) => !column.generated);
    statements.push(sql`versions AS (INSERT INTO ${secretVersions} (${list(stored)}) SELECT ${list(stored, 'j')} FROM ${fromRows(secretVersions, versions)})`);
  }
  statements.push(sql`entry AS (INSERT INTO log_pending (kept, body, mac) SELECT ${entry.kept}, ${entry.body}, decode(${entry.mac.toString('hex')}, 'hex') FROM ${made})`);
  // `fresh`: whether the proof was this change's to spend. Null for a change that spends none.
  const fresh = once === undefined ? sql`NULL::boolean` : sql`EXISTS (SELECT 1 FROM spent)`;
  return { answer: plan.answer, statement: sql`WITH ${sql.join(statements, sql`, `)} SELECT ok, ${fresh} AS fresh FROM same`, hash: entry.hash };
}

/** A part's name goes into the statement as written, so it is a plain word. */
function label(name: string): string {
  if (!/^[a-z][A-Za-z0-9]*$/.test(name)) throw new Error(`a part's name is a plain word, not ${JSON.stringify(name)}`);
  return name;
}

/**
 * Whether a prepared change's write was made. False when nothing was
 * written: a row it read has changed since, the time its decision held
 * until has passed, or its proof was spent before (`written` says which). The lock is taken by a statement of its own,
 * ahead of the write: a statement sees the database as of when it starts,
 * so a write that took the lock itself would compare against rows from
 * before it waited (`bounded`).
 */
export async function commit<A>(vault: Running, prepared: Prepared<A>): Promise<boolean> {
  return (await written(vault, prepared)) === 'made';
}

/**
 * A prepared change's write: made; `moved`, a row it read has changed
 * since or the time its decision held until has passed, either of which
 * starts the change over; or `spent`, its proof was spent before, which
 * refuses it. Only the first writes anything. A row that
 * moved is told first: its proof was not this write's to spend yet.
 */
export async function written<A>(vault: Running, prepared: Prepared<A>): Promise<'made' | 'moved' | 'spent'> {
  // Were the write's answer lost on its way back, this throws for a write that landed, and the signer finds its entry unannounced, as after a vault that died.
  const [same] = await bounded<{ ok: boolean; fresh: boolean | null }>(vault.db, prepared.statement, { first: sql`pg_advisory_xact_lock(${sql.raw(String(CHANGE_LOCK))})` });
  if (!same!.ok) return 'moved';
  if (same!.fresh === false) return 'spent';
  vault.wake(prepared.hash);
  return 'made';
}

/** A refusal is logged once a minute for whoever asked and what they asked: a loop of them does not fill the log. */
const REFUSED_MS = 60_000;
/** The most a memory's map holds, whatever the rate: past it, the oldest go. */
const MOST = 1000;

/** Remember `value`, and forget what is older than `since`, and past `MOST` entries the ones that came first. */
export function keep<V extends { at: number }>(map: Map<string, V>, key: string, value: V, since: number): void {
  map.delete(key);
  map.set(key, value);
  for (const [old, { at }] of map) if (at < since || map.size > MOST) map.delete(old);
}

/**
 * A refused change's entry (D236): among those that age out, with its
 * operation's action and why it was refused. One statement, without the
 * change lock. It never costs the caller their answer: the refusal stands
 * whether or not it could be logged.
 */
async function deny(vault: Running, said: Denied): Promise<void> {
  const at = vault.now();
  const mark = `${said.actor} ${said.action}`;
  if ((vault.refused.get(mark)?.at ?? -Infinity) + REFUSED_MS > at) return;
  // Remembered before the write, not after: refusals side by side log one entry between them, and hold one connection.
  keep(vault.refused, mark, { at }, at - REFUSED_MS);
  const entry = pending(vault.keys[0]!, { ...said, kept: false }, at, []);
  try {
    await bounded(vault.db, sql`INSERT INTO log_pending (kept, body, mac) VALUES (${entry.kept}, ${entry.body}, decode(${entry.mac.toString('hex')}, 'hex'))`);
  } catch (error) {
    console.error('coffre: a refused change was not logged', error);
    // Forgotten, so that the next one is tried: unless a later one took its place meanwhile.
    if (vault.refused.get(mark)?.at === at) vault.refused.delete(mark);
    return;
  }
  vault.wake(entry.hash);
}

/** Make a change: its answer, once committed, or why it is refused. */
export async function change<P extends Parts, A, C = undefined>(vault: Running, operation: Operation<P, A, C>): Promise<{ answer: A } | Refusal> {
  for (let attempt = 0; attempt < ATTEMPTS; attempt += 1) {
    const prepared = await prepare(vault, operation);
    if ('refused' in prepared) {
      if (prepared.said != null) await deny(vault, prepared.said);
      return { refused: prepared.refused };
    }
    const outcome = await written(vault, prepared);
    if (outcome === 'made') return { answer: prepared.answer };
    // Not logged: a proof comes with a change nobody asks, and a refusal nobody who stands asked writes nothing (D236).
    if (outcome === 'spent') return REPLAYED;
  }
  throw new Busy(`a change started ${ATTEMPTS} times over, each time behind another change to the rows it read, or too late for its decision`);
}
