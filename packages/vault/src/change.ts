import type { Database } from '@coffre/db';
import { rowsOf } from '@coffre/db/dialect';
import { later, laterRows } from '@coffre/db/later';
import { sql, type SQL } from 'drizzle-orm';

import { pending, type Entry, type Said } from './entry.ts';
import { fromWire, nameOf, seal, sealedBy, shapeOf, toWire, type Fresh, type Key, type Row, type Sealed, type Wire } from './rows.ts';

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
 * So what an operation says is what it reads and how it decides. Reading
 * again, comparing, writing, sealing each row and logging what it replaced
 * are here, once.
 *
 * Nothing else writes what a MAC covers. A use moves a row's last-seen
 * columns on, one row a statement, and the signer's upkeep is changes like
 * any other. So under the lock, the rows a write compared are the rows it
 * writes over.
 */

/** The vault as it runs: its database, its keys (the first seals, each verifies), its clock, and the signer's wake-up. */
export type Running = {
  db: Database;
  keys: readonly Key[];
  now(): number;
  /** Told the hash of each entry once it is committed. It does not hold the reply. */
  wake(hash: Buffer): void;
};

/**
 * Rows a decision depends on: those of `table` that `where` holds for, a
 * condition on its columns as Drizzle writes one (`eq(principals.id, id)`).
 * Each an index lookup, and few.
 */
export type Part<T extends Sealed = Sealed> = { table: T; where: SQL };

export function part<T extends Sealed>(table: T, where: SQL | undefined): Part<T> {
  if (where === undefined) throw new Error('a part reads the rows a condition holds for, never a whole table by default');
  return { table, where };
}

export type Parts = Readonly<Record<string, Part>>;

/** What a read found, by part: the rows whose MAC is the vault's. */
export type Seen<P extends Parts> = { [K in keyof P]: Row<P[K]['table']>[] };

/**
 * One row written. A row is put in place of the one read (`was`), which has
 * its key, or as a new one; or the row read is dropped. Within one change a
 * row is written once, and a unique value one row gives up is not taken by
 * another: Postgres checks each as it goes, in no set order.
 */
export type Write = { table: Sealed; row: object | null; was: object | null };

export function put<T extends Sealed>(table: T, row: Fresh<T>, was: Row<T> | null = null): Write {
  return { table, row, was };
}

export function drop<T extends Sealed>(table: T, was: Row<T>): Write {
  return { table, row: null, was };
}

/** Why a change is not made. It writes nothing, the log included. */
export type Refusal = { refused: string };

export type Plan<A> = { writes: readonly Write[]; entry: Said; answer: A };

export type Operation<P extends Parts, A> = {
  read: P;
  /** From the rows read and the time, and nothing else. */
  decide(seen: Seen<P>, at: number): Plan<A> | Refusal;
};

/** A change read and decided, not yet written. */
export type Prepared<A> = { answer: A; statement: SQL; hash: Buffer };

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
 * in a row is a crowd on those rows, not bad luck.
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
 * How long a write runs, in milliseconds, its waits included. It is
 * milliseconds of work, so five seconds is a database that cannot keep up,
 * and the write answers busy. An entry is dated as its write is sent, so it
 * commits within this of its date, well inside the minute the signer takes
 * it in (`FRESH_MS` in signer.ts): no entry is refused as too old for a
 * database that was slow.
 */
const WRITE_MS = 5000;

export class Busy extends Error {
  override readonly name = 'Busy';
}

/** Postgres's `lock_not_available` and `query_canceled`: a wait `lock_timeout` ended, or a statement `statement_timeout` did. */
function gaveUp(error: unknown): boolean {
  for (let cause = error; cause instanceof Error; cause = cause.cause) if (['55P03', '57014'].includes((cause as { code?: unknown }).code as string)) return true;
  return false;
}

/**
 * One statement in a transaction of its own that bounds its lock waits and
 * its run, and its rows. `first` is selected ahead of it, in a statement of
 * its own. One round trip: nothing is waited for inside the transaction, so
 * the driver sends BEGIN, the statements and COMMIT together (`later` in
 * @coffre/db). Postgres still runs them one after the other, and skips the
 * rest once one fails. Read committed, said here and not left to the
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
      throw gaveUp(error) ? new Busy(`a statement waited ${LOCK_WAIT_MS} ms for a lock, or ran ${runMs} ms`) : error;
    });
  // Read once the transaction has resolved: it committed.
  return rows;
}

const id = (name: string) => sql.identifier(name);
const list = (names: readonly { name: string }[], of?: string) => sql.join(names.map(({ name }) => (of === undefined ? id(name) : sql`${id(of)}.${id(name)}`)), sql`, `);

/** A change's read and its decision. */
export async function prepare<P extends Parts, A>(vault: Running, operation: Operation<P, A>): Promise<Prepared<A> | Refusal> {
  const parts = Object.entries(operation.read);
  if (parts.length === 0) throw new Error('a change reads at least its caller');
  // With the database's clock, so that no pooler answers the read from a cache (as a use's read, use.ts).
  const found = await rowsOf<{ part: string; row: Wire }>(
    vault.db,
    sql`SELECT part, row, clock_timestamp() AS read_at FROM (${sql.join(parts.map(([name, { table, where }]) => sql`SELECT ${sql.raw(`'${label(name)}'`)} AS part, to_jsonb(${table}) AS row FROM ${table} WHERE ${where}`), sql` UNION ALL `)}) parts`,
  );
  // After the read: the entry's date is the decision's, and the write is sent next.
  const at = vault.now();
  const seen = Object.fromEntries(parts.map(([name]) => [name, [] as object[]]));
  /** Each row read, with its name. One that several parts found is one object each time. */
  const read = new Map<object, string>();
  const tokens: string[] = [];
  for (const { part: name, row: wire } of found) {
    const { table } = operation.read[name]!;
    const row = fromWire(table, wire) as Row<Sealed> & { mac: Buffer };
    tokens.push(`${name}:${row.mac.toString('hex')}`);
    if (sealedBy(vault.keys, table, row) === undefined) continue;
    seen[name]!.push(row);
    read.set(row, nameOf(table, row));
  }
  const plan = operation.decide(seen as Seen<P>, at);
  if ('refused' in plan) return plan;

  const key = vault.keys[0]!;
  const rows: Entry['rows'][number][] = [];
  const written = new Map<string, { table: Sealed; inserts: Wire[]; updates: Wire[]; deletes: Wire[] }>();
  for (const { table, row, was } of plan.writes) {
    if (was !== null && !read.has(was)) throw new Error(`a change of ${shapeOf(table).name} replaces a row its decision did not read`);
    const name = nameOf(table, row ?? was!);
    if (row !== null && was !== null && nameOf(table, was) !== name) throw new Error(`a change of ${name} moves its key`);
    if (rows.some((other) => other.row === name)) throw new Error(`a change writes ${name} twice`);
    const mac = row === null ? null : seal(key, table, row);
    rows.push({ row: name, was: was === null ? null : (was as { mac: Buffer }).mac.toString('hex'), now: mac?.toString('hex') ?? null });
    const shape = shapeOf(table);
    const group = written.get(shape.name) ?? { table, inserts: [], updates: [], deletes: [] };
    written.set(shape.name, group);
    if (row === null) group.deletes.push(toWire(table, was!, shape.key));
    else (was === null ? group.inserts : group.updates).push({ ...toWire(table, row), mac: `\\x${mac!.toString('hex')}` });
  }
  // What it read and left, by the MAC it carried: the same twice.
  for (const [row, name] of read) {
    const mac = (row as { mac: Buffer }).mac.toString('hex');
    if (!rows.some((other) => other.row === name)) rows.push({ row: name, was: mac, now: mac });
  }
  const entry = pending(key, plan.entry, at, rows);

  // The same rows, read again by the same conditions: one that changed, went or came since makes the lists differ.
  const again = sql.join(parts.map(([name, { table, where }]) => sql`SELECT ${sql.raw(`'${label(name)}:'`)} || encode(${table}.mac, 'hex') FROM ${table} WHERE ${where}`), sql` UNION ALL `);
  const statements: SQL[] = [sql`same AS (SELECT (SELECT coalesce(array_agg(x ORDER BY x COLLATE "C"), '{}') FROM (${again}) seen (x)) = ${sql.param(tokens.sort())}::text[] AS ok)`];
  for (const { table, inserts, updates, deletes } of written.values()) {
    const shape = shapeOf(table);
    const from = (wires: Wire[]) => sql`jsonb_populate_recordset(null::${table}, ${JSON.stringify(wires)}::jsonb) j, same WHERE same.ok`;
    const onKey = sql.join(shape.key.map(({ name }) => sql`${table}.${id(name)} = j.${id(name)}`), sql` AND `);
    const stored = shape.columns.filter((column) => !column.generated);
    // A row keeps its key, and what only says when it was last seen, which a use may have moved on since the read.
    const set = shape.columns.filter((column) => (column.sealed || column.name === 'mac') && !column.primary);
    if (inserts.length > 0) statements.push(sql`w${sql.raw(String(statements.length))} AS (INSERT INTO ${table} (${list(stored)}) SELECT ${list(stored, 'j')} FROM ${from(inserts)})`);
    if (updates.length > 0) statements.push(sql`w${sql.raw(String(statements.length))} AS (UPDATE ${table} SET (${list(set)}) = ROW(${list(set, 'j')}) FROM ${from(updates)} AND ${onKey})`);
    if (deletes.length > 0) statements.push(sql`w${sql.raw(String(statements.length))} AS (DELETE FROM ${table} USING ${from(deletes)} AND ${onKey})`);
  }
  statements.push(sql`entry AS (INSERT INTO log_pending (kept, body, mac) SELECT ${entry.kept}, ${entry.body}, decode(${entry.mac.toString('hex')}, 'hex') FROM same WHERE same.ok)`);
  return { answer: plan.answer, statement: sql`WITH ${sql.join(statements, sql`, `)} SELECT ok FROM same`, hash: entry.hash };
}

/** A part's name goes into the statement as written, so it is a plain word. */
function label(name: string): string {
  if (!/^[a-z][A-Za-z0-9]*$/.test(name)) throw new Error(`a part's name is a plain word, not ${JSON.stringify(name)}`);
  return name;
}

/**
 * A prepared change's write. False when a row it read has changed since:
 * nothing was written. The lock is taken by a statement of its own, ahead
 * of the write: a statement sees the database as of when it starts, so a
 * write that took the lock itself would compare against rows from before
 * it waited (`bounded`).
 */
export async function commit<A>(vault: Running, prepared: Prepared<A>): Promise<boolean> {
  // Were the write's answer lost on its way back, this throws for a write that landed, and the signer finds its entry unannounced, as after a vault that died.
  const [same] = await bounded<{ ok: boolean }>(vault.db, prepared.statement, { first: sql`pg_advisory_xact_lock(${sql.raw(String(CHANGE_LOCK))})` });
  if (same!.ok) vault.wake(prepared.hash);
  return same!.ok;
}

/** Make a change: its answer, once committed, or why it is refused. */
export async function change<P extends Parts, A>(vault: Running, operation: Operation<P, A>): Promise<{ answer: A } | Refusal> {
  for (let attempt = 0; attempt < ATTEMPTS; attempt += 1) {
    const prepared = await prepare(vault, operation);
    if ('refused' in prepared) return prepared;
    if (await commit(vault, prepared)) return { answer: prepared.answer };
  }
  throw new Busy(`a change started ${ATTEMPTS} times over, each time behind another change to the rows it read`);
}
