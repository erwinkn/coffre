import { seal as sealValue, type Envelope } from '@coffre/core/envelope';
import type { KekRegistry } from '@coffre/core/kek';
import type { Database } from '@coffre/db';
import { gaveUpCode } from '@coffre/db/dialect';
import { later, laterRows } from '@coffre/db/later';
import { environments, secrets, secretVersions } from '@coffre/db/schema';
import { sql, type SQL } from 'drizzle-orm';
import type { PgTable } from 'drizzle-orm/pg-core';

import { pending, type Entry, type Said } from './entry.ts';
import { fromWire, nameOf, seal, sealedBy, shapeOf, toWire, type Fresh, type Key, type Row, type Sealed, type Wire } from './rows.ts';
import { contextOf } from './value.ts';

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

/**
 * A value a change writes: its version's row but for the encryption, and
 * its text. It is the current version of a secret the same change writes,
 * in an environment the change read or makes: those two rows say what its
 * encryption names, and nothing the operation says beside them.
 */
export type Value = { version: Omit<Row<typeof secretVersions>, keyof Envelope>; text: Buffer };

/** Why a change is not made. Nothing it asked is written. */
export type Refusal = { refused: string };

/**
 * A refusal's entry, as an operation says it: its own action, who asked,
 * and in `detail.refused` why not, which is what tells it from the entry
 * of a change that was made. Always among the entries that age out.
 */
export type Denied = Omit<Said, 'kept' | 'actor'> & { actor: string };

export type Plan<A> = { writes: readonly Write[]; values?: readonly Value[]; entry: Said; answer: A };

export type Operation<P extends Parts, A> = {
  read: P;
  /** From the rows read and the time, and nothing else. */
  decide(seen: Seen<P>, at: number): Plan<A> | Refusal;
  /**
   * What the log says of a refusal, from the same rows: who was refused
   * what, and why. Null for a caller who does not stand, who is told one
   * thing and logged nowhere.
   */
  denied?(seen: Seen<P>, at: number, refusal: Refusal): Denied | null;
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
 * (docs/design/0.16.md).
 */
const WRITE_MS = 5000;

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
 * `named` by table and key, and `tokens`, every row the statement found by
 * its part and MAC, the vault's or not.
 */
export async function readParts<P extends Parts>(vault: Pick<Running, 'db' | 'keys'>, read: P): Promise<{ seen: Seen<P>; named: Map<object, string>; tokens: string[] }> {
  const parts = Object.entries(read);
  if (parts.length === 0) throw new Error('a read names at least one part');
  // With the database's clock, so that no pooler answers the read from a cache (as a use's read, use.ts). Bounded as a
  // change's write is: a lock someone holds on a table it reads makes the call busy, and never holds it, nor the signer's upkeep.
  const found = await bounded<{ part: string; row: Wire }>(
    vault.db,
    sql`SELECT part, row, clock_timestamp() AS read_at FROM (${sql.join(parts.map(([name, { table, where }]) => sql`SELECT ${sql.raw(`'${label(name)}'`)} AS part, to_jsonb(${table}) AS row FROM ${table} WHERE ${where}`), sql` UNION ALL `)}) parts`,
  );
  const seen = Object.fromEntries(parts.map(([name]) => [name, [] as object[]]));
  /** Each row read, with its name. One that several parts found is one object each time. */
  const named = new Map<object, string>();
  const tokens: string[] = [];
  for (const { part: name, row: wire } of found) {
    const { table } = read[name]!;
    const row = fromWire(table, wire) as Row<Sealed> & { mac: Buffer };
    tokens.push(`${name}:${row.mac.toString('hex')}`);
    if (sealedBy(vault.keys, table, row) === undefined) continue;
    seen[name]!.push(row);
    named.set(row, nameOf(table, row));
  }
  return { seen: seen as Seen<P>, named, tokens };
}

/** A change's read and its decision. */
export async function prepare<P extends Parts, A>(vault: Running, operation: Operation<P, A>): Promise<Prepared<A> | (Refusal & { said?: Denied | null })> {
  const parts = Object.entries(operation.read);
  const { seen, named: read, tokens } = await readParts(vault, operation.read);
  // After the read: the entry's date is the decision's, and the write is sent next.
  const at = vault.now();
  const plan = operation.decide(seen, at);
  if ('refused' in plan) {
    // What the log says of it is the operation's to say, and never costs the refusal: one that cannot be said is not logged.
    let said: Denied | null | undefined;
    try {
      said = operation.denied?.(seen, at, plan);
    } catch (error) {
      console.error('coffre: a refused change was not logged', error);
    }
    return { refused: plan.refused, said };
  }

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
  const versions: Wire[] = [];
  /** A row of `table` as this change leaves it, by its key: the one it writes, or else the one it read. None for a row it drops. */
  const rowOf = <T extends Sealed>(table: T, key: object): Fresh<T> | undefined => {
    const name = nameOf(table, key);
    const made = plan.writes.find((write) => write.table === table && nameOf(table, write.row ?? write.was!) === name);
    if (made !== undefined) return (made.row ?? undefined) as Fresh<T> | undefined;
    for (const [row, of] of read) if (of === name) return row as Fresh<T>;
    return undefined;
  };
  for (const { version, text } of plan.values ?? []) {
    // Sealed under what its secret's row and its environment's say, as this change leaves them: a use opens it by the same rows.
    const held = plan.writes.find((write) => write.table === secrets && (write.row as { id?: string } | null)?.id === version.secretId)?.row as Fresh<typeof secrets> | undefined;
    const place = held && rowOf(environments, { id: held.environmentId });
    if (held === undefined || place === undefined || place.projectId !== held.projectId || held.currentVersion !== version.version || held.versions !== version.version) {
      throw new Error('a change writes a value as the current version of a secret it writes, in an environment of its project that it read');
    }
    if (version.plaintext !== null && version.plaintext !== text.toString('utf8')) throw new Error("a plain value's copy is the value");
    versions.push(toWire(secretVersions, { ...version, ...(await sealValue(text, contextOf(held, version, place.owner), vault.keks)) }));
  }
  // Dated now, as the write is sent: sealing a value, through a key service, takes as long as it takes.
  const entry = pending(key, plan.entry, vault.now(), rows);

  // The same rows, read again by the same conditions: one that changed, went or came since makes the lists differ.
  const again = sql.join(parts.map(([name, { table, where }]) => sql`SELECT ${sql.raw(`'${label(name)}:'`)} || encode(${table}.mac, 'hex') FROM ${table} WHERE ${where}`), sql` UNION ALL `);
  const statements: SQL[] = [sql`same AS (SELECT (SELECT coalesce(array_agg(x ORDER BY x COLLATE "C"), '{}') FROM (${again}) seen (x)) = ${sql.param(tokens.sort())}::text[] AS ok)`];
  const fromRows = (table: PgTable, wires: Wire[]) => sql`jsonb_populate_recordset(null::${table}, ${JSON.stringify(wires)}::jsonb) j, same WHERE same.ok`;
  for (const { table, inserts, updates, deletes } of written.values()) {
    const shape = shapeOf(table);
    const from = (wires: Wire[]) => fromRows(table, wires);
    const onKey = sql.join(shape.key.map(({ name }) => sql`${table}.${id(name)} = j.${id(name)}`), sql` AND `);
    const stored = shape.columns.filter((column) => !column.generated);
    // A row keeps its key, and what only says when it was last seen, which a use may have moved on since the read.
    const set = shape.columns.filter((column) => (column.sealed || column.name === 'mac') && !column.primary);
    if (inserts.length > 0) statements.push(sql`w${sql.raw(String(statements.length))} AS (INSERT INTO ${table} (${list(stored)}) SELECT ${list(stored, 'j')} FROM ${from(inserts)})`);
    if (updates.length > 0) statements.push(sql`w${sql.raw(String(statements.length))} AS (UPDATE ${table} SET (${list(set)}) = ROW(${list(set, 'j')}) FROM ${from(updates)} AND ${onKey})`);
    if (deletes.length > 0) statements.push(sql`w${sql.raw(String(statements.length))} AS (DELETE FROM ${table} USING ${from(deletes)} AND ${onKey})`);
  }
  // In the statement that writes its secret's row: the two are there together, or neither.
  if (versions.length > 0) {
    const stored = shapeOf(secretVersions).columns.filter((column) => !column.generated);
    statements.push(sql`versions AS (INSERT INTO ${secretVersions} (${list(stored)}) SELECT ${list(stored, 'j')} FROM ${fromRows(secretVersions, versions)})`);
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
export async function change<P extends Parts, A>(vault: Running, operation: Operation<P, A>): Promise<{ answer: A } | Refusal> {
  for (let attempt = 0; attempt < ATTEMPTS; attempt += 1) {
    const prepared = await prepare(vault, operation);
    if ('refused' in prepared) {
      if (prepared.said != null) await deny(vault, prepared.said);
      return { refused: prepared.refused };
    }
    if (await commit(vault, prepared)) return { answer: prepared.answer };
  }
  throw new Busy(`a change started ${ATTEMPTS} times over, each time behind another change to the rows it read`);
}
