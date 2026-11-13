import { entryLeaf, parseCheckpoint, splitNote, tileLeaves, type LogEntry, type PairNotes, type StoredPair, type Tile, type TileKey, type TreeName } from '@coffre/core/merkle';
import type { StoredEntry } from '@coffre/core/audit';
import type { Database } from '@coffre/db';
import { rowsOf } from '@coffre/db/dialect';
import { changesOf, entryColumns } from '@coffre/db/log';
import { auditLog } from '@coffre/db/schema';
import { and, asc, eq, gt, gte, lt, sql, type SQL } from 'drizzle-orm';

import type { AuditCursor } from './audit-rows.ts';

import { USE_AHEAD_MS, USE_DEADLINE_MS } from './bulk.ts';
import { misplaced, Refused, type CheckpointStore, type Locating } from './checkpointer.ts';
import { changeEntry, KEY_OBJECT, RETENTION_OBJECT, useEntry } from './log-entry.ts';
import type { ProjectionStore, rebuildRow } from './projection.ts';
import type { ReadRow, ReadsStore } from './reads.ts';
import type { CheckStore } from './audit-check.ts';
import type { RetentionStore } from './retention.ts';
import { latestSigned } from './store.ts';

/**
 * The checkpointer's database (checkpointer.ts, `CheckpointStore`): 0.15's
 * log, migration 0022. Every write goes
 * through 0022's functions, which run as their owner: the vault's login
 * reads `log_*` and writes none of it.
 *
 * - The barrier is `close_one`, under the fence exclusive; the window is
 *   read in the statement after it, in a snapshot that sees every append
 *   the barrier waited for (a snapshot from before its lock would miss
 *   those). Changes by number, their key; uses through their one index,
 *   `(at, request_id)`, from the floor the signer holds, and kept by
 *   number.
 * - A checkpoint is `write_checkpoint`: both trees' tiles and the pair, one
 *   call (PairWrittenTogether). Each range of the uses tree's leaf tiles is
 *   made (`make_tiles`) before a tile lands in it, the next one with it.
 * - Every read of uses is bounded by `at`, from the floor of the window it
 *   reads: none scans the history (R48).
 * - Retention (retention.ts, migration 0027): days made ahead, the
 *   retention change, and a day's partition and the tiles below a cut
 *   dropped, each through its function, which holds the vault's login to
 *   what a sealed retention change cuts.
 * - A rotation of the vault's signing key (T168, migration 0053): the
 *   rotation entries, by their object's index, and the rotation written
 *   with `log_rotate_number` and `log_rotate`, under the barrier's locks.
 */

/** How many leaves of the uses tree one range of its leaf tiles holds: 2^24, about 4.7 hours at 1,000 uses a second, 512 MB of tiles. */
export const TILE_RANGE = 2 ** 24;

/**
 * How far past its window's barrier floor a use's `at` may lie: the deadline (`deadline_max()`) and the minute
 * a Worker's clock may run ahead of Postgres's, which `use_credential` holds a use to (it answers `ahead`, and writes
 * nothing, past it). `locate` reads a use's window through the uses' one index within it.
 */
const AT_SLACK_MS = USE_DEADLINE_MS + USE_AHEAD_MS;

type Options = {
  /** Leaves per range of the uses tree's leaf tiles: `TILE_RANGE` unless set, smaller in tests. */
  tileRange?: number;
};

/** The log's rotations of the vault's signing key (T168), as the checkpointer reads and writes them (`Rotations`). */
export type RotationStore = {
  /** Every rotation entry, by number. */
  rotations(): Promise<LogEntry[]>;
  /**
   * The rotations and the newest pair, in one statement, so one snapshot
   * (Rotation.tla's SnapshotRead): what a reader that keeps nothing bounds
   * a replaced key from (keyring.ts).
   */
  keyringRows(): Promise<{ rotations: LogEntry[]; newest: StoredPair | null }>;
  /**
   * The rotation entry, under the barrier's locks (`log_rotate_number`,
   * then `log_rotate`, one transaction), `make` given its number first, so
   * that its payload names it under its MAC (NumberInRotation); and
   * `retire`, the tag of the key it moves the log from, added to the
   * fence's: its number, or null if the fence holds that tag already.
   */
  rotate(make: (number: bigint) => { requestId: string; at: number; payload: string; mac: Buffer }, retire: Buffer): Promise<bigint | null>;
};

/** The checkpointer's database, with retention's part, the projection's, its check's and the rotations'. */
export type LogStore = CheckpointStore & RetentionStore & ReadsStore & RotationStore & ProjectionStore & CheckStore;

export function logStore(db: Database, options: Options = {}): LogStore {
  const range = options.tileRange ?? TILE_RANGE;
  // A range holds whole leaf tiles: 256 leaves each.
  if (!Number.isSafeInteger(range) || range <= 0 || range % 256 !== 0) throw new Error(`tileRange must be a positive multiple of 256, not ${range}`);
  const base = postgresStore(db, range);
  const audit = projectionStore(db);
  return {
    ...base,
    ...audit,
    objects: objectsOf(db),
    async dropDay(day) {
      // The audit projection's rows of the day's uses, and the summary's reads older than its end: retention waits for
      // the projector to pass the cut (retention.ts), so none is listed after.
      await rowsOf(db, sql`SELECT drop_audit_day(${day}::date)`);
      return base.dropDay(day);
    },
  };
}

/** The pair's fields as `write_checkpoint` takes them, from its notes (the checkpointer signed them; nothing is checked here). */
function heads(notes: PairNotes) {
  const changes = parseCheckpoint(splitNote(notes.changes).text);
  const uses = parseCheckpoint(splitNote(notes.uses).text);
  return { upto: changes.upto, at: changes.at, floor: changes.floor, changes, uses };
}

type RawEntry = {
  tree: TreeName; number: string; at: string; requestId: string; mac: string;
  object?: string; actor?: string; payload?: string; seal?: string | null;
  credential?: string; secret?: string; purpose?: number; place?: string | null; route?: string | null;
};

const hex = (value: string | null | undefined) => (value === null || value === undefined ? null : Buffer.from(value, 'hex'));

function toEntry(r: RawEntry): LogEntry {
  if (r.tree === 'changes') {
    return changeEntry({
      number: BigInt(r.number), at: Number(r.at), requestId: r.requestId, object: r.object!, actor: r.actor!, payload: r.payload!, seal: hex(r.seal), mac: hex(r.mac)!,
    });
  }
  return useEntry({
    number: BigInt(r.number), at: Number(r.at), requestId: BigInt(r.requestId), credential: r.credential!, secret: r.secret!, purpose: Number(r.purpose), mac: hex(r.mac)!, place: r.place ?? null, route: r.route ?? null,
  });
}

/** A window read's first `limit` entries, by number, when the caller bounds it (`LogReader.entries`). */
function limitOf(limit: number | undefined): SQL {
  return limit === undefined ? sql`` : sql` LIMIT ${limit}`;
}

/**
 * One tree's half of a bounded read, its first `limit` in its index's
 * order, so that the database too stops there rather than sort every entry
 * above the cursor (PR 8 reviews r2, r3): the changes by number, their key;
 * the uses by `at`, their one index (`log_uses_request_idx`). By number, a
 * use may lie past one of them later by `at`: a read that fills its limit
 * says so, and is not taken as all there is (`verifyLog`'s `above`).
 */
function first(half: SQL, order: SQL, limit: number | undefined): SQL {
  return limit === undefined ? half : sql`SELECT * FROM (${half} ORDER BY ${order} LIMIT ${limit}) f`;
}

/**
 * The `at` a read of the entries in (after, upto] needs: from the floor of the pair at or below `after`, to the slack
 * past the floor of the first pair at or above `upto`, the barrier that sealed it; without one, no upper bound. A
 * verifier gives the floor its pair signed (`floor`): the row's own is a column any writer may raise, which would hide
 * every entry above the newest pair from it (review r9).
 */
function bounds(after: bigint, upto: bigint, floor?: number): [SQL, SQL] {
  return [
    floor === undefined ? sql`coalesce((SELECT k.at_floor FROM log_checkpoints k WHERE k.upto <= ${after} ORDER BY k.upto DESC LIMIT 1), 0)` : sql`${floor}`,
    sql`coalesce((SELECT k.at_floor FROM log_checkpoints k WHERE k.upto >= ${upto} ORDER BY k.upto LIMIT 1) + ${AT_SLACK_MS}, 9223372036854775807)`,
  ];
}

/**
 * The tiles asked, as constants in the statement, `(level = 0 AND leaf = 256) OR …`: Postgres then prunes the leaf
 * ranges as it plans. Passed as an array, every range was planned, 8.7 ms at 150 ranges, a month at 1,000 uses a
 * second, against 0.4 ms (Fable's review). Each is a whole number the code computed, checked before it is written.
 */
export function tileKeys(keys: readonly TileKey[]): SQL {
  return sql.raw(keys.map((k) => {
    const leaf = leafOf(k);
    if (!Number.isSafeInteger(k.level) || !Number.isSafeInteger(leaf) || k.level < 0 || leaf < 0) throw new Error(`not a tile: ${k.level}/${k.index}`);
    return `(t.level = ${k.level} AND t.leaf = ${leaf})`;
  }).join(' OR '));
}

type WindowRow = {
  tree: TreeName; n: string; at: string; request_id: string; mac: Buffer;
  object: string | null; actor: string | null; payload: string | null; seal: Buffer | null;
  credential: string | null; secret: string | null; purpose: number | null; place: string | null; route: string | null;
};

function fromRow(r: WindowRow): LogEntry {
  if (r.tree === 'changes') {
    return changeEntry({ number: BigInt(r.n), at: Number(r.at), requestId: r.request_id, object: r.object!, actor: r.actor!, payload: r.payload!, seal: r.seal, mac: r.mac });
  }
  return useEntry({ number: BigInt(r.n), at: Number(r.at), requestId: BigInt(r.request_id), credential: r.credential!, secret: r.secret!, purpose: r.purpose!, mac: r.mac, place: r.place, route: r.route });
}

type RawPair = { upto: string; changes: string; uses: string };
const toPair = (r: RawPair | null | undefined): StoredPair | null => (r === null || r === undefined ? null : { upto: BigInt(r.upto), notes: { changes: r.changes, uses: r.uses } });

const leafOf = (t: TileKey) => tileLeaves(t).first;
const indexOf = (level: number, leaf: number) => leaf / 2 ** (8 * (level + 1));

/**
 * A window's first `limit` entries by number, of the `limit + 1` read (T169): the one past them kept too when it holds
 * the last one's number (review r2), so that the tick's check sees two entries with one number and refuses, rather
 * than seal through a number whose second entry a writer put past the cut.
 */
function capped<E extends { number: bigint }>(read: E[], limit: number | undefined): E[] {
  if (limit === undefined || read.length <= limit) return read;
  return read[limit]!.number === read[limit - 1]!.number ? read : read.slice(0, limit);
}

/** One row, one JSON column `v`, as the reads below answer. */
async function one<T>(db: Database, query: SQL): Promise<T> {
  const [row] = await rowsOf<{ v: unknown }>(db, query);
  const v = row?.v;
  return (typeof v === 'string' ? JSON.parse(v) : v) as T;
}

/** The widest window of uses a proof reads the leaves of: 4,096 leaf tiles, some 17 minutes at 1,000 uses a second. */
const PROOF_WINDOW = 2 ** 20;

/** What `locate` reads in one statement: the entry, a change's place among its window's changes, and the uses tree's size at each end of the window. */
type Located = { entry: RawEntry | null; before: string | null; from: string | null; to: string | null };

/**
 * The use numbered as asked, in its window: at its time, when the caller
 * knows it (one probe of the uses' index), else anywhere in the `at` the
 * window's uses may hold, from the prior floor to the sealing barrier's slack.
 */
function useAt(at: number | undefined): SQL {
  return at === undefined ? sql`u.at >= p.at_floor AND u.at <= s.at_floor + ${AT_SLACK_MS}` : sql`u.at = ${at}`;
}

/**
 * The entry `locate` found, and its index in its tree. A change's is the
 * changes before it in its window, counted by number, their key. A use's
 * is where its leaf sits among the window's leaves, read from the uses
 * tree's leaf tiles (a tick's worth, two or three tiles at 1,000 uses a
 * second): counting the uses before it by `at` read every use the window's
 * slack holds, about 63,000 index entries at that rate (T119: 9.6 ms and
 * 1,397 buffers a proof, measured at 1M uses). A use whose leaf is not
 * there was changed since its tick. The window's bounds are its rows'
 * sizes, the database's: one wider than `PROOF_WINDOW` leaves is refused,
 * never scanned (PR 8 review r2).
 */
async function located(found: Located | null | undefined, tiles: (keys: TileKey[]) => Promise<Tile[]>, tree?: TreeName): Promise<{ entry: LogEntry; index: number } | null> {
  if (found === null || found === undefined || found.entry === null) return null;
  const entry = toEntry(found.entry);
  if (tree !== undefined && entry.tree !== tree) throw misplaced(entry, tree);
  if (entry.tree === 'changes') return found.before === null ? null : { entry, index: Number(found.before) };
  if (found.from === null || found.to === null) return null;
  const [from, to] = [Number(found.from), Number(found.to)];
  if (!(from <= to && to - from <= PROOF_WINDOW)) {
    throw new Refused(`use ${entry.number}'s window is ${from} to ${to} in the uses tree: no window of ${PROOF_WINDOW.toLocaleString('en')} leaves or fewer, so the database's checkpoint sizes are not the signer's, or a tick sealed a stall longer than a proof reads`);
  }
  const leaf = entryLeaf('uses', entry.number, entry.columns);
  const wanted: TileKey[] = [];
  for (let index = Math.floor(from / 256); index * 256 < to; index += 1) wanted.push({ level: 0, index });
  for (const tile of await tiles(wanted)) {
    for (let i = Math.max(from, tile.index * 256); i < Math.min(to, tile.index * 256 + tile.hashes.length / 32); i += 1) {
      const offset = (i - tile.index * 256) * 32;
      if (tile.hashes.subarray(offset, offset + 32).equals(leaf)) return { entry, index: i };
    }
  }
  throw new Refused(`use ${entry.number} is in none of its window's leaves: the database changed it since its tick`);
}

/** Postgres's read of the entries in (after, upto], by number, uses from `floor` to `ceiling`: the window's rows (`postgresStore`). */
export function postgresWindow(after: bigint, upto: bigint, floor: SQL, ceiling: SQL = sql`9223372036854775807`, limit?: number, byNumber = false): SQL {
  return sql`
      ${first(sql`SELECT 'changes' AS tree, c.number AS n, c.at::text AS at, c.request_id, c.object::text AS object, c.actor, c.payload, c.seal, c.mac,
             NULL::text AS credential, NULL::text AS secret, NULL::smallint AS purpose, NULL::text AS place, NULL::text AS route
        FROM log_changes c WHERE c.number > ${after} AND c.number <= ${upto}`, sql`c.number`, limit)}
      UNION ALL
      ${first(sql`SELECT 'uses', u.number, u.at::text, u.request_id::text, NULL::text, NULL::text, NULL::text, NULL::bytea, u.mac, u.credential::text, u.secret::text, u.purpose, u.place::text, u.route
        FROM log_uses u WHERE u.at >= ${floor} AND u.at <= ${ceiling} AND u.number > ${after} AND u.number <= ${upto}`, byNumber ? sql`u.number` : sql`u.at`, limit)}
      ORDER BY n${limitOf(limit)}`;
}

function postgresStore(db: Database, range: number): CheckpointStore & Omit<RetentionStore, 'auditCursor'> & RotationStore {
  const CHANGE = sql.raw(`json_build_object('tree', 'changes', 'number', c.number::text, 'at', c.at::text, 'requestId', c.request_id,
    'object', c.object::text, 'actor', c.actor, 'payload', c.payload, 'seal', encode(c.seal, 'hex'), 'mac', encode(c.mac, 'hex'))`);
  const USE = sql.raw(`json_build_object('tree', 'uses', 'number', u.number::text, 'at', u.at::text, 'requestId', u.request_id::text,
    'credential', u.credential::text, 'secret', u.secret::text, 'purpose', u.purpose, 'mac', encode(u.mac, 'hex'), 'place', u.place::text, 'route', u.route)`);
  const PAIR = sql.raw(`json_build_object('upto', k.upto::text, 'changes', k.changes_note, 'uses', k.uses_note)`);
  /** The entries in (after, upto], uses read from `floor` on: one JSON array, by number. */
  /**
   * The window as rows, by number: the tick's read, 500 entries every 500 ms at R44's rate, so no JSON is built
   * for it (measured: the window read 6.0 ms p50 as JSON).
   */
  const rows = (after: bigint, upto: bigint, floor: SQL, ceiling?: SQL, limit?: number, byNumber = false) =>
    rowsOf<WindowRow>(db, postgresWindow(after, upto, floor, ceiling, limit, byNumber));
  // The ranges this store made: each made once, not one statement more a tick. Retention (plan PR 7), which drops
  // ranges, forgets the ones it drops here (T119's item 2); and the days it made, which it forgets as it drops them.
  const made = new Set<number>();
  const madeDays = new Set<string>();
  /** The lowest `at` of the uses in (after, upto] from `from` on, null for none: the index by `at`, to the first in range. */
  const lowestAbove = async (after: bigint, upto: bigint, from: number) => {
    const at = await one<string | null>(db, sql`SELECT min(u.at)::text AS v FROM log_uses u WHERE u.at >= ${from}::bigint AND u.number > ${after} AND u.number <= ${upto}`);
    return at === null ? null : Number(at);
  };
  const tiles: LogStore['tiles'] = async (tree, keys) => {
    if (keys.length === 0) return [];
    const rows = await rowsOf<{ level: number; leaf: string; hashes: Buffer }>(db, sql`
      SELECT t.level, t.leaf::text, t.hashes FROM log_tiles t WHERE t.tree = ${tree} AND (${tileKeys(keys)})`);
    return rows.map((r) => ({ level: r.level, index: indexOf(r.level, Number(r.leaf)), hashes: Buffer.from(r.hashes) }));
  };
  return {
    async close(after, from, limit, told) {
      // The barrier, and the newest pair with it: only the checkpointer writes that row, so a snapshot from before the
      // barrier's lock holds it. The window comes in the next statement, a snapshot after the lock.
      // The ceiling is the clock less the deadline once close_one has run, as close_one raises the floor to it: no
      // barrier before this one can have left the floor above it (T169, a late one included).
      const [barrier] = await rowsOf<{ upto: string | null; at_floor: string | null; floor_found: string | null; ceiling: string; newest: RawPair | null }>(db, sql`
        SELECT b.upto::text, b.at_floor::text, b.floor_found::text,
               ((extract(epoch FROM clock_timestamp()) * 1000)::bigint - deadline_max())::text AS ceiling,
               (SELECT ${PAIR} FROM log_checkpoints k ORDER BY k.upto DESC LIMIT 1) AS newest
          FROM close_one() b`);
      const upto = BigInt(barrier?.upto ?? '0');
      told?.(upto);
      // The window by number, its first `limit` (T169): every use of the window read, sorted by number, which costs the
      // window's size; past the limit, the lowest `at` of the uses left above it, which the index finds past those read.
      const read = (await rows(after, upto, sql`${from}::bigint`, undefined, limit === undefined ? undefined : limit + 1, true)).map(fromRow);
      const entries = capped(read, limit);
      const more = entries === read ? null : { above: await lowestAbove(entries.at(-1)!.number, upto, from) };
      return {
        upto,
        newest: toPair(barrier?.newest),
        entries,
        floor: { found: barrier?.floor_found == null ? null : Number(barrier.floor_found), set: Number(barrier?.at_floor ?? 0), ceiling: Number(barrier?.ceiling) },
        more,
      };
    },
    async newest() {
      return toPair(await one<RawPair | null>(db, sql`SELECT ${PAIR} AS v FROM log_checkpoints k ORDER BY k.upto DESC LIMIT 1`));
    },
    async pairs(after, limit) {
      const rows = await one<RawPair[]>(db, sql`SELECT coalesce(json_agg(p.v ORDER BY p.upto), '[]') AS v FROM (
          SELECT k.upto, ${PAIR} AS v FROM log_checkpoints k WHERE k.upto > ${after} ORDER BY k.upto LIMIT ${limit}) p`);
      return rows.map((r) => toPair(r)!);
    },
    async pair(upto) {
      return toPair(await one<RawPair | null>(db, sql`SELECT ${PAIR} AS v FROM log_checkpoints k WHERE k.upto = ${upto}`));
    },
    async entries(after, upto, options = {}) {
      // The uses after `after` were admitted at or above the floor its barrier set (FloorChecked): read from there, up to
      // the slack past the floor of the barrier that sealed `upto`. Past the newest pair, unbounded: the head is near.
      const [floor, ceiling] = bounds(after, upto, options.floor);
      return (await rows(after, upto, floor, ceiling, options.limit)).map(fromRow);
    },
    tiles,
    async write(row, tiles) {
      // Each range a uses leaf tile falls in, and the one after it, made before the write needs them.
      for (const t of tiles.uses) {
        if (t.level !== 0) continue;
        const start = Math.floor(leafOf(t) / range) * range;
        for (const r of [start, start + range]) {
          if (made.has(r)) continue;
          await rowsOf(db, sql`SELECT make_tiles(${r}::bigint, ${r + range}::bigint)`);
          made.add(r);
        }
      }
      const all = [...tiles.changes.map((t) => ['changes', t] as const), ...tiles.uses.map((t) => ['uses', t] as const)];
      const h = heads(row.notes);
      await rowsOf(db, sql`SELECT write_checkpoint(
          ${row.upto}::bigint, ${h.at}::bigint, ${h.floor}::bigint,
          ${h.changes.size}::bigint, ${h.changes.root}::bytea, ${row.notes.changes},
          ${h.uses.size}::bigint, ${h.uses.root}::bytea, ${row.notes.uses},
          ${sql.param(all.map(([tree]) => tree))}::text[], ${sql.param(all.map(([, t]) => t.level))}::smallint[],
          ${sql.param(all.map(([, t]) => String(leafOf(t))))}::bigint[], ${sql.param(all.map(([, t]) => t.hashes))}::bytea[])`);
    },
    async locate(number, { at, tree }: Locating = {}) {
      const found = await one<Located | null>(db, sql`
        WITH sealing AS (SELECT upto, at_floor, uses_size FROM log_checkpoints WHERE upto >= ${number} ORDER BY upto LIMIT 1),
             prior AS (SELECT upto, at_floor, changes_size, uses_size FROM log_checkpoints WHERE upto < ${number} ORDER BY upto DESC LIMIT 1)
        SELECT json_build_object(
          'entry', coalesce(
            (SELECT ${CHANGE} FROM log_changes c WHERE c.number = ${number}),
            (SELECT ${USE} FROM log_uses u, prior p, sealing s WHERE ${useAt(at)} AND u.number = ${number} LIMIT 1)),
          'before', (SELECT p.changes_size + (SELECT count(*) FROM log_changes x WHERE x.number > p.upto AND x.number < ${number}) FROM prior p)::text,
          'from', (SELECT uses_size FROM prior)::text,
          'to', (SELECT uses_size FROM sealing)::text) AS v
        WHERE EXISTS (SELECT 1 FROM sealing)`);
      return located(found, (keys) => tiles('uses', keys), tree);
    },
    async retention() {
      // The newest at or below the newest checkpoint (sealed, as far as the database says: log_cut's), by its object's
      // index; then its place, as a proof reads it.
      const retained = changesOf('c', RETENTION_OBJECT);
      const [r] = await rowsOf<{ n: string | null }>(db, sql`SELECT (SELECT c.number FROM log_changes c
          WHERE ${retained.where} AND c.number <= (SELECT coalesce(max(k.upto), -1) FROM log_checkpoints k)
          ORDER BY ${retained.order} LIMIT 1)::text AS n`);
      return r?.n == null ? null : this.locate(BigInt(r.n), { tree: 'changes' });
    },
    async days() {
      // Every day of uses there is, attached or left detached by a drop that stopped between its two steps: the
      // catalog, not the uses, so that a quiet day, with none, is found too.
      const names = await rowsOf<{ name: string }>(db, sql`
        SELECT c.relname AS name FROM pg_class c WHERE c.relnamespace = 'public'::regnamespace AND c.relkind = 'r' AND c.relname ~ '^log_uses_[0-9]{8}$'`);
      return names.map((n) => `${n.name.slice(9, 13)}-${n.name.slice(13, 15)}-${n.name.slice(15, 17)}`).sort();
    },
    async makeDays(days) {
      for (const day of days) {
        if (madeDays.has(day)) continue;
        await rowsOf(db, sql`SELECT make_day(${day}::date)`);
        madeDays.add(day);
      }
    },
    async cutAt(ms) {
      return toPair(await one<RawPair | null>(db, sql`SELECT ${PAIR} AS v FROM log_checkpoints k WHERE k.at_floor >= ${ms} ORDER BY k.at_floor, k.upto LIMIT 1`));
    },
    async appendRetention(change) {
      const [row] = await rowsOf<{ n: string }>(db, sql`SELECT log_retention(${change.requestId}, ${change.at}::bigint, ${change.payload}, ${change.mac}::bytea)::text AS n`);
      return BigInt(row!.n);
    },
    async rotations() {
      return (await one<RawEntry[]>(db, sql`SELECT coalesce(json_agg(${CHANGE} ORDER BY c.number), '[]') AS v FROM log_changes c WHERE c.object = ${KEY_OBJECT}::uuid`)).map(toEntry);
    },
    async keyringRows() {
      const both = await one<{ rotations: RawEntry[]; newest: RawPair | null }>(db, sql`SELECT json_build_object(
        'rotations', (SELECT coalesce(json_agg(${CHANGE} ORDER BY c.number), '[]') FROM log_changes c WHERE c.object = ${KEY_OBJECT}::uuid),
        'newest', (SELECT ${PAIR} FROM log_checkpoints k ORDER BY k.upto DESC LIMIT 1)) AS v`);
      return { rotations: both.rotations.map(toEntry), newest: toPair(both.newest) };
    },
    async rotate(make, retire) {
      // One transaction: the locks `log_rotate_number` takes hold to its commit, the MAC made in between (a few µs).
      return db.transaction(async (tx) => {
        const [taken] = await rowsOf<{ n: string | null }>(tx, sql`SELECT log_rotate_number(${retire}::bytea)::text AS n`);
        if (taken?.n == null) return null;
        const number = BigInt(taken.n);
        const change = make(number);
        await rowsOf(tx, sql`SELECT log_rotate(${number}::bigint, ${change.requestId}, ${change.at}::bigint, ${change.payload}, ${change.mac}::bytea, ${retire}::bytea)`);
        return number;
      });
    },
    async dropDay(day) {
      const [row] = await rowsOf<{ state: 'detached' | 'dropped' | 'gone' }>(db, sql`SELECT drop_day(${day}::date) AS state`);
      if (row!.state !== 'detached') madeDays.delete(day);
      return row!.state;
    },
    async dropTiles(below) {
      // A step a call; each leaf range detached is forgotten, so that a write would make it again (T119's item 2): none does,
      // a write's tiles being at the edge, at or above every cut.
      let deleted = 0;
      for (let step = 0; step < 10_000; step += 1) {
        const [row] = await rowsOf<{ done: string }>(db, sql`SELECT drop_tiles(${below}::bigint) AS done`);
        const [what, name] = row!.done.split(' ') as [string, string];
        if (what === 'done') return deleted + Number(name);
        // Forgotten whichever step this call took: a DETACH whose answer was lost shows next as the range dropped.
        made.delete(Number(name.slice('log_tiles_uses_'.length)));
        if (what === 'detached') deleted += 1;
      }
      throw new Error('the tiles below the cut were not all dropped in 10,000 steps');
    },
    async pruneBulk(limit) {
      const [row] = await rowsOf<{ n: number }>(db, sql`SELECT prune_bulk(${limit}::int) AS n`);
      return Number(row!.n);
    },
  };
}

/** How many objects one statement of `objects` asks for. */
const OBJECTS_AT_ONCE = 200;

/** The objects a projection reads (reads.ts, `derive`): each asked's first change, or its newest below a number. */
function objectsOf(db: Database): ReadsStore['objects'] {
  const id = (value: string | null) => (value === null ? sql`NULL` : sql`CAST(${value} AS uuid)`);
  const text = (column: string) => sql.raw(`CAST(${column} AS text)`);
  // An asked object's first change and its newest below a number, each by its index (`changesOf`).
  const oldest = changesOf('b', sql.raw('a.object'), 'asc');
  const newest = changesOf('b', sql.raw('a.object'));
  return async (asked) => {
    const found: (LogEntry | null)[] = [];
    for (let at = 0; at < asked.length; at += OBJECTS_AT_ONCE) {
      const batch = asked.slice(at, at + OBJECTS_AT_ONCE);
      // Each asked's place and whether it wants the first change are the code's own whole numbers, written as such.
      const rows = sql.join(batch.map(({ object, below, first }, i) => (i === 0
        ? sql`SELECT ${sql.raw(String(i))} AS i, ${id(object)} AS object, CAST(${String(below)} AS bigint) AS below, ${sql.raw(first ? '1' : '0')} AS first`
        : sql`SELECT ${sql.raw(String(i))}, ${id(object)}, CAST(${String(below)} AS bigint), ${sql.raw(first ? '1' : '0')}`)), sql` UNION ALL `);
      // One probe of `log_changes_object_idx` each: the object's first change, or its newest below the number; whole,
      // for its MAC.
      const read = await rowsOf<{ i: number | string; n: string | number; at: string | number; request_id: string; object: string; actor: string; payload: string; seal: Uint8Array | null; mac: Uint8Array }>(db, sql`
        SELECT a.i, c.number AS n, ${text('c.at')} AS at, ${text('c.request_id')} AS request_id, ${text('c.object')} AS object, c.actor, c.payload, c.seal, c.mac FROM (${rows}) a
          JOIN log_changes c ON c.number = CASE WHEN a.first = 1
            THEN (SELECT b.number FROM log_changes b WHERE ${oldest.where} ORDER BY ${oldest.order} LIMIT 1)
            ELSE (SELECT b.number FROM log_changes b WHERE ${newest.where} AND b.number < a.below ORDER BY ${newest.order} LIMIT 1) END`);
      const byIndex = new Map(read.map((r) => [Number(r.i), r]));
      for (let i = 0; i < batch.length; i += 1) {
        const r = byIndex.get(i);
        found.push(r === undefined ? null : changeEntry({
          number: BigInt(r.n), at: Number(r.at), requestId: r.request_id, object: r.object, actor: r.actor, payload: r.payload,
          seal: r.seal === null ? null : Buffer.from(r.seal), mac: Buffer.from(r.mac),
        }));
      }
    }
    return found;
  };
}

/**
 * The audit projection's database (projection.ts; migration 0087):
 * its cursor, the 0.14 log's anchor and entries, the versions its entries
 * name by number, and the batch's write, `project_audit`, one statement.
 */
function projectionStore(db: Database): Pick<ProjectionStore, 'auditCursor' | 'oldAnchor' | 'oldEntries' | 'lossesAbove' | 'versionIds' | 'writeAudit'> & Pick<CheckStore, 'listed'> {
  const hex = (bytes: Buffer | null) => (bytes === null ? null : bytes.toString('hex'));
  const json = (value: unknown) => JSON.stringify(value, (_, inner: unknown) => (typeof inner === 'bigint' ? String(inner) : inner));
  const cursorJson = (c: AuditCursor) => json({
    through: c.through, pair: c.pair, at: c.at, oldFloor: c.oldFloor, oldFrom: c.oldFrom, oldTop: c.oldTop, oldHash: hex(c.oldHash), mac: hex(c.mac),
  });
  return {
    async auditCursor() {
      type Row = { through: string; pair: string; at: string; old_floor: string; old_from: string; old_top: string; old_hash: Uint8Array; mac: Uint8Array | null };
      const [row] = await rowsOf<Row>(db, sql`SELECT CAST(through AS text) AS through, CAST(pair AS text) AS pair, CAST(at AS text) AS at,
        CAST(old_floor AS text) AS old_floor, CAST(old_from AS text) AS old_from, CAST(old_top AS text) AS old_top, old_hash, mac FROM audit_cursor WHERE only_row`);
      // The migration's one row: gone, nothing is projected (a database writer's doing), never a fresh start.
      if (row === undefined) throw new Error("the audit cursor is gone: a database writer deleted it");
      return {
        through: BigInt(row.through), pair: BigInt(row.pair), at: Number(row.at), oldFloor: BigInt(row.old_floor), oldFrom: BigInt(row.old_from),
        oldTop: BigInt(row.old_top), oldHash: Buffer.from(row.old_hash), mac: row.mac === null ? null : Buffer.from(row.mac),
      };
    },
    async oldAnchor() {
      return (await latestSigned(db)) ?? null;
    },
    async oldEntries(from, below) {
      return await db.select(entryColumns()).from(auditLog).where(and(gte(auditLog.seq, from), lt(auditLog.seq, below))) as StoredEntry[];
    },
    async lossesAbove(seq) {
      return await db.select(entryColumns()).from(auditLog).where(and(eq(auditLog.action, 'audit.loss_accepted'), gt(auditLog.seq, seq))).orderBy(asc(auditLog.seq)) as StoredEntry[];
    },
    async versionIds(asked) {
      const found = new Map<string, string>();
      if (asked.length === 0) return found;
      const rows = await rowsOf<{ secret: string; version: number; id: string }>(db, sql`
        SELECT CAST(v.secret_id AS text) AS secret, v.version, CAST(v.id AS text) AS id
          FROM jsonb_to_recordset(${json(asked)}::jsonb) AS p (secret uuid, version integer)
          JOIN secret_versions v ON v.secret_id = p.secret AND v.version = p.version`);
      for (const row of rows) found.set(`${row.secret}:${Number(row.version)}`, row.id);
      return found;
    },
    async listed({ after, upto, from, to }) {
      const big = (value: bigint | number) => sql`CAST(${String(value)} AS bigint)`;
      type Row = {
        at: string; number: string; log: number | string; author: 'app' | 'vault'; action: string; shown: boolean; allowed: boolean; code: string | null; actor: string;
        subject: string | null; credential: string | null; project: string | null; environment: string | null; secret: string | null; version: string | null;
        places: string[]; request_id: string | null; operation_id: string | null; related: string | null; source_ip: string | null; detail: string; mac: Uint8Array;
        placed: string | number;
      };
      // By the primary key's range of times, each row's places counted on `audit_event_places`'s primary key.
      const rows = await rowsOf<Row>(db, sql`SELECT CAST(e.at AS text) AS at, CAST(e.number AS text) AS number, e.log, e.author, e.action, e.shown, e.allowed, e.code,
          e.actor, e.subject, CAST(e.credential AS text) AS credential, CAST(e.project AS text) AS project, CAST(e.environment AS text) AS environment,
          CAST(e.secret AS text) AS secret, CAST(e.version AS text) AS version, CAST(e.places AS text[]) AS places, e.request_id,
          CAST(e.operation_id AS text) AS operation_id, CAST(e.related AS text) AS related, e.source_ip, e.detail, e.mac,
          (SELECT count(*) FROM audit_event_places p WHERE p.place = ANY(e.places) AND p.at = e.at AND p.number = e.number AND p.log = e.log) AS placed
        FROM audit_events e WHERE e.at >= ${big(from)} AND e.at <= ${big(to)} AND e.log IN (15, 16) AND e.number > ${big(after)} AND e.number <= ${big(upto)}`);
      return rows.map((row) => ({
        at: Number(row.at), number: BigInt(row.number), log: Number(row.log) as 15 | 16, author: row.author, action: row.action, shown: row.shown, allowed: row.allowed,
        code: row.code, actor: row.actor, subject: row.subject, credential: row.credential, project: row.project, environment: row.environment, secret: row.secret,
        version: row.version, places: row.places, requestId: row.request_id, operationId: row.operation_id, related: row.related === null ? null : BigInt(row.related),
        sourceIp: row.source_ip, detail: row.detail, mac: Buffer.from(row.mac), placed: Number(row.placed) === new Set(row.places).size,
      }));
    },
    async writeAudit(events, keys, from, to) {
      const rows = events.map((row) => ({ ...row, mac: hex(row.mac) }));
      const [row] = await rowsOf<{ wrote: boolean }>(db, sql`SELECT project_audit(${json(rows)}::jsonb, ${json(keys)}::jsonb, ${cursorJson(from)}::jsonb,
        ${cursorJson(to)}::jsonb) AS wrote`);
      return row!.wrote === true;
    },
  };
}

/** `rebuild_audit`: the record, the cursor at the start and the tables emptied, one transaction. Its number. */
export async function callRebuild(db: Database, row: ReturnType<typeof rebuildRow>): Promise<bigint> {
  const [written] = await rowsOf<{ n: string }>(db, sql`SELECT CAST(rebuild_audit(
    ${String(row.at)}::bigint, ${row.requestId}::text, ${row.actor}::text, ${row.payload}::text, ${row.mac}::bytea
  ) AS text) AS n`);
  return BigInt(written!.n);
}

export type { ReadRow };
