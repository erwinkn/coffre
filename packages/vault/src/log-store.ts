import { entryLeaf, parseCheckpoint, splitNote, tileLeaves, type LogEntry, type PairNotes, type StoredPair, type Tile, type TileKey, type TreeName } from '@coffre/core/merkle';
import type { Database } from '@coffre/db';
import { engineOf, rowsOf } from '@coffre/db/dialect';
import { sql, type SQL } from 'drizzle-orm';

import { misplaced, Refused, type CheckpointStore, type Locating } from './checkpointer.ts';
import { logObject } from './inputs.ts';
import { changeEntry, RETENTION_ACTOR, RETENTION_OBJECT, useEntry } from './log-entry.ts';
import type { ReadPlace, ReadRow, ReadsCursor, ReadsStore } from './reads.ts';
import type { RetentionStore } from './retention.ts';

/**
 * The checkpointer's database (checkpointer.ts, `CheckpointStore`): 0.15's
 * log, migration 0022 on Postgres and 0018 on SQLite. Every write goes
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
 *
 * On SQLite one transaction runs at a time: the fence is implicit, every
 * number committed is final, and the barrier only moves the floor. The
 * writes are the same statements, in one transaction.
 */

/** How many leaves of the uses tree one range of its leaf tiles holds: 2^24, about 4.7 hours at 1,000 uses a second, 512 MB of tiles. */
export const TILE_RANGE = 2 ** 24;

/**
 * How far past its window's barrier floor a use's `at` may lie: the deadline (`deadline_max()`, 3 s) and the minute
 * a Worker's clock may run ahead of Postgres's, which `use_credential` holds a use to (it answers `ahead`, and writes
 * nothing, past it). `locate` reads a use's window through the uses' one index within it.
 */
const AT_SLACK_MS = 63_000;

type Options = {
  /** Leaves per range of the uses tree's leaf tiles (Postgres): `TILE_RANGE` unless set, smaller in tests. */
  tileRange?: number;
};

/** The checkpointer's database, with retention's part. */
export type LogStore = CheckpointStore & RetentionStore & ReadsStore;

export function logStore(db: Database, options: Options = {}): LogStore {
  const range = options.tileRange ?? TILE_RANGE;
  // A range holds whole leaf tiles: 256 leaves each.
  if (!Number.isSafeInteger(range) || range <= 0 || range % 256 !== 0) throw new Error(`tileRange must be a positive multiple of 256, not ${range}`);
  const base = engineOf(db) === 'postgres' ? postgresStore(db, range) : sqliteStore(db);
  const reads = readsStore(db);
  return {
    ...base,
    readsCursor: reads.readsCursor,
    objects: reads.objects,
    writeReads: reads.writeReads,
    listing: reads.listing,
    makeReadsDays: (days) => reads.makeDays(days),
    // The reads' days with the uses' (T166): made beside them, and gone once they are.
    async makeDays(days) {
      await base.makeDays(days);
      await reads.makeDays(days);
    },
    async dropDay(day) {
      const state = await base.dropDay(day);
      if (state !== 'detached') await reads.dropDay(day);
      return state;
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
  credential?: string; secret?: string; purpose?: number; place?: string | null;
};

const hex = (value: string | null | undefined) => (value === null || value === undefined ? null : Buffer.from(value, 'hex'));

function toEntry(r: RawEntry): LogEntry {
  if (r.tree === 'changes') {
    return changeEntry({
      number: BigInt(r.number), at: Number(r.at), requestId: r.requestId, object: r.object!, actor: r.actor!, payload: r.payload!, seal: hex(r.seal), mac: hex(r.mac)!,
    });
  }
  return useEntry({
    number: BigInt(r.number), at: Number(r.at), requestId: BigInt(r.requestId), credential: r.credential!, secret: r.secret!, purpose: Number(r.purpose), mac: hex(r.mac)!, place: r.place ?? null,
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
  credential: string | null; secret: string | null; purpose: number | null; place: string | null;
};

function fromRow(r: WindowRow): LogEntry {
  if (r.tree === 'changes') {
    return changeEntry({ number: BigInt(r.n), at: Number(r.at), requestId: r.request_id, object: r.object!, actor: r.actor!, payload: r.payload!, seal: r.seal, mac: r.mac });
  }
  return useEntry({ number: BigInt(r.n), at: Number(r.at), requestId: BigInt(r.request_id), credential: r.credential!, secret: r.secret!, purpose: r.purpose!, mac: r.mac, place: r.place });
}

type RawPair = { upto: string; changes: string; uses: string };
const toPair = (r: RawPair | null | undefined): StoredPair | null => (r === null || r === undefined ? null : { upto: BigInt(r.upto), notes: { changes: r.changes, uses: r.uses } });

const leafOf = (t: TileKey) => tileLeaves(t).first;
/** A UTC day, YYYY-MM-DD, as ms since the epoch at its start. */
const dayStart = (day: string) => Date.parse(`${day}T00:00:00Z`);
const DAY_MS = 86_400_000;
const indexOf = (level: number, leaf: number) => leaf / 2 ** (8 * (level + 1));

/** One row, one JSON column `v`, as both dialects answer the reads below. */
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
export function postgresWindow(after: bigint, upto: bigint, floor: SQL, ceiling: SQL = sql`9223372036854775807`, limit?: number): SQL {
  return sql`
      ${first(sql`SELECT 'changes' AS tree, c.number AS n, c.at::text AS at, c.request_id, c.object::text AS object, c.actor, c.payload, c.seal, c.mac,
             NULL::text AS credential, NULL::text AS secret, NULL::smallint AS purpose, NULL::text AS place
        FROM log_changes c WHERE c.number > ${after} AND c.number <= ${upto}`, sql`c.number`, limit)}
      UNION ALL
      ${first(sql`SELECT 'uses', u.number, u.at::text, u.request_id::text, NULL::text, NULL::text, NULL::text, NULL::bytea, u.mac, u.credential::text, u.secret::text, u.purpose, u.place::text
        FROM log_uses u WHERE u.at >= ${floor} AND u.at <= ${ceiling} AND u.number > ${after} AND u.number <= ${upto}`, sql`u.at`, limit)}
      ORDER BY n${limitOf(limit)}`;
}

function postgresStore(db: Database, range: number): CheckpointStore & Omit<RetentionStore, 'readsCursor'> {
  const CHANGE = sql.raw(`json_build_object('tree', 'changes', 'number', c.number::text, 'at', c.at::text, 'requestId', c.request_id,
    'object', c.object::text, 'actor', c.actor, 'payload', c.payload, 'seal', encode(c.seal, 'hex'), 'mac', encode(c.mac, 'hex'))`);
  const USE = sql.raw(`json_build_object('tree', 'uses', 'number', u.number::text, 'at', u.at::text, 'requestId', u.request_id::text,
    'credential', u.credential::text, 'secret', u.secret::text, 'purpose', u.purpose, 'mac', encode(u.mac, 'hex'), 'place', u.place::text)`);
  const PAIR = sql.raw(`json_build_object('upto', k.upto::text, 'changes', k.changes_note, 'uses', k.uses_note)`);
  /** The entries in (after, upto], uses read from `floor` on: one JSON array, by number. */
  /**
   * The window as rows, by number: the tick's read, 500 entries every 500 ms at R44's rate, so no JSON is built
   * for it (measured: the window read 6.0 ms p50 as JSON).
   */
  const rows = (after: bigint, upto: bigint, floor: SQL, ceiling?: SQL, limit?: number) => rowsOf<WindowRow>(db, postgresWindow(after, upto, floor, ceiling, limit));
  // The ranges this store made: each made once, not one statement more a tick. Retention (plan PR 7), which drops
  // ranges, forgets the ones it drops here (T119's item 2); and the days it made, which it forgets as it drops them.
  const made = new Set<number>();
  const madeDays = new Set<string>();
  const tiles: LogStore['tiles'] = async (tree, keys) => {
    if (keys.length === 0) return [];
    const rows = await rowsOf<{ level: number; leaf: string; hashes: Buffer }>(db, sql`
      SELECT t.level, t.leaf::text, t.hashes FROM log_tiles t WHERE t.tree = ${tree} AND (${tileKeys(keys)})`);
    return rows.map((r) => ({ level: r.level, index: indexOf(r.level, Number(r.leaf)), hashes: Buffer.from(r.hashes) }));
  };
  return {
    async close(after, from) {
      // The barrier, and the newest pair with it: only the checkpointer writes that row, so a snapshot from before the
      // barrier's lock holds it. The window comes in the next statement, a snapshot after the lock.
      const [barrier] = await rowsOf<{ upto: string | null; at_floor: string | null; floor_found: string | null; newest: RawPair | null }>(db, sql`
        SELECT b.upto::text, b.at_floor::text, b.floor_found::text, (SELECT ${PAIR} FROM log_checkpoints k ORDER BY k.upto DESC LIMIT 1) AS newest
          FROM close_one() b`);
      const upto = BigInt(barrier?.upto ?? '0');
      return {
        upto,
        newest: toPair(barrier?.newest),
        entries: (await rows(after, upto, sql`${from}::bigint`)).map(fromRow),
        floor: { found: barrier?.floor_found == null ? null : Number(barrier.floor_found), set: Number(barrier?.at_floor ?? 0) },
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
      const [r] = await rowsOf<{ n: string | null }>(db, sql`SELECT (SELECT c.number FROM log_changes c
          WHERE c.object = ${RETENTION_OBJECT}::uuid AND c.number <= (SELECT coalesce(max(k.upto), -1) FROM log_checkpoints k)
          ORDER BY c.number DESC LIMIT 1)::text AS n`);
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

function sqliteStore(db: Database): CheckpointStore & Omit<RetentionStore, 'readsCursor'> {
  const CHANGE = sql.raw(`json_object('tree', 'changes', 'number', CAST(c.number AS TEXT), 'at', CAST(c.at AS TEXT), 'requestId', c.request_id,
    'object', c.object, 'actor', c.actor, 'payload', c.payload, 'seal', CASE WHEN c.seal IS NULL THEN NULL ELSE hex(c.seal) END, 'mac', hex(c.mac))`);
  const USE = sql.raw(`json_object('tree', 'uses', 'number', CAST(u.number AS TEXT), 'at', CAST(u.at AS TEXT), 'requestId', CAST(u.request_id AS TEXT),
    'credential', u.credential, 'secret', u.secret, 'purpose', u.purpose, 'mac', hex(u.mac), 'place', u.place)`);
  const PAIR = sql.raw(`json_object('upto', CAST(k.upto AS TEXT), 'changes', k.changes_note, 'uses', k.uses_note)`);
  const window = (after: bigint, upto: bigint, floor: SQL, ceiling: SQL = sql`9223372036854775807`, limit?: number) => sql`(SELECT coalesce(json_group_array(json(e.v)), '[]') FROM (
      ${first(sql`SELECT c.number AS n, ${CHANGE} AS v FROM log_changes c WHERE c.number > ${after} AND c.number <= ${upto}`, sql`c.number`, limit)}
      UNION ALL
      ${first(sql`SELECT u.number, ${USE} AS v FROM log_uses u WHERE u.at >= ${floor} AND u.at <= ${ceiling} AND u.number > ${after} AND u.number <= ${upto}`, sql`u.at`, limit)}
      ORDER BY 1${limitOf(limit)}
    ) e)`;
  const NOW = sql.raw(`CAST(unixepoch('subsec') * 1000 AS INTEGER)`);
  const tiles: LogStore['tiles'] = async (tree, keys) => {
    if (keys.length === 0) return [];
    const wanted = JSON.stringify(keys.map((k) => [k.level, leafOf(k)]));
    const rows = await rowsOf<{ level: number; leaf: number; hashes: Uint8Array }>(db, sql`
      SELECT t.level, t.leaf, t.hashes FROM log_tiles t
       WHERE t.tree = ${tree} AND (t.level, t.leaf) IN (SELECT json_extract(value, '$[0]'), json_extract(value, '$[1]') FROM json_each(${wanted}))`);
    return rows.map((r) => ({ level: Number(r.level), index: indexOf(Number(r.level), Number(r.leaf)), hashes: Buffer.from(r.hashes) }));
  };
  return {
    async close(after, from) {
      // One writer: every number committed is final. The barrier only moves the floor, as close_one does.
      const barrier = await db.transaction(async (tx) => {
        const [fence] = await rowsOf<{ at_floor: number }>(tx, sql`SELECT at_floor FROM log_fence WHERE only_row`);
        await rowsOf(tx, sql`UPDATE log_fence SET at_floor = max(at_floor, ${NOW} - 3000) WHERE only_row`);
        const [now] = await rowsOf<{ at_floor: number; upto: number | null }>(tx, sql`
          SELECT (SELECT at_floor FROM log_fence WHERE only_row) AS at_floor,
                 max(coalesce((SELECT max(number) FROM log_changes), 0), coalesce((SELECT max(number) FROM log_uses), 0)) AS upto`);
        return { found: fence?.at_floor ?? null, set: Number(now!.at_floor), upto: BigInt(now!.upto ?? 0) };
      });
      const read = await one<{ newest: RawPair | null; entries: RawEntry[] }>(db, sql`SELECT json_object(
          'newest', json((SELECT ${PAIR} FROM log_checkpoints k ORDER BY k.upto DESC LIMIT 1)),
          'entries', json(${window(after, barrier.upto, sql`${from}`)})) AS v`);
      return {
        upto: barrier.upto,
        newest: toPair(read.newest),
        entries: read.entries.map(toEntry),
        floor: { found: barrier.found === null ? null : Number(barrier.found), set: barrier.set },
      };
    },
    async newest() {
      return toPair(await one<RawPair | null>(db, sql`SELECT ${PAIR} AS v FROM log_checkpoints k ORDER BY k.upto DESC LIMIT 1`));
    },
    async pairs(after, limit) {
      const rows = await one<RawPair[]>(db, sql`SELECT coalesce(json_group_array(json(p.v)), '[]') AS v FROM (
          SELECT ${PAIR} AS v FROM log_checkpoints k WHERE k.upto > ${after} ORDER BY k.upto LIMIT ${limit}) p`);
      return rows.map((r) => toPair(r)!);
    },
    async pair(upto) {
      return toPair(await one<RawPair | null>(db, sql`SELECT ${PAIR} AS v FROM log_checkpoints k WHERE k.upto = ${upto}`));
    },
    async entries(after, upto, options = {}) {
      const [floor, ceiling] = bounds(after, upto, options.floor);
      return (await one<RawEntry[]>(db, sql`SELECT ${window(after, upto, floor, ceiling, options.limit)} AS v`)).map(toEntry);
    },
    tiles,
    async write(row, tiles) {
      const h = heads(row.notes);
      await db.transaction(async (tx) => {
        for (const [tree, t] of [...tiles.changes.map((t) => ['changes', t] as const), ...tiles.uses.map((t) => ['uses', t] as const)]) {
          // A tile only grows: written again with the same bytes, or wider, never anything else (write_checkpoint's rule).
          const [kept] = await rowsOf<{ n: number }>(tx, sql`
            INSERT INTO log_tiles (tree, level, leaf, hashes) VALUES (${tree}, ${t.level}, ${leafOf(t)}, ${t.hashes})
            ON CONFLICT (tree, level, leaf) DO UPDATE SET hashes = excluded.hashes
             WHERE substr(excluded.hashes, 1, length(log_tiles.hashes)) = log_tiles.hashes
            RETURNING 1 AS n`);
          if (kept === undefined) throw new Error(`a tile would shrink or change: ${tree} ${t.level}/${t.index}`);
        }
        await rowsOf(tx, sql`INSERT INTO log_checkpoints (upto, at, at_floor, changes_size, changes_root, changes_note, uses_size, uses_root, uses_note)
          VALUES (${row.upto}, ${h.at}, ${h.floor}, ${h.changes.size}, ${h.changes.root}, ${row.notes.changes}, ${h.uses.size}, ${h.uses.root}, ${row.notes.uses})`);
      });
    },
    async locate(number, { at, tree }: Locating = {}) {
      const found = await one<Located | null>(db, sql`
        WITH sealing AS (SELECT upto, at_floor, uses_size FROM log_checkpoints WHERE upto >= ${number} ORDER BY upto LIMIT 1),
             prior AS (SELECT upto, at_floor, changes_size, uses_size FROM log_checkpoints WHERE upto < ${number} ORDER BY upto DESC LIMIT 1)
        SELECT json_object(
          'entry', json(coalesce(
            (SELECT ${CHANGE} FROM log_changes c WHERE c.number = ${number}),
            (SELECT ${USE} FROM log_uses u, prior p, sealing s WHERE ${useAt(at)} AND u.number = ${number} LIMIT 1))),
          'before', CAST((SELECT p.changes_size + (SELECT count(*) FROM log_changes x WHERE x.number > p.upto AND x.number < ${number}) FROM prior p) AS TEXT),
          'from', CAST((SELECT uses_size FROM prior) AS TEXT),
          'to', CAST((SELECT uses_size FROM sealing) AS TEXT)) AS v
        WHERE EXISTS (SELECT 1 FROM sealing)`);
      return located(found, (keys) => tiles('uses', keys), tree);
    },
    // Retention on SQLite (tests and local development): no partitions, so a day's uses and the tiles below a cut are
    // deleted rows, in one statement each; no functions, so no checks but the vault's own.
    async retention() {
      const [r] = await rowsOf<{ n: string | null }>(db, sql`SELECT CAST((SELECT c.number FROM log_changes c
          WHERE c.object = ${RETENTION_OBJECT} AND c.number <= (SELECT coalesce(max(k.upto), -1) FROM log_checkpoints k)
          ORDER BY c.number DESC LIMIT 1) AS TEXT) AS n`);
      return r?.n == null ? null : this.locate(BigInt(r.n), { tree: 'changes' });
    },
    async days() {
      // Each day that holds a use: the first use at or past the end of the one before, by the uses' index, a probe a day.
      const days: string[] = [];
      for (let from = Number.MIN_SAFE_INTEGER; ;) {
        const [r] = await rowsOf<{ at: number | null }>(db, sql`SELECT min(at) AS at FROM log_uses WHERE at >= ${from}`);
        if (r?.at == null) return days;
        const start = Math.floor(Number(r.at) / DAY_MS) * DAY_MS;
        days.push(new Date(start).toISOString().slice(0, 10));
        from = start + DAY_MS;
      }
    },
    async makeDays() {},
    async cutAt(ms) {
      return toPair(await one<RawPair | null>(db, sql`SELECT ${PAIR} AS v FROM log_checkpoints k WHERE k.at_floor >= ${ms} ORDER BY k.at_floor, k.upto LIMIT 1`));
    },
    async appendRetention(change) {
      return db.transaction(async (tx) => {
        const [found] = await rowsOf<{ n: string }>(tx, sql`SELECT CAST(number AS TEXT) AS n FROM log_changes WHERE request_id = ${change.requestId}`);
        if (found !== undefined) return BigInt(found.n);
        const [next] = await rowsOf<{ n: string }>(tx, sql`SELECT CAST(max(coalesce((SELECT max(number) FROM log_changes), 0), coalesce((SELECT max(number) FROM log_uses), 0)) + 1 AS TEXT) AS n`);
        await rowsOf(tx, sql`INSERT INTO log_changes (number, at, request_id, object, actor, payload, seal, mac)
          VALUES (${BigInt(next!.n)}, ${change.at}, ${change.requestId}, ${RETENTION_OBJECT}, ${RETENTION_ACTOR}, ${change.payload}, NULL, ${change.mac})`);
        return BigInt(next!.n);
      });
    },
    async dropDay(day) {
      await rowsOf(db, sql`DELETE FROM log_uses WHERE at >= ${dayStart(day)} AND at < ${dayStart(day) + DAY_MS}`);
      return 'gone';
    },
    async dropTiles(below) {
      // A tile goes once every leaf it stands for lies below the cut; level 7's one tile spans past any (2^64 leaves).
      const deleted = await rowsOf(db, sql`DELETE FROM log_tiles WHERE tree = 'uses' AND level < 7 AND leaf + (1 << (8 * (level + 1))) <= ${below} RETURNING 1 AS n`);
      return deleted.length;
    },
    async pruneBulk(limit) {
      // prune_bulk's bound (migration 0022): the policy's window, its refresh, the deadline and an hour.
      const pruned = await rowsOf(db, sql`DELETE FROM log_bulk WHERE rowid IN (
          SELECT b.rowid FROM log_bulk b, (
            SELECT CAST(json_extract(x.payload, '$.value.bulk.windowMs') AS INTEGER) AS w FROM log_changes x
             WHERE x.object = ${logObject('policy', 'instance')} ORDER BY x.number DESC LIMIT 1) p
           WHERE p.w IS NOT NULL AND b.last < ${NOW} - p.w - min(60000, p.w / 10) - 3000 - 3600000 LIMIT ${limit})
        RETURNING 1 AS n`);
      return pruned.length;
    },
  };
}

/**
 * The projection of reads (reads.ts, T166), on either engine: its cursor,
 * the objects a projection reads, its write, and its days. On Postgres the
 * write is `project_reads`, which takes the rows, each once, and moves the
 * cursor on after them, never past the newest pair; SQLite, one writer and
 * no partitions, writes them in a transaction, and drops a day's by `at`.
 */
/** How many objects one statement of `objects` asks for. */
const OBJECTS_AT_ONCE = 200;

function readsStore(db: Database): Pick<ReadsStore, 'readsCursor' | 'objects' | 'writeReads' | 'listing'> & { makeDays(days: readonly string[]): Promise<void>; dropDay(day: string): Promise<void> } {
  const postgres = engineOf(db) === 'postgres';
  const made = new Set<string>();
  const id = (value: string | null) => (value === null ? sql`NULL` : postgres ? sql`CAST(${value} AS uuid)` : sql`${value}`);
  const text = (column: string) => sql.raw(postgres ? `CAST(${column} AS text)` : column);
  return {
    async readsCursor() {
      const [row] = await rowsOf<{ through: string | number; pair: string | number; at: string | number; mac: Uint8Array | null }>(db, sql`SELECT through, pair, at, mac FROM log_reads_cursor WHERE only_row`);
      return row === undefined ? { through: 0n, pair: 0n, at: 0, mac: null } : { through: BigInt(row.through), pair: BigInt(row.pair), at: Number(row.at), mac: row.mac === null ? null : Buffer.from(row.mac) };
    },
    async objects(asked) {
      const found: (LogEntry | null)[] = [];
      // A few hundred a statement: SQLite takes 500 terms of a compound SELECT at most.
      for (let at = 0; at < asked.length; at += OBJECTS_AT_ONCE) {
        const batch = asked.slice(at, at + OBJECTS_AT_ONCE);
        // Each asked's place and whether it wants the first change are the code's own whole numbers, written as such.
        const rows = sql.join(batch.map(({ object, below, first }, i) => (i === 0
          ? sql`SELECT ${sql.raw(String(i))} AS i, ${id(object)} AS object, CAST(${String(below)} AS ${sql.raw(postgres ? 'bigint' : 'INTEGER')}) AS below, ${sql.raw(first ? '1' : '0')} AS first`
          : sql`SELECT ${sql.raw(String(i))}, ${id(object)}, CAST(${String(below)} AS ${sql.raw(postgres ? 'bigint' : 'INTEGER')}), ${sql.raw(first ? '1' : '0')}`)), sql` UNION ALL `);
        // One probe of `log_changes_object_idx` each: the object's first change, or its newest below the number; whole,
        // for its MAC.
        const read = await rowsOf<{ i: number | string; n: string | number; at: string | number; request_id: string; object: string; actor: string; payload: string; seal: Uint8Array | null; mac: Uint8Array }>(db, sql`
          SELECT a.i, c.number AS n, ${text('c.at')} AS at, ${text('c.request_id')} AS request_id, ${text('c.object')} AS object, c.actor, c.payload, c.seal, c.mac FROM (${rows}) a
            JOIN log_changes c ON c.number = CASE WHEN a.first = 1
              THEN (SELECT min(b.number) FROM log_changes b WHERE b.object = a.object)
              ELSE (SELECT max(b.number) FROM log_changes b WHERE b.object = a.object AND b.number < a.below) END`);
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
    },
    async writeReads(reads, places, cursor) {
      if (postgres) {
        const json = (rows: readonly object[]) => JSON.stringify(rows, (_, value: unknown) => (typeof value === 'bigint' ? String(value) : Buffer.isBuffer(value) ? value.toString('hex') : value));
        const wire = reads.map((row) => ({ ...row, mac: row.mac.toString('hex') }));
        await rowsOf(db, sql`SELECT project_reads(${json(wire)}::jsonb, ${json(places)}::jsonb, ${String(cursor.through)}::bigint, ${String(cursor.pair)}::bigint, ${cursor.at}::bigint, ${cursor.mac}::bytea)`);
        return;
      }
      await db.transaction(async (raw) => {
        const tx = raw as unknown as Database;
        const [cut] = await rowsOf<{ sealed: string | number | null }>(tx, sql`SELECT max(upto) AS sealed FROM log_checkpoints`);
        if (cut?.sealed == null || cursor.through > BigInt(cut.sealed)) throw new Error(`reads through ${cursor.through} are past the newest pair`);
        // The projector's row over any other at its number (ReplaceOnConflict), each place once.
        for (const row of reads) {
          await rowsOf(tx, sql`INSERT INTO log_reads (number, at, credential, purpose, principal, secret, environment, project, place, source, source_environment, source_project, version, mac)
            VALUES (${row.number}, ${row.at}, ${row.credential}, ${row.purpose}, ${row.principal}, ${row.secret}, ${row.environment}, ${row.project}, ${row.place}, ${row.source},
              ${row.sourceEnvironment}, ${row.sourceProject}, ${row.version}, ${row.mac})
            ON CONFLICT (at, number) DO UPDATE SET credential = excluded.credential, purpose = excluded.purpose, principal = excluded.principal, secret = excluded.secret,
              environment = excluded.environment, project = excluded.project, place = excluded.place, source = excluded.source, source_environment = excluded.source_environment,
              source_project = excluded.source_project, version = excluded.version, mac = excluded.mac`);
        }
        for (const place of places) {
          const partners = JSON.stringify(place.partners);
          await rowsOf(tx, sql`INSERT INTO log_read_places (environment, partners, at, number, principal, secret)
            VALUES (${place.environment}, ${partners}, ${place.at}, ${place.number}, ${place.principal}, ${place.secret})
            ON CONFLICT (environment, partners, at, number, secret) DO UPDATE SET principal = excluded.principal`);
          await rowsOf(tx, sql`INSERT INTO log_read_partners (environment, partners) VALUES (${place.environment}, ${partners}) ON CONFLICT DO NOTHING`);
        }
        await rowsOf(tx, sql`UPDATE log_reads_cursor SET through = ${cursor.through}, pair = ${cursor.pair}, at = ${cursor.at}, mac = ${cursor.mac} WHERE only_row AND through < ${cursor.through}`);
      });
    },
    async listing({ after, upto, from, to }, places) {
      const big = (value: bigint | number) => (postgres ? sql`CAST(${String(value)} AS bigint)` : sql`${value}`);
      const found = await rowsOf<{
        number: string | number; at: string | number; credential: string; purpose: string | number; principal: string; secret: string; environment: string; project: string;
        place: string | null; source: string | null; source_environment: string | null; source_project: string | null; version: string | null; mac: Uint8Array;
      }>(db, sql`SELECT number, at, ${text('credential')} AS credential, purpose, principal, ${text('secret')} AS secret, ${text('environment')} AS environment, ${text('project')} AS project,
          ${text('place')} AS place, ${text('source')} AS source, ${text('source_environment')} AS source_environment, ${text('source_project')} AS source_project, ${text('version')} AS version, mac
        FROM log_reads WHERE at >= ${big(from)} AND at <= ${big(to)} AND number > ${big(after)} AND number <= ${big(upto)}`);
      const reads = found.map((row): ReadRow => ({
        number: BigInt(row.number), at: Number(row.at), credential: row.credential, purpose: Number(row.purpose), principal: row.principal, secret: row.secret,
        environment: row.environment, project: row.project, place: row.place, source: row.source, sourceEnvironment: row.source_environment,
        sourceProject: row.source_project, version: row.version, mac: Buffer.from(row.mac),
      }));
      // Each place by its unique index, a probe each, a few hundred to a statement; each set of places by its key.
      const set = (partners: readonly string[]) => (postgres
        ? sql`CAST(${`{${partners.join(',')}}`} AS uuid[])`
        : sql`${JSON.stringify(partners)}`);
      const key = (p: { environment: string; partners: readonly string[]; at?: number; number?: bigint; secret?: string }) => `${p.environment}:${p.partners.join(',')}:${p.at ?? ''}:${p.number ?? ''}:${p.secret ?? ''}`;
      const listedAt = new Map<string, string>();
      const paired = new Set<string>();
      const partnersOf = (value: string | string[]) => (Array.isArray(value) ? value : (JSON.parse(value) as string[]));
      for (let i = 0; i < places.length; i += 500) {
        const chunk = places.slice(i, i + 500);
        const rows = await rowsOf<{ environment: string; partners: string | string[]; at: string | number; number: string | number; principal: string; secret: string }>(db, sql`
          SELECT ${text('environment')} AS environment, ${sql.raw(postgres ? 'CAST(to_json(partners) AS text)' : 'partners')} AS partners, at, number, principal, ${text('secret')} AS secret
            FROM log_read_places WHERE (environment, partners, at, number, secret) IN (VALUES ${sql.join(chunk.map((p) => sql`(${id(p.environment)}, ${set(p.partners)}, ${big(p.at)}, ${big(p.number)}, ${id(p.secret)})`), sql`, `)})`);
        for (const row of rows) listedAt.set(key({ ...row, partners: partnersOf(row.partners), at: Number(row.at), number: BigInt(row.number) }), row.principal);
      }
      const sets = [...new Map(places.map((p) => [key({ environment: p.environment, partners: p.partners }), p])).values()];
      for (let i = 0; i < sets.length; i += 500) {
        const chunk = sets.slice(i, i + 500);
        const rows = await rowsOf<{ environment: string; partners: string | string[] }>(db, sql`
          SELECT ${text('environment')} AS environment, ${sql.raw(postgres ? 'CAST(to_json(partners) AS text)' : 'partners')} AS partners FROM log_read_partners
            WHERE (environment, partners) IN (VALUES ${sql.join(chunk.map((p) => sql`(${id(p.environment)}, ${set(p.partners)})`), sql`, `)})`);
        for (const row of rows) paired.add(key({ environment: row.environment, partners: partnersOf(row.partners) }));
      }
      return {
        reads,
        places: places.map((place) => listedAt.get(key(place)) ?? null),
        pairs: places.map((place) => paired.has(key({ environment: place.environment, partners: place.partners }))),
      };
    },
    async makeDays(days) {
      if (!postgres) return;
      for (const day of days) {
        if (made.has(day)) continue;
        await rowsOf(db, sql`SELECT make_reads_day(${day}::date)`);
        made.add(day);
      }
    },
    async dropDay(day) {
      if (postgres) {
        await rowsOf(db, sql`SELECT drop_reads_day(${day}::date)`);
        made.delete(day);
        return;
      }
      const from = Date.parse(`${day}T00:00:00Z`);
      await rowsOf(db, sql`DELETE FROM log_reads WHERE at >= ${from} AND at < ${from + 86_400_000}`);
      await rowsOf(db, sql`DELETE FROM log_read_places WHERE at >= ${from} AND at < ${from + 86_400_000}`);
    },
  };
}

export type { ReadPlace, ReadRow, ReadsCursor };
