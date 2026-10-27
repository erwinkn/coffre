import { parseCheckpoint, splitNote, tileLeaves, type LogEntry, type PairNotes, type StoredPair, type TileKey, type TreeName } from '@coffre/core/merkle';
import type { Database } from '@coffre/db';
import { engineOf, rowsOf } from '@coffre/db/dialect';
import { sql, type SQL } from 'drizzle-orm';

import type { CheckpointStore } from './checkpointer.ts';
import { changeEntry, useEntry } from './log-entry.ts';

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

export function logStore(db: Database, options: Options = {}): CheckpointStore {
  const range = options.tileRange ?? TILE_RANGE;
  // A range holds whole leaf tiles: 256 leaves each.
  if (!Number.isSafeInteger(range) || range <= 0 || range % 256 !== 0) throw new Error(`tileRange must be a positive multiple of 256, not ${range}`);
  return engineOf(db) === 'postgres' ? postgresStore(db, range) : sqliteStore(db);
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

/**
 * The `at` a read of the entries in (after, upto] needs: from the floor of the pair at or below `after`, to the slack
 * past the floor of the first pair at or above `upto`, the barrier that sealed it; without one, no upper bound.
 */
function bounds(after: bigint, upto: bigint): [SQL, SQL] {
  return [
    sql`coalesce((SELECT k.at_floor FROM log_checkpoints k WHERE k.upto <= ${after} ORDER BY k.upto DESC LIMIT 1), 0)`,
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
const indexOf = (level: number, leaf: number) => leaf / 2 ** (8 * (level + 1));

/** One row, one JSON column `v`, as both dialects answer the reads below. */
async function one<T>(db: Database, query: SQL): Promise<T> {
  const [row] = await rowsOf<{ v: unknown }>(db, query);
  const v = row?.v;
  return (typeof v === 'string' ? JSON.parse(v) : v) as T;
}

function postgresStore(db: Database, range: number): CheckpointStore {
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
  const rows = (after: bigint, upto: bigint, floor: SQL, ceiling: SQL = sql`9223372036854775807`) => rowsOf<WindowRow>(db, sql`
      SELECT 'changes' AS tree, c.number AS n, c.at::text AS at, c.request_id, c.object::text AS object, c.actor, c.payload, c.seal, c.mac,
             NULL::text AS credential, NULL::text AS secret, NULL::smallint AS purpose, NULL::text AS place
        FROM log_changes c WHERE c.number > ${after} AND c.number <= ${upto}
      UNION ALL
      SELECT 'uses', u.number, u.at::text, u.request_id::text, NULL, NULL, NULL, NULL, u.mac, u.credential::text, u.secret::text, u.purpose, u.place::text
        FROM log_uses u WHERE u.at >= ${floor} AND u.at <= ${ceiling} AND u.number > ${after} AND u.number <= ${upto}
      ORDER BY n`);
  // The ranges this store made: each made once, not one statement more a tick. Retention (plan PR 7), which drops
  // ranges, forgets the ones it drops here.
  const made = new Set<number>();
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
    async entries(after, upto) {
      // The uses after `after` were admitted at or above the floor its barrier set (FloorChecked): read from there, up to
      // the slack past the floor of the barrier that sealed `upto`. Past the newest pair, unbounded: the head is near.
      const [floor, ceiling] = bounds(after, upto);
      return (await rows(after, upto, floor, ceiling)).map(fromRow);
    },
    async tiles(tree, keys) {
      if (keys.length === 0) return [];
      const rows = await rowsOf<{ level: number; leaf: string; hashes: Buffer }>(db, sql`
        SELECT t.level, t.leaf::text, t.hashes FROM log_tiles t WHERE t.tree = ${tree} AND (${tileKeys(keys)})`);
      return rows.map((r) => ({ level: r.level, index: indexOf(r.level, Number(r.leaf)), hashes: Buffer.from(r.hashes) }));
    },
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
    async locate(number) {
      // The pair that seals it and the one before: the window is (prior.upto, sealing.upto], its uses at or above the
      // prior floor and, committed before the sealing barrier, within the slack of its floor. The index counts that
      // window alone.
      const found = await one<{ entry: RawEntry | null; before: string | null } | null>(db, sql`
        WITH sealing AS (SELECT upto, at_floor FROM log_checkpoints WHERE upto >= ${number} ORDER BY upto LIMIT 1),
             prior AS (SELECT upto, at_floor, changes_size, uses_size FROM log_checkpoints WHERE upto < ${number} ORDER BY upto DESC LIMIT 1)
        SELECT json_build_object(
          'entry', coalesce(
            (SELECT ${CHANGE} FROM log_changes c WHERE c.number = ${number}),
            (SELECT ${USE} FROM log_uses u, prior p, sealing s WHERE u.at >= p.at_floor AND u.at <= s.at_floor + ${AT_SLACK_MS} AND u.number = ${number} LIMIT 1)),
          'before', CASE
            WHEN EXISTS (SELECT 1 FROM log_changes WHERE number = ${number})
              THEN (SELECT p.changes_size + (SELECT count(*) FROM log_changes x WHERE x.number > p.upto AND x.number < ${number}) FROM prior p)::text
            ELSE (SELECT p.uses_size + (SELECT count(*) FROM log_uses x, sealing s WHERE x.at >= p.at_floor AND x.at <= s.at_floor + ${AT_SLACK_MS}
                    AND x.number > p.upto AND x.number < ${number}) FROM prior p)::text
          END) AS v
        WHERE EXISTS (SELECT 1 FROM sealing)`);
      if (found === null || found === undefined || found.entry === null || found.before === null) return null;
      return { entry: toEntry(found.entry), index: Number(found.before) };
    },
  };
}

function sqliteStore(db: Database): CheckpointStore {
  const CHANGE = sql.raw(`json_object('tree', 'changes', 'number', CAST(c.number AS TEXT), 'at', CAST(c.at AS TEXT), 'requestId', c.request_id,
    'object', c.object, 'actor', c.actor, 'payload', c.payload, 'seal', CASE WHEN c.seal IS NULL THEN NULL ELSE hex(c.seal) END, 'mac', hex(c.mac))`);
  const USE = sql.raw(`json_object('tree', 'uses', 'number', CAST(u.number AS TEXT), 'at', CAST(u.at AS TEXT), 'requestId', CAST(u.request_id AS TEXT),
    'credential', u.credential, 'secret', u.secret, 'purpose', u.purpose, 'mac', hex(u.mac), 'place', u.place)`);
  const PAIR = sql.raw(`json_object('upto', CAST(k.upto AS TEXT), 'changes', k.changes_note, 'uses', k.uses_note)`);
  const window = (after: bigint, upto: bigint, floor: SQL, ceiling: SQL = sql`9223372036854775807`) => sql`(SELECT coalesce(json_group_array(json(e.v)), '[]') FROM (
      SELECT c.number AS n, ${CHANGE} AS v FROM log_changes c WHERE c.number > ${after} AND c.number <= ${upto}
      UNION ALL
      SELECT u.number, ${USE} FROM log_uses u WHERE u.at >= ${floor} AND u.at <= ${ceiling} AND u.number > ${after} AND u.number <= ${upto}
      ORDER BY 1
    ) e)`;
  const NOW = sql.raw(`CAST(unixepoch('subsec') * 1000 AS INTEGER)`);
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
    async entries(after, upto) {
      const [floor, ceiling] = bounds(after, upto);
      return (await one<RawEntry[]>(db, sql`SELECT ${window(after, upto, floor, ceiling)} AS v`)).map(toEntry);
    },
    async tiles(tree, keys) {
      if (keys.length === 0) return [];
      const wanted = JSON.stringify(keys.map((k) => [k.level, leafOf(k)]));
      const rows = await rowsOf<{ level: number; leaf: number; hashes: Uint8Array }>(db, sql`
        SELECT t.level, t.leaf, t.hashes FROM log_tiles t
         WHERE t.tree = ${tree} AND (t.level, t.leaf) IN (SELECT json_extract(value, '$[0]'), json_extract(value, '$[1]') FROM json_each(${wanted}))`);
      return rows.map((r) => ({ level: Number(r.level), index: indexOf(Number(r.level), Number(r.leaf)), hashes: Buffer.from(r.hashes) }));
    },
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
    async locate(number) {
      const found = await one<{ entry: RawEntry | null; before: string | null } | null>(db, sql`
        WITH sealing AS (SELECT upto, at_floor FROM log_checkpoints WHERE upto >= ${number} ORDER BY upto LIMIT 1),
             prior AS (SELECT upto, at_floor, changes_size, uses_size FROM log_checkpoints WHERE upto < ${number} ORDER BY upto DESC LIMIT 1)
        SELECT json_object(
          'entry', json(coalesce(
            (SELECT ${CHANGE} FROM log_changes c WHERE c.number = ${number}),
            (SELECT ${USE} FROM log_uses u, prior p, sealing s WHERE u.at >= p.at_floor AND u.at <= s.at_floor + ${AT_SLACK_MS} AND u.number = ${number} LIMIT 1))),
          'before', CAST(CASE
            WHEN EXISTS (SELECT 1 FROM log_changes WHERE number = ${number})
              THEN (SELECT p.changes_size + (SELECT count(*) FROM log_changes x WHERE x.number > p.upto AND x.number < ${number}) FROM prior p)
            ELSE (SELECT p.uses_size + (SELECT count(*) FROM log_uses x, sealing s WHERE x.at >= p.at_floor AND x.at <= s.at_floor + ${AT_SLACK_MS}
                    AND x.number > p.upto AND x.number < ${number}) FROM prior p)
          END AS TEXT)) AS v
        WHERE EXISTS (SELECT 1 FROM sealing)`);
      if (found === null || found === undefined || found.entry === null || found.before === null) return null;
      return { entry: toEntry(found.entry), index: Number(found.before) };
    },
  };
}
