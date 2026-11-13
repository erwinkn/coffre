import { Edge, leafHash, tileMap } from '@coffre/core/log';
import type { Database } from '@coffre/db';
import { later, laterRows } from '@coffre/db/later';
import * as schema from '@coffre/db/schema';
import { is, sql, type SQL } from 'drizzle-orm';
import { PgTable } from 'drizzle-orm/pg-core';

import { entryOf, type Entry } from './entry.ts';
import { macOf, shapeOf, type Key, type Sealed } from './rows.ts';

/**
 * The signer (docs/design/0.16.md, "The log" and "The signer's mirror";
 * formal/quint/log.qnt is its model, step for step). It stands outside the
 * database, with storage of its own, against someone who writes the
 * database and holds no key.
 *
 * A run is three steps:
 *
 * 1. `read`: one statement, the entries that wait and, on a full run, the
 *    MAC of every sealed row and each tree's size.
 * 2. `sign`: no database. It takes each entry whose MAC is the vault's, that
 *    it has not signed, dated within its window; holds each change to the
 *    mirror; numbers what it took and extends the two trees. What it
 *    decided is in its storage before anything moves.
 * 3. `move`: one statement, the entries into `log` with their index rows,
 *    the tiles and the head. A run that died before it is finished by the
 *    next.
 *
 * What it finds it keeps until it is taken (`take`), and goes on (D216): a
 * run that fails after a finding has not lost it.
 */

/**
 * The signer's storage: outside the database, so whoever writes the database
 * does not write it. A Durable Object's, in a deployment.
 */
export type Store = {
  /** Everything kept, by key. */
  read(): Promise<Map<string, unknown>>;
  /** All of it or none of it, and each write after the one asked before it. A key set to `undefined` is removed. */
  write(changes: ReadonlyMap<string, unknown>): Promise<void>;
};

export type Signing = { db: Database; keys: readonly Key[]; now(): number; store: Store };

/**
 * What a run found, and of what: an entry by its hash (or `pending:<id>` for
 * one that is nobody's), a row by its name, a tree.
 *
 * - `forged`: a waiting entry whose MAC is not the vault's.
 * - `replayed`: one already signed, put back.
 * - `stale`: one dated before the window, which nothing remembers signing.
 * - `missing`: one the vault told of, gone before it was signed.
 * - `rewritten`: a change replaced a MAC that is not the one the mirror holds: false history.
 * - `row`: on a full run, a row that is not what the entries say.
 * - `cut`: on a full run, a tree that does not end with the entry signed last.
 * - `lost`: an entry signed, and not in the log as it was signed once moved.
 */
export type Finding = { found: 'forged' | 'replayed' | 'stale' | 'missing' | 'rewritten' | 'row' | 'cut' | 'lost'; of: string };

/**
 * How far before its last read the signer still takes an entry's date. The
 * window slides with the signer, not the clock: one that was away takes
 * what waited for it. It bounds what the signer remembers signing, and must
 * outlast the longest a commit or a wake-up takes.
 */
const FRESH_MS = 60_000;
/** The most entries one run takes: a tile's worth. More wait for the next, at once. */
const MOST = 256;
/**
 * How long a statement of the signer's waits for a lock, as a change does,
 * and how long it runs: half the minute its full run comes round in. Whoever
 * writes the database can hold a lock for good; the run then fails, and the
 * next one tries again, where it would have waited for ever.
 */
const LOCK_WAIT_MS = 2000;
const STATEMENT_MS = 30_000;

const TREES = ['kept', 'aging'] as const;
type Tree = (typeof TREES)[number];
const treeOf = (kept: boolean): Tree => (kept ? 'kept' : 'aging');

/** Every table whose rows carry the vault's MAC: the mirror holds each one's. */
const MIRRORED = (Object.values(schema) as unknown[]).filter((table): table is Sealed => is(table, PgTable) && 'mac' in table && table !== schema.logPending && table !== schema.logHead && table !== schema.auditArchive);

/** An entry's hash as the database works it out: RFC 9162's leaf hash of its body. */
const leafOf = (body: string) => sql.raw(`sha256('\\x00'::bytea || convert_to(${body}, 'UTF8'))`);

// By id, which for changes is the order they committed in: each takes its id under the change lock, held until its
// commit shows (`commit` in change.ts), and the sequence hands ids out one at a time. Uses commit in any order, and write no row.
const WAITING = sql`SELECT 'pending' AS part, id::text AS name, NULL::jsonb AS key, kept, body, mac FROM (SELECT * FROM log_pending ORDER BY id LIMIT ${MOST + 1}) waiting`;
const ROWS = sql.join(
  MIRRORED.map((table) => {
    const { name, key } = shapeOf(table);
    return sql`SELECT 'row', ${sql.raw(`'${name}'`)}, jsonb_build_array(${sql.join(key.map((column) => sql.identifier(column.name)), sql`, `)}), NULL, NULL, mac FROM ${sql.identifier(name)}`;
  }),
  sql` UNION ALL `,
);
// Where each tree ends: its last leaf and that entry's hash, one step down an index. A count would read the whole log.
const ENDS = sql`SELECT 'end', encode(${leafOf('last.body')}, 'hex'), to_jsonb(coalesce(last.leaf + 1, 0)), tree.kept, NULL, NULL
  FROM (VALUES (true), (false)) tree(kept) LEFT JOIN LATERAL (SELECT leaf, body FROM log WHERE log.kept = tree.kept ORDER BY leaf DESC LIMIT 1) last ON true`;

type Waiting = { id: string; kept: boolean; body: string; mac: Uint8Array };
/** Where a tree ends: how many leaves, and the last one's hash, hex. */
type End = { size: number; last: string | null };

/** What one read found, and what the signer had been told to expect before it. */
export type Snapshot = {
  at: number;
  expected: ReadonlySet<string>;
  pending: Waiting[];
  /** Nothing waits past these. Only then is a missing entry missing, and the rows comparable. */
  drained: boolean;
  /** On a full run: each sealed row's MAC by the row's name, and where each tree ends. */
  rows: Map<string, string> | null;
  ends: Record<Tree, End> | null;
};

/** What was signed and is not yet moved, as its statement takes it. */
type Move = {
  taken: { id: string; kept: boolean; seq: number; leaf: number; hash: string }[];
  refused: string[];
  tiles: { kept: boolean; level: number; number: number; hashes: string }[];
  head: { size: number; keptSize: number; keptRoot: string; agingSize: number; agingRoot: string; agingFrom: number; signedAt: number; mac: string };
};

/** What the head's MAC covers: both trees at once, so the two never disagree about when. No entry's body begins as it does. */
export const headText = (head: Omit<Move['head'], 'mac'>) => `head\n${JSON.stringify([head.size, head.keptSize, head.keptRoot, head.agingSize, head.agingRoot, head.agingFrom, head.signedAt])}`;

/** Beside the mirror and the entries: when it last read everything that waited, and each tree's growing edge and end. */
/** The entries among `taken` that are in the log as they were signed: number, tree, leaf and hash. */
const asSigned = (taken: Move['taken']) => sql`
  SELECT l.seq::int FROM log l JOIN jsonb_to_recordset(${JSON.stringify(taken)}::jsonb) AS t(kept boolean, seq bigint, leaf bigint, hash text)
  ON l.seq = t.seq AND l.kept = t.kept AND l.leaf = t.leaf AND ${leafOf('l.body')} = decode(t.hash, 'hex')`;

type Kept = { drained: number; trees: Record<Tree, End & { tiles: { level: number; index: number; hashes: string }[] }> };

export class Signer {
  readonly #on: Signing;
  /** Each sealed row's MAC, hex, by the row's name: what the entries signed so far say the rows are. */
  readonly #mirror = new Map<string, string>();
  /** The entries the vault told of, not yet signed, by hash. */
  readonly #expected = new Set<string>();
  /** The entries signed that it would still take, by hash, with their dates. */
  readonly #signed = new Map<string, number>();
  /** When it last read everything that waited. */
  #drained = 0;
  #trees: Record<Tree, Edge> = { kept: Edge.empty(), aging: Edge.empty() };
  /** Each tree's last leaf, hex: what the log must end with. */
  #last: Record<Tree, string | null> = { kept: null, aging: null };
  #moving: Move | null = null;
  /** What it found and nobody has taken yet. */
  #found: Finding[] = [];
  /** A full run asked for and not yet done, and whether entries waited past the last read. In memory only: the next minute asks again. */
  #owed = false;
  #behind = false;
  #running = false;
  /** Its memory and its storage may differ: it does nothing more. */
  #dead = false;

  private constructor(on: Signing) {
    this.#on = on;
  }

  static async open(on: Signing): Promise<Signer> {
    const signer = new Signer(on);
    for (const [key, value] of await on.store.read()) {
      const space = key.indexOf(' ');
      const [kind, name] = space < 0 ? [key, ''] : [key.slice(0, space), key.slice(space + 1)];
      if (kind === 'row') signer.#mirror.set(name, value as string);
      else if (kind === 'expected') signer.#expected.add(name);
      else if (kind === 'signed') signer.#signed.set(name, value as number);
      else if (kind === 'moving') signer.#moving = value as Move;
      else if (kind === 'found') signer.#found = value as Finding[];
      else if (kind === 'state') {
        const { drained, trees } = value as Kept;
        signer.#drained = drained;
        for (const tree of TREES) {
          signer.#trees[tree] = Edge.load(trees[tree].size, tileMap(trees[tree].tiles.map((tile) => ({ ...tile, hashes: Buffer.from(tile.hashes, 'hex') }))));
          signer.#last[tree] = trees[tree].last;
        }
      }
    }
    return signer;
  }

  /**
   * A step: the signer's memory changes, at once, and then its storage, by
   * one write. So steps reach the storage in the order they changed the
   * memory, a wake-up beside a run included. If the write fails the two
   * differ, and the signer is opened again from its storage.
   */
  async #step(change: (changes: Map<string, unknown>) => void): Promise<void> {
    this.#alive();
    const changes = new Map<string, unknown>();
    try {
      change(changes);
      if (changes.size > 0) await this.#on.store.write(changes);
    } catch (error) {
      this.#dead = true;
      throw error;
    }
  }

  #alive(): void {
    if (this.#dead) throw new Error('this signer failed a step: open another');
  }

  #find(changes: Map<string, unknown>, found: Finding['found'], of: string): void {
    this.#found.push({ found, of });
    changes.set('found', [...this.#found]);
  }

  /** A statement in a transaction of its own that bounds its waits, in one round trip (`later` in @coffre/db). */
  async #ask<Row>(statement: SQL): Promise<Row[]> {
    let rows!: Promise<Row[]>;
    await this.#on.db.transaction(
      async (tx) => {
        later(tx, sql`SELECT set_config('lock_timeout', ${String(LOCK_WAIT_MS)}, true), set_config('statement_timeout', ${String(STATEMENT_MS)}, true)`);
        rows = laterRows<Row>(tx, statement);
      },
      { isolationLevel: 'read committed' },
    );
    return rows;
  }

  /** The vault's word that an entry was committed (D223). One already signed is not expected again. */
  wake(hash: Uint8Array): Promise<void> {
    const hex = Buffer.from(hash).toString('hex');
    return this.#step((changes) => {
      if (this.#signed.has(hex) || this.#expected.has(hex)) return;
      this.#expected.add(hex);
      changes.set(`expected ${hex}`, true);
    });
  }

  /**
   * What was found since this was last asked: where a finding goes is its
   * caller's. Kept in the signer's storage until then, so that neither a
   * run that fails after a finding nor a signer that dies loses it.
   */
  async take(): Promise<Finding[]> {
    let found: Finding[] = [];
    await this.#step((changes) => {
      found = this.#found;
      this.#found = [];
      if (found.length > 0) changes.set('found', undefined);
    });
    return found;
  }

  /**
   * One read, in one statement: the rows and the entries that wait are of
   * one moment. What is expected is noted before it: an entry told of during
   * the read may be in it or not. The database's clock is read with it so
   * that no pooler answers from a cache (`read` in use.ts).
   *
   * `read`, `sign` and `move` are a run's steps, apart so that the model's
   * runs can be replayed one step at a time (test/replay-log.ts). Anything
   * else calls `run`.
   */
  async read(full: boolean): Promise<Snapshot> {
    this.#alive();
    if (this.#moving !== null) throw new Error('the last run is not moved yet');
    const expected = new Set(this.#expected);
    const at = this.#on.now();
    const found = await this.#ask<{ part: 'pending' | 'row' | 'end'; name: string | null; key: unknown; kept: boolean; body: string; mac: Uint8Array }>(
      sql`SELECT parts.*, clock_timestamp() AS read_at FROM (${full ? sql`${WAITING} UNION ALL ${ROWS} UNION ALL ${ENDS}` : WAITING}) parts`,
    );
    const waiting = found.filter((row) => row.part === 'pending').map(({ name, kept, body, mac }) => ({ id: name!, kept, body, mac }));
    waiting.sort((a, b) => (BigInt(a.id) < BigInt(b.id) ? -1 : 1));
    return {
      at,
      expected,
      pending: waiting.slice(0, MOST),
      drained: waiting.length <= MOST,
      rows: full ? new Map(found.filter((row) => row.part === 'row').map((row) => [JSON.stringify([row.name, ...(row.key as unknown[])]), Buffer.from(row.mac).toString('hex')])) : null,
      ends: full ? (Object.fromEntries(found.filter((row) => row.part === 'end').map((row) => [treeOf(row.kept), { size: row.key, last: row.name }])) as Record<Tree, End>) : null,
    };
  }

  /** Decide on a read, with no database, and keep the decision before anything moves. */
  sign(snapshot: Snapshot): Promise<void> {
    return this.#step((changes) => {
      if (this.#moving !== null) throw new Error('the last run is not moved yet');
      const taken: Move['taken'] = [];
      const hashes: Record<Tree, Buffer[]> = { kept: [], aging: [] };
      const refused: string[] = [];
      /** The vault's entries among those that wait, taken or not. */
      const seen = new Set<string>();
      for (const row of snapshot.pending) {
        const entry = entryOf(this.#on.keys, row);
        const hash = leafHash(Buffer.from(row.body));
        const hex = hash.toString('hex');
        const found = entry === undefined ? 'forged' : this.#signed.has(hex) ? 'replayed' : entry.at + FRESH_MS < this.#drained ? 'stale' : null;
        if (entry !== undefined) seen.add(hex);
        if (entry === undefined || found !== null) {
          this.#find(changes, found!, entry === undefined ? `pending:${row.id}` : hex);
          refused.push(row.id);
          continue;
        }
        // In the order written: each change moves the mirror on from the MAC it replaced.
        for (const { row: name, was, now } of entry.rows) {
          if ((this.#mirror.get(name) ?? null) !== was) this.#find(changes, 'rewritten', name);
          if (now === null) this.#mirror.delete(name);
          else this.#mirror.set(name, now);
          changes.set(`row ${name}`, now ?? undefined);
        }
        const tree = treeOf(row.kept);
        taken.push({ id: row.id, kept: row.kept, seq: this.#trees.kept.size + this.#trees.aging.size + taken.length, leaf: this.#trees[tree].size + hashes[tree].length, hash: hex });
        hashes[tree].push(hash);
        this.#signed.set(hex, entry.at);
        changes.set(`signed ${hex}`, entry.at);
      }
      // Told of before the read, and not in it: gone. Known only when the read took everything that waited.
      const gone = snapshot.drained ? [...snapshot.expected].filter((hex) => !seen.has(hex)) : [];
      for (const hex of gone) this.#find(changes, 'missing', hex);
      for (const hex of [...seen, ...gone]) if (this.#expected.delete(hex)) changes.set(`expected ${hex}`, undefined);

      if (snapshot.drained && snapshot.rows !== null && snapshot.ends !== null) {
        for (const name of new Set([...snapshot.rows.keys(), ...this.#mirror.keys()])) if (snapshot.rows.get(name) !== this.#mirror.get(name)) this.#find(changes, 'row', name);
        // Before this run's entries: the log read is the one the last run signed, and must end as that one did.
        for (const tree of TREES) if (snapshot.ends[tree].size !== this.#trees[tree].size || snapshot.ends[tree].last !== this.#last[tree]) this.#find(changes, 'cut', tree);
      }

      const tiles: Move['tiles'] = [];
      for (const tree of TREES) {
        for (const { level, index, hashes: tile } of this.#trees[tree].append(hashes[tree])) tiles.push({ kept: tree === 'kept', level, number: index, hashes: tile.toString('hex') });
        this.#last[tree] = hashes[tree].at(-1)?.toString('hex') ?? this.#last[tree];
      }
      if (snapshot.drained) {
        this.#drained = snapshot.at;
        // What it would no longer take, it need not remember.
        for (const [hex, at] of this.#signed) {
          if (at + FRESH_MS >= this.#drained) continue;
          this.#signed.delete(hex);
          changes.set(`signed ${hex}`, undefined);
        }
      }
      if (taken.length > 0 || refused.length > 0) {
        const { kept, aging } = this.#trees;
        // `agingFrom`: the first use pruning has kept, once there is pruning.
        const head = { size: kept.size + aging.size, keptSize: kept.size, keptRoot: kept.root().toString('hex'), agingSize: aging.size, agingRoot: aging.root().toString('hex'), agingFrom: 0, signedAt: this.#on.now() };
        const key = this.#on.keys[0]!;
        this.#moving = { taken, refused, tiles, head: { ...head, mac: macOf(key, key.entries, headText(head)).toString('hex') } };
        changes.set('moving', this.#moving);
      }
      // With whatever else is kept, never alone: an idle run writes nothing, and its storage's window is only wider for it.
      if (changes.size === 0) return;
      const trees = Object.fromEntries(TREES.map((tree) => [tree, { size: this.#trees[tree].size, last: this.#last[tree], tiles: this.#trees[tree].edgeTiles().map(({ level, index, hashes: tile }) => ({ level, index, hashes: tile.toString('hex') })) }])) as Kept['trees'];
      changes.set('state', { drained: this.#drained, trees } satisfies Kept);
    });
  }

  /**
   * Into the log, in one statement: each entry signed, if it still waits as
   * it was signed, with a row of the index per object it mentions; the
   * tiles; the head. Run again after it committed, it changes nothing. An
   * entry that is not in the log as it was signed once this is done, gone
   * from where it waited or with another row in its place, is `lost`.
   */
  async move(): Promise<void> {
    this.#alive();
    const moving = this.#moving;
    if (moving === null) return;
    const { head } = moving;
    const bytes = (hex: string) => sql`decode(${hex}, 'hex')`;
    const time = sql`${new Date(head.signedAt).toISOString()}::timestamptz`;
    // Each list is named with its columns: a bare name would be read as a column of a table around it, where one has it.
    const put = await this.#ask<{ seq: number }>(sql`
      WITH taken AS (SELECT * FROM jsonb_to_recordset(${JSON.stringify(moving.taken)}::jsonb) AS t(id bigint, kept boolean, seq bigint, leaf bigint, hash text)),
        moved AS (DELETE FROM log_pending p USING taken t WHERE p.id = t.id AND p.kept = t.kept AND ${leafOf('p.body')} = decode(t.hash, 'hex') RETURNING t.seq, t.kept, t.leaf, p.body),
        logged AS (INSERT INTO log (seq, kept, leaf, body) SELECT seq, kept, leaf, body FROM moved ON CONFLICT DO NOTHING RETURNING seq),
        indexed AS (
          INSERT INTO log_index (object, seq) SELECT DISTINCT mentioned.object, moved.seq FROM moved JOIN logged USING (seq), jsonb_array_elements_text(moved.body::jsonb -> 'objects') AS mentioned(object)
          ON CONFLICT DO NOTHING),
        refused AS (DELETE FROM log_pending p USING jsonb_array_elements_text(${JSON.stringify(moving.refused)}::jsonb) AS refused(id) WHERE p.id = refused.id::bigint),
        tiled AS (
          INSERT INTO log_tiles (kept, level, number, hashes) SELECT kept, level, number, decode(hashes, 'hex') FROM jsonb_to_recordset(${JSON.stringify(moving.tiles)}::jsonb) AS t(kept boolean, level smallint, number bigint, hashes text)
          ON CONFLICT (kept, level, number) DO UPDATE SET hashes = excluded.hashes),
        headed AS (
          INSERT INTO log_head (only_row, size, kept_size, kept_root, aging_size, aging_root, aging_from, signed_at, mac)
          VALUES (true, ${head.size}, ${head.keptSize}, ${bytes(head.keptRoot)}, ${head.agingSize}, ${bytes(head.agingRoot)}, ${head.agingFrom}, ${time}, ${bytes(head.mac)})
          ON CONFLICT (only_row) DO UPDATE SET size = excluded.size, kept_size = excluded.kept_size, kept_root = excluded.kept_root, aging_size = excluded.aging_size, aging_root = excluded.aging_root, aging_from = excluded.aging_from, signed_at = excluded.signed_at, mac = excluded.mac)
      SELECT seq::int FROM logged`);
    // Not put there now: there already from a run that died after this statement, whose commit this one may not have seen, or lost. Read apart, and after.
    const there = new Set(put.map((row) => row.seq));
    const absent = moving.taken.filter((entry) => !there.has(entry.seq));
    if (absent.length > 0) for (const { seq } of await this.#ask<{ seq: number }>(asSigned(absent))) there.add(seq);
    await this.#step((changes) => {
      for (const { seq, hash } of moving.taken) if (!there.has(seq)) this.#find(changes, 'lost', hash);
      this.#moving = null;
      changes.set('moving', undefined);
    });
  }

  /**
   * One run: the last one's move if it died before it, then a read, its
   * signing and its move. Only one at a time, and a second is refused, not
   * queued: two that read the same entries would each sign them. A full run
   * reads the rows once nothing waited past the last read; until then it is
   * owed. Its answer: whether to run again at once. What it found is
   * `take`'s, whether it ends or fails.
   */
  async run(full: boolean): Promise<boolean> {
    if (this.#running) throw new Error('the signer runs one at a time');
    this.#running = true;
    try {
      this.#owed ||= full;
      await this.move();
      const snapshot = await this.read(this.#owed && !this.#behind);
      await this.sign(snapshot);
      await this.move();
      this.#behind = !snapshot.drained;
      if (snapshot.drained && snapshot.rows !== null) this.#owed = false;
      return this.#behind || this.#owed;
    } finally {
      this.#running = false;
    }
  }
}
