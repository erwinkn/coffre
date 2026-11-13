import { Edge, leafHash, tileMap } from '@coffre/core/log';
import type { Database } from '@coffre/db';
import { rowsOf } from '@coffre/db/dialect';
import * as schema from '@coffre/db/schema';
import { is, sql } from 'drizzle-orm';
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
 * What it finds it reports, and goes on (D216).
 */

/** The signer's storage: outside the database, so whoever writes the database does not write it. */
export type Store = {
  /** Everything kept, by key. */
  read(): Promise<Map<string, unknown>>;
  /** All of it or none of it. A key set to `undefined` is removed. */
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
 * - `cut`: on a full run, a tree shorter or longer than was signed.
 * - `lost`: an entry signed, then gone or changed before it was moved.
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

const TREES = ['kept', 'aging'] as const;
type Tree = (typeof TREES)[number];

/** Every table whose rows carry the vault's MAC: the mirror holds each one's. */
const MIRRORED = (Object.values(schema) as unknown[]).filter((table): table is Sealed => is(table, PgTable) && 'mac' in table && table !== schema.logPending && table !== schema.logHead && table !== schema.auditArchive);

const WAITING = sql`SELECT 'pending' AS part, id::text AS name, NULL::jsonb AS key, kept, body, mac FROM (SELECT * FROM log_pending ORDER BY id LIMIT ${MOST + 1}) waiting`;
const ROWS = sql.join(
  MIRRORED.map((table) => {
    const { name, key } = shapeOf(table);
    return sql`SELECT 'row', ${sql.raw(`'${name}'`)}, jsonb_build_array(${sql.join(key.map((column) => sql.identifier(column.name)), sql`, `)}), NULL, NULL, mac FROM ${sql.identifier(name)}`;
  }),
  sql` UNION ALL `,
);
// Each tree's size by its last leaf, one step down an index: a count would read the whole log.
const SIZES = sql`SELECT 'size', NULL, to_jsonb(coalesce((SELECT max(leaf) FROM log WHERE log.kept = tree.kept) + 1, 0)), kept, NULL, NULL FROM (VALUES (true), (false)) tree(kept)`;

type Waiting = { id: string; kept: boolean; body: string; mac: Uint8Array };

/** What one read found, and what the signer had been told to expect before it. */
export type Snapshot = {
  at: number;
  expected: ReadonlySet<string>;
  pending: Waiting[];
  /** Nothing waits past these. Only then is a missing entry missing, and the rows comparable. */
  drained: boolean;
  /** On a full run: each sealed row's MAC by the row's name, and each tree's size. */
  rows: Map<string, string> | null;
  sizes: Record<Tree, number> | null;
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

type Kept = { drained: number; size: number; agingFrom: number; trees: Record<Tree, { size: number; tiles: { level: number; index: number; hashes: string }[] }> };

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
  /** How many entries are numbered, and the first use pruning has kept. */
  #size = 0;
  #agingFrom = 0;
  #trees: Record<Tree, Edge> = { kept: Edge.empty(), aging: Edge.empty() };
  #moving: Move | null = null;
  /** Its storage refused a write after its memory moved on: nothing more is asked of it. */
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
      else if (kind === 'state') {
        const { drained, size, agingFrom, trees } = value as Kept;
        signer.#drained = drained;
        signer.#size = size;
        signer.#agingFrom = agingFrom;
        for (const tree of TREES) signer.#trees[tree] = Edge.load(trees[tree].size, tileMap(trees[tree].tiles.map((tile) => ({ ...tile, hashes: Buffer.from(tile.hashes, 'hex') }))));
      }
    }
    return signer;
  }

  /** Its memory has moved on before its storage: if the write fails, the two differ, and the signer is opened again. */
  async #keep(changes: ReadonlyMap<string, unknown>): Promise<void> {
    try {
      await this.#on.store.write(changes);
    } catch (error) {
      this.#dead = true;
      throw error;
    }
  }

  #alive(): void {
    if (this.#dead) throw new Error('this signer lost a write to its storage: open another');
  }

  /** The vault's word that an entry was committed (D223). One already signed is not expected again. */
  async wake(hash: Uint8Array): Promise<void> {
    this.#alive();
    const hex = Buffer.from(hash).toString('hex');
    if (this.#signed.has(hex) || this.#expected.has(hex)) return;
    this.#expected.add(hex);
    await this.#keep(new Map([[`expected ${hex}`, true]]));
  }

  /** One read. What is expected is noted before it: an entry told of during the read may be in it or not. */
  async read(full: boolean): Promise<Snapshot> {
    this.#alive();
    const expected = new Set(this.#expected);
    const at = this.#on.now();
    const found = await rowsOf<{ part: 'pending' | 'row' | 'size'; name: string; key: unknown; kept: boolean; body: string; mac: Uint8Array }>(
      this.#on.db,
      full ? sql`${WAITING} UNION ALL ${ROWS} UNION ALL ${SIZES}` : WAITING,
    );
    const waiting = found.filter((row) => row.part === 'pending').map(({ name: id, kept, body, mac }) => ({ id, kept, body, mac }));
    waiting.sort((a, b) => (BigInt(a.id) < BigInt(b.id) ? -1 : 1));
    const sizes = Object.fromEntries(found.filter((row) => row.part === 'size').map((row) => [row.kept ? 'kept' : 'aging', row.key])) as Record<Tree, number>;
    return {
      at,
      expected,
      pending: waiting.slice(0, MOST),
      drained: waiting.length <= MOST,
      rows: full ? new Map(found.filter((row) => row.part === 'row').map((row) => [JSON.stringify([row.name, ...(row.key as unknown[])]), Buffer.from(row.mac).toString('hex')])) : null,
      sizes: full ? sizes : null,
    };
  }

  /** Decide on a read, with no database, and keep the decision before anything moves. */
  async sign(snapshot: Snapshot): Promise<Finding[]> {
    this.#alive();
    if (this.#moving !== null) throw new Error('the last run is not moved yet');
    const findings: Finding[] = [];
    const changes = new Map<string, unknown>();
    const taken: { id: string; kept: boolean; hash: Buffer; hex: string; entry: Entry; seq: number; leaf: number }[] = [];
    const refused: string[] = [];
    /** The vault's entries among those that wait, taken or not. */
    const seen = new Set<string>();
    for (const row of snapshot.pending) {
      const entry = entryOf(this.#on.keys, row);
      const hash = leafHash(Buffer.from(row.body));
      const hex = hash.toString('hex');
      const found = entry === undefined ? 'forged' : this.#signed.has(hex) || seen.has(hex) ? 'replayed' : entry.at + FRESH_MS < this.#drained ? 'stale' : null;
      if (entry !== undefined) seen.add(hex);
      if (entry === undefined || found !== null) {
        findings.push({ found: found!, of: entry === undefined ? `pending:${row.id}` : hex });
        refused.push(row.id);
        continue;
      }
      // In the order written: each change moves the mirror on from the MAC it replaced.
      for (const { row: name, was, now } of entry.rows) {
        if ((this.#mirror.get(name) ?? null) !== was) findings.push({ found: 'rewritten', of: name });
        if (now === null) this.#mirror.delete(name);
        else this.#mirror.set(name, now);
        changes.set(`row ${name}`, now ?? undefined);
      }
      taken.push({ id: row.id, kept: row.kept, hash, hex, entry, seq: this.#size + taken.length, leaf: 0 });
    }
    // Told of before the read, and not in it: gone. Known only when the read took everything that waited.
    const gone = snapshot.drained ? [...snapshot.expected].filter((hex) => !seen.has(hex)) : [];
    for (const hex of gone) findings.push({ found: 'missing', of: hex });
    for (const hex of [...seen, ...gone]) if (this.#expected.delete(hex)) changes.set(`expected ${hex}`, undefined);

    if (snapshot.drained && snapshot.rows !== null && snapshot.sizes !== null) {
      for (const name of new Set([...snapshot.rows.keys(), ...this.#mirror.keys()])) if (snapshot.rows.get(name) !== this.#mirror.get(name)) findings.push({ found: 'row', of: name });
      // Before this run's entries: the log read is the one the last run signed.
      for (const tree of TREES) if (snapshot.sizes[tree] !== this.#trees[tree].size) findings.push({ found: 'cut', of: tree });
    }

    const tiles: Move['tiles'] = [];
    for (const tree of TREES) {
      const mine = taken.filter((each) => each.kept === (tree === 'kept'));
      mine.forEach((each, i) => (each.leaf = this.#trees[tree].size + i));
      for (const { level, index, hashes } of this.#trees[tree].append(mine.map((each) => each.hash))) tiles.push({ kept: tree === 'kept', level, number: index, hashes: hashes.toString('hex') });
    }
    this.#size += taken.length;
    for (const { hex, entry } of taken) {
      this.#signed.set(hex, entry.at);
      changes.set(`signed ${hex}`, entry.at);
    }
    if (snapshot.drained) this.#drained = snapshot.at;
    // What it would no longer take, it need not remember.
    for (const [hex, at] of this.#signed) {
      if (at + FRESH_MS >= this.#drained) continue;
      this.#signed.delete(hex);
      changes.set(`signed ${hex}`, undefined);
    }

    if (taken.length > 0 || refused.length > 0) {
      const head = { size: this.#size, keptSize: this.#trees.kept.size, keptRoot: this.#trees.kept.root().toString('hex'), agingSize: this.#trees.aging.size, agingRoot: this.#trees.aging.root().toString('hex'), agingFrom: this.#agingFrom, signedAt: this.#on.now() };
      const key = this.#on.keys[0]!;
      this.#moving = { taken: taken.map(({ id, kept, seq, leaf, hex }) => ({ id, kept, seq, leaf, hash: hex })), refused, tiles, head: { ...head, mac: macOf(key, key.entries, headText(head)).toString('hex') } };
      changes.set('moving', this.#moving);
    }
    const trees = Object.fromEntries(TREES.map((tree) => [tree, { size: this.#trees[tree].size, tiles: this.#trees[tree].edgeTiles().map(({ level, index, hashes }) => ({ level, index, hashes: hashes.toString('hex') })) }])) as Kept['trees'];
    changes.set('state', { drained: this.#drained, size: this.#size, agingFrom: this.#agingFrom, trees } satisfies Kept);
    await this.#keep(changes);
    return findings;
  }

  /**
   * Into the log, in one statement: each entry signed, if it still waits as
   * it was signed, with a row of the index per object it mentions; the
   * tiles; the head. Run again after it committed, it changes nothing.
   */
  async move(): Promise<Finding[]> {
    this.#alive();
    const moving = this.#moving;
    if (moving === null) return [];
    const { head } = moving;
    const bytes = (hex: string) => sql`decode(${hex}, 'hex')`;
    const time = sql`${new Date(head.signedAt).toISOString()}::timestamptz`;
    const [{ moved, there }] = (await rowsOf<{ moved: number; there: number }>(
      this.#on.db,
      sql`
      WITH taken AS (SELECT * FROM jsonb_to_recordset(${JSON.stringify(moving.taken)}::jsonb) AS t(id bigint, kept boolean, seq bigint, leaf bigint, hash text)),
        moved AS (DELETE FROM log_pending p USING taken t WHERE p.id = t.id AND p.kept = t.kept AND sha256('\\x00'::bytea || convert_to(p.body, 'UTF8')) = decode(t.hash, 'hex') RETURNING t.seq, t.kept, t.leaf, p.body),
        logged AS (INSERT INTO log (seq, kept, leaf, body) SELECT seq, kept, leaf, body FROM moved ON CONFLICT (seq) DO UPDATE SET kept = excluded.kept, leaf = excluded.leaf, body = excluded.body),
        indexed AS (INSERT INTO log_index (object, seq) SELECT DISTINCT object, seq FROM moved, jsonb_array_elements_text(body::jsonb -> 'objects') object ON CONFLICT DO NOTHING),
        refused AS (DELETE FROM log_pending WHERE id IN (SELECT id::bigint FROM jsonb_array_elements_text(${JSON.stringify(moving.refused)}::jsonb) id)),
        tiled AS (
          INSERT INTO log_tiles (kept, level, number, hashes) SELECT kept, level, number, decode(hashes, 'hex') FROM jsonb_to_recordset(${JSON.stringify(moving.tiles)}::jsonb) AS t(kept boolean, level smallint, number bigint, hashes text)
          ON CONFLICT (kept, level, number) DO UPDATE SET hashes = excluded.hashes),
        headed AS (
          INSERT INTO log_head (only_row, size, kept_size, kept_root, aging_size, aging_root, aging_from, signed_at, mac)
          VALUES (true, ${head.size}, ${head.keptSize}, ${bytes(head.keptRoot)}, ${head.agingSize}, ${bytes(head.agingRoot)}, ${head.agingFrom}, ${time}, ${bytes(head.mac)})
          ON CONFLICT (only_row) DO UPDATE SET size = excluded.size, kept_size = excluded.kept_size, kept_root = excluded.kept_root, aging_size = excluded.aging_size, aging_root = excluded.aging_root, aging_from = excluded.aging_from, signed_at = excluded.signed_at, mac = excluded.mac)
      SELECT (SELECT count(*) FROM moved)::int AS moved, (SELECT count(*) FROM log WHERE seq IN (SELECT seq FROM taken))::int AS there`,
    )) as [{ moved: number; there: number }];
    this.#moving = null;
    await this.#keep(new Map([['moving', undefined]]));
    // Moved now, or there already from a run that died after its statement: anything else was taken from under it.
    return moved + there === moving.taken.length ? [] : [{ found: 'lost', of: 'log' }];
  }

  /** One run: the last one's move if it died before it, then a read, its signing and its move. `more`: entries still wait. */
  async run(full: boolean): Promise<{ findings: Finding[]; more: boolean }> {
    const findings = await this.move();
    const snapshot = await this.read(full);
    findings.push(...(await this.sign(snapshot)), ...(await this.move()));
    return { findings, more: !snapshot.drained };
  }
}
