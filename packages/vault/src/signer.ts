import { Edge, HASH_SIZE, leafHash, tileMap, WIDTH } from '@coffre/core/log';
import type { Database } from '@coffre/db';
import * as schema from '@coffre/db/schema';
import { is, sql, type SQL } from 'drizzle-orm';
import { PgTable } from 'drizzle-orm/pg-core';

import { bounded } from './change.ts';
import { entryOf, type Entry } from './entry.ts';
import { macOf, shapeOf, type Key, type Sealed } from './rows.ts';
import { expire, pruned, recheck, type Walk } from './upkeep.ts';

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

/** `keepUsesDays`: how long a use is kept, from its date as signed (`log.keepUsesDays`). Null keeps every one. */
export type Signing = { db: Database; keys: readonly Key[]; now(): number; store: Store; keepUsesDays: number | null };

/**
 * What a run found, and of what: an entry by its hash (or `pending:<id>` for
 * one that is nobody's), a row by its name, a tree.
 *
 * - `forged`: a waiting entry whose MAC is not the vault's.
 * - `replayed`: one already signed, put back.
 * - `stale`: one dated before the window, which nothing remembers signing.
 * - `missing`: one the vault told of, gone before it was signed.
 * - `rewritten`: a change replaced a row, or was decided on one, whose MAC is not the one the mirror holds: false history.
 * - `row`: on a full run, a row that is not what the entries say; or the head (`["log_head"]`) that is not the one signed last.
 * - `cut`: on a full run, a tree that does not end with the entry signed last.
 * - `lost`: an entry signed, and not in the log as it was signed once moved, or later by the re-check (upkeep.ts); or a
 *   block of them, by its leaves (`aging 512-767`), whose tiles do not prove.
 */
export type Finding = { found: 'forged' | 'replayed' | 'stale' | 'missing' | 'rewritten' | 'row' | 'cut' | 'lost'; of: string };

/**
 * How far before its last read the signer still takes an entry's date. The
 * window slides with the signer, not the clock: one that was away takes
 * what waited for it. It bounds what the signer remembers signing, and must
 * outlast the longest a commit and its wake-up take: an entry is dated as
 * its write is sent, and the write is bounded once it has a connection
 * (`LOCK_WAIT_MS` and `WRITE_MS` in change.ts), as is Hyperdrive's wait for
 * one.
 */
const FRESH_MS = 60_000;
/** The most entries one run takes: a tile's worth. More wait for the next, at once. */
const MOST = 256;
/**
 * The most rows one check names. What a run found is one value of the
 * signer's storage, which has a size: after a restore from a backup every
 * row changed since is wrong, and whoever writes the database can make as
 * many wrong as they like, which must not cost the check its findings.
 */
const MOST_ROWS = 1000;
/**
 * How long a statement of the signer's runs: half the minute its full run
 * comes round in. Whoever writes the database can hold a lock for good; the
 * run then fails, and the next one tries again, where it would have waited
 * for ever.
 */
const STATEMENT_MS = 30_000;

const TREES = ['kept', 'aging'] as const;
export type Tree = (typeof TREES)[number];
const treeOf = (kept: boolean): Tree => (kept ? 'kept' : 'aging');

/** The action of the log's first entry, the adoption's (adopt.ts): the mirror starts from the rows it sealed. */
export const ADOPTION = 'vault.adopt';

/** Every table whose rows carry the vault's MAC: the mirror holds each one's, and the adoption seals each one. */
export const MIRRORED = (Object.values(schema) as unknown[]).filter((table): table is Sealed => is(table, PgTable) && 'mac' in table && table !== schema.logPending && table !== schema.logHead && table !== schema.auditArchive);

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
// The head as the database holds it, by its MAC: no entry writes it, so the mirror has no row for it.
const HEAD = sql`SELECT 'head', NULL, NULL, NULL, NULL, mac FROM log_head`;
/** What a finding names when the head is not the one last signed, as it names a row. */
export const HEAD_ROW = JSON.stringify(['log_head']);

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
  /** On a full run: each sealed row's MAC by the row's name, where each tree ends, and the head's MAC, hex, if there is a head. */
  rows: Map<string, string> | null;
  ends: Record<Tree, End> | null;
  head: string | null;
};

/** What was signed and is not yet moved, as its statement takes it. */
type Move = {
  taken: { id: string; kept: boolean; seq: number; leaf: number; hash: string }[];
  refused: string[];
  tiles: { kept: boolean; level: number; number: number; hashes: string }[];
  /**
   * The first use kept before: the uses from it to the head's `agingFrom` are pruned, with their index rows and tiles.
   * Each of their blocks' tile as the signer proved it, by its SHA-256, hex: only the entries that hash to it go.
   */
  pruning: number;
  pruned: string[];
  head: { size: number; keptSize: number; keptRoot: string; agingSize: number; agingRoot: string; agingFrom: number; signedAt: number; mac: string };
};

/** What the head's MAC covers: both trees at once, so the two never disagree about when. No entry's body begins as it does. */
export const headText = (head: Omit<Move['head'], 'mac'>) => `head\n${JSON.stringify([head.size, head.keptSize, head.keptRoot, head.agingSize, head.agingRoot, head.agingFrom, head.signedAt])}`;

/** The entries among `taken` that are in the log as they were signed: number, tree, leaf and hash. */
const asSigned = (taken: Move['taken']) => sql`
  SELECT l.seq::int FROM log l JOIN jsonb_to_recordset(${JSON.stringify(taken)}::jsonb) AS t(kept boolean, seq bigint, leaf bigint, hash text)
  ON l.seq = t.seq AND l.kept = t.kept AND l.leaf = t.leaf AND ${leafOf('l.body')} = decode(t.hash, 'hex')`;

/** Beside the mirror and the entries: when it last read everything that waited, and each tree's growing edge and end. */
type Kept = { drained: number; trees: Record<Tree, End & { tiles: { level: number; index: number; hashes: string }[] }> };

export class Signer {
  readonly #on: Signing;
  /** Each sealed row's MAC, hex, by the row's name: what the entries signed so far say the rows are. */
  readonly #mirror = new Map<string, string>();
  /** The entries the vault told of, not yet signed, by hash. */
  readonly #expected = new Set<string>();
  /** Whether the vault ever told it of one: kept once an entry it was told of is signed, or goes missing. */
  #told = false;
  /** The entries signed that it would still take, by hash, with their dates. */
  readonly #signed = new Map<string, number>();
  /** When it last read everything that waited. */
  #drained = 0;
  #trees: Record<Tree, Edge> = { kept: Edge.empty(), aging: Edge.empty() };
  /** Each tree's last leaf, hex: what the log must end with. */
  #last: Record<Tree, string | null> = { kept: null, aging: null };
  #moving: Move | null = null;
  /**
   * The MAC, hex, of the head it last signed: what `log_head` must hold. A
   * head's own MAC says the vault signed it, not that it signed none since:
   * an older one put back is genuine, and only this tells it from the last.
   */
  #head: string | null = null;
  /** The first use of the aging tree it keeps: those before it are pruned. */
  #agingFrom = 0;
  /** Where the re-check of old entries goes on. */
  #walk: Walk = { tree: 'kept', block: 0, since: 0, ends: { kept: 0, aging: 0 } };
  /** What it found and nobody has taken yet. */
  #found: Finding[] = [];
  /** The rows and the trees its last check found wrong. One still wrong at the next is no news. */
  #stands: Finding[] = [];
  /** When its last full check completed. */
  #checked: number;
  /** A full run asked for and not yet done, or failed, and whether entries waited past the last read. In memory only: the next minute asks again. */
  #owed = false;
  #behind = false;
  #running = false;
  /** Its memory and its storage may differ: it does nothing more. */
  #dead = false;

  private constructor(on: Signing) {
    this.#on = on;
    this.#checked = on.now();
  }

  /**
   * When the signer last compared the rows and the log's end with what it
   * signed. It cannot say of itself that it is stopped: whoever runs it
   * says so once this is minutes old, whether its runs fail, on a lock the
   * database's writer holds or a table they flooded, or nothing runs it.
   */
  get checked(): number {
    return this.#checked;
  }

  static async open(on: Signing): Promise<Signer> {
    const signer = new Signer(on);
    const kept = await on.store.read();
    // From its first opening, not its latest: a signer that has never completed a check does not look new each time it is opened.
    if (!kept.has('checked')) await on.store.write(new Map([['checked', signer.#checked]]));
    for (const [key, value] of kept) {
      const space = key.indexOf(' ');
      const [kind, name] = space < 0 ? [key, ''] : [key.slice(0, space), key.slice(space + 1)];
      if (kind === 'row') signer.#mirror.set(name, value as string);
      else if (kind === 'expected') signer.#expected.add(name);
      else if (kind === 'told') signer.#told = true;
      else if (kind === 'signed') signer.#signed.set(name, value as number);
      else if (kind === 'moving') signer.#moving = value as Move;
      else if (kind === 'head') signer.#head = value as string;
      else if (kind === 'found') signer.#found = value as Finding[];
      else if (kind === 'stands') signer.#stands = value as Finding[];
      else if (kind === 'checked') signer.#checked = value as number;
      else if (kind === 'agingFrom') signer.#agingFrom = value as number;
      else if (kind === 'walk') signer.#walk = value as Walk;
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

  /**
   * Whether it has signed nothing and is told of nothing: the one signer
   * that may adopt its database (adopt.ts). A database that shows no log
   * to one that has was emptied behind it, and is not adopted again.
   */
  get blank(): boolean {
    this.#alive();
    return this.#trees.kept.size + this.#trees.aging.size === 0 && this.#moving === null && !this.#told;
  }

  /** The rows and the trees the last check found wrong. */
  get standing(): Finding[] {
    return [...this.#stands];
  }

  /** Whether a step failed: its memory and its storage may differ, and whoever runs it opens another. */
  get dead(): boolean {
    return this.#dead;
  }

  #alive(): void {
    if (this.#dead) throw new Error('this signer failed a step: open another');
  }

  #find(changes: Map<string, unknown>, found: Finding['found'], of: string): void {
    this.#found.push({ found, of });
    changes.set('found', [...this.#found]);
  }

  #ask<Row>(statement: SQL): Promise<Row[]> {
    return bounded<Row>(this.#on.db, statement, { runMs: STATEMENT_MS });
  }

  /** The vault's word that an entry was committed (D223). One already signed is not expected again. */
  wake(hash: Uint8Array): Promise<void> {
    const hex = Buffer.from(hash).toString('hex');
    return this.#step((changes) => {
      if (this.#signed.has(hex) || this.#expected.has(hex)) return;
      this.#expected.add(hex);
      changes.set(`expected ${hex}`, true);
      if (this.#told) return;
      this.#told = true;
      changes.set('told', true);
    });
  }

  /**
   * What was found and not yet let go, to `send`, which says where a
   * finding goes; let go once `send` has returned. One that throws leaves
   * them for the next call, and the same ones are sent again: twice is
   * better than never. Kept in the signer's storage until then, so that
   * neither a run that fails after a finding nor a signer that dies loses
   * it. `send` answers whether they reached someone: if not, what stands
   * is news again to the next check.
   */
  async take(send: (found: Finding[]) => boolean | Promise<boolean> = () => true): Promise<Finding[]> {
    this.#alive();
    const found = [...this.#found];
    const reached = await send(found);
    await this.#step((changes) => {
      // Those sent, and not what a run found meanwhile.
      const sent = new Set(found);
      this.#found = this.#found.filter((each) => !sent.has(each));
      if (found.length > 0) changes.set('found', this.#found.length > 0 ? [...this.#found] : undefined);
      if (reached || this.#stands.length === 0) return;
      this.#stands = [];
      changes.set('stands', undefined);
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
    const found = await this.#ask<{ part: 'pending' | 'row' | 'end' | 'head'; name: string | null; key: unknown; kept: boolean; body: string; mac: Uint8Array }>(
      sql`SELECT parts.*, clock_timestamp() AS read_at FROM (${full ? sql`${WAITING} UNION ALL ${ROWS} UNION ALL ${ENDS} UNION ALL ${HEAD}` : WAITING}) parts`,
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
      head: found.filter((row) => row.part === 'head').map((row) => Buffer.from(row.mac).toString('hex'))[0] ?? null,
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
        // The first entry kept, the adoption's: it names no row, and the mirror is the rows read with it, as it sealed them.
        if (entry.action === ADOPTION && this.#trees.kept.size + hashes.kept.length === 0) {
          if (snapshot.rows === null) throw new Error("the adoption's entry is signed by a run that reads the rows it sealed");
          for (const [name, mac] of snapshot.rows) {
            this.#mirror.set(name, mac);
            changes.set(`row ${name}`, mac);
          }
        }
        // In the order written: each change moves the mirror on from the MAC it replaced.
        for (const { row: name, was, now } of entry.rows) {
          if ((this.#mirror.get(name) ?? null) !== was) this.#find(changes, 'rewritten', name);
          // A row read and left moves nothing: the mirror stays what the entries wrote.
          if (now === was) continue;
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
        const wrong = [...new Set([...snapshot.rows.keys(), ...this.#mirror.keys()])].filter((name) => snapshot.rows!.get(name) !== this.#mirror.get(name));
        const stands: Finding[] = [
          // More than it names at once: the first by name, the same at each check, and the rest by the checks after those are put right.
          ...(wrong.length > MOST_ROWS ? wrong.sort().slice(0, MOST_ROWS) : wrong).map((of) => ({ found: 'row' as const, of })),
          // Before this run's entries: the log read is the one the last run signed, and must end as that one did.
          ...TREES.filter((tree) => snapshot.ends![tree].size !== this.#trees[tree].size || snapshot.ends![tree].last !== this.#last[tree]).map((of) => ({ found: 'cut' as const, of })),
          // Before this run's head: the one read is the last signed, or an older one was put back, it was edited, or it is gone.
          ...(snapshot.head === this.#head ? [] : [{ found: 'row' as const, of: HEAD_ROW }]),
        ];
        // Found when it turns wrong, once: what the last check found wrong too is no news, nor what still waits to be said.
        const known = new Set([...this.#stands, ...this.#found].map(({ found, of }) => `${found} ${of}`));
        for (const { found, of } of stands) if (!known.has(`${found} ${of}`)) this.#find(changes, found, of);
        if (stands.length > 0 || this.#stands.length > 0) changes.set('stands', stands.length > 0 ? stands : undefined);
        this.#stands = stands;
      }

      const tiles: Move['tiles'] = [];
      for (const tree of TREES) {
        for (const { level, index, hashes: tile } of this.#trees[tree].append(hashes[tree])) tiles.push({ kept: tree === 'kept', level, number: index, hashes: tile.toString('hex') });
        this.#last[tree] = hashes[tree].at(-1)?.toString('hex') ?? this.#last[tree];
      }
      if (snapshot.drained) {
        // Never back: under a clock set back, an entry it has forgotten signing would be taken again.
        this.#drained = Math.max(this.#drained, snapshot.at);
        // What it would no longer take, it need not remember.
        for (const [hex, at] of this.#signed) {
          if (at + FRESH_MS >= this.#drained) continue;
          this.#signed.delete(hex);
          changes.set(`signed ${hex}`, undefined);
        }
      }
      if (taken.length > 0 || refused.length > 0) this.#move(changes, { taken, refused, tiles, pruning: this.#agingFrom, pruned: [] });
      // With an entry or a finding, never alone: an idle run writes nothing here, and its storage's window is only wider for it.
      if (changes.size === 0) return;
      const trees = Object.fromEntries(TREES.map((tree) => [tree, { size: this.#trees[tree].size, last: this.#last[tree], tiles: this.#trees[tree].edgeTiles().map(({ level, index, hashes: tile }) => ({ level, index, hashes: tile.toString('hex') })) }])) as Kept['trees'];
      changes.set('state', { drained: this.#drained, trees } satisfies Kept);
    });
  }

  /** What is to move, with the head it signs: in its storage before anything moves. */
  #move(changes: Map<string, unknown>, move: Omit<Move, 'head'>): void {
    const { kept, aging } = this.#trees;
    const head = { size: kept.size + aging.size, keptSize: kept.size, keptRoot: kept.root().toString('hex'), agingSize: aging.size, agingRoot: aging.root().toString('hex'), agingFrom: this.#agingFrom, signedAt: this.#on.now() };
    const key = this.#on.keys[0]!;
    this.#moving = { ...move, head: { ...head, mac: macOf(key, key.entries, headText(head)).toString('hex') } };
    changes.set('moving', this.#moving);
    // With the move, in one write: no read comes before the move is done (`read`), so the head read is this one or not the last.
    this.#head = this.#moving.head.mac;
    changes.set('head', this.#head);
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
        refused AS (DELETE FROM log_pending p USING jsonb_array_elements_text(${JSON.stringify(moving.refused)}::jsonb) AS r(id) WHERE p.id = r.id::bigint),
        -- Each block's tile goes, and of its entries those that hash to it as the signer proved it: a body swapped since stays,
        -- and is never parsed, so no row a writer plants stops the move. The tiles proven apart, and the entries by their
        -- range: joined on a list the planner cannot count, it hashes each tile once per entry, and compiles every move.
        untiled AS (
          DELETE FROM log_tiles t WHERE t.kept = false AND t.level = 0 AND t.number >= ${moving.pruning / WIDTH} AND t.number < ${head.agingFrom / WIDTH}
          RETURNING t.number, t.hashes, sha256(t.hashes) AS digest),
        proven AS MATERIALIZED (
          SELECT u.number, u.hashes FROM untiled u, jsonb_array_elements_text(${JSON.stringify(moving.pruned)}::jsonb) WITH ORDINALITY AS d(digest, n)
          WHERE u.number = ${moving.pruning / WIDTH} + d.n - 1 AND u.digest = decode(d.digest, 'hex')),
        pruned AS (
          DELETE FROM log l USING proven t WHERE l.kept = false AND l.leaf >= ${moving.pruning} AND l.leaf < ${head.agingFrom} AND t.number = l.leaf / ${WIDTH}
            AND ${leafOf('l.body')} = substring(t.hashes FROM ((l.leaf - t.number * ${WIDTH}) * ${HASH_SIZE} + 1)::int FOR ${HASH_SIZE})
          RETURNING l.seq, l.body),
        -- By each entry's own keys, one probe each, however many rows of an object lie between them. Unnested from arrays, a
        -- list the planner takes for short: from the entries' lists, it counts a hundred each and reads all of the index.
        mentions AS (SELECT array_agg(o.object) AS objects, array_agg(p.seq) AS seqs FROM pruned p, jsonb_array_elements_text(p.body::jsonb -> 'objects') AS o(object)),
        unindexed AS (DELETE FROM log_index i USING mentions m, unnest(m.objects, m.seqs) AS k(object, seq) WHERE i.object = k.object AND i.seq = k.seq),
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
   * After a check (upkeep.ts): the oldest uses pruned, as a move, so that
   * what is kept from is in its storage before anything goes; the rows that
   * lapsed deleted; a slice of the log held to what it signed, last, so that
   * what it finds is kept with nothing between to fail. Its answer: whether
   * an entry of its own waits.
   */
  async #upkeep(at: number): Promise<boolean> {
    const ask = <Row>(statement: SQL) => this.#ask<Row>(statement);
    const from = this.#agingFrom;
    const { to, tiles } = await pruned(ask, this.#on, this.#trees, from);
    if (to > from) {
      await this.#step((changes) => {
        this.#agingFrom = to;
        changes.set('agingFrom', to);
        this.#move(changes, { taken: [], refused: [], tiles: [], pruning: from, pruned: tiles });
      });
      await this.move();
    }
    const waits = await expire(this.#on, ask, (hash) => this.wake(hash));
    const { found, walk } = await recheck(ask, this.#on.now(), this.#trees, to, this.#walk);
    await this.#step((changes) => {
      for (const { of } of found) this.#find(changes, 'lost', of);
      this.#walk = walk;
      changes.set('walk', walk);
      // Checked once its upkeep ended too: one that fails, on a row or a lock a writer holds, is said stopped as a check that fails is.
      this.#checked = at;
      changes.set('checked', at);
    });
    return waits;
  }

  /**
   * One run: the last one's move if it died before it, then a read, its
   * signing and its move. Only one at a time, and a second is refused, not
   * queued: two that read the same entries would each sign them. A full run
   * reads the rows once nothing waited past the last read; until then it is
   * owed. A full read that fails, on a lock held or a table flooded, does
   * not stop the signing: the run reads what waits alone, and fails once it
   * has moved it; the next full run asked for tries again. Its answer: whether to run again at once. What it found
   * is `take`'s, whether it ends or fails.
   */
  async run(full: boolean): Promise<boolean> {
    if (this.#running) throw new Error('the signer runs one at a time');
    this.#running = true;
    try {
      this.#owed ||= full;
      await this.move();
      const checking = this.#owed && !this.#behind;
      let [snapshot, failed] = await this.read(checking).then(
        (read) => [read, null] as const,
        async (error: unknown) => {
          if (!checking) throw error;
          return [await this.read(false), error] as const;
        },
      );
      // The adoption's entry is signed with the rows it sealed (`sign`): a quick read that finds it waiting reads them too,
      // and fails as the full read did if it does again.
      if (snapshot.rows === null && this.#trees.kept.size === 0 && snapshot.pending.some((row) => entryOf(this.#on.keys, row)?.action === ADOPTION)) {
        snapshot = await this.read(true);
        failed = null;
      }
      await this.sign(snapshot);
      await this.move();
      this.#behind = !snapshot.drained;
      // Done, or failed: a check that fails is tried again by the next minute's run, not by every run until then.
      if (failed !== null || (snapshot.drained && snapshot.rows !== null)) this.#owed = false;
      if (failed !== null) throw failed;
      const waits = snapshot.drained && snapshot.rows !== null && (await this.#upkeep(snapshot.at));
      return this.#behind || this.#owed || waits;
    } finally {
      this.#running = false;
    }
  }
}
