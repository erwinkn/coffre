import {
  decodePair,
  Edge,
  edgeOf,
  EMPTY_ROOT,
  encodePair,
  entryLeaf,
  inclusionProof,
  leafData,
  nodesFrom,
  openPair,
  pairVerifiers,
  proveConsistency,
  samePair,
  signPair,
  tileMap,
  tilesFor,
  treeHash,
  TREES,
  verifyInclusion,
  witnessPair,
  type Hash,
  type Heads,
  type LogEntry,
  type LogReader,
  type NoteSigner,
  type Pair,
  type PairNotes,
  type PairProofs,
  type PairSigners,
  type PairVerifiers,
  type StoredPair,
  type Tile,
  type TreeName,
  type WitnessAnswer,
  type WitnessState,
} from '@coffre/core/merkle';

/**
 * 0.15's checkpointer (docs/design/audit-tree.md): every tick it seals what
 * has committed into the two trees, signs both heads as one pair, remembers
 * the pair outside the database, writes it, and hands it to the witnesses.
 * The rest of the vault sees one seam: `tick()` (the window in, a signed pair
 * out), `sealThrough(number)` for a change that waits for its seal (R51), and
 * `prove(number)`. The trees' shape stays behind it.
 *
 * What it stands on, each a protection formal/Seal.tla shows necessary:
 * - the barrier (`close`): every number at or below the `upto` it returns has
 *   ended, committed or not, so a window is final once read;
 * - the signer's memory (`Memory`, core, R54): the last pair it signed, kept
 *   where a database writer cannot reach, written before the database
 *   (RememberFirst) and checked at every open, so neither a tail cut nor a
 *   rollback gets a second history signed;
 * - each tick compares the database's newest row with the pair it holds
 *   (RowChecked), so a deleted row shows within a tick, traffic or not;
 * - nothing is sealed over an entry that fails its MAC (`authentic`), is out
 *   of its window, or is much older than the pair it holds (a replay).
 */

/** What the checkpointer needs of the database. Postgres and SQLite implement it; so do the tests. */
export type CheckpointStore = LogReader & {
  /**
   * The barrier and the window, as one statement: `upto`, such that every
   * number at or below it has ended; the entries in (after, upto], by number;
   * and the `upto` of the newest checkpoint row, or null if there is none.
   */
  close(after: bigint): Promise<{ upto: bigint; newest: bigint | null; entries: LogEntry[] }>;
  /** The newest checkpoint row, if any. */
  newest(): Promise<StoredPair | null>;
  /** One statement: both trees' tiles and the pair's row. No state holds one head without the other. */
  write(row: StoredPair, tiles: Record<TreeName, Tile[]>): Promise<void>;
  /** Entry `number` and its leaf index in its tree, if it is in the log. */
  locate(number: bigint): Promise<{ entry: LogEntry; index: number } | null>;
};

/**
 * The signer's memory: the one record holding the last pair it signed. A
 * Durable Object's storage on Workers, a synced file beside a Node vault.
 */
export type Memory = { last(): Promise<string | null>; remember(record: string): Promise<void> };

/** Somewhere each signed pair goes that a database writer cannot reach: a witness, an archive (R40's plugin). */
export type Witness = {
  name: string;
  /** Publishes the pair; `proofs(from)` gives each tree's consistency proof from the sizes the witness holds. */
  publish(notes: PairNotes, proofs: (from: Record<TreeName, number>) => Promise<PairProofs>): Promise<WitnessAnswer>;
};

/**
 * How much older than the pair the signer holds an entry it seals may be.
 * A use stamps `at`, which its MAC covers, and takes its number within its
 * deadline (3 s, R53), so an older entry is a replay: the copy of a use whose
 * day retention dropped, say, which no lookup of its request can match. The
 * bound is the signer's own pair, not a row a writer can delete.
 */
export const FRESH_MS = 10 * 60_000;

/** How long a change waits for the witnesses once sealed before it answers unwitnessed (R51). */
export const WITNESS_DEADLINE_MS = 2000;

export type Tick = {
  /** Whether a new pair was signed and written. */
  signed: boolean;
  upto: bigint;
  sizes: Record<TreeName, number>;
  entries: number;
  /** Why nothing was signed, when something is wrong: each is an alarm for an operator. */
  failures: string[];
  /** Database time: the barrier and window, then the write. */
  closeMs: number;
  writeMs: number;
};

export type Sealed = {
  pair: Pair;
  notes: PairNotes;
  /** null when no witness is set up, so nothing reads "witnessed" there. */
  witnessed: boolean | null;
  failures: string[];
  /** The pair as each witness that took it in time cosigned it. */
  cosigned: PairNotes[];
};

export type InclusionProof = {
  number: bigint;
  tree: TreeName;
  index: number;
  size: number;
  /** The leaf's data: the whole entry. */
  leaf: Buffer;
  proof: Hash[];
  /** The pair it is proved against. */
  notes: PairNotes;
};

type Pump = {
  busy: boolean;
  next: { notes: PairNotes; pair: Pair } | null;
  acked: bigint;
  held: Record<TreeName, number> | null;
  cosigned: PairNotes | null;
  failure: string | null;
  waiters: { upto: bigint; done: () => void }[];
};

type Options = {
  memory: Memory;
  witnesses?: readonly Witness[];
  /** Whether an entry's MAC holds: the vault checks it with its key before anything is sealed. */
  authentic: (entry: LogEntry) => boolean;
  /** Where alarms go: refused ticks, unwitnessed changes, memory and database out of step. */
  alert?: (message: string) => void;
  freshMs?: number;
  now?: () => number;
};

export class Checkpointer {
  private store: CheckpointStore;
  private signers: PairSigners;
  private options: Required<Omit<Options, 'witnesses'>> & { witnesses: readonly Witness[] };
  private edges: Record<TreeName, Edge>;
  private head: { pair: Pair; notes: PairNotes };
  private running: Promise<unknown> = Promise.resolve();
  private pumps = new Map<Witness, Pump>();

  private constructor(store: CheckpointStore, signers: PairSigners, options: Options, edges: Record<TreeName, Edge>, head: { pair: Pair; notes: PairNotes }) {
    this.store = store;
    this.signers = signers;
    // Each default by itself: an option passed as undefined takes it too.
    this.options = {
      memory: options.memory,
      authentic: options.authentic,
      witnesses: options.witnesses ?? [],
      alert: options.alert ?? (() => {}),
      freshMs: options.freshMs ?? FRESH_MS,
      now: options.now ?? Date.now,
    };
    this.edges = edges;
    this.head = head;
  }

  /** The newest pair the signer signed and the database holds. */
  get pair(): { pair: Pair; notes: PairNotes } {
    return this.head;
  }

  /**
   * From the newest checkpoint row, checked against what the signer
   * remembers, which comes first: nothing is signed or remembered before the
   * two are compared. The signer remembers a pair before the database has it
   * (RememberFirst), so the memory may be ahead of the database: after a crash
   * between the two, or because a writer deleted the newest rows. Either way,
   * if the entries the database holds give the remembered pair, its row is
   * written again and nothing was lost; if they do not, the database lost
   * entries the signer sealed, and it refuses. A database beside the memory,
   * another pair at the same place, is refused too.
   */
  static async open(store: CheckpointStore, signers: PairSigners, options: Options): Promise<Checkpointer> {
    const verifiers = await pairVerifiers({ changes: signers.changes.verifierKey, uses: signers.uses.verifierKey });
    const record = await options.memory.last();
    let mine: { pair: Pair; notes: PairNotes } | null = null;
    if (record !== null) {
      const notes = decodePair(record);
      const pair = notes === null ? null : await openPair(notes, verifiers);
      if (pair === null) throw new Error('the signer remembers a pair it did not sign');
      mine = { pair, notes: notes! };
    }
    const row = await store.newest();
    if (row === null) {
      if (mine !== null && (mine.pair.upto !== 0n || TREES.some((tree) => mine.pair[tree].size > 0))) {
        throw new Error(`the database holds no checkpoint; the signer signed up to ${mine.pair.upto} (${sizes(mine.pair)})`);
      }
      // A new log: both trees empty at number 0, sealing nothing, so the first tick seals every entry there is.
      const empty = { size: 0, root: EMPTY_ROOT };
      const genesis = await signPair(signers, 0n, (options.now ?? Date.now)(), { changes: empty, uses: empty });
      await options.memory.remember(encodePair(genesis.notes));
      await store.write({ upto: 0n, notes: genesis.notes }, { changes: [], uses: [] });
      return new Checkpointer(store, signers, options, { changes: Edge.empty(), uses: Edge.empty() }, genesis);
    }
    const newest = await openPair(row.notes, verifiers);
    if (newest === null || newest.upto !== row.upto) throw new Error(`the newest checkpoint (${row.upto}) is not a pair signed by this log`);
    let head = { pair: newest, notes: row.notes };
    let edges = await loadEdges(store, newest);
    if (mine !== null && !samePair(mine.pair, newest)) {
      if (mine.pair.upto === newest.upto) throw new Error(`the database's checkpoint at ${newest.upto} is not the pair the signer signed`);
      if (mine.pair.upto > newest.upto) {
        // The memory is ahead: seal again from the newest row up to the remembered pair, from the entries, and require
        // exactly that pair in both trees.
        const entries = await store.entries(newest.upto, mine.pair.upto);
        const tiles = appendWindow(edges, entries);
        const lost = TREES.filter((tree) => edges[tree].size !== mine.pair[tree].size || !edges[tree].root().equals(mine.pair[tree].root));
        if (lost.length > 0) {
          throw new Error(`the database lost entries the signer sealed: up to ${mine.pair.upto} it holds ${sizes(edges)}, the signer signed ${sizes(mine.pair)}`);
        }
        await store.write({ upto: mine.pair.upto, notes: mine.notes }, tiles);
        head = mine;
      } else {
        // The database is ahead, which RememberFirst rules out for this signer (a memory restored from a backup, say):
        // accepted only if the remembered pair is a prefix of it, in both trees.
        for (const tree of TREES) {
          const { size, root } = mine.pair[tree];
          const prefix = size <= newest[tree].size
            && treeHash(nodesFrom(tileMap(await store.tiles(tree, tilesFor((n) => treeHash(n, size))))), size).equals(root);
          if (!prefix) throw new Error(`the database's ${tree} head (${newest[tree].size} up to ${newest.upto}) does not extend the one the signer remembers (${size} up to ${mine.pair.upto})`);
        }
        await options.memory.remember(encodePair(row.notes));
      }
      edges = await loadEdges(store, head.pair);
    } else if (mine === null) {
      // A signer with no memory (a new one on an existing log, or its storage reset) can only take the database's word
      // for the newest pair: said where an operator sees it, and remembered before anything is signed on top of it.
      options.alert?.(`the audit signer remembers no pair; it starts from the database's, up to ${newest.upto}`);
      await options.memory.remember(encodePair(row.notes));
    }
    return new Checkpointer(store, signers, options, edges, head);
  }

  /**
   * One checkpoint: seal what has committed, sign it, remember it, store it,
   * publish it. Ticks run one at a time, the regular ones and those a change
   * asks for.
   */
  tick(): Promise<Tick> {
    const run = this.running.then(() => this.tickNow());
    this.running = run.catch(() => {});
    return run;
  }

  private async tickNow(): Promise<Tick> {
    const { pair } = this.head;
    const t0 = performance.now();
    const { upto, newest, entries } = await this.store.close(pair.upto);
    const closeMs = performance.now() - t0;
    const failures: string[] = [];
    // A running signer seals from the pair it holds and never takes the database's word for it; but the database's
    // newest row must still be that pair. Rows deleted since show here, within a tick; nothing is signed over them.
    if (newest !== pair.upto) failures.push(`the database's newest checkpoint is ${newest ?? 'gone'}, the signer's is at ${pair.upto}`);
    if (upto < pair.upto) failures.push(`the barrier says ${upto} is final, below the signer's ${pair.upto}`);
    let previous = pair.upto;
    for (const e of entries) {
      if (e.number <= previous || e.number > upto) failures.push(`${e.number}: outside the window (${previous}, ${upto}]: two entries with one number, or out of order`);
      else if (!TREES.includes(e.tree)) failures.push(`${e.number}: in no tree`);
      else if (!this.options.authentic(e)) failures.push(`${e.number}: its MAC does not hold`);
      // A use takes its number within its deadline of `at`; an entry much older than the pair the signer holds is a
      // replay, e.g. the copy of a use whose day was dropped, which no lookup can match.
      else if (e.at < pair.at - this.options.freshMs) failures.push(`${e.number}: at ${e.at}, older than the signer's pair (${pair.at}): a replay`);
      previous = e.number > previous ? e.number : previous;
    }
    const result = (signed: boolean, writeMs = 0): Tick => ({
      signed, upto: this.head.pair.upto, sizes: sizes(this.head.pair), entries: entries.length, failures, closeMs, writeMs,
    });
    if (failures.length > 0) {
      for (const f of failures) this.options.alert(`audit checkpoint refused: ${f}`);
      return result(false);
    }
    if (upto === pair.upto) {
      // Nothing new. A quiet log: hand the newest pair again to any witness that failed to take it.
      for (const w of this.options.witnesses) {
        const p = this.pump(w);
        if (p.acked < pair.upto && !p.busy) this.publish();
      }
      return result(false);
    }
    // The edges move on a copy, kept only once the pair is written: a failure at any step leaves the signer at the pair
    // the database holds. (A pair remembered but not written is the memory being ahead, which the next tick passes.)
    const edges = { changes: this.edges.changes.clone(), uses: this.edges.uses.clone() };
    const tiles = appendWindow(edges, entries);
    const heads: Heads = { changes: { size: edges.changes.size, root: edges.changes.root() }, uses: { size: edges.uses.size, root: edges.uses.root() } };
    const next = await signPair(this.signers, upto, Math.max(this.options.now(), pair.at), heads);
    // Remembered outside the database before the database has it (RememberFirst): a crash between the two and a
    // rollback can then never get a second pair signed for the same place.
    await this.options.memory.remember(encodePair(next.notes));
    const t1 = performance.now();
    await this.store.write({ upto, notes: next.notes }, tiles);
    const writeMs = performance.now() - t1;
    this.edges = edges;
    this.head = next;
    this.publish();
    return result(true, writeMs);
  }

  /**
   * A change answers once its entry is sealed and, where witnesses are set
   * up, witnessed (R51): seal now unless a pair already covers it, then wait
   * for every witness to hold a pair that covers it, whichever tick sealed it,
   * for at most `deadline`. A witness silent that long lets the change answer
   * unwitnessed, alerted: the change is in force either way, and its entry is
   * sealed in the database and in the signer's memory. A tick that cannot seal
   * (an entry failing its MAC) fails the wait rather than spinning.
   */
  async sealThrough(number: bigint, deadline = WITNESS_DEADLINE_MS): Promise<Sealed> {
    while (this.head.pair.upto < number) {
      const before = this.head.pair.upto;
      const t = await this.tick();
      if (this.head.pair.upto === before) throw new Error(`cannot seal ${number}: ${t.failures.join('; ') || 'the barrier has not passed it'}`);
    }
    const { pair, notes } = this.head;
    const failures = await this.witnessed(number, deadline);
    const cosigned = this.options.witnesses.map((w) => this.pump(w)).filter((p) => p.acked >= number && p.cosigned !== null).map((p) => p.cosigned!);
    const witnessed = this.options.witnesses.length === 0 ? null : failures.length === 0;
    if (witnessed === false) this.options.alert(`change ${number} answered unwitnessed: ${failures.join('; ')}`);
    return { pair, notes, witnessed, failures, cosigned };
  }

  /** Entry `number`'s inclusion proof against the newest pair, checked before it is handed out; null if not sealed. */
  async prove(number: bigint): Promise<InclusionProof | null> {
    const { pair, notes } = this.head;
    if (number > pair.upto) return null;
    const found = await this.store.locate(number);
    if (found === null) return null;
    const { entry, index } = found;
    const size = pair[entry.tree].size;
    if (index >= size) return null;
    const nodes = nodesFrom(tileMap(await this.store.tiles(entry.tree, tilesFor((n) => inclusionProof(n, index, size)))));
    const proof = inclusionProof(nodes, index, size);
    if (!verifyInclusion(entryLeaf(entry.tree, entry.number, entry.columns), index, size, proof, pair[entry.tree].root)) {
      throw new Error(`entry ${number} is not at ${index} of the ${entry.tree} tree the signer signed: the database changed it`);
    }
    return { number, tree: entry.tree, index, size, leaf: leafData(entry.tree, entry.number, entry.columns), proof, notes };
  }

  /** Each witness's pump: one publication in flight at a time, always of the newest pair (a witness needs only that). */
  private pump(w: Witness): Pump {
    let p = this.pumps.get(w);
    if (p === undefined) {
      p = { busy: false, next: null, acked: -1n, held: null, cosigned: null, failure: null, waiters: [] };
      this.pumps.set(w, p);
    }
    return p;
  }

  private publish(): void {
    for (const w of this.options.witnesses) {
      const p = this.pump(w);
      p.next = this.head;
      if (!p.busy) void this.drain(w, p);
    }
  }

  private async drain(w: Witness, p: Pump): Promise<void> {
    p.busy = true;
    while (p.next !== null) {
      const { notes, pair } = p.next;
      p.next = null;
      // A witness that holds more leaves than this pair has seen another history: no proof, and it refuses.
      const prove = (tree: TreeName, from: number) => (from > pair[tree].size ? [] : proveConsistency(this.store, tree, from, pair[tree].size));
      const proofs = async (from: Record<TreeName, number>) => ({ changes: await prove('changes', from.changes), uses: await prove('uses', from.uses) });
      const a: WitnessAnswer = await w.publish(notes, proofs).catch((e: Error) => ({ ok: false as const, reason: `unreachable: ${e.message}` }));
      if (a.ok && pair.upto > p.acked) {
        p.acked = pair.upto;
        p.held = sizes(pair);
        p.cosigned = a.cosigned;
      }
      p.failure = a.ok ? null : a.reason;
      p.waiters = p.waiters.filter((x) => {
        if (x.upto > p.acked) return true;
        x.done();
        return false;
      });
    }
    p.busy = false;
    // Someone still waits on this witness after a failed try: try again shortly, with the newest pair.
    if (p.waiters.length > 0 && p.failure !== null) {
      const retry = setTimeout(() => {
        if (!p.busy && p.waiters.length > 0) {
          p.next = this.head;
          void this.drain(w, p);
        }
      }, 100);
      (retry as { unref?: () => void }).unref?.();
    }
  }

  /** The witnesses that do not hold a pair sealing `upto` within the deadline, each with its last failure. */
  private async witnessed(upto: bigint, deadline: number): Promise<string[]> {
    const answers = await Promise.all(this.options.witnesses.map((w) => {
      const p = this.pump(w);
      if (p.acked >= upto) return null;
      const answer = new Promise<string | null>((resolve) => {
        const waiter = { upto, done: () => { clearTimeout(timer); resolve(null); } };
        // At the deadline the waiter goes, so nothing keeps retrying on its behalf after the change has answered.
        const timer = setTimeout(() => {
          p.waiters = p.waiters.filter((x) => x !== waiter);
          resolve(`witness ${w.name}: no answer within ${deadline} ms${p.failure === null ? '' : ` (last: ${p.failure})`}`);
        }, deadline);
        p.waiters.push(waiter);
      });
      // A witness behind and idle (its last try failed) is asked again now, with the newest pair.
      if (!p.busy) {
        p.next = this.head;
        void this.drain(w, p);
      }
      return answer;
    }));
    return answers.filter((a): a is string => a !== null);
  }
}

/** An in-process witness: what the witness's Durable Object does, without the network. */
export function localWitness(name: string, log: PairVerifiers, self: NoteSigner): Witness & { held(): WitnessState } {
  let state: WitnessState = null;
  return {
    name,
    held: () => state,
    async publish(notes, proofs) {
      const r = await witnessPair(state, notes, await proofs(state === null ? { changes: 0, uses: 0 } : sizes(state.pair)), log, self);
      state = r.state;
      return r.answer;
    },
  };
}

const sizes = (heads: Record<TreeName, { size: number }>) => ({ changes: heads.changes.size, uses: heads.uses.size });

/** Appends a window's entries, in number order, each to its tree: the tiles to write. */
function appendWindow(edges: Record<TreeName, Edge>, entries: readonly LogEntry[]): Record<TreeName, Tile[]> {
  const leaves = (tree: TreeName) => entries.filter((e) => e.tree === tree).map((e) => entryLeaf(tree, e.number, e.columns));
  return { changes: edges.changes.append(leaves('changes')), uses: edges.uses.append(leaves('uses')) };
}

async function loadEdges(store: Pick<LogReader, 'tiles'>, pair: Pair): Promise<Record<TreeName, Edge>> {
  const edges = {} as Record<TreeName, Edge>;
  for (const tree of TREES) {
    const { size, root } = pair[tree];
    edges[tree] = Edge.load(size, tileMap(await store.tiles(tree, edgeOf(size).filter((e) => e.width > 0))));
    if (!edges[tree].root().equals(root)) throw new Error(`the ${tree} tiles at the edge do not give the signed head (up to ${pair.upto})`);
  }
  return edges;
}
