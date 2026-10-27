import {
  decodePair,
  Edge,
  EMPTY_ROOT,
  encodePair,
  entryLeaf,
  inclusionProof,
  leafData,
  loadEdges,
  nodesFrom,
  openPair,
  pairVerifiers,
  proveConsistency,
  samePair,
  signPair,
  tileMap,
  tilesFor,
  TREES,
  verifyConsistency,
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
   * The barrier, then the window: `upto`, such that every number at or below
   * it has ended; the entries in (after, upto], by number; and the newest
   * pair, as `newest()` reads it. The window is read after the barrier's lock
   * is let go, in a snapshot of its own (`close_one`, then one read): a
   * snapshot from before the lock would miss what committed while it waited.
   */
  close(after: bigint): Promise<{ upto: bigint; newest: StoredPair | null; entries: LogEntry[] }>;
  /**
   * The newest pair: each tree's own newest note, `upto` the larger of theirs
   * (Seal.tla's PairChecked). Stored as one row a pair, that is the newest
   * row; stored as a row a tree, never one tree's newest row for both, since
   * deleting the other tree's newest row would then pass unseen. Notes of two
   * places then fail every check that wants one pair.
   */
  newest(): Promise<StoredPair | null>;
  /**
   * One statement: both trees' tiles and both notes (PairWrittenTogether). No
   * state holds one head without the other.
   */
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
  /**
   * Publishes the pair; `proofs(from)` gives each tree's consistency proof
   * from the sizes the witness holds. A try that outlives its bound (2 s) is
   * a failure to the pump, and `signal` aborts: an implementation that makes
   * a request passes it on, so abandoned tries do not pile up.
   */
  publish(notes: PairNotes, proofs: (from: Record<TreeName, number>) => Promise<PairProofs>, signal: AbortSignal): Promise<WitnessAnswer>;
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
  /**
   * Whether a pair landed in the database this tick: a new one, or a pending
   * one finished. A tick can finish a pending pair and then refuse its own
   * window: `failures` says so.
   */
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
  /**
   * Each witness's cosignature of the newest pair it took in time: a pair
   * covering the change, which may be later than `pair` if a tick landed
   * meanwhile. Each note says its own place.
   */
  cosigned: PairNotes[];
  /** The change's entry, proved in the pair: what the admin's client checks and can keep. */
  proof: InclusionProof;
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
  cosigned: PairNotes | null;
  failure: string | null;
  waiters: { upto: bigint; done: () => void }[];
};

type Pending = { next: { pair: Pair; notes: PairNotes }; edges: Record<TreeName, Edge>; tiles: Record<TreeName, Tile[]> };

type Options = {
  memory: Memory;
  witnesses?: readonly Witness[];
  /**
   * Whether an entry's MAC holds: the vault checks it with its key before
   * anything is sealed. The MAC must cover the entry's tree (Seal.tla's
   * KindInMac): otherwise a change moved into the uses partition before its
   * tick would be sealed into the uses tree, and pruned with the uses.
   */
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
  /**
   * A pair signed, perhaps remembered, not known to be written: the memory
   * may hold it, or the database may (a write that committed, then threw).
   * It is finished before anything else is signed, never replaced by another
   * pair for its place.
   */
  private pending: Pending | null = null;

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
      // A new log: both trees empty at number 0, sealing nothing, so the first tick seals every entry there is. A
      // genesis already remembered (a crash before its write) is written as it was, never signed again.
      const empty = { size: 0, root: EMPTY_ROOT };
      // Its time is 0: it seals nothing, and no clock is trusted before the first entry holds it (the tick's rule).
      const genesis = mine ?? (await signPair(signers, 0n, 0, { changes: empty, uses: empty }));
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
        // exactly that pair in both trees, at a time no earlier than the row's.
        if (mine.pair.at < newest.at) throw new Error(`the database's newest pair (up to ${newest.upto}) was signed at ${newest.at}, after the later one the signer remembers (${mine.pair.at}): time runs back`);
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
        // Time never comes down along one history either (what retention's freshness step rests on).
        if (newest.at < mine.pair.at) throw new Error(`the database's newest pair (up to ${newest.upto}) was signed at ${newest.at}, before the one the signer remembers (${mine.pair.at})`);
        // accepted only if the remembered pair is a prefix of it, in both trees: by a consistency proof between the two
        // signed roots, never a head recomputed from tiles, which hold each subtree at several levels and could be
        // planted at one the newest head never reads.
        for (const tree of TREES) {
          const { size, root } = mine.pair[tree];
          const proof = size > newest[tree].size ? null : await proveConsistency(store, tree, size, newest[tree].size).catch(() => null);
          const prefix = proof !== null && verifyConsistency(size, newest[tree].size, root, newest[tree].root, proof);
          if (!prefix) throw new Error(`the database's ${tree} head (${newest[tree].size} up to ${newest.upto}) does not extend the one the signer remembers (${size} up to ${mine.pair.upto})`);
        }
        options.alert?.(`the audit signer's memory (up to ${mine.pair.upto}) is behind the database (up to ${newest.upto}): restored from a backup, or another signer on this key; accepted as a prefix`);
        await options.memory.remember(encodePair(row.notes));
      }
      edges = await loadEdges(store, head.pair);
    } else if (mine === null) {
      // A signer with no memory (a new one on an existing log, or its storage reset) can only take the database's word
      // for the newest pair: said where an operator sees it, and remembered before anything is signed on top of it.
      options.alert?.(`the audit signer remembers no pair; it starts from the database's, up to ${newest.upto}`);
      await options.memory.remember(encodePair(row.notes));
    } else if (encodePair(mine.notes) !== encodePair(row.notes)) {
      // The same heads signed twice, at two times (a pending pair re-signed by an earlier version, say): the memory
      // takes the row's notes, so that it and the head are one record again.
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
    let finished = false;
    if (this.pending !== null) {
      await this.finish(this.pending);
      finished = true;
    }
    const { pair } = this.head;
    const t0 = performance.now();
    const { upto, newest, entries } = await this.store.close(pair.upto);
    const closeMs = performance.now() - t0;
    const failures: string[] = [];
    // A running signer seals from the pair it holds and never takes the database's word for it; but the database's
    // newest row must still be that pair, note for note. Rows deleted or replaced since show here, within a tick;
    // nothing is signed over them.
    if (!holds(newest, this.head)) failures.push(`the database's newest checkpoint is ${newest === null ? 'gone' : newest.upto === pair.upto ? 'another pair' : newest.upto}, the signer's is at ${pair.upto}`);
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
    // The pair's `at` never comes down: retention's freshness step (plan PR 7) needs the bound it sets to hold, so that
    // a replay of a dropped use can never be fresh again when a clock steps back. Nor may it run ahead: one tick on a
    // signer clock that has jumped forward would otherwise sign a time that makes every honest entry read as a replay
    // until real time caught up. So it is the signer's clock, held to at most the bound past the window's newest entry
    // (stamped within seconds of its number): a clock ahead moves it one bound at most, a signer that stalled on a
    // quiet log still seals, and a window of gaps alone, with no entry to hold the clock against, keeps the last time.
    const newestAt = entries.reduce((max, e) => Math.max(max, e.at), -Infinity);
    const at = entries.length === 0 ? pair.at : Math.max(pair.at, Math.min(this.options.now(), newestAt + this.options.freshMs));
    const result = (signed: boolean, writeMs = 0): Tick => ({
      signed: signed || finished, upto: this.head.pair.upto, sizes: sizes(this.head.pair), entries: entries.length, failures, closeMs, writeMs,
    });
    if (failures.length > 0) {
      for (const f of failures) this.options.alert(`audit checkpoint refused: ${f}`);
      return result(false);
    }
    if (upto === pair.upto) {
      // Nothing new. A quiet log: hand the newest pair again to any witness that failed to take it.
      for (const w of this.options.witnesses) if (this.pump(w).acked < pair.upto) this.kick(w);
      return result(false);
    }
    // The edges move on a copy, kept once the pair is written. Until then the pair is pending: a failure leaves it to
    // be finished by the next tick, and the signer at the pair the database holds meanwhile.
    const edges = { changes: this.edges.changes.clone(), uses: this.edges.uses.clone() };
    const tiles = appendWindow(edges, entries);
    const heads: Heads = { changes: { size: edges.changes.size, root: edges.changes.root() }, uses: { size: edges.uses.size, root: edges.uses.root() } };
    const next = await signPair(this.signers, upto, at, heads);
    this.pending = { next, edges, tiles };
    // Remembered outside the database before the database has it (RememberFirst): a crash between the two and a
    // rollback can then never get a second pair signed for the same place.
    await this.options.memory.remember(encodePair(next.notes));
    const t1 = performance.now();
    await this.store.write({ upto, notes: next.notes }, tiles);
    const writeMs = performance.now() - t1;
    this.commit(this.pending);
    return result(true, writeMs);
  }

  /**
   * Finishes a pending pair: remembered again (the first try may have failed,
   * or not), then held by the database, which may hold it already; else it is
   * written now over the pair the signer holds. A database at neither pair
   * is refused until the checkpointer is reopened, whose rules then apply.
   */
  private async finish(p: Pending): Promise<void> {
    await this.options.memory.remember(encodePair(p.next.notes));
    const row = await this.store.newest();
    if (!holds(row, p.next)) {
      if (!holds(row, this.head)) {
        const message = `the database's newest checkpoint is ${row?.upto ?? 'gone'}; the signer's is at ${this.head.pair.upto}, with ${p.next.pair.upto} to write: reopen the checkpointer`;
        this.options.alert(`audit checkpoint refused: ${message}`);
        throw new Error(message);
      }
      await this.store.write({ upto: p.next.pair.upto, notes: p.next.notes }, p.tiles);
    }
    this.commit(p);
  }

  private commit(p: Pending): void {
    this.edges = p.edges;
    this.head = p.next;
    this.pending = null;
    this.publish();
  }

  /**
   * A change answers once its entry is sealed and, where witnesses are set
   * up, witnessed (R51): seal now unless a pair already covers it, then wait
   * for every witness to hold a pair that covers it, whichever tick sealed it,
   * for at most `deadline`. A witness silent that long lets the change answer
   * unwitnessed, alerted: the change is in force either way, and its entry is
   * sealed in the database and in the signer's memory. A tick that cannot seal
   * (an entry failing its MAC) fails the wait rather than spinning.
   *
   * A pair covering the number is not enough: the entry must be in it. An
   * entry deleted before its tick leaves its number a gap the pair calls
   * final, and nothing could ever show the change again; so the change is
   * proved in the pair, and refused, alerted, if it is not there.
   */
  async sealThrough(number: bigint, deadline = WITNESS_DEADLINE_MS): Promise<Sealed> {
    while (this.head.pair.upto < number) {
      const before = this.head.pair.upto;
      const t = await this.tick();
      if (this.head.pair.upto === before) throw new Error(`cannot seal ${number}: ${t.failures.join('; ') || 'the barrier has not passed it'}`);
    }
    const head = this.head;
    // From the changes tree (KindInMac): the MAC does not cover the number, so a writer could delete the change and
    // renumber a use into its place before the tick; that use is sealed, and provable, but in the uses tree.
    const proof = await this.proveAt(number, head);
    if (proof === null || proof.tree !== 'changes') {
      const message = `change ${number} is not in the signed changes tree: its entry was lost before its seal${proof === null ? '' : ', and a use holds its number'}`;
      this.options.alert(message);
      throw new Error(message);
    }
    const failures = await this.witnessed(number, deadline);
    const cosigned = this.options.witnesses.map((w) => this.pump(w)).filter((p) => p.acked >= number && p.cosigned !== null).map((p) => p.cosigned!);
    const witnessed = this.options.witnesses.length === 0 ? null : failures.length === 0;
    if (witnessed === false) this.options.alert(`change ${number} answered unwitnessed: ${failures.join('; ')}`);
    return { pair: head.pair, notes: head.notes, witnessed, failures, cosigned, proof };
  }

  /** Entry `number`'s inclusion proof against the newest pair, checked before it is handed out; null if not sealed. */
  prove(number: bigint): Promise<InclusionProof | null> {
    return this.proveAt(number, this.head);
  }

  private async proveAt(number: bigint, { pair, notes }: { pair: Pair; notes: PairNotes }): Promise<InclusionProof | null> {
    if (number > pair.upto) return null;
    const found = await this.store.locate(number);
    if (found === null) return null;
    const { entry, index } = found;
    if (entry.number !== number || !TREES.includes(entry.tree) || !Number.isSafeInteger(index) || index < 0) {
      throw new Error(`the database answered for another entry than ${number}`);
    }
    // An entry numbered at or below the pair's place is in its tree by construction: an index past the tree is the
    // database's answer, not the tree's.
    const size = pair[entry.tree].size;
    if (index >= size) throw new Error(`the database places entry ${number} at ${index}, past the ${entry.tree} tree the signer signed (${size})`);
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
      p = { busy: false, next: null, acked: -1n, cosigned: null, failure: null, waiters: [] };
      this.pumps.set(w, p);
    }
    return p;
  }

  private publish(): void {
    for (const w of this.options.witnesses) this.kick(w);
  }

  /** Hands a witness the newest pair: sent now if its pump is idle, else next. */
  private kick(w: Witness): void {
    const p = this.pump(w);
    p.next = this.head;
    if (!p.busy) void this.drain(w, p);
  }

  private async drain(w: Witness, p: Pump): Promise<void> {
    p.busy = true;
    try {
      await this.publishAll(w, p);
    } finally {
      p.busy = false;
    }
    // Someone still waits on this witness after a failed try: try again shortly, with the newest pair.
    if (p.waiters.length > 0 && p.failure !== null) {
      const retry = setTimeout(() => {
        if (!p.busy && p.waiters.length > 0) this.kick(w);
      }, 100);
      (retry as { unref?: () => void }).unref?.();
    }
  }

  private async publishAll(w: Witness, p: Pump): Promise<void> {
    while (p.next !== null) {
      const { notes, pair } = p.next;
      p.next = null;
      // A witness that holds more leaves than this pair has seen another history: no proof, and it refuses.
      const prove = (tree: TreeName, from: number) => (from > pair[tree].size ? [] : proveConsistency(this.store, tree, from, pair[tree].size));
      const proofs = async (from: Record<TreeName, number>) => ({ changes: await prove('changes', from.changes), uses: await prove('uses', from.uses) });
      const a = await attempt((signal) => w.publish(notes, proofs, signal), WITNESS_DEADLINE_MS);
      if (a.ok && pair.upto > p.acked) {
        p.acked = pair.upto;
        p.cosigned = a.cosigned;
      }
      p.failure = a.ok ? null : a.reason;
      p.waiters = p.waiters.filter((x) => {
        if (x.upto > p.acked) return true;
        x.done();
        return false;
      });
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
      if (!p.busy) this.kick(w);
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

/**
 * One publication, bounded: a witness that never answers, or throws before it
 * returns a promise, is a failed try, so its pump moves on to the next pair
 * instead of waiting on it for the life of the process.
 */
async function attempt(publish: (signal: AbortSignal) => Promise<WitnessAnswer>, ms: number): Promise<WitnessAnswer> {
  const abort = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const expired = new Promise<WitnessAnswer>((resolve) => {
    timer = setTimeout(() => {
      abort.abort(new Error(`no answer within ${ms} ms`));
      resolve({ ok: false, reason: `no answer within ${ms} ms` });
    }, ms);
  });
  try {
    return await Promise.race([Promise.resolve().then(() => publish(abort.signal)), expired]);
  } catch (error) {
    return { ok: false, reason: `unreachable: ${(error as Error).message}` };
  } finally {
    clearTimeout(timer);
  }
}

/** Whether a row is exactly this pair: the same place and the same two notes, byte for byte. */
const holds = (row: StoredPair | null, head: { pair: Pair; notes: PairNotes }) =>
  row !== null && row.upto === head.pair.upto && row.notes.changes === head.notes.changes && row.notes.uses === head.notes.uses;

const sizes = (heads: Record<TreeName, { size: number }>) => ({ changes: heads.changes.size, uses: heads.uses.size });

/** Appends a window's entries, in number order, each to its tree: the tiles to write. */
function appendWindow(edges: Record<TreeName, Edge>, entries: readonly LogEntry[]): Record<TreeName, Tile[]> {
  const leaves = (tree: TreeName) => entries.filter((e) => e.tree === tree).map((e) => entryLeaf(tree, e.number, e.columns));
  return { changes: edges.changes.append(leaves('changes')), uses: edges.uses.append(leaves('uses')) };
}
