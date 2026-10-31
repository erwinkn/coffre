import { createHash } from 'node:crypto';

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
  pairSigners,
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
import { UNSEALED, type Sealing } from '@coffre/core/vault';
import { isUnavailable } from '@coffre/db/dialect';

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
 *
 * And nothing it awaits is unbounded (T169): a tick that runs past
 * `TICK_BOUND_MS` stalls the checkpointer, closed for good behind its
 * `Fence`, so that its host opens another while the database still holds
 * the old one's statement (Seal.tla's Fenced); a change waits at most
 * `SEAL_WAIT_MS` for its seal, then answers `Unsealed`.
 */

/** What the checkpointer needs of the database. Postgres and SQLite implement it; so do the tests. */
export type CheckpointStore = LogReader & {
  /**
   * The barrier, then the window: `upto`, such that every number at or below
   * it has ended; the entries in (after, upto], by number; and the newest
   * pair, as `newest()` reads it. The window is read after the barrier's lock
   * is let go, in a snapshot of its own (`close_one`, then one read): a
   * snapshot from before the lock would miss what committed while it waited.
   *
   * The barrier also raises the floor of `at` (`close_one`): `floor.found` is
   * the floor it found, null if none, and `floor.set` the one it left. The
   * window's uses are read from `from`, the floor the signer holds, as the
   * last barrier set it. `floor.ceiling` is the database's clock less the
   * use deadline, read once the barrier has run: the highest floor any
   * barrier before it can have left (HotPathOne.tla's BarrierAcceptsLate).
   *
   * With `limit` (T169), the window's first `limit` entries by number, and
   * `more` when there were more: `more.above`, the lowest `at` of the uses
   * the window holds above the last of them, from `from` on (null: none).
   * `barrier`, told the barrier's `upto` before the window is read.
   */
  close(after: bigint, from: number, limit?: number, barrier?: (upto: bigint) => void): Promise<{
    upto: bigint; newest: StoredPair | null; entries: LogEntry[]; floor: { found: number | null; set: number; ceiling: number };
    more?: { above: number | null } | null;
  }>;
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
  /**
   * Entry `number` and its leaf index in its tree, if it is in the log; a
   * use found at `at` when the caller knows its time, which spares a scan
   * of its window's time. With `tree`, an entry in the other is refused
   * (`misplaced`) before its index is sought.
   */
  locate(number: bigint, options?: Locating): Promise<{ entry: LogEntry; index: number } | null>;
};

/**
 * The signer's memory: the one record holding the last pair it signed. A
 * Durable Object's storage on Workers, a synced file beside a Node vault.
 */
export type Memory = { last(): Promise<string | null>; remember(record: string): Promise<void> };

/** What a proof asks of `locate`: the use's time, if known, and the tree the entry must be in. */
export type Locating = { at?: number; tree?: TreeName };

/**
 * An answer of the database a proof refuses: an entry in the other tree, a
 * window no checkpoints make, an entry changed since its tick. Never an I/O
 * failure, which a caller may ask again past; `sealThrough` alarms on these
 * alone (PR 8 review r4 of W240).
 */
export class Refused extends Error {}

/**
 * An entry found in the other tree than the one asked: a writer who deleted
 * a change and renumbered a use into its place (KindInMac). Refused before
 * its index is sought, which for a use reads its window's tiles, whose
 * bounds are the database's (PR 8 review r2).
 */
export function misplaced(entry: LogEntry, tree: TreeName): Refused {
  return new Refused(`entry ${entry.number} is in the ${entry.tree} tree, not the ${tree}: a ${entry.tree === 'uses' ? 'use' : 'change'} holds its number`);
}

/**
 * The pairs a memory's record holds outside the database, for the verifier
 * (`VaultOptions.heldOutside`): none before the first, and a record that does
 * not read as a pair refused, never read as none, which would drop the walk's
 * anchor in silence (review r11).
 */
export function heldIn(record: string | null): PairNotes[] {
  if (record === null) return [];
  const notes = decodePair(record);
  if (notes === null) throw new Error("the signer's memory does not read as a pair: the log is not checked against it");
  return [notes];
}

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

/**
 * How long a tick may run (T169). A tick seals a tick's window, tens of
 * milliseconds at R44's rate; one past this waits on a database that
 * stalled under it (a connection that went dead, a connect that never
 * answers, a lock never let go), and the checkpointer stalls: closed for
 * good, its fence with it, so that its host opens another.
 */
export const TICK_BOUND_MS = 10_000;

/**
 * How long a change waits for the ticks that seal it, and its proof (T169).
 * Past it the change, committed and in force, answers `Unsealed`: the app
 * says 503, try again. The witnesses' 2 s come after.
 */
export const SEAL_WAIT_MS = 5000;

/** How long after its last tick that ended well a checkpointer still seals, for readiness (T169): ten ticks. */
export const SEALING_STALE_MS = 5000;

/**
 * Whether a checkpointer seals, from its host's view (`Vault.sealing`): open, no failure standing, and its last
 * tick ended well within `SEALING_STALE_MS`, at `last.at` by the host's clock.
 */
export function sealingOf(state: { open: boolean; failed: string | null; last: { at: number; failures: readonly string[] } | null }, now = Date.now()): Sealing {
  if (state.failed !== null) return { ok: false, reason: state.failed };
  if (!state.open) return { ok: false, reason: 'the checkpointer is not open' };
  if (state.last === null) return { ok: false, reason: 'the checkpointer has not ticked yet' };
  if (state.last.failures.length > 0) return { ok: false, reason: `its last tick was refused: ${state.last.failures.join('; ')}` };
  if (now - state.last.at > SEALING_STALE_MS) return { ok: false, reason: `its last tick ended ${now - state.last.at} ms ago` };
  return { ok: true };
}

/**
 * The most entries a tick seals (T169): a window past it is sealed a part
 * at a time, each part a pair, the next tick at once. After a stall of
 * minutes at R44's rate, the backlog is hundreds of thousands: read and
 * sealed whole, it would run past `TICK_BOUND_MS` and stall again, for good.
 */
export const WINDOW_MAX = 10_000;

/**
 * How much longer than `TICK_BOUND_MS` a tick may run for each number its
 * barrier's window spans (review by Fable): its read sorts the window's
 * uses by number, which have no index by number, so it costs the whole
 * backlog left, 1.4 µs a use measured (1.6 s at a million). A tick is
 * bounded by the work asked of it, never by a clock alone: a drain of
 * millions goes on, a few times slower than measured, and a stall is
 * still one.
 */
export const WINDOW_ENTRY_MS = 0.01;

/** A wait past its bound (`within`). */
export class TimedOut extends Error {}

/** What a fence closed refuses: no alarm, since another checkpointer holds its memory and does the work. */
export class FenceClosed extends Error {}

/** A tick past `TICK_BOUND_MS`: the checkpointer stalled, and is closed for good. */
export class Stalled extends Error {}

/**
 * A change committed whose seal did not come in time (T169): the
 * checkpointer stalled, is reopening, or its database does not answer. Its
 * message carries core's `UNSEALED`, which the app answers with 503 and
 * Retry-After; the change is in force, and the next tick seals it.
 */
export class Unsealed extends Error {
  constructor(number: bigint, why: string, cause?: unknown) {
    super(`change ${number} ${UNSEALED}: ${why}; try again shortly`, { cause });
  }
}

/**
 * `work`, or `TimedOut` once `ms` have passed, `expired` run first: what a
 * host cuts there (the connection), so that what `work` still awaits fails
 * rather than waits on. `work` may go on; whatever it still does, its fence
 * refuses.
 */
export function within<T>(work: Promise<T>, ms: number, what: string, expired?: () => void): Promise<T> {
  const until = performance.now() + ms;
  return withinUntil(work, () => until, () => `${what} did not end within ${ms} ms`, expired);
}

/** `within`, its deadline `until()` read again when it comes: one that moved on is waited for. */
function withinUntil<T>(work: Promise<T>, until: () => number, said: () => string, expired?: () => void): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const past = new Promise<never>((_, reject) => {
    const arm = () => {
      timer = setTimeout(() => {
        if (performance.now() < until()) return arm();
        expired?.();
        reject(new TimedOut(said()));
      }, Math.max(0, until() - performance.now()));
      (timer as { unref?: () => void }).unref?.();
    };
    arm();
  });
  return Promise.race([work, past]).finally(() => clearTimeout(timer));
}

/**
 * What a checkpointer given up on may still do (T169; Seal.tla's Fenced):
 * nothing it starts once its fence is closed. Every call it makes to its
 * store, and every write to its memory, is checked against the fence
 * first. What it sent before may still land: a database write is refused
 * where a row holds its place (`write_checkpoint`, one statement), and a
 * barrier raises the floor no higher than the next one does
 * (HotPathOne.tla's LateBarrier); the memory writes in flight, `close`
 * waits for, so that the next checkpointer reads them.
 */
export class Fence {
  #closed: string | null = null;
  readonly #landing = new Set<Promise<void>>();

  /** Why it was closed; null while it is open. */
  get closed(): string | null {
    return this.#closed;
  }

  /** Closed for good; resolves once the memory writes already sent have landed. */
  close(why: string): Promise<void> {
    this.#closed ??= why;
    return Promise.allSettled([...this.#landing]).then(() => {});
  }

  #check(): void {
    if (this.#closed !== null) throw new FenceClosed(`this checkpointer was closed (${this.#closed}): another holds its memory`);
  }

  /**
   * `answer`, refused if the fence closed while it was awaited: what a call sent before the fence closed answers too
   * late to be read, so that a checkpointer given up on never acts on it, nor alarms on it (review r1).
   */
  #late<T>(answer: T): T {
    if (!(answer instanceof Promise)) return answer;
    return answer.then((value: unknown) => {
      this.#check();
      return value;
    }) as T;
  }

  /** The store, each of its calls refused once the fence is closed, and each answer that comes after. */
  store<T extends object>(store: T): T {
    return new Proxy(store, {
      get: (target, key) => {
        const value = Reflect.get(target, key) as unknown;
        if (typeof value !== 'function') return value;
        return (...args: unknown[]) => {
          this.#check();
          return this.#late((value as (...a: unknown[]) => unknown).apply(target, args));
        };
      },
    });
  }

  /** The memory, its writes refused once the fence is closed, and those in flight kept for `close`. */
  memory(memory: Memory): Memory {
    return {
      last: () => {
        this.#check();
        return this.#late(memory.last());
      },
      remember: (record) => {
        this.#check();
        const landing = memory.remember(record);
        const settled = landing.then(() => {}, () => {});
        this.#landing.add(settled);
        void settled.then(() => this.#landing.delete(settled));
        return landing;
      },
    };
  }
}

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
  /** Whether the window held more than this tick sealed (`WINDOW_MAX`): its host ticks again at once. */
  more: boolean;
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
   * meanwhile. Each note says its own place. An archive cosigns nothing and
   * adds none: whether the change was witnessed is `witnessed`, never the
   * length of this.
   */
  cosigned: PairNotes[];
  /** The change's entry, proved in the pair: what the admin's client checks and can keep. */
  proof: InclusionProof;
};

/**
 * The change path's seam (plan PR 4): a change, once committed, asks for its
 * seal and answers with what this gives it (R51). The Node checkpointer's
 * `sealThrough` is one; on Workers, `durableSealThrough` asks the
 * checkpointer's Durable Object.
 */
export type SealThrough = (number: bigint, deadline?: number) => Promise<Sealed>;

/** An alarm the checkpointer raised, as its host keeps it for whoever watches (R40's plugin, PR 8's surfaces). */
export type Alarm = { at: number; message: string };

/** The log's origin for a signing seed: one per key, `coffre.log/<the first 8 bytes of SHA-256 of the seed's changes key, hex>`. */
export async function logOrigin(seed: Uint8Array): Promise<string> {
  const { changes } = await pairSigners('coffre.log', seed);
  return `coffre.log/${createHash('sha256').update(changes.publicKey).digest('hex').slice(0, 16)}`;
}

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
  /**
   * What closes this checkpointer for good (T169): a host bounding the open
   * passes its own, to close it if the open stalls. One is made otherwise.
   */
  fence?: Fence;
  /** `TICK_BOUND_MS`, `SEAL_WAIT_MS` and `WINDOW_MAX`, for the tests. */
  tickBoundMs?: number;
  sealWaitMs?: number;
  windowMax?: number;
};

export class Checkpointer {
  private store: CheckpointStore;
  private signers: PairSigners;
  private options: Required<Omit<Options, 'witnesses' | 'fence'>> & { witnesses: readonly Witness[] };
  private fence: Fence;
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
  /**
   * The floor of `at` signed into the newest pair: windows are read from it.
   * It moves only when a pair carrying a new floor is written.
   */
  private floor: number;
  /**
   * The floor this process's last barrier set, which the next barrier must
   * find exactly; null until its first barrier (a restart cannot know what
   * barriers whose pairs went unsigned raised it to).
   */
  private barrier: number | null = null;
  /** Set once a barrier finds the floor elsewhere: every tick refuses until the checkpointer is reopened. */
  private floorAlarm: string | null = null;
  /** The failures the last refused tick alerted: a refusal that stands is alerted once, not every tick. */
  private refused: string | null = null;

  /** The log's public keys, which open its pairs. */
  readonly verifiers: PairVerifiers;

  private constructor(store: CheckpointStore, signers: PairSigners, verifiers: PairVerifiers, options: Options & { fence: Fence }, edges: Record<TreeName, Edge>, head: { pair: Pair; notes: PairNotes }) {
    this.store = store;
    this.fence = options.fence;
    this.signers = signers;
    this.verifiers = verifiers;
    // Each default by itself: an option passed as undefined takes it too.
    this.options = {
      memory: options.memory,
      authentic: options.authentic,
      witnesses: options.witnesses ?? [],
      alert: options.alert ?? (() => {}),
      freshMs: options.freshMs ?? FRESH_MS,
      now: options.now ?? Date.now,
      tickBoundMs: options.tickBoundMs ?? TICK_BOUND_MS,
      sealWaitMs: options.sealWaitMs ?? SEAL_WAIT_MS,
      windowMax: options.windowMax ?? WINDOW_MAX,
    };
    this.edges = edges;
    this.head = head;
    this.floor = head.pair.floor;
  }

  /**
   * What stands against it sealing, whichever tick met it, an alarm's or a change's: why it stalled, or the refusal of
   * its last tick; null when its last tick held. Readiness reads it beside its host's own view (T169, review r5).
   */
  get standing(): string | null {
    return this.stalled ?? (this.closed ? 'this checkpointer was closed' : this.refused);
  }

  /** The newest pair the signer signed and the database holds. */
  get pair(): { pair: Pair; notes: PairNotes } {
    return this.head;
  }

  /** How much older than its pair an entry the signer seals may be (`FRESH_MS`): retention drops a day two of these past its cut. */
  get freshMs(): number {
    return this.options.freshMs;
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
    // Everything this checkpointer does to the database and its memory, its open included, goes through its fence.
    const fence = options.fence ?? new Fence();
    store = fence.store(store);
    options = { ...options, memory: fence.memory(options.memory), fence };
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
        throw new Error(`the database holds no checkpoint; the signer signed up to ${mine.pair.upto} (${said(mine.pair)})`);
      }
      // A new log: both trees empty at number 0, sealing nothing, so the first tick seals every entry there is. A
      // genesis already remembered (a crash before its write) is written as it was, never signed again.
      const empty = { size: 0, root: EMPTY_ROOT };
      // Its time is 0: it seals nothing, and no clock is trusted before the first entry holds it (the tick's rule).
      const genesis = mine ?? (await signPair(signers, 0n, 0, { changes: empty, uses: empty }));
      await options.memory.remember(encodePair(genesis.notes));
      await rewrite(store, { upto: 0n, notes: genesis.notes }, { changes: [], uses: [] });
      return new Checkpointer(store, signers, verifiers, { ...options, fence }, { changes: Edge.empty(), uses: Edge.empty() }, genesis);
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
        if (mine.pair.at < newest.at || mine.pair.floor < newest.floor) {
          throw new Error(`the database's newest pair (up to ${newest.upto}, at ${newest.at}, floor ${newest.floor}) is ahead in time or floor of the later one the signer remembers (at ${mine.pair.at}, floor ${mine.pair.floor}): time runs back`);
        }
        const entries = await store.entries(newest.upto, mine.pair.upto);
        const tiles = appendWindow(edges, entries);
        const lost = TREES.filter((tree) => edges[tree].size !== mine.pair[tree].size || !edges[tree].root().equals(mine.pair[tree].root));
        if (lost.length > 0) {
          throw new Error(`the database lost entries the signer sealed: up to ${mine.pair.upto} it holds ${said(edges)}, the signer signed ${said(mine.pair)}`);
        }
        await rewrite(store, { upto: mine.pair.upto, notes: mine.notes }, tiles);
        head = mine;
      } else {
        // The database is ahead, which RememberFirst rules out for this signer (a memory restored from a backup, say):
        // Time never comes down along one history either (what retention's freshness step rests on).
        if (newest.at < mine.pair.at || newest.floor < mine.pair.floor) {
          throw new Error(`the database's newest pair (up to ${newest.upto}, at ${newest.at}, floor ${newest.floor}) is behind in time or floor the one the signer remembers (at ${mine.pair.at}, floor ${mine.pair.floor}): time runs back`);
        }
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
      // takes the row's notes, so that it and the head are one record again; never a time or floor that runs back.
      if (newest.at < mine.pair.at || newest.floor < mine.pair.floor) {
        throw new Error(`the database's pair up to ${newest.upto} is the one the signer remembers, signed again earlier or at a lower floor (at ${newest.at}, floor ${newest.floor}; remembered at ${mine.pair.at}, floor ${mine.pair.floor}): time runs back`);
      }
      await options.memory.remember(encodePair(row.notes));
    }
    return new Checkpointer(store, signers, verifiers, { ...options, fence }, edges, head);
  }

  /**
   * One checkpoint: seal what has committed, sign it, remember it, store it,
   * publish it. Ticks run one at a time, the regular ones and those a change
   * asks for.
   */
  /**
   * Stops this checkpointer for good: every tick after, and every change
   * that would tick, is refused, and its fence refuses whatever its tick in
   * flight still does. Resolves once that tick has ended or stalled
   * (`TICK_BOUND_MS`), and its memory writes in flight have landed. A host
   * that opens another over the same memory closes this one first, so that
   * two signers never act at once.
   */
  close(): Promise<void> {
    this.closed = true;
    return Promise.all([this.fence.close('closed by its host'), this.running]).then(() => {});
  }

  private closed = false;
  /** Why it stalled (T169): a tick past its bound. */
  private stalled: string | null = null;
  /** When the tick in flight stalls: `TICK_BOUND_MS` after it started, and more for a long window. */
  private until = 0;
  /** What the tick in flight awaits, which a stall says, so that an operator sees what stalled. */
  private phase: 'finish' | 'barrier' | 'sign' | 'remember' | 'write' = 'barrier';

  /**
   * A tick: the one queued behind the running one, if there is one yet,
   * else a new one. Its barrier comes after every commit made before it
   * starts, so whoever asks before it starts is sealed by it as well as by
   * one of their own: many changes waiting at once share ticks, rather than
   * each waiting for a tick per change before it (0.15-plan.md, "As built:
   * PR 4b", measured).
   */
  tick(): Promise<Tick> {
    if (this.queued !== null) return this.queued;
    const run = this.running.then(() => {
      this.queued = null;
      // Bounded (T169): past it the checkpointer stalls, its fence closed, whatever the tick still awaits. Its window,
      // once the barrier has said how far, adds to the bound (`WINDOW_ENTRY_MS`).
      const t0 = performance.now();
      this.until = t0 + this.options.tickBoundMs;
      return withinUntil(this.tickNow(), () => this.until, () => `a tick did not end within ${Math.round(this.until - t0)} ms`, () => {
        this.stalled ??= `a tick ran past ${Math.round(this.until - t0)} ms in its ${this.phase}: the database stalled under it`;
        this.closed = true;
        void this.fence.close(this.stalled);
      }).catch((error: unknown) => {
        throw error instanceof TimedOut ? new Stalled(this.stalled!) : error;
      });
    });
    this.queued = run;
    this.running = run.catch(() => {});
    return run;
  }

  private queued: Promise<Tick> | null = null;

  private async tickNow(): Promise<Tick> {
    if (this.stalled !== null) throw new Stalled(`this checkpointer stalled (${this.stalled}): its host opens another`);
    if (this.closed) throw new Error('this checkpointer was closed: another took over its memory');
    let finished = false;
    if (this.pending !== null) {
      this.phase = 'finish';
      await this.finish(this.pending);
      finished = true;
    }
    const { pair } = this.head;
    const t0 = performance.now();
    this.phase = 'barrier';
    const { upto, newest, entries, floor, more = null } = await this.store.close(pair.upto, this.floor, this.options.windowMax, (upto) => {
      if (upto > pair.upto) this.until += Number(upto - pair.upto) * WINDOW_ENTRY_MS;
    });
    const closeMs = performance.now() - t0;
    const failures: string[] = [];
    // The floor is an unsigned row (HotPathOne.tla's BarrierChecksFloor): a writer who lowered it would let a use in
    // below it, which a window read from the floor the signer holds misses; one who raised it would get its value
    // signed, and so kept. Each barrier must find it exactly where this process's last one left it, else the tick is
    // refused, and every tick after it, until the checkpointer is reopened (sticky, as the model's alarm: a later
    // barrier can land the row back on the expected value, but not undo what the floor let in meanwhile). After a
    // restart the first barrier may find it above the newest pair's honestly (barriers whose pairs went unsigned
    // raised it), never below.
    // Above where its last barrier left it is a barrier of a checkpointer given up on, landing late (T169), so long as it
    // is no higher than this barrier's own clock less the deadline, which this barrier raised it past anyway
    // (HotPathOne.tla's BarrierAcceptsLate): higher, a writer raised it.
    // The first barrier after an open too (review by Fable): the barriers whose pairs went unsigned left the floor at
    // most at their own clock less the deadline, which this barrier's ceiling is past; higher, a writer raised it.
    const expected = this.barrier ?? this.floor;
    const raised = floor.found !== null && floor.found > (this.barrier ?? -Infinity) && floor.found > floor.ceiling;
    if (floor.found === null || floor.found < expected || raised) {
      this.floorAlarm ??= `the floor of at is ${floor.found ?? 'gone'}, not the ${expected} the signer's barrier set: ${floor.found !== null && floor.found > expected ? 'raised' : 'lowered'} by a writer; reopen the checkpointer once it is put right`;
    } else {
      this.barrier = floor.set;
    }
    if (this.floorAlarm !== null) failures.push(this.floorAlarm);
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
    // A part of the window (T169) is held to its own newest entry, no further: the rest of a backlog may be stamped long
    // before now, and is no replay.
    const newestAt = entries.reduce((max, e) => Math.max(max, e.at), -Infinity);
    const at = entries.length === 0 ? pair.at : Math.max(pair.at, Math.min(this.options.now(), newestAt + (more === null ? this.options.freshMs : 0)));
    const result = (signed: boolean, writeMs = 0): Tick => ({
      signed: signed || finished, upto: this.head.pair.upto, sizes: sizes(this.head.pair), entries: entries.length, failures, closeMs, writeMs,
      more: signed && more !== null,
    });
    if (failures.length > 0) {
      const said = failures.join('\n');
      if (said !== this.refused) for (const f of failures) this.options.alert(`audit checkpoint refused: ${f}`);
      this.refused = said;
      return result(false);
    }
    this.refused = null;
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
    // The pair carries the floor this barrier left, which the signer reads from once the pair is written, and the floor
    // of the pair before it: so the pair's own note says whether it is the first past a time (retention's cut).
    // A part of the window (T169) ends at its last entry, every number below it read, and carries the lowest `at` of the
    // uses left above it, if below the barrier's floor (HotPathOne.tla's ChunkFloor): the next window is read from it,
    // and the rest of a backlog may be stamped long before the barrier. Its own uses sit within 63 s of it
    // (CeilingHolds): each was numbered before the barrier and before any use left above it, within [at − 60 s,
    // at + 3 s] by Postgres's clock (`ahead`, the deadline).
    const place = more === null ? upto : entries.at(-1)!.number;
    const signedFloor = more === null ? floor.set : Math.max(this.floor, Math.min(floor.set, more.above ?? floor.set));
    this.phase = 'sign';
    const next = await signPair(this.signers, place, at, heads, signedFloor, pair.floor);
    this.pending = { next, edges, tiles };
    // Remembered outside the database before the database has it (RememberFirst): a crash between the two and a
    // rollback can then never get a second pair signed for the same place.
    this.phase = 'remember';
    await this.options.memory.remember(encodePair(next.notes));
    const t1 = performance.now();
    this.phase = 'write';
    await this.store.write({ upto: place, notes: next.notes }, tiles);
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
        // Alerted once while it stands, as a refused tick is: every tick finds it again.
        if (message !== this.refused) this.options.alert(`audit checkpoint refused: ${message}`);
        this.refused = message;
        throw new Error(message);
      }
      await this.store.write({ upto: p.next.pair.upto, notes: p.next.notes }, p.tiles);
    }
    this.commit(p);
  }

  private commit(p: Pending): void {
    this.edges = p.edges;
    this.head = p.next;
    this.floor = p.next.pair.floor;
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
    // Its ticks and its proof within `SEAL_WAIT_MS` (T169): past it, or once the checkpointer stalled or its database does
    // not answer, the change answers `Unsealed`, committed, and the next checkpointer that ticks seals it.
    const until = performance.now() + this.options.sealWaitMs;
    const bounded = <T>(work: Promise<T>, what: string): Promise<T> =>
      within(work, until - performance.now(), what).catch((error: unknown) => {
        if (error instanceof TimedOut || error instanceof Stalled || this.closed || isUnavailable(error)) throw new Unsealed(number, (error as Error).message, error);
        throw error;
      });
    while (this.head.pair.upto < number) {
      const before = this.head.pair.upto;
      const t = await bounded(this.tick(), 'its seal');
      if (this.head.pair.upto === before) throw new Error(`cannot seal ${number}: ${t.failures.join('; ') || 'the barrier has not passed it'}`);
    }
    const head = this.head;
    // From the changes tree (KindInMac): the MAC does not cover the number, so a writer could delete the change and
    // renumber a use into its place before the tick; that use is sealed, and provable, but in the uses tree.
    // A proof the database answers wrongly for (an entry changed since its tick, `locate`'s refusal) is the same alarm.
    let proof: InclusionProof | null;
    try {
      proof = await bounded(this.proveAt(number, head, { tree: 'changes' }), 'the proof of its seal');
    } catch (error) {
      if (!(error instanceof Refused)) throw error;
      const message = `change ${number} cannot be proved in the signed changes tree: ${error.message}`;
      this.options.alert(message);
      throw new Error(message);
    }
    if (proof === null) {
      const message = `change ${number} is not in the signed changes tree: its entry was lost before its seal`;
      this.options.alert(message);
      throw new Error(message);
    }
    const failures = await this.witnessed(number, deadline);
    const cosigned = this.options.witnesses.map((w) => this.pump(w)).filter((p) => p.acked >= number && p.cosigned !== null).map((p) => p.cosigned!);
    const witnessed = this.options.witnesses.length === 0 ? null : failures.length === 0;
    if (witnessed === false) this.options.alert(`change ${number} answered unwitnessed: ${failures.join('; ')}`);
    return { pair: head.pair, notes: head.notes, witnessed, failures, cosigned, proof };
  }

  /**
   * Entry `number`'s inclusion proof against the newest pair, checked before
   * it is handed out; null if not sealed. A use's `at`, if known, finds it
   * in one probe; with `tree`, an entry in the other is refused.
   */
  prove(number: bigint, options: Locating = {}): Promise<InclusionProof | null> {
    return this.proveAt(number, this.head, options);
  }

  private proveAt(number: bigint, head: { pair: Pair; notes: PairNotes }, options: Locating = {}): Promise<InclusionProof | null> {
    return proveIn(this.store, number, head, options);
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

  /** Hands a witness the newest pair: sent now if its pump is idle, else next. A checkpointer closed hands none. */
  private kick(w: Witness): void {
    if (this.closed) return;
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
        p.cosigned = a.cosigned ?? null;
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

/**
 * Entry `number`'s inclusion proof against the pair `head`, checked before it is handed out; null if not sealed. The
 * checkpointer's (`prove`, a change's seal), and the vault's, which proves the cutover's change from its database
 * alone (T169): a pair covering a number may cover the gap a writer moved an entry into, so the entry is proved.
 */
export async function proveIn(store: Pick<CheckpointStore, 'locate' | 'tiles'>, number: bigint, { pair, notes }: { pair: Pair; notes: PairNotes }, options: Locating = {}): Promise<InclusionProof | null> {
  if (number > pair.upto) return null;
  const found = await store.locate(number, options);
  if (found === null) return null;
  const { entry, index } = found;
  if (options.tree !== undefined && entry.tree !== options.tree) throw misplaced(entry, options.tree);
  if (entry.number !== number || !TREES.includes(entry.tree) || !Number.isSafeInteger(index) || index < 0) {
    throw new Refused(`the database answered for another entry than ${number}`);
  }
  // An entry numbered at or below the pair's place is in its tree by construction: an index past the tree is the
  // database's answer, not the tree's.
  const size = pair[entry.tree].size;
  if (index >= size) throw new Refused(`the database places entry ${number} at ${index}, past the ${entry.tree} tree the signer signed (${size})`);
  const nodes = nodesFrom(tileMap(await store.tiles(entry.tree, tilesFor((n) => inclusionProof(n, index, size)))));
  const proof = inclusionProof(nodes, index, size);
  if (!verifyInclusion(entryLeaf(entry.tree, entry.number, entry.columns), index, size, proof, pair[entry.tree].root)) {
    throw new Refused(`entry ${number} is not at ${index} of the ${entry.tree} tree the signer signed: the database changed it`);
  }
  return { number, tree: entry.tree, index, size, leaf: leafData(entry.tree, entry.number, entry.columns), proof, notes };
}

/** An in-process witness: what the witness's Durable Object does, without the network. */
export function localWitness(name: string, log: PairVerifiers, self: NoteSigner): Witness & { held(): WitnessState } {
  let state: WitnessState = null;
  // One publication at a time, as the Durable Object's input gate gives it: a try the pump gave up on, landing late,
  // must not put back an older pair over a newer one.
  let queue: Promise<unknown> = Promise.resolve();
  return {
    name,
    held: () => state,
    publish(notes, proofs) {
      const run = queue.then(async () => {
        const r = await witnessPair(state, notes, await proofs(state === null ? { changes: 0, uses: 0 } : sizes(state.pair)), log, self);
        state = r.state;
        return r.answer;
      });
      queue = run.catch(() => {});
      return run;
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

/**
 * A pair the signer signed before written again, at an open: one a
 * checkpointer given up on had sent may have landed meanwhile (T169), which
 * refuses this write, a row at its place. That row being the pair is what
 * the write was for.
 */
async function rewrite(store: CheckpointStore, row: StoredPair, tiles: Record<TreeName, Tile[]>): Promise<void> {
  try {
    await store.write(row, tiles);
  } catch (error) {
    const newest = await store.newest();
    if (newest === null || newest.upto !== row.upto || newest.notes.changes !== row.notes.changes || newest.notes.uses !== row.notes.uses) throw error;
  }
}

/** Whether a row is exactly this pair: the same place and the same two notes, byte for byte. */
const holds = (row: StoredPair | null, head: { pair: Pair; notes: PairNotes }) =>
  row !== null && row.upto === head.pair.upto && row.notes.changes === head.notes.changes && row.notes.uses === head.notes.uses;

const sizes = (heads: Record<TreeName, { size: number }>) => ({ changes: heads.changes.size, uses: heads.uses.size });
/** Both trees' sizes as a message says them: `changes 4, uses 120`. */
const said = (heads: Record<TreeName, { size: number }>) => `changes ${heads.changes.size}, uses ${heads.uses.size}`;

/** Appends a window's entries, in number order, each to its tree: the tiles to write. */
function appendWindow(edges: Record<TreeName, Edge>, entries: readonly LogEntry[]): Record<TreeName, Tile[]> {
  const leaves = (tree: TreeName) => entries.filter((e) => e.tree === tree).map((e) => entryLeaf(tree, e.number, e.columns));
  return { changes: edges.changes.append(leaves('changes')), uses: edges.uses.append(leaves('uses')) };
}
