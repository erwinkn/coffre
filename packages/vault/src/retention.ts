import { leafData, openPair, proveConsistency, TREES, verifyConsistency, type Cut, type LogEntry, type StoredPair } from '@coffre/core/merkle';

import type { Checkpointer, CheckpointStore } from './checkpointer.ts';
import { entryMac, RETENTION_ACTOR, RETENTION_OBJECT, retentionCut, retentionPayload } from './log-entry.ts';

/**
 * Retention (docs/design/0.15-plan.md, PR 7; formal/Seal.tla's retention):
 * days of uses dropped once a sealed retention change cuts the uses tree
 * above them, and the uses tree's tiles below the cut, the one holding it at
 * each level kept. Changes are kept for good: the changes tree is never cut.
 *
 * A day goes in these steps, oldest first, each a precondition of the next:
 * 1. Its cut: the first pair whose floor of `at` is past the day's end. Every
 *    use of the day took its number at or below it (a use's `at` is held to
 *    the floor), so all of them lie below the cut; a few of the next day's
 *    do too (stragglers), and stay until their own day goes. The cut must be
 *    a pair the signer signed, the first past the day's end by its own note
 *    (its `prev`, the floor of the pair signed before it, below the end:
 *    CutFirst), on its history (a consistency proof to its head in both
 *    trees), at or below its head.
 * 2. The retention change naming it, unless the newest sealed one already
 *    cuts at or past it (a quiet day, or a retry): appended, and sealed in
 *    the signer's pair (DropAfterSeal; else the verifier, walking the uses
 *    from genesis, would find the day gone).
 * 3. Freshness: the pair that sealed it (or the signer's, for a day an older
 *    change cuts) at least two freshness bounds past the cut (FreshBeforeDrop).
 *    The signer refuses any entry stamped a bound before its pair (FRESH_MS),
 *    so no copy of a dropped use, which keeps its stamp and has no original
 *    left for a request-ID check to find, is ever sealed again. Two bounds,
 *    not one: one for the clocks.
 * 4. The day's partition: detached, and dropped by the next run (`drop_day`).
 *    Measured at 1,000 uses a second (0.15-plan.md, "As built: PR 7"): a DROP
 *    right after the DETACH lands while every backend replans its plan of
 *    `log_uses`, and stalls uses 200 to 400 ms; seconds later, it stalls none.
 *    A crash between any two steps is finished by the next run.
 * Then the tiles below the newest cut (`drop_tiles`).
 *
 * The signer's checks are the vault's: its memory, its pair, its keys. The
 * database's functions check what they can see, so that the vault's login
 * drops nothing a retention change it holds does not cut.
 */
export type RetentionStore = {
  /** The UTC days of uses the database holds, oldest first: YYYY-MM-DD. */
  days(): Promise<string[]>;
  /** Makes each day's partition of uses (`make_day`), once a store. */
  makeDays(days: readonly string[]): Promise<void>;
  /** The first checkpoint whose floor of `at` is at or past `ms`. */
  cutAt(ms: number): Promise<StoredPair | null>;
  /** The newest retention change at or below the newest checkpoint, with its leaf index; null if none. */
  retention(): Promise<{ entry: LogEntry; index: number } | null>;
  /** Appends a retention change, or finds the one its request ID names: its number. */
  appendRetention(change: { requestId: string; at: number; payload: string; mac: Buffer }): Promise<bigint>;
  /** One step of dropping a day: detached, dropped, or gone. */
  dropDay(day: string): Promise<'detached' | 'dropped' | 'gone'>;
  /** The uses tree's tiles wholly below leaf `below`: how many were deleted or ranges dropped. */
  dropTiles(below: number): Promise<number>;
  /** At most `limit` of the bulk cap's rows that its window no longer counts: how many went. */
  pruneBulk(limit: number): Promise<number>;
};

export const DAY_MS = 86_400_000;

/** A UTC day, YYYY-MM-DD, of a time in ms. */
export const dayOf = (ms: number) => new Date(ms).toISOString().slice(0, 10);

export type RetentionRun = {
  /** The days whose uses went this run, each with the retention change written for it, if one was. */
  dropped: { day: string; change: bigint | null }[];
  /** Of those, the days detached and not dropped yet: the next run drops them. */
  detached: string[];
  /**
   * Why the run stopped before a due day (`day`) or the tiles (no day), when it waits for something: the log to move on,
   * or (`lock`) a reader holding the uses past the lock timeout. No alarm; a lock standing a day is one (`upkeep`).
   */
  waiting: { day: string | null; lock: boolean; reason: string } | null;
  /** Tiles deleted or leaf ranges dropped below the newest cut. */
  tiles: number;
};

type Options = {
  /** Full days of uses kept before today's: a day goes once `keepDays` days have ended after it. */
  keepDays: number;
  /** The log's MAC key (`logMacKey`): the retention change is an entry like any. */
  macKey: Buffer;
  now?: () => number;
};

/**
 * One run. Throws on what is an alarm (a cut off the signer's history, a
 * retention change not sealed, a day the database refuses); returns `waiting`
 * when a day is not ready yet.
 */
export async function retain(cp: Checkpointer, store: CheckpointStore & RetentionStore, options: Options): Promise<RetentionRun> {
  if (!Number.isSafeInteger(options.keepDays) || options.keepDays < 1) throw new Error(`keepDays must be a whole number of days, at least 1, not ${options.keepDays}`);
  const now = options.now ?? Date.now;
  const run: RetentionRun = { dropped: [], detached: [], waiting: null, tiles: 0 };
  const last = dayOf(now() - (options.keepDays + 1) * DAY_MS);
  for (const day of (await store.days()).filter((d) => d <= last)) {
    const done = await retainDay(cp, store, day, options.macKey, now);
    if ('reason' in done) {
      run.waiting = { day, ...done };
      break;
    }
    run.dropped.push({ day, change: done.change });
    // One DETACH a run: each invalidates every backend's plan of log_uses, and a second landing while they replan stalls
    // uses (measured for a DROP: 0.15-plan.md, "As built: PR 7"). A backlog of days goes a day an hour.
    if (done.detached) {
      run.detached.push(day);
      break;
    }
  }
  // The tiles below the newest cut, once its sealing is two freshness bounds past it, as a day goes (FreshBeforeDrop).
  const newest = await sealedCut(cp, store);
  if (newest !== null && cp.pair.pair.at >= newest.at + 2 * cp.freshMs) {
    const tiles = await waitingOnLock(() => store.dropTiles(newest.uses.size));
    if (typeof tiles === 'number') run.tiles = tiles;
    else run.waiting ??= { day: null, lock: true, reason: `the tiles below ${newest.upto}: ${tiles.reason}` };
  }
  return run;
}

/** One day: dropped, with the change written for it if any; or why it waits. */
type Wait = { lock: boolean; reason: string };

async function retainDay(cp: Checkpointer, store: CheckpointStore & RetentionStore, day: string, macKey: Buffer, now: () => number): Promise<{ change: bigint | null; detached: boolean } | Wait> {
  const end = Date.parse(`${day}T00:00:00Z`) + DAY_MS;
  const head = cp.pair.pair;
  if (head.floor < end) return { lock: false, reason: `the signer's newest pair (up to ${head.upto}) is not past the day's end yet` };
  // 1. The cut: a pair of this log at or below the signer's, the first it signed past the day's end by its own note (its
  // floor at or past the end, the floor before it below: CutFirst). The rows say which pair that is, and a writer who
  // deletes some, or edits their floors, would make a later one pass for it, and every use between go unwalked.
  const row = await store.cutAt(end);
  const cut = row === null ? null : await openPair(row.notes, cp.verifiers);
  if (row === null || cut === null || cut.upto !== row.upto || cut.floor < end || cut.prev >= end || cut.upto > head.upto) {
    throw new Error(`retention of ${day}: the database holds no pair of this log, at or below the signer's (up to ${head.upto}), that is the first past the day's end: checkpoints were deleted or replaced`);
  }
  // On the signer's history, by a consistency proof to its head; unless the newest sealed cut is at or past it (a day a
  // change already cut, or one waiting to be dropped): that cut was proved when it was sealed, and the tiles below it,
  // which a proof from this one would read, may be gone.
  const sealed = await sealedCut(cp, store);
  if (sealed === null || sealed.upto < cut.upto) {
    for (const tree of TREES) {
      if (cut[tree].size === head[tree].size && cut.upto === head.upto) continue;
      const proof = cut[tree].size > head[tree].size ? null : await proveConsistency(store, tree, cut[tree].size, head[tree].size).catch(() => null);
      if (proof === null || !verifyConsistency(cut[tree].size, head[tree].size, cut[tree].root, head[tree].root, proof)) {
        throw new Error(`retention of ${day}: the cut's ${tree} head (up to ${cut.upto}) is not on the signer's history`);
      }
    }
  }
  // 2. The retention change, unless the newest sealed one cuts at or past this day's.
  let change: bigint | null = null;
  let freshAt = head.at;
  if (sealed === null || sealed.upto < cut.upto) {
    const named: Cut = { upto: cut.upto, at: cut.at, uses: { size: cut.uses.size, root: cut.uses.root } };
    const at = now();
    const requestId = `retention:${day}`;
    const payload = retentionPayload(day, named);
    const mac = entryMac(macKey, { tree: 'changes', row: { at, requestId, object: RETENTION_OBJECT, actor: RETENTION_ACTOR, payload, seal: null } });
    change = await store.appendRetention({ requestId, at, payload, mac });
    // Sealed in the signer's pair, witnessed or not: its proof is checked against the pair. A retry finds the change it
    // made before, whose cut is this day's (the first pair past its end) unless the rows moved: then nothing is dropped.
    const answer = await cp.sealThrough(change);
    const entry = (await store.retention())?.entry;
    const written = entry?.number === change ? retentionCut(entry) : null;
    if (written === null || written.upto !== cut.upto || !leafData('changes', entry!.number, entry!.columns).equals(answer.proof.leaf)) {
      throw new Error(`retention of ${day}: the retention change ${change} is not the one sealed, or does not cut at ${cut.upto}`);
    }
    freshAt = answer.pair.at;
  }
  // 3. Freshness, against the signer's own pair, never a row.
  const bound = Math.max(cut.at, end) + 2 * cp.freshMs;
  if (freshAt < bound) return { lock: false, reason: `the pair sealing its cut (at ${freshAt}) is not two freshness bounds past it (${bound}) yet` };
  // 4. The day's partition: detached now, and dropped by a later run, never right after its DETACH (see above). A reader
  // holding log_uses longer than `drop_day`'s lock_timeout (a backup, say) makes it give up: the next run tries again.
  let state = await waitingOnLock(() => store.dropDay(day));
  if (state === 'dropped') state = await waitingOnLock(() => store.dropDay(day));
  if (typeof state === 'object') return state;
  if (state === 'dropped') throw new Error(`retention of ${day}: its uses were not dropped`);
  return { change, detached: state === 'detached' };
}

/** What `work` answers, or, when the database gave up waiting for a lock (55P03, lock_timeout), why: no alarm. */
async function waitingOnLock<T>(work: () => Promise<T>): Promise<T | Wait> {
  try {
    return await work();
  } catch (error) {
    const e = error as { code?: unknown; cause?: { code?: unknown } };
    if (e.code === '55P03' || e.cause?.code === '55P03') return { lock: true, reason: 'a reader holds the table past the lock timeout: the next run tries again' };
    throw error;
  }
}

/** The newest retention change's cut, proved in the signer's pair; null if there is none. */
async function sealedCut(cp: Checkpointer, store: RetentionStore): Promise<Cut | null> {
  const found = await store.retention();
  if (found === null) return null;
  const cut = retentionCut(found.entry);
  const proof = await cp.prove(found.entry.number, { tree: 'changes' });
  if (cut === null || proof === null || proof.tree !== 'changes' || !proof.leaf.equals(leafData('changes', found.entry.number, found.entry.columns))) {
    throw new Error(`the retention change ${found.entry.number} is not sealed in the signer's changes tree as the database holds it`);
  }
  return cut;
}
