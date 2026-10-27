import { createHash, createHmac, hkdfSync, timingSafeEqual } from 'node:crypto';

import { MAX_NUMBER, openPair, pairSigners, pairVerifiers, verifyLog, type LogEntry, type PairNotes, type PairVerifiers } from '@coffre/core/merkle';
import type { TreeVerification } from '@coffre/core/vault';
import type { Database } from '@coffre/db';
import { SNAPSHOT } from '@coffre/db/dialect';

import { refreshMs, USE_DEADLINE_MS } from './bulk.ts';
import { loggedChange } from './changes.ts';
import { FRESH_MS, logOrigin } from './checkpointer.ts';
import { MAX_BULK_WINDOW_MINUTES, type BulkLimit } from './config.ts';
import { alike, refOf, sealKey, type Input, type SealKeys } from './inputs.ts';
import { authentic, logMacKey } from './log-entry.ts';
import { emptyReplay, purposeOf, replay, type Logged, type Replayed } from './log-replay.ts';
import { logStore } from './log-store.ts';
import { bulkRows, heldObjects, keepReplay, keptReplay, keptUptos, now, requestsUnique, type KeptReplay } from './store.ts';

/**
 * 0.15's verifier (docs/design/0.15-plan.md, PR 8): what holds 0.15's log
 * to itself and the rows to the log, for the audit page, `coffre verify
 * log` and conformance.
 *
 * A walk goes on from a signed pair:
 * - **the trees** (`verifyLog` in @coffre/core/merkle): every pair after it
 *   rebuilt from the entries, both heads, so an entry deleted, added,
 *   changed or moved after its seal shows at the next pair;
 * - **each entry** by its MAC (the checkpointer's `authentic`), and its
 *   request once (RequestIdChecked): a copy of an entry is a replay;
 * - **the replay** (log-replay.ts), on from the replay kept at that pair:
 *   each change applied with `applyOp` and its seal held to the object the
 *   replay has, each use decided again and the bulk cap moved as the use's
 *   statement moves it;
 * - **the rows,** once the walk reaches the present, in the snapshot it
 *   read the log in: every object's rows hold the object the replay has,
 *   with its newest seal, and every bulk row is the replay's. A row put back
 *   from before a change, a row written with no change, a change's entry
 *   deleted before its seal (its row then carries a seal no entry left):
 *   each is a row the log does not make.
 *
 * What a walk replayed is kept at the pair it ended at, under the vault's
 * MAC (`log_replays`), and the next walk goes on from there: a check costs
 * the entries since the last one kept, never a walk from the first (R25).
 * The checkpoint job keeps it moving (`vault.checkpoint`), so a page's check
 * reads about a beat's worth. A walk from the first entry is asked for
 * (`from: 'start'`), a stretch of `limit` entries a call, each ending at a
 * pair whose replay it keeps for the next.
 *
 * What it cannot see, by design: an entry deleted or reordered before its
 * tick (R51's window; a change answers only once sealed, so this is a use's),
 * and entries swapped whose replay is the same either way.
 */

/** The keys a walk needs: the trees' public keys, the entries' MAC key, the seal keys, and what kept replays are MAC'd under. */
export type VerifierKeys = { verifiers: PairVerifiers; mac: Buffer; seals: SealKeys; replays: readonly Buffer[] };

/** The verifier's keys from the vault's signing seeds: the trees' and the entries' from the first, as the checkpointer has them (log-checkpointer.ts). */
export async function verifierKeys(seeds: readonly Uint8Array[]): Promise<VerifierKeys> {
  const seed = seeds[0]!;
  const signers = await pairSigners(await logOrigin(seed), seed);
  return {
    verifiers: await pairVerifiers({ changes: signers.changes.verifierKey, uses: signers.uses.verifierKey }),
    mac: logMacKey(seed),
    seals: seeds.map((s) => sealKey(s)),
    replays: seeds.map((s) => Buffer.from(hkdfSync('sha256', s, new Uint8Array(0), 'coffre.log.replay.v1', 32))),
  };
}

export type VerifyOptions = {
  /** `start`, or a pair's `upto` whose replay was kept: a stretch of a walk that replays the log. */
  from?: string;
  /** Entries a call walks at most, to the first pair past them. */
  limit: number;
  /**
   * Replay on from the newest replay kept, audit every row at the present,
   * and keep both: the checkpoint job's walk. Without it, and without
   * `from`, a page's check: the trees and the entries from the newest
   * verdict kept, and that verdict.
   */
  replay?: boolean;
  /**
   * Pairs held outside the database: the signer's memory, a witness's
   * (`VaultOptions.heldOutside`). The walk must reach each: a database
   * rolled back whole to an earlier pair, rows and kept replays with it,
   * otherwise passes until the signer's next tick refuses it.
   */
  anchors?: readonly PairNotes[];
  /** Added to the database's clock where a verdict's age is judged; tests move time with it. */
  clockOffset?: number;
  /**
   * A replay a stretch before handed on (`Walked.carry`): the job's run goes
   * on from it in memory, rather than reading back and writing the whole
   * replay every stretch (review r6).
   */
  carried?: Carried;
  /** The caller carries each stretch's replay on (`Walked.carry`), and keeps where its run stops (`keepCarried`): no stretch is kept. */
  carrying?: boolean;
};

/** A replay at a pair, in memory, for the next stretch of one run. */
export type Carried = { upto: bigint; notes: PairNotes; replayed: Replayed };

/**
 * How long a kept row older than the newest verdict and the newest replay
 * is kept: a whole walk's next stretch asks for the one before within
 * seconds, and each stretch kept forgets the one it went on from.
 */
export const REPLAYS_KEPT_MS = 10 * 60_000;

/**
 * How old the newest verdict may be before a page's check says it is out
 * of date: three runs of the checkpoint job, which keeps one every five
 * minutes it reaches the present. Older, the job has stopped or fallen
 * behind, or a writer keeps its verdict from landing (review r5): the seal
 * is withheld.
 */
export const VERDICT_STALE_MS = 15 * 60_000;

/**
 * What a walk that reached the present found, and when: the replay's
 * faults and every row held to it. A page's check says it again.
 */
type Found = { at: number; problems: string[] };

/**
 * The verdict as `verifyTrees` gives it; whether the database ended behind
 * a pair held outside (`Verdict.behind`); and, for a stretch that stopped
 * short of the present over a log that holds, its replay to go on from.
 */
export type Walked = Extract<TreeVerification, { kept: true }> & { behind: boolean; carry: Carried | null };

/**
 * Two kinds of walk (review r5).
 *
 * **A page's check** (no `from`, no `replay`) costs the entries since the
 * newest verdict kept (R25), never the instance's size:
 * - it walks the trees and checks every entry, its MAC and its request,
 *   from the pair that verdict is at;
 * - it does not replay, nor read any row: it says the verdict, which the
 *   last replaying walk found, and when.
 * With no verdict kept yet, it replays as the job does.
 *
 * **A replaying walk:** the checkpoint job's (`replay`), on from the newest
 * replay kept, and each stretch of a walk from the first entry (`from`).
 * - It replays every entry; at the present it holds every row to the
 *   replay, an O(objects) read.
 * - It keeps the replay where it ends, and at the present the verdict, even
 *   one that finds the log broken, so that a page says it.
 * - Between verdicts, every use refuses a row put back `stale` (decide.ts).
 */
export async function verifyTrees(db: Database, keys: VerifierKeys, options: VerifyOptions): Promise<Walked> {
  const problems: string[] = [];
  /** Kept rows a walk passed over, not the vault's: named, and forgotten by the next row kept. */
  const passedOver: bigint[] = [];
  const result = (walk: Partial<Walked>): Walked => ({
    kept: true as const, ok: problems.length === 0, problems, from: null, checkpoint: null, checkpoints: 0, sealed: 0, unsealed: 0, done: false, next: null, audited: null, stale: false, behind: false, carry: null, ...walk,
  });
  const page = options.from === undefined && options.replay !== true;
  const carrying = options.carrying === true || options.carried !== undefined;

  const walked = await db.transaction(async (tx) => {
    const store = logStore(tx as unknown as Database);
    // A kept row at its pair, if it is the vault's over that pair, and its replay, read only when it is to be replayed on.
    const opened = async (upto: bigint, withState: boolean) => {
      const kept = await keptReplay(tx, upto, withState);
      const pair = kept === null ? null : await store.pair(upto);
      if (kept === null || pair === null || !keptMacHolds(keys, kept, pair.notes)) return null;
      if (!withState) return { notes: pair.notes, upto, replayed: null, found: foundOf(kept.verdict) };
      if (kept.state === null || !createHash('sha256').update(kept.state).digest().equals(kept.stateHash!)) return null;
      const replayed = stateOf(kept.state);
      return replayed === null ? null : { notes: pair.notes, upto, replayed, found: foundOf(kept.verdict) };
    };
    // Newest first: one that is not the vault's is named and passed over, never gone on from, and never left to stop
    // every check after (review r3).
    const newestOpened = async (holding: 'state' | 'verdict') => {
      for (const upto of await keptUptos(tx, holding)) {
        const found = await opened(upto, holding === 'state');
        if (found !== null) return found;
        if (!passedOver.includes(upto)) passedOver.push(upto);
      }
      return null;
    };
    let start = null as Awaited<ReturnType<typeof opened>>;
    let replaying = !page;
    if (options.carried !== undefined) {
      start = { ...options.carried, found: null };
    } else if (page) {
      start = await newestOpened('verdict');
      // No verdict kept yet: a walk that replays, as the job's.
      if (start === null) [replaying, start] = [true, await newestOpened('state')];
    } else if (options.from === undefined) {
      start = await newestOpened('state');
    } else if (options.from !== 'start') {
      const upto = parseUpto(options.from);
      if (upto === null) return { refused: `not a pair to go on from: ${options.from}` };
      start = await opened(upto, true);
      if (start === null) return { refused: `no replay the vault kept is at ${upto}: walk again from the first entry` };
    }
    const replayed = replaying ? (start?.replayed ?? emptyReplay()) : null;
    const newest = await store.newest();
    // The replay as it stands at the newest pair, taken as the walk passes it: entries above it are not sealed yet.
    let atNewest: Saved | null = null;
    const requests = new Requests();
    const check = (entry: LogEntry): string | null => {
      if (replayed !== null && newest !== null && atNewest === null && entry.number > newest.upto) atNewest = saved(replayed);
      if (!authentic(keys.mac)(entry)) return 'its MAC does not hold';
      if (!requests.once(entry)) return 'a second entry under the request of another: a replay';
      const one = logged(entry);
      if (typeof one === 'string') return one;
      if (replayed === null) return null;
      const faults = replayed.faults.length;
      replay(keys.seals, [one], undefined, replayed);
      return replayed.faults.length > faults ? replayed.faults.splice(faults).map((fault) => fault.replace(/^\d+: /, '')).join('; ') : null;
    };
    const verdict = await verifyLog(store, {
      verifiers: keys.verifiers, ...(start === null ? {} : { from: start.notes }), ...(options.anchors === undefined ? {} : { anchors: options.anchors }), check, limit: options.limit,
    });
    problems.push(...verdict.problems);
    if (!(await requestsUnique(tx))) problems.push('the indexes that keep each request to one entry are gone: a copy of an entry would pass');
    const at = await now(tx);
    // At the present, a replaying walk holds every row to its replay: what it found is its verdict, the log's own
    // problems with it. A page's check says the verdict it went on from.
    const found: Found | null = replayed !== null && verdict.done
      ? { at, problems: [...problems, ...audit(replayed, await heldObjects(tx), await bulkRows(tx), at)] }
      : start?.found ?? null;
    return {
      verdict, start, at, found, replaying, newest, replayed,
      // A stretch whose replay a run carries on in memory is written once, where the run stops (`keepCarried`).
      state: replayed === null || (!verdict.done && carrying) ? null : JSON.stringify(verdict.done ? (atNewest ?? saved(replayed)) : saved(replayed)),
    };
  }, SNAPSHOT);
  if ('refused' in walked) {
    problems.push(walked.refused!);
    return result({ from: options.from === undefined || options.from === 'start' ? null : options.from });
  }
  const { verdict, start, at, found, replaying, newest } = walked;
  const head = verdict.head === null ? null : await openPair(verdict.head, keys.verifiers);
  // The kept row it went on from, a stretch's, forgotten once this one is kept: a whole walk holds one at a time.
  const before = options.from !== undefined && options.from !== 'start' && start !== null ? [start.upto] : [];
  if (replaying && verdict.done && newest !== null && !verdict.behind) {
    // The verdict, at the newest pair, kept whatever it found, but a database behind the signer, which may be its own
    // write a moment away. The replay to go on from with it only over a log that holds, or one this walk replayed
    // nothing past: the one it started from, still the vault's (review r6).
    const state = problems.length === 0 || (start !== null && start.upto === newest.upto) ? walked.state : null;
    await keep(db, keys, { upto: newest.upto, notes: newest.notes, at, state, verdict: JSON.stringify(found) }, passedOver, before);
  } else if (replaying && !verdict.done && head !== null && problems.length === 0 && !carrying) {
    // A stretch's replay, for the next stretch to go on from.
    await keep(db, keys, { upto: head.upto, notes: verdict.head!, at, state: walked.state, verdict: null }, passedOver, before);
  }
  // What it says: the kept rows it passed over; then a replaying walk's own verdict at the present, the log's problems
  // among them, or a page's check's, the log's problems and the verdict it went on from, if not out of date.
  const named = passedOver.map((upto) => `the replay kept at ${upto} is not the vault's over the checkpoint there: passed over`);
  const said = replaying ? (verdict.done && found !== null ? found.problems : [...problems]) : [...problems, ...(found?.problems ?? [])];
  problems.splice(0, problems.length, ...named, ...said);
  // An out-of-date verdict is not known to hold, nor known not to: said apart from what is wrong (review r6).
  const stale = !replaying && found !== null && found.at < at + (options.clockOffset ?? 0) - VERDICT_STALE_MS;
  return result({
    from: start === null ? null : start.upto.toString(),
    checkpoint: head === null ? null : { upto: head.upto.toString(), at: head.at },
    checkpoints: verdict.checkpoints,
    sealed: verdict.sealed,
    unsealed: verdict.unsealed,
    done: verdict.done,
    next: !replaying || verdict.done || head === null ? null : head.upto.toString(),
    audited: verdict.done ? (found?.at ?? null) : null,
    stale,
    behind: verdict.behind,
    carry: replaying && !verdict.done && head !== null && problems.length === 0 && walked.replayed !== null
      ? { upto: head.upto, notes: verdict.head!, replayed: walked.replayed }
      : null,
  });
}

/** Keep the replay a run carried, where it stopped short of the present: the next run goes on from it. */
export function keepCarried(db: Database, keys: VerifierKeys, carry: Carried, at: number): Promise<void> {
  return keep(db, keys, { upto: carry.upto, notes: carry.notes, at, state: JSON.stringify(saved(carry.replayed)), verdict: null }, [], []);
}

/** Keep a row at `upto`, MAC'd over the pair's notes, its replay's hash and its verdict. */
function keep(
  db: Database,
  keys: VerifierKeys,
  row: { upto: bigint; notes: PairNotes; at: number; state: string | null; verdict: string | null },
  forged: readonly bigint[],
  done: readonly bigint[],
): Promise<void> {
  const stateHash = row.state === null ? null : createHash('sha256').update(row.state).digest();
  const mac = keptMac(keys.replays[0]!, row.upto, row.notes, stateHash, row.verdict);
  return keepReplay(db, { upto: row.upto, at: row.at, state: row.state, stateHash, verdict: row.verdict, mac }, REPLAYS_KEPT_MS, forged, done);
}

function parseUpto(from: string): bigint | null {
  return /^\d{1,19}$/.test(from) && BigInt(from) <= MAX_NUMBER ? BigInt(from) : null;
}

// --- entries ------------------------------------------------------------------------------------------

/** An entry as the replay takes it, from the columns its tree seals (log-entry.ts), or why it cannot be one. */
function logged(entry: LogEntry): Logged | string {
  const c = entry.columns;
  if (entry.tree === 'changes') {
    // [at, request, object, actor, payload, seal, mac]
    const [object, payload, seal] = [c[2], c[4], c[5]];
    let change = null;
    try {
      if (typeof object === 'string' && typeof payload === 'string' && (seal === null || seal instanceof Uint8Array)) {
        change = loggedChange({ number: entry.number, at: entry.at, object, payload, seal: seal === null ? null : Buffer.from(seal) });
      }
    } catch {}
    return change ?? 'a change whose payload names no object, or another than its own';
  }
  // [at, request, credential, secret, purpose, place, mac]
  const [credential, secret, code, place] = [c[2], c[3], c[4], c[5]];
  const purpose = typeof code === 'number' ? purposeOf(code) : null;
  if (purpose === null || typeof credential !== 'string' || typeof secret !== 'string' || (place !== null && typeof place !== 'string')) return 'a use no release writes';
  return { kind: 'use', number: entry.number, request: { credential, secretId: secret, place, at: entry.at, ...purpose } };
}

/**
 * Each entry's request, seen once (RequestIdChecked): a change's by its id,
 * a use's by its time and id, which its MAC covers. A copy shares them, and
 * a copy is sealed only within FRESH_MS of the pair the signer holds, so
 * only requests that recent are kept; a copy across two stretches is what
 * the database's unique indexes refuse, which the walk checks stand.
 */
class Requests {
  readonly #seen = new Map<string, number>();
  #newest = -Infinity;

  once(entry: LogEntry): boolean {
    const key = entry.tree === 'changes' ? `c:${String(entry.columns[1])}` : `u:${entry.at}:${String(entry.columns[1])}`;
    if (this.#seen.has(key)) return false;
    this.#seen.set(key, entry.at);
    this.#newest = Math.max(this.#newest, entry.at);
    if (this.#seen.size % 10_000 === 0) for (const [k, at] of this.#seen) if (at < this.#newest - 2 * FRESH_MS) this.#seen.delete(k);
    return true;
  }
}

// --- the replay kept ----------------------------------------------------------------------------------

/** A replay as `log_replays` keeps it: each object with its seal, the objects the log deleted, the cap and its rows. */
type Saved = {
  v: 1;
  rows: [key: string, row: Input, seal: string][];
  gone: string[];
  limit: BulkLimit | null;
  bulk: [principal: string, rows: [secret: string, last: number][]][];
  last: string;
};

/**
 * The replay as JSON. Bulk rows that can count for nothing again are left
 * out: older than the longest window, its refresh, the deadline and an
 * hour, before the newest use's time.
 */
function saved(replayed: Replayed): Saved {
  let newest = -Infinity;
  for (const held of replayed.bulk.values()) for (const last of held.values()) newest = Math.max(newest, last);
  const horizon = newest - MAX_BULK_WINDOW_MINUTES * 60_000 - 60_000 - USE_DEADLINE_MS - 3_600_000;
  return {
    v: 1,
    rows: [...replayed.rows].map(([key, { row, seal }]) => [key, row, seal!.toString('base64')]),
    gone: [...replayed.newest].filter(([, seal]) => seal === null).map(([key]) => key),
    limit: replayed.limit,
    bulk: [...replayed.bulk].map(([principal, held]) => [principal, [...held].filter(([, last]) => last > horizon)] as [string, [string, number][]]).filter(([, held]) => held.length > 0),
    last: replayed.last.toString(),
  };
}

/** A kept replay, as the walk goes on from it; its MAC and hash already checked. */
function stateOf(text: string): Replayed | null {
  const state = JSON.parse(text) as Saved;
  if (state.v !== 1) return null;
  const replayed = emptyReplay();
  for (const [key, row, seal] of state.rows) {
    replayed.rows.set(key, { row, seal: Buffer.from(seal, 'base64') });
    replayed.newest.set(key, Buffer.from(seal, 'base64'));
  }
  for (const key of state.gone) replayed.newest.set(key, null);
  replayed.limit = state.limit;
  for (const [principal, held] of state.bulk) replayed.bulk.set(principal, new Map(held));
  replayed.last = BigInt(state.last);
  return replayed;
}

/** A kept verdict, its MAC already checked. */
function foundOf(text: string | null): Found | null {
  return text === null ? null : (JSON.parse(text) as Found);
}

/** Whether a kept row's MAC is the vault's, by any of its keys, over the pair's notes, its replay's hash and its verdict. */
function keptMacHolds(keys: VerifierKeys, kept: KeptReplay, notes: PairNotes): boolean {
  if ((kept.state !== null || kept.stateHash !== null) && kept.stateHash?.length !== 32) return false;
  return keys.replays.some((key) => timingSafeEqual(keptMac(key, kept.upto, notes, kept.stateHash, kept.verdict), kept.mac));
}

function keptMac(key: Buffer, upto: bigint, notes: PairNotes, stateHash: Buffer | null, verdict: string | null): Buffer {
  return createHmac('sha256', key)
    .update(`coffre.log.replay.v1\0${upto}\0${notes.changes}\0${notes.uses}\0${stateHash?.toString('hex') ?? '-'}\0`)
    .update(verdict ?? '-')
    .digest();
}

// --- the rows -----------------------------------------------------------------------------------------

/**
 * Every row held to the replay: each object the log holds is in its rows,
 * as the replay has it, with its newest seal; each the log deleted (a key
 * archived) has none, and no seal; a row the log never heard of carries no
 * seal and is 0.14's, before the cutover (plan PR 9), but for the roles'
 * and the policy's, which only a change writes. Then each principal's bulk
 * rows, those that may still count: the database forgets older ones
 * (`prune_bulk`), the replay too.
 */
function audit(replayed: Replayed, held: Awaited<ReturnType<typeof heldObjects>>, bulk: Map<string, Map<string, number>>, now: number): string[] {
  const problems: string[] = [];
  const name = (key: string) => {
    const row = replayed.rows.get(key)?.row;
    const ref = held.get(key)?.ref ?? (row === undefined ? undefined : refOf(row));
    return ref === undefined ? `object ${key}` : `the ${ref.kind} ${ref.id}`;
  };
  for (const [key, seal] of replayed.newest) {
    const rows = held.get(key);
    if (seal === null) {
      if (rows !== undefined && (rows.row !== null || rows.seal !== null)) problems.push(`${name(key)}: its rows hold what the log deleted`);
      continue;
    }
    const object = replayed.rows.get(key)!.row;
    if (rows?.unreadable === true) problems.push(`${name(key)}: its rows do not read as an object`);
    else if (rows === undefined || (rows.row === null && rows.sealOnly === undefined)) problems.push(`${name(key)}: the log holds it, its rows do not`);
    else if (rows.seal === null || !rows.seal.equals(seal)) problems.push(`${name(key)}: its rows carry ${rows.seal === null ? 'no seal' : "another change's seal than the newest"}: put back, or written around the vault`);
    else if (rows.sealOnly === undefined && !alike(rows.row!, object)) problems.push(`${name(key)}: its rows are not the object the log makes`);
  }
  for (const [key, rows] of held) {
    if (replayed.newest.has(key)) continue;
    if (rows.seal !== null) problems.push(`${name(key)}: sealed, and the log holds no change of it`);
    else if (rows.ref.kind === 'roles' || rows.ref.kind === 'policy') problems.push(`${name(key)}: written with no change: only a change writes it`);
  }
  const limit = replayed.limit;
  if (limit === null) {
    if ([...bulk.values()].some((rows) => rows.size > 0)) problems.push('bulk rows, and no cap in the log to move them');
    return problems;
  }
  // As prune_bulk bounds it, by the database's clock: older rows may be gone from either side.
  const horizon = now - limit.windowMs - refreshMs(limit) - USE_DEADLINE_MS - 3_600_000;
  for (const principal of new Set([...bulk.keys(), ...replayed.bulk.keys()])) {
    const [stored, made] = [bulk.get(principal) ?? new Map<string, number>(), replayed.bulk.get(principal) ?? new Map<string, number>()];
    for (const secret of new Set([...stored.keys(), ...made.keys()])) {
      const [a, b] = [stored.get(secret), made.get(secret)];
      if ((a ?? -Infinity) <= horizon && (b ?? -Infinity) <= horizon) continue;
      if (a !== b) problems.push(`the bulk cap of ${principal}: its row for ${secret} says ${a ?? 'none'}, the log ${b ?? 'none'}`);
    }
  }
  return problems;
}
