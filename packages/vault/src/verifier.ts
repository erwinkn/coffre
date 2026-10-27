import { createHmac, hkdfSync, timingSafeEqual } from 'node:crypto';

import { MAX_NUMBER, openPair, pairSigners, pairVerifiers, verifyLog, type LogEntry, type PairNotes, type PairVerifiers } from '@coffre/core/merkle';
import type { TreeVerification } from '@coffre/core/vault';
import type { Database } from '@coffre/db';
import { SNAPSHOT } from '@coffre/db/dialect';

import { refreshMs, USE_DEADLINE_MS } from './bulk.ts';
import { loggedChange } from './changes.ts';
import { FRESH_MS, logOrigin } from './checkpointer.ts';
import { MAX_BULK_WINDOW_MINUTES, type BulkLimit } from './config.ts';
import { alike, objectKey, refOf, sealKey, type Input, type Ref, type SealKeys } from './inputs.ts';
import { authentic, logMacKey } from './log-entry.ts';
import { emptyReplay, purposeOf, replay, type Logged, type Replayed } from './log-replay.ts';
import { logStore } from './log-store.ts';
import { bulkRows, heldObjects, keepReplay, keptReplay, now, requestsUnique, type KeptReplay } from './store.ts';

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
  /** `start`, a pair's `upto` whose replay was kept, or the newest kept when absent. */
  from?: string;
  /** Entries a call walks at most, to the first pair past them. */
  limit: number;
  /** Keep the replay where the walk ends, however few entries it read: the checkpoint job's walk. */
  keep?: boolean;
  /**
   * Pairs held outside the database: the signer's memory, a witness's
   * (`VaultOptions.heldOutside`). The walk must reach each: a database
   * rolled back whole to an earlier pair, rows and kept replays with it,
   * otherwise passes until the signer's next tick refuses it.
   */
  anchors?: readonly PairNotes[];
};

/** A walk that read at least this many entries keeps its replay, so the next check reads fewer. */
export const KEEP_AFTER = 1000;

/** How long a replay older than the newest is kept: a walk's next stretch asks for it within seconds. */
export const REPLAYS_KEPT_MS = 3_600_000;

/**
 * Which rows a walk holds to the replay, when it reaches the present. A
 * check from a kept replay, a page's, holds only the objects its entries
 * changed or read, and their principals' bulk rows: R25's cost, the entries
 * since. Every other walk holds every row, an O(objects) read: the
 * checkpoint job's, every five minutes; one from the first entry; the last
 * stretch of a whole walk; and a check with no replay kept yet. What the
 * last full audit found is kept with the replay, and each check after says
 * it again until a full audit finds the rows whole.
 */
type Audited = { at: number; problems: string[] };

export async function verifyTrees(db: Database, keys: VerifierKeys, options: VerifyOptions): Promise<Extract<TreeVerification, { kept: true }>> {
  const problems: string[] = [];
  const result = (walk: Partial<Extract<TreeVerification, { kept: true }>>) => ({
    kept: true as const, ok: problems.length === 0, problems, from: null, checkpoint: null, checkpoints: 0, sealed: 0, unsealed: 0, done: false, next: null, ...walk,
  });

  // The walk's start, read in its snapshot: a replay kept at a pair, checked by its MAC over the pair's notes.
  const walked = await db.transaction(async (tx) => {
    const store = logStore(tx as unknown as Database);
    let start: { notes: PairNotes; upto: bigint; replayed: Replayed; audited: Audited | null } | null = null;
    if (options.from !== 'start') {
      const upto = options.from === undefined ? undefined : parseUpto(options.from);
      if (upto === null) return { refused: `not a pair to go on from: ${options.from}` };
      const kept = await keptReplay(tx, upto);
      if (kept === null && upto !== undefined) return { refused: `no replay is kept at ${upto}: walk again from the first entry` };
      if (kept !== null) {
        const pair = await store.pair(kept.upto);
        const read = pair === null ? null : opened(keys, kept, pair.notes);
        if (pair === null || read === null) return { refused: `the replay kept at ${kept.upto} is not the vault's over the checkpoint there: walk again from the first entry` };
        start = { notes: pair.notes, upto: kept.upto, ...read };
      }
    }
    const replayed = start?.replayed ?? emptyReplay();
    const newest = await store.newest();
    // The replay as it stands at the newest pair, taken as the walk passes it: entries above it are not sealed yet.
    let atNewest: Saved | null = null;
    const requests = new Requests();
    // What the entries changed or read, for a check that holds only those rows: each object by its key, and the bulk
    // rows of each principal a use counted against.
    const touched = new Map<string, Ref>();
    const counted = new Set<string>();
    const check = (entry: LogEntry): string | null => {
      if (newest !== null && atNewest === null && entry.number > newest.upto) atNewest = saved(replayed);
      if (!authentic(keys.mac)(entry)) return 'its MAC does not hold';
      if (!requests.once(entry)) return 'a second entry under the request of another: a replay';
      const one = logged(entry);
      if (typeof one === 'string') return one;
      const faults = replayed.faults.length;
      replay(keys.seals, [one], undefined, replayed);
      if (one.kind === 'change') touched.set(objectKey(one.ref), one.ref);
      else {
        for (const ref of [{ kind: 'credential', id: one.request.credential }, { kind: 'secret', id: one.request.secretId }] as const) touched.set(objectKey(ref), ref);
        const credential = replayed.rows.get(objectKey({ kind: 'credential', id: one.request.credential }))?.row;
        if (credential?.kind === 'credential') {
          touched.set(objectKey({ kind: 'principal', id: credential.principal }), { kind: 'principal', id: credential.principal });
          counted.add(credential.principal);
        }
      }
      return replayed.faults.length > faults ? replayed.faults.splice(faults).map((fault) => fault.replace(/^\d+: /, '')).join('; ') : null;
    };
    const verdict = await verifyLog(store, {
      verifiers: keys.verifiers, ...(start === null ? {} : { from: start.notes }), ...(options.anchors === undefined ? {} : { anchors: options.anchors }), check, limit: options.limit,
    });
    problems.push(...verdict.problems);
    if (!(await requestsUnique(tx))) problems.push('the indexes that keep each request to one entry are gone: a copy of an entry would pass');
    const at = await now(tx);
    // The rows: every one, or a page's check's, those its entries touched, beside what the last full audit found.
    let audited = start?.audited ?? null;
    const rows: string[] = [];
    if (verdict.done && (start === null || options.from !== undefined || options.keep === true)) {
      audited = { at, problems: audit(replayed, await heldObjects(tx), await bulkRows(tx), at) };
      rows.push(...audited.problems);
    } else if (verdict.done) {
      const only = { keys: new Set(touched.keys()), principals: counted };
      rows.push(...(audited?.problems ?? []), ...audit(replayed, await heldObjects(tx, [...touched.values()]), await bulkRows(tx, [...counted]), at, only));
    }
    // The replay at the pair the walk ended at: the newest, passed before the entries above it, or where a stretch stopped.
    return { verdict, start, at, rows, audited, state: verdict.done ? (atNewest ?? saved(replayed)) : saved(replayed) };
  }, SNAPSHOT);
  if ('refused' in walked) {
    problems.push(walked.refused!);
    return result({ from: options.from === undefined || options.from === 'start' ? null : options.from });
  }
  const { verdict, start, at, rows, audited } = walked;
  const head = verdict.head === null ? null : await openPair(verdict.head, keys.verifiers);
  // What it replayed, kept at the pair it ended at, for the next stretch, or the next check once it read enough to be
  // worth it; never over a log that does not hold. Rows a full audit found wrong are kept with it, for every check after
  // to say; a page's check that finds one keeps nothing, so the next reads its entries again.
  const fullAudit = audited !== (start?.audited ?? null);
  const keep = problems.length === 0 && (rows.length === 0 || fullAudit) && head !== null && verdict.head !== null && head.upto > (start?.upto ?? -1n)
    && (options.keep === true || !verdict.done || verdict.sealed >= KEEP_AFTER);
  if (keep) {
    const state = JSON.stringify({ ...walked.state, audited });
    await keepReplay(db, { upto: head!.upto, at, state, mac: replayMac(keys.replays[0]!, head!.upto, verdict.head!, state) }, REPLAYS_KEPT_MS);
  }
  problems.push(...rows);
  return result({
    from: start === null ? null : start.upto.toString(),
    checkpoint: head === null ? null : { upto: head.upto.toString(), at: head.at },
    checkpoints: verdict.checkpoints,
    sealed: verdict.sealed,
    unsealed: verdict.unsealed,
    done: verdict.done,
    next: verdict.done || head === null ? null : head.upto.toString(),
  });
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
  /** What the last full audit of the rows found, and when; null before the first. */
  audited?: Audited | null;
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
  const state: Saved = {
    v: 1,
    rows: [...replayed.rows].map(([key, { row, seal }]) => [key, row, seal!.toString('base64')]),
    gone: [...replayed.newest].filter(([, seal]) => seal === null).map(([key]) => key),
    limit: replayed.limit,
    bulk: [...replayed.bulk].map(([principal, held]) => [principal, [...held].filter(([, last]) => last > horizon)] as [string, [string, number][]]).filter(([, held]) => held.length > 0),
    last: replayed.last.toString(),
  };
  return state;
}

/** A kept replay, and what the last full audit found, if its MAC is the vault's over the pair's notes and itself. */
function opened(keys: VerifierKeys, kept: KeptReplay, notes: PairNotes): { replayed: Replayed; audited: Audited | null } | null {
  if (!keys.replays.some((key) => timingSafeEqual(replayMac(key, kept.upto, notes, kept.state), kept.mac))) return null;
  const state = JSON.parse(kept.state) as Saved;
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
  return { replayed, audited: state.audited ?? null };
}

function replayMac(key: Buffer, upto: bigint, notes: PairNotes, state: string): Buffer {
  return createHmac('sha256', key).update(`coffre.log.replay.v1\0${upto}\0${notes.changes}\0${notes.uses}\0`).update(state).digest();
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
function audit(
  replayed: Replayed,
  held: Awaited<ReturnType<typeof heldObjects>>,
  bulk: Map<string, Map<string, number>>,
  now: number,
  only?: { keys: ReadonlySet<string>; principals: ReadonlySet<string> },
): string[] {
  const problems: string[] = [];
  const name = (key: string) => {
    const row = replayed.rows.get(key)?.row;
    const ref = held.get(key)?.ref ?? (row === undefined ? undefined : refOf(row));
    return ref === undefined ? `object ${key}` : `the ${ref.kind} ${ref.id}`;
  };
  for (const [key, seal] of replayed.newest) {
    if (only !== undefined && !only.keys.has(key)) continue;
    const rows = held.get(key);
    if (seal === null) {
      if (rows !== undefined && (rows.row !== null || rows.seal !== null)) problems.push(`${name(key)}: its rows hold what the log deleted`);
      continue;
    }
    const object = replayed.rows.get(key)!.row;
    if (rows === undefined || (rows.row === null && rows.sealOnly === undefined)) problems.push(`${name(key)}: the log holds it, its rows do not`);
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
    if (only !== undefined && !only.principals.has(principal)) continue;
    const [stored, made] = [bulk.get(principal) ?? new Map<string, number>(), replayed.bulk.get(principal) ?? new Map<string, number>()];
    for (const secret of new Set([...stored.keys(), ...made.keys()])) {
      const [a, b] = [stored.get(secret), made.get(secret)];
      if ((a ?? -Infinity) <= horizon && (b ?? -Infinity) <= horizon) continue;
      if (a !== b) problems.push(`the bulk cap of ${principal}: its row for ${secret} says ${a ?? 'none'}, the log ${b ?? 'none'}`);
    }
  }
  return problems;
}
