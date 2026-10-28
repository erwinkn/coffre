import { openPair, pairSigners, pairVerifiers, verifyLog, type LogEntry, type PairNotes, type PairVerifiers } from '@coffre/core/merkle';
import type { TreesBusy, TreeVerification } from '@coffre/core/vault';
import type { Database } from '@coffre/db';
import { SNAPSHOT } from '@coffre/db/dialect';

import { loggedChange } from './changes.ts';
import { FRESH_MS, logOrigin } from './checkpointer.ts';
import { alike, refOf, sealKey, type Input, type SealKeys } from './inputs.ts';
import { authentic, logMacKey, retentionCut } from './log-entry.ts';
import { emptyReplay, purposeOf, replay, type Logged, type Replayed } from './log-replay.ts';
import { logStore } from './log-store.ts';
import { heldObjects, requestsUnique, walkSlot } from './store.ts';

/**
 * 0.15's verifier (docs/design/0.15-plan.md, PR 8): what holds 0.15's log
 * to itself and the rows to the log, for the audit page, `coffre verify
 * log` and conformance. Two checks, and nothing kept between calls.
 *
 * **A page's check** (R25), on every visit: the newest signed pair, its
 * signatures and the pairs held outside (the signer's memory), then every
 * entry above it by its MAC and its request. A tick's worth of entries,
 * whatever the log's size; no replay, no row read.
 *
 * **The whole walk**, which someone asks for ("Verify whole log", `coffre
 * verify log`), in the one call that asked, read in batches (a page of
 * pairs and their entries at a time):
 * - **the trees** (`verifyLog` in @coffre/core/merkle): every pair rebuilt
 *   from the entries, both heads, from the first; so an entry deleted,
 *   added, changed or moved after its seal shows at the next pair;
 * - **each entry** by its MAC (the checkpointer's `authentic`), and its
 *   request once (RequestIdChecked): a copy of an entry is a replay;
 * - **the replay** (log-replay.ts): each change applied with `applyOp` and
 *   its seal held to the object the replay has;
 * - **the rows,** at the present, in the snapshot it read the log in: every
 *   object's rows hold the object the replay has, with its newest seal. A
 *   row put back from before a change, a row written with no change, a
 *   change's entry deleted before its seal (its row then carries a seal no
 *   entry left): each is a row the log does not make.
 * Uses are not replayed, and the bulk cap's rows are not held to the log:
 * their replay must agree with the live cap across `prune_bulk`, retention
 * cuts and windows changed, which is modelled first (T138, R45).
 * Past `limit` entries (a Worker's CPU time) it stops at the next pair and
 * says so, with where to walk it instead (`tooLarge`).
 *
 * Between whole walks, every use refuses a row put back `stale` (decide.ts).
 * What neither can see, by design: an entry deleted or reordered before its
 * tick (R51's window; a change answers only once sealed, so this is a use's),
 * and entries swapped whose replay is the same either way.
 */

/** The keys a walk needs: the trees' public keys, the entries' MAC key, and the seal keys. */
export type VerifierKeys = { verifiers: PairVerifiers; mac: Buffer; seals: SealKeys };

/** The verifier's keys from the vault's signing seeds: the trees' and the entries' from the first, as the checkpointer has them (log-checkpointer.ts). */
export async function verifierKeys(seeds: readonly Uint8Array[]): Promise<VerifierKeys> {
  const seed = seeds[0]!;
  const signers = await pairSigners(await logOrigin(seed), seed);
  return {
    verifiers: await pairVerifiers({ changes: signers.changes.verifierKey, uses: signers.uses.verifierKey }),
    mac: logMacKey(seed),
    seals: seeds.map((s) => sealKey(s)),
  };
}

export type VerifyOptions = {
  /** The walk from the first entry, with the replay and the row audit; else a page's check. */
  whole?: boolean;
  /** Sealed entries a whole walk takes in one call, to the first pair past them; past it, `tooLarge`. */
  limit?: number;
  /**
   * Pairs held outside the database: the signer's memory, a witness's
   * (`VaultOptions.heldOutside`). Each check must reach each: a database
   * rolled back whole to an earlier pair, rows with it, otherwise passes
   * until the signer's next tick refuses it.
   */
  anchors?: readonly PairNotes[];
};

/** The verdict as the vault gives it, and whether the database ended behind a pair held outside (`Verdict.behind`). */
export type Walked = Extract<TreeVerification, { kept: true }> & { behind: boolean };

/** When a whole walk refused, as many as `WHOLE_WALKS` under way already (review r11), asks again, in seconds. */
const WALK_RETRY_S = 5;

export async function verifyTrees(db: Database, keys: VerifierKeys, options: VerifyOptions): Promise<Walked | TreesBusy> {
  const whole = options.whole === true;
  const walked = await db.transaction(async (raw) => {
    const tx = raw as unknown as Database;
    if (whole && !(await walkSlot(tx))) return null;
    const store = logStore(tx);
    // A page's check starts at the newest pair, which its signatures and the pairs held outside vouch for. It walks no
    // use below it, so retention's cut is not its to check: the newest pair and the signer's are at or above every cut.
    const newest = whole ? null : await store.newest();
    const replayed = whole ? emptyReplay() : null;
    const requests = new Requests();
    const macHolds = authentic(keys.mac);
    const check = (entry: LogEntry): string | null => {
      if (!macHolds(entry)) return 'its MAC does not hold';
      if (!requests.once(entry)) return 'a second entry under the request of another: a replay';
      const one = logged(entry);
      if (typeof one === 'string') return one;
      // The changes alone: a use's replay moves only the bulk cap, which T138 holds to the log.
      if (replayed === null || one === null || one.kind === 'use') return null;
      const faults = replayed.faults.length;
      replay(keys.seals, [one], undefined, replayed);
      return replayed.faults.length > faults ? replayed.faults.splice(faults).map((fault) => fault.replace(/^\d+: /, '')).join('; ') : null;
    };
    const verdict = await verifyLog(store, {
      verifiers: keys.verifiers,
      check,
      ...(newest === null ? {} : { from: newest.notes }),
      ...(options.anchors === undefined ? {} : { anchors: options.anchors }),
      ...(whole ? { cut: retentionCut } : {}),
      ...(whole && options.limit !== undefined ? { limit: options.limit } : {}),
    });
    const problems = [...verdict.problems];
    if (!(await requestsUnique(tx))) problems.push('the indexes that keep each request to one entry are gone: a copy of an entry would pass');
    // At the present, the whole walk holds every row to its replay.
    if (replayed !== null && verdict.done) problems.push(...audit(replayed, await heldObjects(tx)));
    return { verdict, problems };
  }, SNAPSHOT);
  if (walked === null) return { busy: true, retryAfter: WALK_RETRY_S };
  const { verdict, problems } = walked;
  const head = verdict.head === null ? null : await openPair(verdict.head, keys.verifiers);
  const tooLarge = verdict.done ? null : `0.15's log holds more than this vault walks in one call: the walk stopped after ${verdict.sealed.toLocaleString('en')} entries${head === null ? '' : `, at the checkpoint up to ${head.upto}`}, short of the present. A Worker's call has a limit on its CPU time: walk the log whole on Node, where a call has none, with a Node deployment of coffre over this database, or over a copy \`coffre restore\` made, under the same vault key; then \`coffre verify log\` there`;
  return {
    kept: true,
    whole,
    ok: problems.length === 0 && verdict.done,
    problems,
    tooLarge,
    checkpoint: head === null ? null : { upto: head.upto.toString(), at: head.at },
    checkpoints: verdict.checkpoints,
    sealed: verdict.sealed,
    unsealed: verdict.unsealed,
    behind: verdict.behind,
  };
}

// --- entries ------------------------------------------------------------------------------------------

/**
 * An entry as the replay takes it, from the columns its tree seals
 * (log-entry.ts), or why it cannot be one; null for a retention change,
 * the log's own, which changes no input.
 */
function logged(entry: LogEntry): Logged | string | null {
  const c = entry.columns;
  if (retentionCut(entry) !== null) return null;
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
 * only requests that recent are kept; a copy further apart, or one below
 * the pair a page's check starts at, is what the database's unique indexes
 * refuse, which every check holds to standing.
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

// --- the rows -----------------------------------------------------------------------------------------

/** Whether a row's object is the replay's; one of a shape no release writes, which the comparison cannot read, is not. */
function same(row: Input, object: Input): boolean {
  try {
    return alike(row, object);
  } catch {
    return false;
  }
}

/**
 * Every row held to the replay: each object the log holds is in its rows,
 * as the replay has it, with its newest seal; each the log deleted (a key
 * archived) has none, and no seal; a row the log never heard of carries no
 * seal and is 0.14's, before the cutover (plan PR 9), but for the roles'
 * and the policy's, which only a change writes.
 */
function audit(replayed: Replayed, held: Awaited<ReturnType<typeof heldObjects>>): string[] {
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
    else if (rows.sealOnly === undefined && !same(rows.row!, object)) problems.push(`${name(key)}: its rows are not the object the log makes`);
  }
  for (const [key, rows] of held) {
    if (replayed.newest.has(key)) continue;
    if (rows.seal !== null) problems.push(`${name(key)}: sealed, and the log holds no change of it`);
    else if (rows.ref.kind === 'roles' || rows.ref.kind === 'policy') problems.push(`${name(key)}: written with no change: only a change writes it`);
  }
  return problems;
}
