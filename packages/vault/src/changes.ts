import { randomUUID } from 'node:crypto';

import type { Queryable, Transaction } from '@coffre/db';

import { applyOp, canonical, objectKey, refOf, sealOf, sealed, type Input, type Op, type Ref, type SealKeys } from './inputs.ts';
import type { LoggedChange } from './log-replay.ts';
import { entryMac } from './log-entry.ts';
import { changeInputs, isStale, newestChange, readObject, type ChangeCall, type ReadKind } from './store.ts';

/**
 * 0.15's change path (plan PR 4a; formal/HotPathOne.tla's change actions):
 * the changes one decision makes to the objects of the log, each logged
 * by `change_input` (migration 0023) in the decision's own transaction.
 *
 * A decision of 0.14's writes members, grants and its entries as it always
 * has, until 0.16 (the plan's dual fencing); with 0.15's log on, it also
 * stages, beside each write, the op that write is (`stage`), and once its
 * writes have run, `commit` logs them:
 *
 * 1. **Before the writes:** each object is read once, its seal checked
 *    (`tampered` if the vault never made it over the row, `stale` if it is
 *    not the seal of the object's newest change), and every op applied to
 *    it in turn with `applyOp`, the replay's own function. An op that does
 *    nothing there is a bug of the decision's, which fails it.
 * 2. **After them,** in the same transaction: a member's row and grants,
 *    which the decision wrote, are read back and must be the object the ops
 *    leave (a grant written around the vault meanwhile fails it); then every
 *    op is one call of `change_input`, which takes the fence exclusive,
 *    checks the row's seal against the newest change again under it
 *    (ChangeChecksSeal), moves it only from the seal read (ChangeCAS), writes
 *    what it keeps of the object (an environment's, the roles', the
 *    policy's: `value`), and numbers the entry under the lock
 *    (ChangeNumberUnderLock).
 *
 * Locks: the decision took its members' rows, then the log's head, before
 * any of this; `change_input` takes the same, then the fence: row, head,
 * fence, Migration015.tla's RowFirst and ChangeHeadFirst.
 *
 * An object that has a row but no seal, and no change in the log, is one
 * from before the cutover (plan PR 9): 0.14's log is its record, and the
 * cutover's genesis seals it as 0.14 left it. A decision changes it as
 * 0.14 does, and logs nothing of it here. One with neither row nor change
 * is new: only an op that makes it applies.
 */

/** Why an object a decision would change is not the log's: its seal is not the vault's over it, or not its newest change's. */
export class NotLogged extends Error {
  readonly ref: Ref | null;
  readonly fault: 'tampered' | 'stale';

  constructor(ref: Ref | null, fault: 'tampered' | 'stale') {
    super(`${ref === null ? 'an object' : `the ${ref.kind} ${ref.id}`} is ${fault === 'tampered' ? 'not sealed by the vault' : "not its newest change's"}: 0.15's log refuses to change it`);
    this.ref = ref;
    this.fault = fault;
  }
}

/** One of these changes' rows moved from the seal it was read at, under the locks: whoever wrote it went around the vault. */
export class Moved extends Error {}

/** The keys a change is made with: seals (inputs.ts) and entries' MACs (log-entry.ts). */
export type ChangeKeys = { seals: SealKeys; mac: Buffer };

type Step = { op: Op; actor: string };
type Read = { logged: false } | { logged: true; seal: Buffer | null; now: Input | null; afters: (Input | null)[] };
type Staged = { ref: Ref & { kind: ReadKind }; steps: Step[]; read?: Read };

export class Changes {
  readonly #keys: ChangeKeys;
  readonly #staged = new Map<string, Staged>();

  constructor(keys: ChangeKeys) {
    this.#keys = keys;
  }

  /** `op` to `ref`, by `actor`, as the decision's write will make it, in the order the writes run. */
  stage(ref: Ref & { kind: ReadKind }, op: Op, actor: string): void {
    const key = objectKey(ref);
    const staged = this.#staged.get(key) ?? { ref, steps: [] };
    if (staged.read !== undefined) throw new Error('a change staged after its object was read: stage every op before the writes run');
    staged.steps.push({ op, actor });
    this.#staged.set(key, staged);
  }

  /**
   * Read and check each object staged, in `db` before the decision's writes
   * run, and apply its ops to it in turn.
   */
  async prepare(db: Queryable): Promise<void> {
    for (const staged of this.#staged.values()) {
      if (staged.read !== undefined) continue;
      const read = await this.#read(db, staged.ref);
      if (read.logged) {
        for (const { op } of staged.steps) {
          const after = applyOp(read.now, staged.ref, op);
          if (after === undefined) throw new Error(`${op.op} does nothing to the ${staged.ref.kind} ${staged.ref.id} as the log has it: the decision and its change disagree`);
          read.afters.push(after);
          read.now = after;
        }
      }
      staged.read = read;
    }
  }

  async #read(db: Queryable, ref: Ref & { kind: ReadKind }): Promise<Read> {
    const [{ row, seal }, newest] = await Promise.all([readObject(db, ref), newestChange(db, ref)]);
    // Before the cutover: a row, unsealed, that the log has never heard of; or the roles, whose edits 0.14's policy
    // holds until the cutover's genesis writes them (a role defined before it is 0.14's alone).
    if (newest === null && seal === null && (row !== null || ref.kind === 'roles')) return { logged: false };
    if (row !== null && !sealed(this.#keys.seals, ref, row, seal)) throw new NotLogged(ref, 'tampered');
    // A row whose seal is not its newest change's; one with no row the log has a change for (deleted outright).
    if (newest !== null ? seal === null || newest.seal === null || !newest.seal.equals(seal) : row !== null) throw new NotLogged(ref, 'stale');
    return { logged: true, seal, now: row, afters: [] };
  }

  /**
   * Log every staged change, in the decision's transaction, once its writes
   * have run, at `at`: the numbers of their entries, which the decision
   * waits to see sealed before it answers (R51). Throws `NotLogged` for a
   * row a writer put back (ChangeChecksSeal), and `Moved` for one whose
   * seal moved since it was read (ChangeCAS), which the decision then reads
   * again.
   */
  async commit(tx: Transaction, at: number): Promise<bigint[]> {
    if ([...this.#staged.values()].some((staged) => staged.read === undefined)) throw new Error('changes committed before they were prepared: prepare reads each object before the writes run');
    const calls: ChangeCall[] = [];
    for (const { ref, steps, read } of this.#staged.values()) {
      if (!read!.logged) continue;
      const { seal: base, now, afters } = read!;
      // The member's own rows, which the decision wrote: they must be what the ops leave, or something wrote around it.
      if (ref.kind === 'principal' && !sameObject(this.#keys.seals[0]!, ref, (await readObject(tx, ref)).row, now)) throw new NotLogged(ref, 'tampered');
      let from = base;
      steps.forEach(({ op, actor }, i) => {
        // No op of these deletes an object: each leaves one to seal.
        const after = afters[i]!;
        const seal = sealOf(this.#keys.seals[0]!, ref, after);
        const row = { at, requestId: randomUUID(), object: objectKey(ref), actor, payload: payloadOf(ref, op), seal };
        calls.push({ ref, ...row, value: writes(ref) ? canonical(after) : null, sealFrom: from, mac: entryMac(this.#keys.mac, { tree: 'changes', row }) });
        from = seal;
      });
    }
    let numbers: (bigint | null)[];
    try {
      numbers = await changeInputs(tx, calls);
    } catch (error) {
      if (isStale(error)) throw new NotLogged(calls.length === 1 ? calls[0]!.ref : null, 'stale');
      throw error;
    }
    if (numbers.some((number) => number === null)) throw new Moved();
    return numbers as bigint[];
  }
}

/** Whether `change_input` writes the object's rows from its value: those the vault's login cannot write. */
function writes(ref: Ref): boolean {
  return ref.kind === 'environment' || ref.kind === 'roles' || ref.kind === 'policy';
}

/** Two objects alike as a seal sees them (a principal's grants a set). */
function sameObject(key: Buffer, ref: Ref, a: Input | null, b: Input | null): boolean {
  if (a === null || b === null) return a === b;
  return sealOf(key, ref, a).equals(sealOf(key, ref, b));
}

/**
 * A change's payload, as `log_changes` holds it: the op, and the object it
 * is to (`ref`), which the entry's `object` column holds only as a key a
 * replay cannot read back. Canonical JSON, so that a retry sends the same
 * bytes (`change_input` finds its entry by request id and payload).
 */
export function payloadOf(ref: Ref, op: Op): string {
  return canonical({ ...op, ref: { kind: ref.kind, id: ref.id } });
}

/**
 * A `log_changes` row as the replay takes it (log-replay.ts): its object
 * from its payload's `ref`, or a genesis's value, and checked against the
 * row's key; null for a payload that names no object, or another than the
 * row's.
 */
export function loggedChange(row: { number: bigint; at: number; object: string; payload: string; seal: Buffer | null }): LoggedChange | null {
  const { ref: named, ...op } = JSON.parse(row.payload) as Op & { ref?: Ref };
  const ref = named ?? (op.op === 'genesis' ? refOf(op.value) : undefined);
  if (ref === undefined || objectKey(ref) !== row.object) return null;
  return { kind: 'change', number: row.number, at: row.at, ref: { kind: ref.kind, id: ref.id }, op: op as Op, seal: row.seal };
}
