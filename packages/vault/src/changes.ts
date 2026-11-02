import { randomUUID } from 'node:crypto';

import type { ObjectChange, PreparedChange } from '@coffre/core/vault';
import type { Queryable, Transaction } from '@coffre/db';
import { isMovedChange, type ChangeNumbers } from '@coffre/db/log';

import { applyOp, canonical, indexBytes, objectKey, refOf, sealOf, sealed, type Input, type Op, type Ref, type SealKeys } from './inputs.ts';
import type { LoggedChange } from './log-replay.ts';
import { entryMac, type LogMacKey } from './log-entry.ts';
import { connectionObject, credentialObject, environmentObject, secretObject } from './objects.ts';
import { isStale, laterInputs, loggedChanges, newestChange, readObject, type ChangeCall, type CheckedChange, type NewestChange, type ReadKind } from './store.ts';

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
 *    leave (0.14's `#seal` refuses a grant written around the vault
 *    meanwhile: a difference left is the decision's own bug); then every
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
 * 0.14 does, and logs nothing of it here. So are the roles with no row
 * yet, whose edits 0.14's policy holds until the cutover. The roles' and
 * the policy's rows are written only sealed, by `change_input`: one with
 * no seal was planted, and is refused. Any other object with neither row
 * nor change is new: only an op that makes it applies.
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

/**
 * An object as the log has it: `unlogged`, 0.14's alone (no change, no seal
 * on its row: before the cutover); `gone`, the log's newest change of it
 * left none (a key archived or deleted: `secret.delete`); else its object,
 * its row checked against its seal and that seal the newest change's.
 */
export type Held = { log: 'unlogged' } | { log: 'gone' } | { log: 'live'; object: Input };

/**
 * Whether `ref` has an object, from its log, never its row's columns (an
 * `archived_at` a writer set is no archive), and the object, checked: what
 * a decision may weigh (formal/SealedObjects.tla, LivenessFromLog,
 * ReferenceInObject). Throws `NotLogged` for a row the log does not bear
 * out: a seal no change wrote, a gone object's row live again, a live one's
 * row gone, or a row its seal does not cover.
 */
export async function heldByLog(keys: ChangeKeys, db: Queryable, ref: Ref & { kind: ReadKind }): Promise<Held> {
  const [read, newest] = await Promise.all([readObject(db, ref), newestChange(db, ref, macsOf(keys))]);
  return heldFrom(keys.seals, ref, read, newest);
}

/** Every MAC key a change's entry may be under (`ChangeKeys.macs`). */
export function macsOf(keys: ChangeKeys): readonly LogMacKey[] {
  return keys.macs ?? [keys.mac];
}

/** `heldByLog`, on an object's row and its newest change as read. */
export function heldFrom(keys: SealKeys, ref: Ref & { kind: ReadKind }, { row, seal }: { row: Input | null; seal: Buffer | null }, newest: NewestChange | null): Held {
  // Its newest change's MAC does not hold over the seal it records (T190): the log, not only the row, was written around.
  if (newest !== null && !newest.holds) throw new NotLogged(ref, 'tampered');
  if (newest === null) {
    if (seal !== null) throw new NotLogged(ref, 'stale');
    return { log: 'unlogged' };
  }
  if (newest.seal === null) {
    if (row !== null || seal !== null) throw new NotLogged(ref, 'stale');
    return { log: 'gone' };
  }
  if (row === null) throw new NotLogged(ref, 'stale');
  if (!sealed(keys, ref, row, seal)) throw new NotLogged(ref, 'tampered');
  if (seal === null || !newest.seal.equals(seal)) throw new NotLogged(ref, 'stale');
  return { log: 'live', object: row };
}

/** One of these changes' rows moved from the seal it was read at, under the locks: whoever wrote it went around the vault. */
export class Moved extends Error {}

/** The keys a change is made with: seals (inputs.ts) and entries' MACs (log-entry.ts). */
export type ChangeKeys = {
  seals: SealKeys;
  mac: LogMacKey;
  /**
   * The MAC keys of every signing key the vault holds, `mac` first: what the newest change a row is held to is checked
   * under (T190, `changeHolds`), as `seals` are every one's. Absent: `mac` alone, a vault of one signing key.
   */
  macs?: readonly LogMacKey[];
};

type Step = { op: Op; actor: string };
type Read = { logged: false } | { logged: true; seal: Buffer | null; now: Input | null; afters: (Input | null)[] };
type Staged = { ref: Ref & { kind: ReadKind }; steps: Step[]; read?: Read; old?: bigint };

export class Changes {
  readonly #keys: ChangeKeys;
  readonly #staged = new Map<string, Staged>();
  /**
   * The proxy's objects as `held` read them in this decision's transaction, which `prepare` takes rather than
   * read them again: nothing writes between the two but the decision, whose writes come after `prepare`.
   */
  readonly #seen = new Map<string, [{ row: Input | null; seal: Buffer | null }, NewestChange | null]>();
  /** The calls `commit` made, once it has: what the transaction's failure is of (`failed`). */
  #made: readonly ChangeCall[] | null = null;

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
   * The newest entry of 0.14's log this decision's changes to `ref`
   * account for: a member's newest access entry (the `access_seq` 0.14's
   * row names), or the `policy.change` an environment's protection or a
   * role came with. Each of its changes carries it (`payloadOf`'s `old`),
   * so that a use sees a 0.14 write the new log has not accounted for
   * (Migration015.tla's UsesSeeOldWrites, plan PR 5).
   */
  cite(ref: Ref, seq: bigint): void {
    const staged = this.#staged.get(objectKey(ref));
    if (staged !== undefined) staged.old = seq;
  }

  /**
   * An object as the log has it (`heldByLog`), checked against its seal, for
   * a decision to weigh before it stages anything.
   */
  async held(db: Queryable, ref: Ref & { kind: ReadKind }): Promise<Held> {
    const read = await Promise.all([readObject(db, ref), newestChange(db, ref, macsOf(this.#keys))]);
    if (ref.kind === 'proxy' || ref.kind === 'proxy-reserved') this.#seen.set(objectKey(ref), read);
    return heldFrom(this.#keys.seals, ref, ...read);
  }

  /** What a key with no object would be unarchived as (`keptObjects`): null for one its log never held. */
  async kept(db: Queryable, ref: Ref & { kind: 'secret' }): Promise<Input | null> {
    return (await keptObjects(this.#keys, db, [ref])).get(objectKey(ref))?.object ?? null;
  }

  /**
   * That an archived key's rows make its kept object, as its unarchive
   * would read them, before a decision changes that object (an end, T134):
   * `stale` otherwise, as a live object's rows not its seal's refuse it.
   */
  async rowsAsKept(db: Queryable, ref: Ref & { kind: 'secret' }, kept: Input): Promise<void> {
    const { row } = await readObject(db, ref, { archived: true });
    if (!sameObject(this.#keys.seals[0]!, ref, row, kept)) throw new NotLogged(ref, 'stale');
  }

  /**
   * Read and check each object staged, in `db` before the decision's writes
   * run, and apply its ops to it in turn.
   */
  async prepare(db: Queryable): Promise<void> {
    const unread = [...this.#staged.values()].filter((staged) => staged.read === undefined);
    // Each object's reads asked together: one round trip for them all.
    const reads = await Promise.all(unread.map((staged) => this.#read(db, staged.ref, staged.steps[0]?.op.op === 'proxy.save' && staged.steps[0].op.replace)));
    for (const [i, staged] of unread.entries()) {
      const read = reads[i]!;
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

  async #read(db: Queryable, ref: Ref & { kind: ReadKind }, whole = false): Promise<Read> {
    // An environment's proxy definitions replaced whole (an Owner's one save of a forged object, docs/design/proxy-ui.md,
    // section 8): from no object, whatever its row holds, moved on from its newest change's seal, which `change_input`
    // holds it to under the fence. Nothing of the row is weighed, so nothing forged is carried on.
    if (whole) {
      // Its seal whatever the change's MAC: nothing of the change or the row is carried on, and a whole save is how an
      // Owner replaces an object whose log a writer forged too.
      const newest = await newestChange(db, ref, macsOf(this.#keys));
      return { logged: true, seal: newest?.seal ?? null, now: null, afters: [] };
    }
    const [{ row, seal }, newest] = this.#seen.get(objectKey(ref)) ?? await Promise.all([readObject(db, ref), newestChange(db, ref, macsOf(this.#keys))]);
    // Its newest change's MAC does not hold over the seal it records (T190; HotPathOne.tla, ChangeChecksMac): a row put
    // back with its old seal, written into that change too, would pass every check below, and this change would seal
    // the writer's row as the log's. Refused, as a row its seal does not cover is.
    if (newest !== null && !newest.holds) throw new NotLogged(ref, 'tampered');
    // Before the cutover: a row, unsealed, that the log has never heard of; or the roles, whose edits 0.14's policy
    // holds until the cutover's genesis writes them (a role defined before it is 0.14's alone). Not the roles' or the
    // policy's row, which only change_input writes, sealed: one with no seal was planted.
    if (newest === null && seal === null) {
      if (row === null ? ref.kind === 'roles' : ref.kind !== 'roles' && ref.kind !== 'policy') return { logged: false };
      if (row !== null) throw new NotLogged(ref, 'tampered');
    }
    if (row !== null && !sealed(this.#keys.seals, ref, row, seal)) throw new NotLogged(ref, 'tampered');
    // Gone (a key archived: `secret.delete`), its row no object and no seal: only an op that makes one applies.
    if (newest !== null && newest.seal === null && row === null && seal === null) return { logged: true, seal, now: null, afters: [] };
    // A row whose seal is not its newest change's; one with no row the log has a change for (deleted outright).
    if (newest !== null ? seal === null || newest.seal === null || !newest.seal.equals(seal) : row !== null) throw new NotLogged(ref, 'stale');
    return { logged: true, seal, now: row, afters: [] };
  }

  /**
   * Log every staged change, in the decision's transaction, once its writes
   * have run, at `at`, `written` holding the members' objects as the
   * decision read them back after its writes, if it did: the numbers of their entries, which the decision
   * waits to see sealed before it answers (R51), and which answer with its COMMIT, which they go with
   * (`laterInputs`). A row a writer put back (ChangeChecksSeal), or whose seal moved since it was read
   * (ChangeCAS), fails the transaction, which `failed` says is `NotLogged`, or `Moved`, read again.
   */
  async commit(tx: Transaction, at: number, written: ReadonlyMap<string, Input> = new Map()): Promise<ChangeNumbers> {
    if ([...this.#staged.values()].some((staged) => staged.read === undefined)) throw new Error('changes committed before they were prepared: prepare reads each object before the writes run');
    const calls: ChangeCall[] = [];
    for (const { ref, steps, read, old } of this.#staged.values()) {
      if (!read!.logged) continue;
      const { seal: base, now, afters } = read!;
      // The member's own rows, which the decision wrote: they must be what the ops leave, or something wrote around it.
      // As the decision read them back to seal them (`written`), or read again here.
      // A grant written around the vault meanwhile is refused before this (`#seal`, under the member's row lock): what is
      // left to differ is the decision's writes and its ops, a bug of the vault's, never the member's tampering.
      if (ref.kind === 'principal') {
        const held = written.get(objectKey(ref)) ?? (await readObject(tx, ref)).row;
        if (!sameObject(this.#keys.seals[0]!, ref, held, now)) throw new Error(`the ${ref.kind} ${ref.id}'s rows are not what its staged changes leave: the decision and its changes disagree`);
      }
      let from = base;
      steps.forEach(({ op, actor }, i) => {
        // A key deleted again (an archived holder's end) leaves no object, and no seal.
        const after = afters[i]!;
        const seal = after === null ? null : sealOf(this.#keys.seals[0]!, ref, after);
        const row = { at, requestId: randomUUID(), object: objectKey(ref), actor, payload: payloadOf(ref, op, old), seal };
        calls.push({ ref, ...row, value: writes(ref) && after !== null ? rowValue(after) : null, sealFrom: from, mac: entryMac(this.#keys.mac, { tree: 'changes', row }) });
        from = seal;
      });
    }
    this.#made = calls;
    return laterInputs(tx, calls);
  }

  /**
   * What the decision's transaction failed with, as the vault hears it, once its changes went with its COMMIT
   * (`commit`): a row that is not its object's newest change's is `NotLogged`, reported; one moved since it was read,
   * `Moved`, read again (ChangeRereads).
   */
  failed(error: unknown): unknown {
    if (this.#made === null) return error;
    if (isStale(error)) return new NotLogged(this.#made.length === 1 ? this.#made[0]!.ref : null, 'stale');
    if (isMovedChange(error)) return new Moved();
    return error;
  }
}

/**
 * What each key in `refs` would be unarchived as: the object its log's
 * newest change with a seal left it, by the key's key in the log; null for a
 * key the log never held (0.14's alone, before the cutover). An archived
 * key's newest change is its archive (`secret.delete`, which leaves no
 * seal), and the one before it the write or genesis it archived, its whole
 * object: both read in one statement (`loggedChanges`), both held to their
 * MACs (T190), so that a writer who blanks that write's seal cannot make an
 * older one look the newest sealed. That change's seal is checked over the
 * object its payload makes (`tampered` otherwise). Read outside any
 * transaction: `app_change` holds the seal to the log's newest sealed one
 * again under the fence (formal/SealedObjects.tla, RestorePinned).
 */
export async function keptObjects(keys: ChangeKeys, db: Queryable, refs: readonly (Ref & { kind: 'secret' })[]): Promise<Map<string, { object: Input; seal: Buffer } | null>> {
  const found = await loggedChanges(db, macsOf(keys), refs, refs);
  return new Map(refs.map((ref) => [objectKey(ref), keptFrom(keys.seals, ref, found.get(objectKey(ref)) ?? [])]));
}

/** `keptObjects` for one key, from its newest change and the one before it as `loggedChanges` read them. */
export function keptFrom(keys: SealKeys, ref: Ref & { kind: 'secret' }, changes: readonly CheckedChange[]): { object: Input; seal: Buffer } | null {
  if (changes.length === 0) return null;
  if (changes.some((change) => !change.holds)) throw new NotLogged(ref, 'tampered');
  // A key not archived restores its newest (which `app_change` refuses: its row is no object); else the write its archive ended.
  const kept = changes[0]!.seal !== null ? changes[0]! : changes[1];
  if (kept === undefined || kept.seal === null) throw new NotLogged(ref, 'stale');
  // Its payload names the key (`loggedChange` holds it to the row's key in the log), and makes its whole object.
  const change = loggedChange(kept);
  const object = change === null ? undefined : applyOp(null, ref, change.op);
  if (object == null || !sealed(keys, ref, object, kept.seal)) throw new NotLogged(ref, 'tampered');
  return { object, seal: kept.seal };
}

/**
 * Throws `tampered` for the first of `refs` whose newest change's MAC does
 * not hold (T190): what a write goes on from where its statement holds a
 * row to its object's newest seal in SQL, which cannot check a MAC. A row
 * put back and its object's newest change's seal written to match would
 * pass that comparison, and the write would seal the rollback, a revoked
 * credential renewed live again. One statement for them all; what it read,
 * by object key, each object's newest change first.
 */
export async function changesHold(keys: ChangeKeys, db: Queryable, refs: readonly Ref[]): Promise<Map<string, CheckedChange[]>> {
  const found = await loggedChanges(db, macsOf(keys), refs);
  for (const ref of refs) if (found.get(objectKey(ref))?.[0]?.holds === false) throw new NotLogged(ref, 'tampered');
  return found;
}

/**
 * The changes the app is about to write to objects its own rows hold (plan
 * PR 4b, `prepare`): credentials, keys and environments, sealed for its
 * transaction to commit (`app_change`, 0025), at `at`, by `actor`. Pure:
 * what the vault reads is `kept`, each unarchived key's object as its log
 * last sealed it (`keptObjects`).
 *
 * - **Before:** the row's columns as the app read them, and their seal,
 *   which must be the vault's over them (else `tampered`). That it is the
 *   object's newest change's, and still the row's, is `app_change`'s to
 *   check under its locks (the fence; an issue, the issue lock: 0026)
 *   (ChangeChecksSeal, ChangeCAS), as `change_input`
 *   does for the vault's own. A row with no seal is 0.14's, before the
 *   cutover: its call logs nothing, and only checks that the log has no
 *   change of its object either (as `Changes` leaves such a row alone). No
 *   before is no object: no row, or a key archived, whose seal its delete
 *   left null.
 * - **The changes:** what turns the object before into the object after,
 *   each one of the replay's ops (`opsBetween`), applied with `applyOp` and
 *   sealed in turn, each from the seal the one before leaves; a key's
 *   delete leaves none. Columns no op reaches (a credential's principal, a
 *   key moved to another environment, an environment's parent or its
 *   protection, which is the vault's) are a bug of the app's, which fails
 *   the call. Columns no object holds (a credential's MAC, a key's name, an
 *   environment's display name) are no change.
 * - **An unarchive** (`restores`) restores the object its key's log last
 *   sealed, its rows having no seal while archived (T134): rows that make
 *   any other (a version, a reference row or a source edited meanwhile, an
 *   older version put back, an end cleared) are `stale`. Its change carries
 *   that seal, which `app_change` holds to the log's newest sealed one. A
 *   key its log never held is 0.14's, before the cutover: logged nothing.
 */
export function prepareChanges(keys: ChangeKeys, at: number, actor: string, changes: readonly ObjectChange[], kept: ReadonlyMap<string, { object: Input; seal: Buffer } | null>): PreparedChange[] {
  const prepared: PreparedChange[] = [];
  for (const change of changes) {
    const { kind, id, before } = change;
    if (!Object.hasOwn(OBJECTS, kind)) throw new Error(`the app makes no change to a ${String(kind)}`);
    const after = objectOf(change);
    if ((after !== null && refOf(after).id !== id) || (before !== null && before.columns.id !== id)) {
      throw new Error(`a change to a ${kind} names its row by its id, before and after`);
    }
    const ref: Ref = { kind, id };
    const object = objectKey(ref);
    const unlogged = { kind, id, requestId: null, at, object, actor, payload: null, sealFrom: null, seal: null, mac: null, restores: null };
    if (before !== null && before.seal === null) {
      prepared.push(unlogged);
      continue;
    }
    let restores: Buffer | null = null;
    if (change.kind === 'secret' && change.restores === true) {
      if (before !== null || after === null) throw new Error(`an unarchive makes an archived key's object again: the ${kind} ${id} is none to restore`);
      const last = kept.get(object);
      if (last === undefined) throw new Error(`the ${kind} ${id} is restored from what its log last sealed, which was not read`);
      if (last === null) {
        prepared.push(unlogged);
        continue;
      }
      if (!sameObject(keys.seals[0]!, ref, last.object, after)) throw new NotLogged(ref, 'stale');
      restores = last.seal;
    }
    let now: Input | null = before === null ? null : OBJECTS[kind](before.columns as never);
    let from: Buffer | null = before === null ? null : Buffer.from(before.seal!, 'base64');
    if (now !== null && !sealed(keys.seals, ref, now, from)) throw new NotLogged(ref, 'tampered');
    for (const op of opsBetween(now, after)) {
      const next = applyOp(now, ref, op);
      if (next === undefined) throw new Error(`${op.op} does nothing to the ${kind} ${id}: the app's write and its change disagree`);
      // A key deleted leaves no object, and no seal: its row's is null, as a use reads it (decide.ts, checkSeals).
      const seal = next === null ? null : sealOf(keys.seals[0]!, ref, next);
      const row = { at, requestId: randomUUID(), object, actor, payload: payloadOf(ref, op), seal };
      const mac = entryMac(keys.mac, { tree: 'changes', row });
      prepared.push({
        kind, id, ...row, seal: seal?.toString('base64') ?? null, sealFrom: from?.toString('base64') ?? null, mac: mac.toString('base64'),
        restores: restores?.toString('base64') ?? null,
      });
      now = next;
      from = seal;
    }
    if (!sameObject(keys.seals[0]!, ref, now, after)) throw new Error(`the ${kind} ${id} the app would write is no change the log knows from the one it read`);
  }
  return prepared;
}

/** Each kind of the app's objects, from its columns (objects.ts). */
const OBJECTS = { credential: credentialObject, connection: connectionObject, secret: secretObject, environment: environmentObject } as const;

/** The object a change leaves: null for a key archived or erased. */
function objectOf(change: ObjectChange): Input | null {
  if (change.after === null) return null;
  return OBJECTS[change.kind](change.after as never);
}

/**
 * The ops that make `after` from `before`, in the order they apply; what
 * else differs, they do not reach.
 * - a credential: its issue (and a revoke, issued revoked); its scope
 *   written, its end moved, then its revoke;
 * - an MCP connection: made, then its revoke (made revoked: a step-up's
 *   earlier one never is); nothing else of it moves;
 * - a key: written whole, its value or its reference (`secret.write`); or
 *   deleted, archived or erased;
 * - an environment: made, with the protection its id was given; renamed,
 *   archived or restored, its project archived or restored, then deleted.
 */
function opsBetween(before: Input | null, after: Input | null): Op[] {
  if (after === null) return before === null ? [] : [{ op: 'secret.delete' }];
  switch (after.kind) {
    case 'credential': {
      if (before === null) {
        const { principal, caller, scope, expiresAt, generation } = after;
        return [{ op: 'credential.issue', principal, caller, scope, expiresAt, generation }, ...(after.revoked ? [{ op: 'credential.revoke' } as const] : [])];
      }
      if (before.kind !== 'credential') return [];
      const ops: Op[] = [];
      if (canonical(before.scope) !== canonical(after.scope)) ops.push({ op: 'credential.scope', scope: after.scope });
      if (before.expiresAt !== after.expiresAt) ops.push({ op: 'credential.renew', expiresAt: after.expiresAt });
      if (!before.revoked && after.revoked) ops.push({ op: 'credential.revoke' });
      return ops;
    }
    case 'connection': {
      if (before === null) return [{ op: 'connection.make', value: { ...after, revoked: false } }, ...(after.revoked ? [{ op: 'connection.revoke' } as const] : [])];
      if (before.kind !== 'connection') return [];
      return !before.revoked && after.revoked ? [{ op: 'connection.revoke' }] : [];
    }
    case 'secret': {
      if (before !== null && canonical(before) === canonical(after)) return [];
      const { projectId, environmentId, version, nature, key, digest, source, reference } = after;
      return [{ op: 'secret.write', projectId, environmentId, version, nature, key, digest, source, reference }];
    }
    case 'environment': {
      const ops: Op[] = [];
      if (before === null) {
        const { projectId, slug, owner, parentId } = after;
        ops.push({ op: 'environment.create', projectId, slug, owner, parentId, protected: after.protected });
        if (after.archived) ops.push({ op: 'environment.archive', archived: true });
        if (after.projectArchived) ops.push({ op: 'project.archive', archived: true });
        return ops;
      }
      if (before.kind !== 'environment') return [];
      if (before.slug !== after.slug) ops.push({ op: 'environment.rename', slug: after.slug });
      if (before.archived !== after.archived) ops.push({ op: 'environment.archive', archived: after.archived });
      // A deletion clears it (`environment.delete`): no restore of the project's logged on the way.
      if (before.projectArchived !== after.projectArchived && !after.deleted) ops.push({ op: 'project.archive', archived: after.projectArchived });
      if (!before.deleted && after.deleted) ops.push({ op: 'environment.delete' });
      return ops;
    }
    default:
      return [];
  }
}

/**
 * Whether `change_input` writes the object's rows from its value: those the
 * vault's login cannot write. A key's, the one change the vault makes of
 * one: its reference's end (`ended_at`, 0029).
 */
function writes(ref: Ref): boolean {
  return ref.kind === 'environment' || ref.kind === 'secret' || ref.kind === 'roles' || ref.kind === 'policy' || ref.kind === 'proxy' || ref.kind === 'proxy-reserved';
}

/**
 * What `change_input` writes an object's row from: the object, but an
 * environment's proxy definitions as their row holds them, the items and
 * their index (`digests`, base64), and the reserved names as their set.
 */
function rowValue(after: Input): string {
  // Not canonical: the row's own encoding (jsonb) is none, and the seal covers the index, whose digests are canonical.
  if (after.kind === 'proxy') return JSON.stringify({ items: after.items, digests: indexBytes(after.items).toString('base64') });
  if (after.kind === 'proxy-reserved') return canonical({ names: after.names });
  return canonical(after);
}

/** Two objects alike as a seal sees them (a principal's grants a set). */
function sameObject(key: Buffer, ref: Ref, a: Input | null, b: Input | null): boolean {
  if (a === null || b === null) return a === b;
  return sealOf(key, ref, a).equals(sealOf(key, ref, b));
}

/**
 * A change's payload, as `log_changes` holds it: the op, the object it is
 * to (`ref`), which the entry's `object` column holds only as a key a
 * replay cannot read back, and, when it has one, the newest entry of
 * 0.14's log it accounts for (`old`, its seq in decimal: `cite`).
 * Canonical JSON, so that a retry sends the same bytes (`change_input`
 * finds its entry by request id and payload).
 */
export function payloadOf(ref: Ref, op: Op, old?: bigint): string {
  return canonical({ ...op, ref: { kind: ref.kind, id: ref.id }, ...(old === undefined ? {} : { old: old.toString() }) });
}

/**
 * A `log_changes` row as the replay takes it (log-replay.ts): its object
 * from its payload's `ref`, or a genesis's value, and checked against the
 * row's key; null for a payload that names no object, or another than the
 * row's.
 */
export function loggedChange(row: { number: bigint; at: number; object: string; payload: string; seal: Buffer | null }): LoggedChange | null {
  // What a change records besides its op, which the replay leaves: the 0.14 entry it accounts for, and a sign-in's, a revoke's, an issue's or a binding's own (credentials.ts).
  const { ref: named, old: _, signIn: _signIn, revoke: _revoke, issue: _issue, bind: _bind, unbind: _unbind, ...op } = JSON.parse(row.payload) as Op & {
    ref?: Ref; old?: string; signIn?: unknown; revoke?: unknown; issue?: unknown; bind?: unknown; unbind?: unknown;
  };
  const ref = named ?? (op.op === 'genesis' ? refOf(op.value) : undefined);
  if (ref === undefined || objectKey(ref) !== row.object) return null;
  return { kind: 'change', number: row.number, at: row.at, ref: { kind: ref.kind, id: ref.id }, op: op as Op, seal: row.seal };
}

/**
 * The cutover's change for one object (plan PR 9): its row sealed as it
 * is, the object it holds the payload's `value`. An environment's carries
 * the object as `value` too, which writes its protection, which 0.14 kept
 * in its policy; the roles' and the policy's rows are made from the
 * payload. From no seal: an object the log has never held. `old`: the
 * newest entry of 0.14's it accounts for (`cite`): a member's `access_seq`,
 * or the `policy.change` an environment's protection or the roles came
 * from.
 */
export function genesisCall(keys: ChangeKeys, ref: Ref, input: Input, at: number, actor: string, old?: bigint): ChangeCall {
  const op: Op = { op: 'genesis', value: input };
  const seal = sealOf(keys.seals[0]!, ref, input);
  const row = { at, requestId: randomUUID(), object: objectKey(ref), actor, payload: payloadOf(ref, op, old), seal };
  return { ref, ...row, value: ref.kind === 'environment' ? canonical(input) : null, sealFrom: null, mac: entryMac(keys.mac, { tree: 'changes', row }) };
}
