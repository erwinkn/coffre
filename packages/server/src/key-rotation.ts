// Moving the app to a new key (docs/deploy.md, "Rotating the app key"),
// as the vault moves to a new vault key: the first start under the new
// `auditChainKey`, with the old one in `previousAuditChainKeys`, signs again
// under it every row the old one signed, signs everyone out, and writes
// `key.rotate`. From the first step on, the log names the old key as one
// it moves from, and the old key writes no more (`KeyRetired` in
// @coffre/db/log); from `key.rotate` on, nothing accepts it but the
// verification of the entries before.
//
// It goes a step at a time, each a transaction under the log's head: a
// step signs up to `STEP_ROWS` rows again and appends a `key.reseal` entry
// that says where the next goes on. Once every row is signed, the audit
// anchor is sealed again under the new key, and then `key.rotate`. So a
// rotation survives a crash between steps and goes on from the last, any
// number of isolates or processes may step it at once, one after another
// under the head, and a Worker's step stays within its CPU. The app serves
// nothing else until it is done (`keyReady` in app.ts).
//
//   key.reseal  { from: 'app:1f…', resealed: 69, signedOut: 31, unsigned: [], next: { table: 'credentials', after: '7c…' } }
//   key.reseal  { from: 'app:1f…', resealed: 12, signedOut: 0, unsigned: [], next: null }
//   (the anchor sealed again)
//   key.rotate  { from: 'app:1f…' }
import { verifyEntries, type StoredEntry } from '@coffre/core/audit';
import type { Database, Queryable, Transaction } from '@coffre/db';
import { SNAPSHOT } from '@coffre/db/dialect';
import { lockLogHead, lockLogHeadIfFree } from '@coffre/db/log';

import { signedAgain, signedBy, type AuthRow, type AuthTable } from './auth-rows.ts';
import { appendAudit, appLogKey, type AppKeys, type AuditEntry } from './db/audit.ts';
import { movedFrom, newestAppEntry, newestMove, reseal, signedRowsAfter, wroteUnder, type Resealed } from './db/rotation.ts';

/** Every table whose rows carry the app's MAC, in the order a rotation signs them again. */
export const SIGNED_TABLES: readonly AuthTable[] = [
  'identities', 'credentials', 'device_authorizations', 'service_bindings', 'oauth_clients', 'mcp_connections', 'enrollments',
];

/** The credentials a rotation signs out: people's sessions, the browser's and the CLI's, which a sign-in gives back. */
const SESSIONS = new Set(['browser', 'cli']);

/** Rows a step reads and signs again, at most: their MACs some 1 to 2.5 ms of CPU in Node, warm or cold, to keep a step within a Worker's 10. */
export const STEP_ROWS = 100;

/** Rows a step names in its entry that it could not sign again, at most; the count is whole. */
const NAMED = 20;

const ROTATION: Pick<AuditEntry, 'actorType' | 'actorId'> = { actorType: 'system', actorId: 'coffre-key-rotation' };

/** Where a rotation goes on from: a table, after the row with this id, or from its first. */
export type Cursor = { table: AuthTable; after: string | null };

const START: Cursor = { table: SIGNED_TABLES[0]!, after: null };

/**
 * Where the app stands with its key, as the log says: under it; moving to
 * it from `from`, its rows going on from `next`; every row signed again,
 * the audit anchor to seal again before `key.rotate` (`sealing`); or
 * refused, and why, for a key the log has moved on from, or a rotation it
 * cannot finish.
 */
export type KeyState =
  | { kind: 'settled' }
  | { kind: 'rotating'; from: Buffer; next: Cursor }
  | { kind: 'sealing'; from: Buffer }
  | { kind: 'refused'; reason: string }
  /** A step that found the head taken, and left the step to whoever holds it. */
  | { kind: 'busy' };

/**
 * Where the app stands, from the log. A key a move names as moved from is
 * refused: a rollback, or an instance a newer deployment replaced. The
 * newest `key.reseal` or `key.rotate`, checked by its MAC under the key it
 * names, says whether a rotation is under way, and to which key. Then each
 * key held as replaced that wrote entries and was never moved from is
 * moved from, every row it signed signed again, whatever wrote after it:
 * rows the new key signed meanwhile are left as they are, and the order
 * the keys are listed in changes nothing. A key the app does not hold,
 * the log's newest, is said and served under: as before rotations, its
 * rows fail and the log does not verify, but the instance does not stop. A few indexed reads; a key
 * held as replaced is looked for among the entries until one is found.
 */
export async function keyState(db: Queryable, keys: AppKeys): Promise<KeyState> {
  const current = appLogKey(keys.chainKey).keyId;
  const previous = keys.previousChainKeys.map((key) => ({ id: appLogKey(key).keyId, key }));
  const held = new Map([[current, keys.chainKey], ...previous.map(({ id, key }) => [id, key] as const)]);
  const moved = await movedFrom(db, [...held.keys()]);
  if (moved.has(current)) {
    return refused(`the log moved on from ${current}, this app's key: a key the app moved on from writes no more, and comes back only as a new key's rotation`);
  }
  const move = await newestMove(db);
  let unknown = move !== undefined && !held.has(move.keyId) ? move.keyId : null;
  if (move !== undefined && unknown === null) {
    const under = held.get(move.keyId)!;
    if (!authentic(move, under)) return refused(forged(move));
    if (move.action === 'key.reseal') {
      if (move.keyId !== current) {
        return refused(`a rotation to ${move.keyId} is under way, and this app's key is ${current}: deploy that one as auditChainKey to finish it`);
      }
      const from = held.get(move.subjectPrincipal ?? '');
      if (from === undefined) {
        return refused(`the rotation under way moves from ${move.subjectPrincipal}, a key missing from previousAuditChainKeys: put it back to finish it`);
      }
      const next = nextOf(move);
      if (next === undefined) return refused(`entry ${move.seq}, the rotation's last step, does not say where it goes on`);
      return next === null ? { kind: 'sealing', from } : { kind: 'rotating', from, next };
    }
    // The log is under the key its newest rotation moved to, a key this app replaced: it moves on from that one in turn.
    if (move.keyId !== current) return { kind: 'rotating', from: under, next: START };
  }
  for (const { id, key } of previous) {
    if (moved.has(id)) continue;
    if (await wroteUnder(db, id)) return { kind: 'rotating', from: key, next: START };
    unused(id);
  }
  if (move === undefined) {
    const latest = await newestAppEntry(db);
    if (latest !== undefined && !held.has(latest.keyId)) unknown = latest.keyId;
  }
  if (unknown !== null) unheld(unknown, current);
  return { kind: 'settled' };
}

/**
 * Where the app stands, as `keyState` reads it in one snapshot: its reads
 * see the log as of one moment, so a step another start commits between
 * two of them cannot make the verdict a mix of before and after it, such
 * as `settled` halfway through. No lock: steps take the head themselves.
 */
export function keyStateNow(db: Database, keys: AppKeys): Promise<KeyState> {
  return db.transaction((tx) => keyState(tx, keys), SNAPSHOT);
}

/**
 * Whether a step may go on: the head taken, waiting for it, or, with
 * `wait: false`, only if it is free; a step that finds it taken leaves the
 * rotation to the start that holds it, and says it is still under way.
 */
async function headFor(tx: Transaction, wait: boolean): Promise<boolean> {
  if (wait) await lockLogHead(tx);
  return wait || lockLogHeadIfFree(tx);
}

/**
 * One step of the rotation, in a transaction under the log's head: where
 * it stands read again under it, then up to `rows` rows signed again from
 * there, and its entry. Rows the old key signed are signed under the new
 * one; a session is signed out as well, and a device's login approved but
 * not yet taken is used up; rows the new one signed already are left; a
 * row neither signed is left as it is, which fails it as it failed
 * before, and named. Where the app stands after: `sealing` once every row
 * is signed.
 */
export async function rotateStep(db: Database, keys: AppKeys, { rows = STEP_ROWS, wait = true }: { rows?: number; wait?: boolean } = {}): Promise<KeyState> {
  const unsigned: { table: AuthTable; id: string }[] = [];
  const state = await db.transaction(async (tx): Promise<KeyState> => {
    if (!(await headFor(tx, wait))) return busy;
    const standing = await keyState(tx, keys);
    if (standing.kind !== 'rotating') return standing;
    const { from } = standing;
    let next: Cursor | null = standing.next;
    let [left, resealed, signedOut] = [rows, 0, 0];
    const now = new Date();
    while (next !== null && left > 0) {
      const { table, after }: Cursor = next as Cursor;
      const asked = left;
      const read = await signedRowsAfter(tx, table, after, asked);
      const changes: Resealed[] = [];
      for (const row of read) {
        const ends = endsAt(table, row, now);
        const mac = signedAgain(from, keys.chainKey, table, row, (ends === null ? {} : ends) as never);
        if (mac !== null) changes.push({ id: row.id, was: row.authMac, mac, ends: ends === null ? null : now });
        // Signed under the new key already, by a step that was cut short; or by neither, and left.
        else if (!signedBy(keys.chainKey, table, row)) unsigned.push({ table, id: row.id });
      }
      const changed = new Set(await reseal(tx, table, changes));
      for (const change of changes) {
        if (!changed.has(change.id)) unsigned.push({ table, id: change.id });
        else if (change.ends !== null) signedOut += 1;
        else resealed += 1;
      }
      left -= read.length;
      // A table read to its end goes on to the next; one cut short by the budget, after its last row read.
      const following: AuthTable | undefined = SIGNED_TABLES[SIGNED_TABLES.indexOf(table) + 1];
      next = read.length < asked ? (following === undefined ? null : { table: following, after: null }) : { table, after: read.at(-1)!.id };
    }
    const fromId = appLogKey(from).keyId;
    await appendAudit(tx, keys.chainKey, [{
      ...ROTATION,
      action: 'key.reseal',
      decision: 'allow',
      subject: fromId,
      metadata: { from: fromId, resealed, signedOut, unsigned: unsigned.slice(0, NAMED), unsignedCount: unsigned.length, next },
    }]);
    return next === null ? { kind: 'sealing', from } : { kind: 'rotating', from, next };
  });
  if (unsigned.length > 0) {
    console.error({ event: 'auth_row_unsigned', rows: unsigned.slice(0, NAMED), count: unsigned.length }, 'rows neither app key signed are left as they are, and fail as before');
  }
  return state;
}

/**
 * The rotation's end, once its rows are signed and the caller has sealed
 * the audit anchor again under the new key: `key.rotate`,
 * in a transaction under the log's head that reads again where it stands.
 * From here on the old key vouches for nothing. Where the app stands
 * after, read again: another key may be due to move from in turn.
 */
export async function finishRotation(db: Database, keys: AppKeys, { wait = true }: { wait?: boolean } = {}): Promise<KeyState> {
  return db.transaction(async (tx): Promise<KeyState> => {
    if (!(await headFor(tx, wait))) return busy;
    const standing = await keyState(tx, keys);
    if (standing.kind !== 'sealing') return standing;
    const fromId = appLogKey(standing.from).keyId;
    await appendAudit(tx, keys.chainKey, [{ ...ROTATION, action: 'key.rotate', decision: 'allow', subject: fromId, metadata: { from: fromId } }]);
    return keyState(tx, keys);
  });
}

/** What a step answers when another holds the head: under way, for the start that holds it to go on with. */
const busy: KeyState = { kind: 'busy' };

/** What a rotation ends of a row as it signs it again: a live session, signed out; a device's approved login not yet taken, used up. */
function endsAt(table: AuthTable, row: AuthRow, now: Date): { revokedAt: Date } | { consumedAt: Date } | null {
  const fields = row as { kind?: string; revokedAt?: Date | null; decision?: string; consumedAt?: Date | null };
  if (table === 'credentials' && SESSIONS.has(fields.kind!) && fields.revokedAt === null) return { revokedAt: now };
  if (table === 'device_authorizations' && fields.decision === 'approved' && fields.consumedAt === null) return { consumedAt: now };
  return null;
}

const told = new Set<string>();

/**
 * Said once a process or isolate: a key in previousAuditChainKeys that
 * wrote no entry and was never moved from verifies nothing, and costs each
 * new isolate a read of the log for its first entry.
 */
function unused(keyId: string): void {
  if (told.has(keyId)) return;
  told.add(keyId);
  console.warn({ event: 'app_key_unused', keyId }, 'a key in previousAuditChainKeys wrote no entry of the log: it verifies nothing, and can go');
}

/**
 * Said once a process or isolate: the log's newest move or entry is under
 * a key this app does not hold, lost or never given it, and it serves all
 * the same, as it did before rotations: what that key signed fails.
 */
function unheld(keyId: string, current: string): void {
  if (told.has(keyId)) return;
  told.add(keyId);
  console.error(
    { event: 'app_key_unheld', keyId, current },
    `the log's newest entries are under ${keyId}, an app key this app does not hold: every row and entry it signed fails, and everyone signs in again. If you still have it, list it in previousAuditChainKeys`,
  );
}

function refused(reason: string): KeyState {
  return { kind: 'refused', reason };
}

/** Whether `entry` carries the MAC of `key`, the app key it names, over the link it names. */
function authentic(entry: StoredEntry, key: Buffer): boolean {
  return verifyEntries([entry], { startSeq: entry.seq, startPrevHash: entry.prevHash, keys: [appLogKey(key)] }).ok;
}

function forged(entry: StoredEntry): string {
  return `entry ${entry.seq}, in the app's name under ${entry.keyId}, does not carry its MAC: forged, or rewritten since`;
}

/** Where the step `entry` wrote said the next goes on: null for no row left, undefined if it does not say. */
function nextOf(entry: StoredEntry): Cursor | null | undefined {
  try {
    const { next } = JSON.parse(entry.metadata) as { next?: { table?: unknown; after?: unknown } | null };
    if (next === null) return null;
    if (typeof next !== 'object') return undefined;
    const table = SIGNED_TABLES.find((name) => name === next.table);
    const after = next.after === null || typeof next.after === 'string' ? next.after : undefined;
    return table === undefined || after === undefined ? undefined : { table, after };
  } catch {
    return undefined;
  }
}
