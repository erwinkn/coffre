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
// that says where the next goes on, the last one `key.rotate` too. So a
// rotation survives a crash between steps and goes on from the last, any
// number of isolates or processes may step it at once, one after another
// under the head, and a Worker's step stays within its CPU. The app serves
// nothing else until it is done (`keyReady` in app.ts).
//
//   key.reseal  { from: 'app:1f…', resealed: 69, signedOut: 31, unsigned: [], next: { table: 'credentials', after: '7c…' } }
//   key.reseal  { from: 'app:1f…', resealed: 12, signedOut: 0, unsigned: [], next: null }
//   key.rotate  { from: 'app:1f…' }
import { verifyEntries, type StoredEntry } from '@coffre/core/audit';
import type { Database, Queryable } from '@coffre/db';
import { lockLogHead } from '@coffre/db/log';

import { signedAgain, signedBy, type AuthRow, type AuthTable } from './auth-rows.ts';
import { appendAudit, appLogKey, type AppKeys, type AuditEntry } from './db/audit.ts';
import { newestAppEntry, newestMove, reseal, signedRowsAfter, type Resealed } from './db/rotation.ts';

/** Every table whose rows carry the app's MAC, in the order a rotation signs them again. */
export const SIGNED_TABLES: readonly AuthTable[] = [
  'identities', 'credentials', 'device_authorizations', 'service_bindings', 'oauth_clients', 'mcp_connections', 'enrollments',
];

/** The credentials a rotation signs out: people's sessions, the browser's and the CLI's, which a sign-in gives back. */
const SESSIONS = new Set(['browser', 'cli']);

/** Rows a step reads and signs again, at most: some 2 ms of CPU warm, 5 cold, well within a Worker's 10. */
export const STEP_ROWS = 100;

/** Rows a step names in its entry that it could not sign again, at most; the count is whole. */
const NAMED = 20;

const ROTATION: Pick<AuditEntry, 'actorType' | 'actorId'> = { actorType: 'system', actorId: 'coffre-key-rotation' };

/** Where a rotation goes on from: a table, after the row with this id, or from its first. */
export type Cursor = { table: AuthTable; after: string | null };

const START: Cursor = { table: SIGNED_TABLES[0]!, after: null };

/**
 * Where the app stands with its key, as the log says: under it, with the
 * key the log last moved from if this app still holds it, the audit
 * anchor's to seal again (`movedFrom`); moving to it from `from`, going on
 * from `next`; or refused, and why, for a key the log has moved on from
 * or does not know.
 */
export type KeyState =
  | { kind: 'settled'; movedFrom: Buffer | null }
  | { kind: 'rotating'; from: Buffer; next: Cursor }
  | { kind: 'refused'; reason: string };

/**
 * Where the app stands, from the log: its newest `key.reseal` or
 * `key.rotate`, and when it has none, its newest entry. Each checked by its
 * MAC under the key it names, which the app must hold. Two indexed reads,
 * at most.
 */
export async function keyState(db: Queryable, keys: AppKeys): Promise<KeyState> {
  const current = appLogKey(keys.chainKey).keyId;
  const held = new Map([keys.chainKey, ...keys.previousChainKeys].map((key) => [appLogKey(key).keyId, key]));
  const move = await newestMove(db);
  if (move === undefined) {
    const newest = await newestAppEntry(db);
    if (newest === undefined || newest.keyId === current) return { kind: 'settled', movedFrom: null };
    const from = held.get(newest.keyId);
    if (from === undefined) {
      return refused(`the app's entries are under ${newest.keyId}, a key this app does not hold: it was given the wrong app key, or the one it replaced is missing from previousAuditChainKeys`);
    }
    return authentic(newest, from) ? { kind: 'rotating', from, next: START } : refused(forged(newest));
  }
  const under = held.get(move.keyId);
  if (under === undefined) {
    return refused(`the log moved on to ${move.keyId}, a key this app does not hold: a deployment given a newer app key replaced this one, and a key the app moved on from writes no more`);
  }
  if (!authentic(move, under)) return refused(forged(move));
  const from = held.get(move.subjectPrincipal ?? '');
  if (move.action === 'key.rotate') {
    // Under this key since; or under one this app replaced, which it moves on from in turn.
    return move.keyId === current ? { kind: 'settled', movedFrom: from ?? null } : { kind: 'rotating', from: under, next: START };
  }
  if (move.keyId !== current) {
    return refused(`a rotation to ${move.keyId} is under way, and this app's key is ${current}: deploy that one as auditChainKey to finish it`);
  }
  if (from === undefined) {
    return refused(`the rotation under way moves from ${move.subjectPrincipal}, a key missing from previousAuditChainKeys: put it back to finish it`);
  }
  const next = nextOf(move);
  return next === undefined ? refused(`entry ${move.seq}, the rotation's last step, does not say where it goes on`) : { kind: 'rotating', from, next };
}

/**
 * One step of the rotation, in a transaction under the log's head: where
 * it stands read again under it, then up to `rows` rows signed again from
 * there, and its entry. Rows the old key signed are signed under the new
 * one, and a session is signed out as well; rows the new one signed
 * already are left; a row neither signed is left as it is, which fails it
 * as it failed before, and named. Where the app stands after.
 */
export async function rotateStep(db: Database, keys: AppKeys, rows = STEP_ROWS): Promise<KeyState> {
  const unsigned: { table: AuthTable; id: string }[] = [];
  const state = await db.transaction(async (tx): Promise<KeyState> => {
    await lockLogHead(tx);
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
        const session = table === 'credentials' && SESSIONS.has((row as AuthRow & { kind: string }).kind) && (row as { revokedAt: Date | null }).revokedAt === null;
        const mac = signedAgain(from, keys.chainKey, table, row, (session ? { revokedAt: now } : {}) as never);
        if (mac !== null) changes.push({ id: row.id, was: row.authMac, mac, signOut: session ? now : null });
        // Signed under the new key already, by a step that was cut short; or by neither, and left.
        else if (!signedBy(keys.chainKey, table, row)) unsigned.push({ table, id: row.id });
      }
      const changed = new Set(await reseal(tx, table, changes));
      for (const change of changes) {
        if (!changed.has(change.id)) unsigned.push({ table, id: change.id });
        else if (change.signOut !== null) signedOut += 1;
        else resealed += 1;
      }
      left -= read.length;
      // A table read to its end goes on to the next; one cut short by the budget, after its last row read.
      const following: AuthTable | undefined = SIGNED_TABLES[SIGNED_TABLES.indexOf(table) + 1];
      next = read.length < asked ? (following === undefined ? null : { table: following, after: null }) : { table, after: read.at(-1)!.id };
    }
    const fromId = appLogKey(from).keyId;
    const step: AuditEntry = {
      ...ROTATION,
      action: 'key.reseal',
      decision: 'allow',
      subject: fromId,
      metadata: { from: fromId, resealed, signedOut, unsigned: unsigned.slice(0, NAMED), unsignedCount: unsigned.length, next },
    };
    const rotated: AuditEntry = { ...ROTATION, action: 'key.rotate', decision: 'allow', subject: fromId, metadata: { from: fromId } };
    await appendAudit(tx, keys.chainKey, next === null ? [step, rotated] : [step]);
    return next === null ? { kind: 'settled', movedFrom: from } : { kind: 'rotating', from, next };
  });
  if (unsigned.length > 0) {
    console.error({ event: 'auth_row_unsigned', rows: unsigned.slice(0, NAMED), count: unsigned.length }, 'rows neither app key signed are left as they are, and fail as before');
  }
  return state;
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

/** Where the step `entry` wrote said the next goes on, if it says. */
function nextOf(entry: StoredEntry): Cursor | undefined {
  try {
    const { next } = JSON.parse(entry.metadata) as { next?: { table?: unknown; after?: unknown } | null };
    if (typeof next !== 'object' || next === null) return undefined;
    const table = SIGNED_TABLES.find((name) => name === next.table);
    const after = next.after === null || typeof next.after === 'string' ? next.after : undefined;
    return table === undefined || after === undefined ? undefined : { table, after };
  } catch {
    return undefined;
  }
}
