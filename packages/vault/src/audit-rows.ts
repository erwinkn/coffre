import { createHmac, timingSafeEqual } from 'node:crypto';

import { keysAt, type Keyring } from './keyring.ts';
import type { LogMacKey } from './log-entry.ts';

// The audit projection's rows and what their MACs cover (0.16; docs/design/state-rows.md, section 2; migration
// 0087). The one home of both MAC inputs: the projector writes under them (projection.ts), and whatever checks a row a
// page shows, or the cursor, checks them here. Each is HMAC-SHA256 under the log's MAC key (its key, not its tag: a
// row is no entry of the log), over a domain of its own, then JSON of every column but the MAC, cut to 16 bytes.

/** Which log an entry is of: 0.14's `audit_log`, 0.15's changes, 0.15's uses. */
export type AuditLog = 14 | 15 | 16;

/** An entry of any log as the pages list it (`audit_events`), every id lower-case. */
export type AuditEvent = {
  /** Ms: the entry's own time. */
  at: number;
  /** Its number in its log: a 0.14 entry's seq, a change's or a use's number. */
  number: bigint;
  log: AuditLog;
  /** Who wrote it: a 0.14 entry's author, else the vault. */
  author: 'app' | 'vault';
  action: string;
  /** False for sign-ins and technical steps (`DETAIL_ACTIONS` on the server), listed only when asked. */
  shown: boolean;
  allowed: boolean;
  /** A refusal's reason. */
  code: string | null;
  actor: string;
  /** The member it is about. */
  subject: string | null;
  /** The way in it came through: a credential, a connection, a binding, or behind Access the person. */
  credential: string | null;
  project: string | null;
  environment: string | null;
  secret: string | null;
  version: string | null;
  /** Every place it is listed at (`audit_event_places`), sorted, each once. */
  places: string[];
  requestId: string | null;
  operationId: string | null;
  related: bigint | null;
  sourceIp: string | null;
  /** What the API returns as its `metadata`: JSON text, which no SQL parses. */
  detail: string;
  mac: Buffer;
};

/**
 * How far the projector has gone. The chains: every entry numbered at or
 * below `through` is listed; `pair`, the signed pair at or below it, whose
 * range the next batch reads; `at`, the signed time of the newest pair
 * whose entries are all listed. `audit_log`: every seq below `oldFloor`,
 * and from `oldFrom` up to below `oldTop`; the walk goes on below
 * `oldFrom`, whose entry must hash to `oldHash`, down to `oldFloor`.
 */
export type AuditCursor = {
  through: bigint;
  pair: bigint;
  at: number;
  /** Temporary, outside the MAC: it goes once the old log is frozen and walked once down to its first entry. Never sign it back in. */
  oldFloor: bigint;
  oldFrom: bigint;
  /** Temporary, outside the MAC: it goes once the old log is frozen, with no newer 0.14 checkpoint. Never sign it back in. */
  oldTop: bigint;
  oldHash: Buffer;
  /** Null at the start only. */
  mac: Buffer | null;
};

const MAC_BYTES = 16;

/** The start: nothing listed of any log (migration 0087's row, and `rebuild_audit`'s). */
export const CURSOR_START: Omit<AuditCursor, 'mac'> = { through: 0n, pair: 0n, at: 0, oldFloor: 0n, oldFrom: 0n, oldTop: 0n, oldHash: Buffer.alloc(32) };

/** The columns of `audit_events` an event's MAC covers, in its input's order: every one but `mac` (audit-rows.test.ts). */
export const EVENT_MAC_COLUMNS = [
  'at', 'number', 'log', 'author', 'action', 'shown', 'allowed', 'code', 'actor', 'subject', 'credential', 'project', 'environment', 'secret', 'version',
  'places', 'request_id', 'operation_id', 'related', 'source_ip', 'detail',
] as const;

/**
 * The columns of `audit_cursor` its MAC covers, in order: every one but `only_row`, `mac`, retention's `reads_from`,
 * and the temporary `old_floor` and `old_top`. While those two stand, a database writer can raise them and hide 0.14
 * entries from the page, but not forge or reorder one: each step of the walk is hash-checked down from a signed
 * anchor.
 */
export const CURSOR_MAC_COLUMNS = ['through', 'pair', 'at', 'old_from', 'old_hash'] as const;

/** The temporary columns of `audit_cursor`, outside its MAC, which go with the projector's `lossesAbove` (projection.ts). */
export const CURSOR_INTERIM_COLUMNS = ['old_floor', 'old_top'] as const;

/**
 * What an event's MAC covers: every column but itself, in the table's order,
 * numbers in decimal, its places sorted. Two rows alike in these are the
 * same row.
 */
export const eventColumns = (row: Omit<AuditEvent, 'mac'>): string => JSON.stringify([
  String(row.at), String(row.number), String(row.log), row.author, row.action, row.shown, row.allowed, row.code, row.actor, row.subject,
  row.credential, row.project, row.environment, row.secret, row.version, row.places, row.requestId, row.operationId,
  row.related === null ? null : String(row.related), row.sourceIp, row.detail,
]);

/** An event's MAC under `key`. */
export function eventMac(key: LogMacKey, row: Omit<AuditEvent, 'mac'>): Buffer {
  return createHmac('sha256', key.key).update('coffre.audit.event.v1\0').update(eventColumns(row)).digest().subarray(0, MAC_BYTES);
}

/** What the cursor's MAC covers (`CURSOR_MAC_COLUMNS`): where it stands in the chains, and where the walk of `audit_log` goes on, `oldHash` in hex. */
export const cursorColumns = (cursor: Omit<AuditCursor, 'mac'>): string => JSON.stringify([
  String(cursor.through), String(cursor.pair), String(cursor.at), String(cursor.oldFrom), cursor.oldHash.toString('hex'),
]);

/** The cursor's MAC under `key`. */
export function cursorMac(key: LogMacKey, cursor: Omit<AuditCursor, 'mac'>): Buffer {
  return createHmac('sha256', key.key).update('coffre.audit.cursor.v1\0').update(cursorColumns(cursor)).digest().subarray(0, MAC_BYTES);
}

const holds = (expected: Buffer, mac: Buffer) => mac.length === MAC_BYTES && timingSafeEqual(expected, mac);

/**
 * Whether an event's MAC holds under a key that vouches for it: the
 * current one, or one it replaced, below that key's rotation for a row of
 * the chains. A row of the frozen log has no chain number: every key held
 * vouches for it, as each was current when some of them were projected; the
 * recheck holds them to the log.
 */
export const eventVouched = (ring: Keyring, row: AuditEvent): boolean =>
  keysAt(ring, row.log === 14 ? 0n : row.number).some((key) => holds(eventMac(key.mac, row), row.mac));

/**
 * Whether a walk down `audit_log` is under way: entries of the log before
 * 0.16 are still being listed, newest first, so its history stops early
 * (`oldBatch` starts a new walk only when it is not; the pages say so).
 */
export const oldWalkOpen = (cursor: Pick<AuditCursor, 'oldFloor' | 'oldFrom'>): boolean => cursor.oldFrom > cursor.oldFloor;

/**
 * Whether the cursor is the projector's: at the start, with no MAC; else
 * under a key that vouches where it stands in the chains, `pair` at or
 * below `through` as the projector moves it, and the old log's positions
 * in order, as the table's check holds them too: the MAC leaves out
 * `oldFloor` and `oldTop`, so the order is all that holds them.
 */
export function cursorVouched(ring: Keyring, cursor: AuditCursor): boolean {
  if (cursor.mac === null) return cursorColumns(cursor) === cursorColumns(CURSOR_START) && cursor.oldFloor === 0n && cursor.oldTop === 0n;
  if (cursor.pair > cursor.through || cursor.oldFloor > cursor.oldFrom || cursor.oldFrom > cursor.oldTop) return false;
  return keysAt(ring, cursor.through).some((key) => holds(cursorMac(key.mac, cursor), cursor.mac!));
}
