import type { CheckState, EventAuthor, NoteInput, NotePayload } from '@coffre/core/vault';

import { canonical, logObject } from './inputs.ts';
import { entryMac, type LogMacKey } from './log-entry.ts';

/**
 * An event's row in `log_changes` (`Vault.note` in @coffre/core/vault, which says what is written and
 * when it answers): what no object's change records, a refusal the app decides alone, a refusal the vault decides, a
 * refused sign-in, a finding. Its object is its own, from its id, so no reader that asks an object's newest change ever
 * takes it. This file is its encoding, for every writer and reader of one.
 *
 * A row is an event when its object is `eventObject` of its `request_id` and its payload's `op` is `event`, whatever
 * its id. The id is opaque: its writer draws it, a UUID, and resends it unchanged; a writer of no request that may run
 * twice derives it from what it reports, in the one form pinned here for it (`findingEventId`), so that it writes the
 * event once.
 *
 * Only the audit projector reads an event. The replay, and the full walk that replays the log, pass over it as
 * one of the log's own changes (`LOGS_OWN`, log-replay.ts): its op changes no object a decision reads.
 */

/** The kind an event's object is filed under: `log_object('event', <event id>)`. */
export const EVENT_KIND = 'event';

/** An event's object, the row's `object` column. */
export function eventObject(id: string): string {
  return logObject(EVENT_KIND, id);
}

/**
 * The id of the beat's finding: `system:vault/finding:<checkpoint>:<state>`, the
 * number of the newest signed checkpoint its check read (`none` before the first) and what the check said. One finding
 * per checkpoint and state, by design: a checkpointer stuck at 4410 is one `late` finding, however many beats see it,
 * and a second `broken` at 4410 for another reason is the same finding. Each other writer of no request that may run
 * twice pins its own form here, `<its system actor>/<its noun>:…`, before it writes one; no two share a noun.
 *
 *   findingEventId(4410n, 'late') = 'system:vault/finding:4410:late'
 */
export function findingEventId(checkpoint: bigint | null, state: Exclude<CheckState, 'ok'>): string {
  return `system:vault/finding:${checkpoint ?? 'none'}:${state}`;
}

/**
 * An event's payload, the row's `payload` column: canonical JSON of `NotePayload`. `author` is who decided it, never
 * the app's to say: `note` and `prepare` write `app` for every event the app hands over; the vault's own writers (its
 * refusals, the beat's findings) write `vault`.
 */
export function notePayload(input: NoteInput, author: EventAuthor): string {
  // Field by field, never a spread: a field `NoteInput` does not name stays out of the signed payload.
  const { action, allowed, code, subject, places, credential, requestId, operationId, sourceIp, detail } = input;
  const { projectId, environmentId, secretId, versionId } = places;
  const payload: NotePayload = {
    action,
    allowed,
    author,
    code,
    credential,
    detail,
    op: 'event',
    operationId,
    places: { projectId, environmentId, secretId, versionId },
    ref: { kind: EVENT_KIND, id: input.id },
    requestId,
    sourceIp,
    subject,
  };
  return canonical(payload);
}

/**
 * An event's row as `log_events` takes it, signed at `at` (the vault's clock) under `key`: what `note` writes and what
 * `prepare` hands the app for its transaction (`NotedRow`, its MAC in bytes here). The MAC is a change's, over every
 * column but the number (`entryMac`), so the row is signed before it has one.
 */
export function eventRow(key: LogMacKey, at: number, input: NoteInput, author: EventAuthor): { at: number; requestId: string; object: string; actor: string; payload: string; seal: null; mac: Buffer } {
  const row = { at, requestId: input.id, object: eventObject(input.id), actor: input.actor, payload: notePayload(input, author), seal: null };
  return { ...row, mac: entryMac(key, { tree: 'changes', row }) };
}
