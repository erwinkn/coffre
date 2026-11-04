import { randomUUID } from 'node:crypto';

import { openUnder, sealUnder } from './admit.ts';
import { canonical, logObject } from './inputs.ts';
import { entryMac, type LogMacKey } from './log-entry.ts';

export { callRefusal } from './refusal.postgres.ts';

/**
 * A refusal's record (T179 PR 6; docs/design/two-trips.md, "As built: PR 6"; formal/Writing.tla, `Refuse`): what a
 * key write or a member's first add the vault's decision refused on its read leaves in 0.15's log, in place of the 0.14
 * deny entry today's path writes. A row of `log_changes`, so that the checkpoints seal it, the trees hold it and
 * retention keeps it as they do every change, but a change of nothing: its object is the request's own
 * (`log_object('request', id)`), which no other row's is, so no reader that asks an object's newest change (a use, a
 * hold, a member's watermark) ever takes it, and the replay passes over it as the log's own (`REFUSALS`).
 *
 *   Ada's PATCH market/dev { API_KEY: "sk-…" }, no grant there:
 *   vault  write_request: the read, the number                                       one round trip
 *          the Worker: refused, `no_grant`; the record prepared (the ticket)
 *   app    the rows' auth_mac, in memory; 403 as today's path answers it, once …
 *   vault  log_refusal: the record, under the fence shared, as a use's               one round trip
 *          the seal wait (R51, as a change's)
 *
 * Its payload, canonical (keys sorted, so it starts `{"code":"`, as no other change's does: change-records.ts):
 *
 *   {"code":"no_grant","credential":"<id>","environmentId":"<id>","identity":"<id>","keys":["API_KEY"],
 *    "op":"write.refused","path":"market/dev","projectId":"<id>","read":"<digest>",
 *    "ref":{"id":"<the record's request id>","kind":"request"},"request":{"number":"<n>","operationId":…,"requestId":…}}
 *
 * An add's names the member asked for, the role and the scope as asked, and no number (its read numbers nothing).
 */

/** The ops of a refusal's record: a key write's, an add's. */
export const REFUSALS: ReadonlySet<string> = new Set(['write.refused', 'add.refused']);

/** The refusal, as the decision made it: who asked, by ids, as the checked read resolved them (ActorFromRead), and the read's digest. */
type Refusing = { code: string; actor: string; credential: string; identity: string | null; read: string; operationId: string | null; requestId: string | null };

/** What a key write's refusal names: its request's number, its place by ids and by its path's slugs, its keys by name. */
export type WriteRefusing = Refusing & { number: bigint; projectId: string; environmentId: string; path: string; keys: readonly string[] };

/** What an add's refusal names: the member, and the role and scope as asked. */
export type AddRefusing = Refusing & { principal: string; role?: string; scope?: unknown };

/** The record as the vault prepared it, which the app hands back to `recordRefusal` and can neither change nor make. */
export type RefusalTicket = { v: 1; until: number; actor: string; requestId: string; payload: string };

/** How long a refusal's ticket is taken: the record follows its decision by the app's check, in memory. */
export const REFUSAL_MS = 30_000;

const REFUSAL_DOMAIN = 'coffre.refusal.v1\0';

/** A key write's refusal, its record prepared. */
export function writeRefusal(key: LogMacKey, at: number, r: WriteRefusing): string {
  const { code, credential, identity, read, operationId, requestId, number, projectId, environmentId, path, keys } = r;
  return ticketOf(key, at, r.actor, (id) => ({
    code, credential, identity, read, op: 'write.refused', ref: { kind: 'request', id }, request: { number: number.toString(), operationId, requestId },
    projectId, environmentId, path, keys: [...keys],
  }));
}

/** An add's refusal, its record prepared. */
export function addRefusal(key: LogMacKey, at: number, r: AddRefusing): string {
  const { code, credential, identity, read, operationId, requestId, principal, role, scope } = r;
  return ticketOf(key, at, r.actor, (id) => ({
    code, credential, identity, read, op: 'add.refused', ref: { kind: 'request', id }, request: { operationId, requestId }, principal, role, scope,
  }));
}

function ticketOf(key: LogMacKey, at: number, actor: string, payload: (id: string) => Record<string, unknown>): string {
  // The record's own request id, drawn here: the same each time the ticket is written (`log_refusal` finds it), never
  // a change's (each key write's is derived from its number and object, `writeRequestId`; an add's is drawn too).
  const requestId = randomUUID();
  const ticket: RefusalTicket = { v: 1, until: at + REFUSAL_MS, actor, requestId, payload: canonical(payload(requestId)) };
  return sealUnder(REFUSAL_DOMAIN, key, ticket);
}

/** The record a ticket carries, if one of these keys sealed it: `expired` once its time is past at `now`; else null, no ticket of the vault's. */
export function openRefusal(keys: readonly LogMacKey[], sealed: unknown, now: number): RefusalTicket | 'expired' | null {
  const ticket = openUnder<RefusalTicket>(REFUSAL_DOMAIN, keys, sealed);
  if (ticket === null || ticket.v !== 1 || typeof ticket.until !== 'number' || typeof ticket.payload !== 'string') return null;
  return now > ticket.until ? 'expired' : ticket;
}

/** A refusal's record as `log_refusal` writes it, its number aside. */
export type RefusalRow = { at: number; requestId: string; object: string; actor: string; payload: string; seal: null; mac: Buffer };

/** The record's row, MAC'd under `key` at `at`, the vault's clock as it writes it (the checkpointer takes no entry stamped long before). */
export function refusalRow(key: LogMacKey, ticket: RefusalTicket, at: number): RefusalRow {
  const row = { at, requestId: ticket.requestId, object: logObject('request', ticket.requestId), actor: ticket.actor, payload: ticket.payload, seal: null };
  return { ...row, mac: entryMac(key, { tree: 'changes', row }) };
}
