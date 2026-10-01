import { deriveLogKey, type LogKey } from '@coffre/core/audit';
import type { Transaction } from '@coffre/db';
import { appendEntries, type Appended } from '@coffre/db/log';

export type AuditEntry = {
  actorType: 'user' | 'service' | 'system';
  actorId: string;
  action: string;
  decision: 'allow' | 'deny';
  projectId?: string | null;
  environmentId?: string | null;
  secretId?: string | null;
  /** One id for everything one action did, shared with the vault's entries for it. */
  operationId?: string | null;
  requestId?: string | null;
  sourceIp?: string | null;
  /** The vault's entry this one follows from: a write's `key.wrap`, a restore's `key.rewrap`. */
  relatedSeq?: number | null;
  metadata?: Record<string, unknown>;
};

/**
 * Append the app's entries to the audit log, inside the caller's transaction.
 *
 * This is deliberately NOT a queue, NOT a background write, and NOT
 * best-effort. Infisical's audit queue returned early and dropped every entry
 * silently; that failure mode is the reason this project exists. If the append
 * throws, the caller's transaction rolls back and the read that would have
 * been unlogged does not happen either.
 *
 * The append itself, which locks the log's head, dates, MACs and chains the
 * entries, is @coffre/db's: the vault appends to the same log the same way,
 * under its own key.
 */
export async function appendAudit(tx: Transaction, chainKey: Buffer, entries: readonly AuditEntry[]): Promise<Appended> {
  return appendEntries(
    tx,
    appLogKey(chainKey),
    entries.map((entry) => ({
      actor: actorOf(entry.actorType, entry.actorId),
      action: entry.action,
      decision: entry.decision,
      projectId: entry.projectId,
      environmentId: entry.environmentId,
      secretId: entry.secretId,
      operationId: entry.operationId,
      requestId: entry.requestId,
      sourceIp: entry.sourceIp,
      relatedSeq: entry.relatedSeq === undefined || entry.relatedSeq === null ? null : BigInt(entry.relatedSeq),
      metadata: JSON.stringify(entry.metadata ?? {}),
    })),
  );
}

const logKeys = new WeakMap<Buffer, LogKey>();

/**
 * The key the app's entries are MACed with, derived from `auditChainKey`.
 * One object per configured key, so the append's memory of the heads it
 * found lasts as long as the configuration does.
 */
export function appLogKey(chainKey: Buffer): LogKey {
  let key = logKeys.get(chainKey);
  if (key === undefined) logKeys.set(chainKey, (key = deriveLogKey('app', chainKey)));
  return key;
}

const ACTOR_PREFIX = { user: 'user', service: 'token', system: 'system' } as const;

/**
 * An entry's actor as the log stores it: `user:<email>`, `token:<id>`,
 * `sync:<id>` or `system:<name>`. A sync acts as the system with its own
 * principal as its id, which is already the canonical form.
 */
export function actorOf(type: AuditEntry['actorType'], id: string): string {
  if (type === 'system' && id.startsWith('sync:')) return id;
  return `${ACTOR_PREFIX[type]}:${id}`;
}

/** An actor as the API shows it, a type and an id: `actorOf` undone. */
export function actorParts(actor: string): { actorType: AuditEntry['actorType']; actorId: string } {
  const colon = actor.indexOf(':');
  const [prefix, rest] = [actor.slice(0, colon), actor.slice(colon + 1)];
  if (prefix === 'user') return { actorType: 'user', actorId: rest };
  if (prefix === 'token') return { actorType: 'service', actorId: rest };
  if (prefix === 'sync') return { actorType: 'system', actorId: actor };
  return { actorType: 'system', actorId: rest };
}
