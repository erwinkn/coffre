import type { StoredEntry } from '@coffre/core/audit';
import type { LogVerification } from '@coffre/core/vault';
import type { Queryable } from '@coffre/db';

import { entriesFrom } from './store.ts';

type Intent = {
  entry: StoredEntry;
  operation: string;
  expiresAt: number;
  keys: { item: number; secretId: string; version: number; subject: string }[];
  seen: Set<number>;
};

/** The chain can hold while a process died between an intent and its outcomes. */
export async function verifyAccounting(db: Queryable, at: number): Promise<LogVerification | null> {
  const intents = new Map<bigint, Intent>();
  const ids = new Set<string>();
  const broken = (entry: StoredEntry, reason: string): LogVerification => ({ ok: false, failedAtSeq: Number(entry.seq), reason });
  let next = 0n;
  for (;;) {
    const batch = await entriesFrom(db, next, 1000);
    if (batch.length === 0) break;
    for (const entry of batch) {
      if (entry.author !== 'vault') continue;
      if (entry.action === 'key.intent') {
        const detail = payload(entry.metadata);
        if (detail === null) return broken(entry, 'key intent has no valid accounting payload');
        const { operation, expiresAt, keys } = detail;
        if (
          entry.operationId === null || ids.has(entry.operationId) || typeof operation !== 'string' ||
          !['wrap', 'unwrap', 'rewrap'].includes(operation) ||
          typeof expiresAt !== 'number' || !Number.isSafeInteger(expiresAt) || expiresAt < entry.occurredAt || !Array.isArray(keys) ||
          !keys.every((key, item) => key !== null && key.item === item && typeof key.secretId === 'string' &&
            Number.isSafeInteger(key.version) && key.version > 0 && typeof key.subject === 'string')
        ) {
          return broken(entry, 'key intent has no valid accounting identity or item list');
        }
        ids.add(entry.operationId);
        if (keys.length > 0) intents.set(entry.seq, { entry, operation, expiresAt, keys, seen: new Set() });
      } else if (['wrap', 'unwrap', 'rewrap'].includes(entry.action) && (entry.relatedSeq !== null || entry.operationId !== null)) {
        const intent = entry.relatedSeq === null ? undefined : intents.get(entry.relatedSeq);
        const detail = payload(entry.metadata);
        if (detail === null) return broken(entry, 'key outcome has no valid accounting payload');
        const item = detail.item;
        const key = typeof item === 'number' ? intent?.keys[item] : undefined;
        if (
          intent === undefined || typeof item !== 'number' || !Number.isSafeInteger(item) || key === undefined || intent.seen.has(item) ||
          entry.operationId !== intent.entry.operationId || entry.actor !== intent.entry.actor || entry.action !== intent.operation ||
          (entry.secretId ?? detail.secretId) !== key.secretId || detail.version !== key.version || detail.subject !== key.subject
        ) {
          return broken(entry, 'key outcome does not identify one item of its intent');
        }
        intent.seen.add(item);
        if (intent.seen.size === intent.keys.length) intents.delete(intent.entry.seq);
      }
    }
    next = batch[batch.length - 1].seq + 1n;
    if (batch.length < 1000) break;
  }
  const unfinished = [...intents.values()].sort((a, b) => a.expiresAt - b.expiresAt);
  if (unfinished.length === 0) return null;
  const reason = unfinished.map((intent) => {
    const missing = intent.keys.length - intent.seen.size;
    const state = at < intent.expiresAt ? 'still running' : 'overdue';
    return `key intent ${intent.entry.operationId} is ${state}: ${missing} of ${intent.keys.length} outcomes missing`;
  }).join('; ');
  return broken(unfinished[0].entry, reason);
}

function payload(text: string): Record<string, unknown> | null {
  try {
    const value: unknown = JSON.parse(text);
    return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : null;
  } catch {
    return null;
  }
}
