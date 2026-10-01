import type { StoredEntry } from '@coffre/core/audit';
import type { LogVerification } from '@coffre/core/vault';
import type { Queryable } from '@coffre/db';

import { VERIFY_BATCH } from './log.ts';
import { entriesFrom } from './store.ts';

const KEY_ACTIONS = new Set(['wrap', 'unwrap', 'rewrap']);

type Item = { item: number; secretId: string; version: number; subject: string };
type ParsedIntent = { operationId: string; operation: string; expiresAt: number; keys: Item[] };
type ParsedOutcome = Item & { operationId: string; relatedSeq: bigint };
type Intent = ParsedIntent & { entry: StoredEntry; seen: Set<number> };
type Accounting = { ok: true; pending: number } | Extract<LogVerification, { ok: false }>;

/** The chain can hold while a process died between an intent and its outcomes. */
export async function verifyAccounting(db: Queryable, at: number): Promise<Accounting> {
  const intents = new Map<bigint, Intent>();
  const ids = new Set<string>();
  const broken = (entry: StoredEntry, reason: string): Accounting => ({ ok: false, failedAtSeq: Number(entry.seq), reason });
  let next = 0n;
  for (;;) {
    const batch = await entriesFrom(db, next, VERIFY_BATCH);
    if (batch.length === 0) break;
    for (const entry of batch) {
      if (entry.author !== 'vault') continue;
      if (entry.action === 'key.intent') {
        const parsed = parseIntent(entry);
        if (typeof parsed === 'string') return broken(entry, parsed);
        if (ids.has(parsed.operationId)) return broken(entry, 'key intent repeats an operation identity');
        ids.add(parsed.operationId);
        if (parsed.keys.length > 0) intents.set(entry.seq, { ...parsed, entry, seen: new Set() });
      } else if (KEY_ACTIONS.has(entry.action) && (entry.relatedSeq !== null || entry.operationId !== null)) {
        const parsed = parseOutcome(entry);
        if (typeof parsed === 'string') return broken(entry, parsed);
        const intent = intents.get(parsed.relatedSeq);
        const key = intent?.keys[parsed.item];
        if (intent === undefined || key === undefined || intent.seen.has(parsed.item)) {
          return broken(entry, 'key outcome does not identify one item of its intent');
        }
        if (parsed.operationId !== intent.operationId || entry.actor !== intent.entry.actor || entry.action !== intent.operation) {
          return broken(entry, 'key outcome belongs to another operation');
        }
        if (parsed.secretId !== key.secretId || parsed.version !== key.version || parsed.subject !== key.subject) {
          return broken(entry, 'key outcome does not match its intended secret');
        }
        intent.seen.add(parsed.item);
        // Completed batches need no state, and another outcome for one is a duplicate.
        if (intent.seen.size === intent.keys.length) intents.delete(intent.entry.seq);
      }
    }
    next = batch[batch.length - 1].seq + 1n;
    if (batch.length < VERIFY_BATCH) break;
  }
  // Live calls can finish after this snapshot. Only a missed deadline is a fault.
  const overdue = [...intents.values()].filter((intent) => intent.expiresAt <= at).sort((a, b) => a.expiresAt - b.expiresAt);
  if (overdue.length === 0) return { ok: true, pending: intents.size };
  const reason = overdue.map((intent) => {
    const missing = intent.keys.length - intent.seen.size;
    return `key intent ${intent.operationId} is overdue: ${missing} of ${intent.keys.length} outcomes missing`;
  }).join('; ');
  return broken(overdue[0].entry, reason);
}

function parseIntent(entry: StoredEntry): ParsedIntent | string {
  const detail = payload(entry.metadata);
  if (detail === null) return 'key intent has no valid accounting payload';
  if (entry.operationId === null) return 'key intent has no operation identity';
  const { operation, expiresAt } = detail;
  if (typeof operation !== 'string' || !KEY_ACTIONS.has(operation)) return 'key intent has an invalid operation';
  if (typeof expiresAt !== 'number' || !Number.isSafeInteger(expiresAt) || expiresAt < entry.occurredAt) {
    return 'key intent has no valid deadline';
  }
  if (!Array.isArray(detail.keys)) return 'key intent has no valid item list';
  const keys: Item[] = [];
  for (const [index, value] of detail.keys.entries()) {
    const key = record(value);
    if (key === null || key.item !== index) return 'key intent items are not numbered in order';
    const { secretId, version, subject } = key;
    if (typeof secretId !== 'string' || typeof subject !== 'string') return 'key intent item has no secret identity';
    if (typeof version !== 'number' || !Number.isSafeInteger(version) || version < 1) return 'key intent item has no valid version';
    keys.push({ item: index, secretId, version, subject });
  }
  return { operationId: entry.operationId, operation, expiresAt, keys };
}

function parseOutcome(entry: StoredEntry): ParsedOutcome | string {
  if (entry.operationId === null || entry.relatedSeq === null) return 'key outcome has no intent identity';
  const detail = payload(entry.metadata);
  if (detail === null) return 'key outcome has no valid accounting payload';
  const { item, version, subject } = detail;
  if (typeof item !== 'number' || !Number.isSafeInteger(item) || item < 0) return 'key outcome has no valid item number';
  const secretId = entry.secretId ?? detail.secretId;
  if (typeof secretId !== 'string' || typeof subject !== 'string') return 'key outcome has no secret identity';
  if (typeof version !== 'number' || !Number.isSafeInteger(version) || version < 1) return 'key outcome has no valid version';
  return { operationId: entry.operationId, relatedSeq: entry.relatedSeq, item, secretId, version, subject };
}

function payload(text: string): Record<string, unknown> | null {
  try {
    return record(JSON.parse(text));
  } catch {
    return null;
  }
}

function record(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : null;
}
