import type { StoredEntry } from '@coffre/core/audit';
import type { LogVerification } from '@coffre/core/vault';

const KEY_ACTIONS = new Set(['secret.read', 'key.wrap', 'key.rewrap']);

type Item = { item: number; secretId: string; version: number; subject: string };
type ParsedIntent = { intentId: string; operation: string; expiresAt: number; keys: Item[] };
type ParsedOutcome = Item & { intentId: string; relatedSeq: bigint };
type Intent = ParsedIntent & { entry: StoredEntry; seen: Set<number> };
type Accounting = { ok: true; pending: number } | Extract<LogVerification, { ok: false }>;

/**
 * Every key operation's intent and its outcomes, entry by entry, oldest
 * first, as the full check reads the vault's entries (`add`); then what is
 * still open (`result`). The chain can hold while a process died between an
 * intent and its outcomes: only a missed deadline is a fault.
 */
export class KeyAccounting {
  readonly #intents = new Map<bigint, Intent>();
  readonly #ids = new Set<string>();
  #fault: Extract<Accounting, { ok: false }> | null = null;

  add(entry: StoredEntry): void {
    if (this.#fault !== null || entry.author !== 'vault') return;
    const broken = (reason: string) => {
      this.#fault = { ok: false, failedAtSeq: Number(entry.seq), reason };
    };
    if (entry.action === 'key.intent') {
      const parsed = parseIntent(entry);
      if (typeof parsed === 'string') return broken(parsed);
      if (this.#ids.has(parsed.intentId)) return broken('key intent repeats an operation identity');
      this.#ids.add(parsed.intentId);
      if (parsed.keys.length > 0) this.#intents.set(entry.seq, { ...parsed, entry, seen: new Set() });
    } else if (KEY_ACTIONS.has(entry.action) && entry.relatedSeq !== null) {
      // An outcome names its intent; a key released with no service to call has none.
      const parsed = parseOutcome(entry);
      if (typeof parsed === 'string') return broken(parsed);
      const intent = this.#intents.get(parsed.relatedSeq);
      const key = intent?.keys[parsed.item];
      if (intent === undefined || key === undefined || intent.seen.has(parsed.item)) {
        return broken('key outcome does not identify one item of its intent');
      }
      if (parsed.intentId !== intent.intentId || entry.actor !== intent.entry.actor || entry.action !== intent.operation) {
        return broken('key outcome belongs to another operation');
      }
      if (parsed.secretId !== key.secretId || parsed.version !== key.version || parsed.subject !== key.subject) {
        return broken('key outcome does not match its intended secret');
      }
      intent.seen.add(parsed.item);
      // Completed batches need no state, and another outcome for one is a duplicate.
      if (intent.seen.size === intent.keys.length) this.#intents.delete(intent.entry.seq);
    }
  }

  /** The first fault, or the batches still under way at `at`: live calls can finish after the snapshot. */
  result(at: number): Accounting {
    if (this.#fault !== null) return this.#fault;
    const intents = [...this.#intents.values()];
    const overdue = intents.filter((intent) => intent.expiresAt <= at).sort((a, b) => a.expiresAt - b.expiresAt);
    if (overdue.length === 0) return { ok: true, pending: intents.length };
    const reason = overdue.map((intent) => {
      const missing = intent.keys.length - intent.seen.size;
      return `key intent ${intent.intentId} is overdue: ${missing} of ${intent.keys.length} outcomes missing`;
    }).join('; ');
    return { ok: false, failedAtSeq: Number(overdue[0]!.entry.seq), reason };
  }
}

function parseIntent(entry: StoredEntry): ParsedIntent | string {
  const detail = payload(entry.metadata);
  if (detail === null) return 'key intent has no valid accounting payload';
  const { intent, operation, expiresAt } = detail;
  if (typeof intent !== 'string') return 'key intent has no operation identity';
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
  return { intentId: intent, operation, expiresAt, keys };
}

function parseOutcome(entry: StoredEntry): ParsedOutcome | string {
  const detail = payload(entry.metadata);
  if (detail === null) return 'key outcome has no valid accounting payload';
  const { intent, item, version, subject } = detail;
  if (typeof intent !== 'string' || entry.relatedSeq === null) return 'key outcome has no intent identity';
  if (typeof item !== 'number' || !Number.isSafeInteger(item) || item < 0) return 'key outcome has no valid item number';
  const secretId = entry.secretId ?? detail.secretId;
  if (typeof secretId !== 'string' || typeof subject !== 'string') return 'key outcome has no secret identity';
  if (typeof version !== 'number' || !Number.isSafeInteger(version) || version < 1) return 'key outcome has no valid version';
  return { intentId: intent, relatedSeq: entry.relatedSeq, item, secretId, version, subject };
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
