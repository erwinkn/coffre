import type { StoredEntry } from '@coffre/core/audit';
import type { LogVerification } from '@coffre/core/vault';

const KEY_ACTIONS = new Set(['secret.read', 'key.wrap', 'key.rewrap']);

type Item = { item: number; secretId: string; version: number; subject: string };
type ParsedIntent = { intentId: string; operation: string; expiresAt: number; keys: Item[] };
/** An outcome entry: one item of its intent, or several, for a read logged once per place. */
type ParsedOutcome = { intentId: string; relatedSeq: bigint; items: Item[] };
type Intent = ParsedIntent & { seq: bigint; actor: string; seen: Set<number> };
type Accounting = { ok: true; pending: number } | Extract<LogVerification, { ok: false }>;
type Broken = Extract<Accounting, { ok: false }>;

/** A key batch still under way, as a checkpoint keeps it: its intent's entry, and the items whose outcomes are logged. */
export type OpenIntent = { seq: number; intentId: string; operation: string; expiresAt: number; actor: string; keys: Item[]; seen: number[] };

/** Where the accounting stands, as a checkpoint keeps it: the batches still open, and the first fault, once found. */
export type AccountingState = { intents: OpenIntent[]; fault: { failedAtSeq: number; reason: string } | null };

/**
 * Every key operation's intent and its outcomes, entry by entry, oldest
 * first, as a walk reads the vault's entries (`add`); then what is still
 * open (`result`). The chain can hold while a process died between an
 * intent and its outcomes: only a missed deadline is a fault.
 *
 * A walk resumes from a checkpoint's `state()`: the batches open there, and
 * nothing of those that closed. So an intent's identity is checked against
 * those still open and those since, not every one the log ever held: a
 * closed batch takes no more outcomes in any case, since each names its
 * intent's entry.
 */
export class KeyAccounting {
  readonly #intents = new Map<bigint, Intent>();
  readonly #ids = new Set<string>();
  #fault: Broken | null = null;

  constructor(from: AccountingState = { intents: [], fault: null }) {
    for (const { seq, seen, ...open } of from.intents) {
      this.#intents.set(BigInt(seq), { ...open, seq: BigInt(seq), seen: new Set(seen) });
      this.#ids.add(open.intentId);
    }
    this.#fault = from.fault === null ? null : { ok: false, ...from.fault };
  }

  /** Where it stands, to resume from: the batches open, oldest first. */
  state(): AccountingState {
    const intents = [...this.#intents.values()]
      .sort((a, b) => (a.seq < b.seq ? -1 : 1))
      .map(({ seq, seen, ...open }) => ({ ...open, seq: Number(seq), seen: [...seen].sort((a, b) => a - b) }));
    return { intents, fault: this.#fault === null ? null : { failedAtSeq: this.#fault.failedAtSeq!, reason: this.#fault.reason } };
  }

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
      if (parsed.keys.length > 0) this.#intents.set(entry.seq, { ...parsed, seq: entry.seq, actor: entry.actor, seen: new Set() });
    } else if (KEY_ACTIONS.has(entry.action) && entry.relatedSeq !== null) {
      // An outcome names its intent; a key released with no service to call has none.
      const parsed = parseOutcome(entry);
      if (typeof parsed === 'string') return broken(parsed);
      const intent = this.#intents.get(parsed.relatedSeq);
      for (const outcome of parsed.items) {
        const key = intent?.keys[outcome.item];
        if (intent === undefined || key === undefined || intent.seen.has(outcome.item)) {
          return broken('key outcome does not identify one item of its intent');
        }
        if (parsed.intentId !== intent.intentId || entry.actor !== intent.actor || entry.action !== intent.operation) {
          return broken('key outcome belongs to another operation');
        }
        if (outcome.secretId !== key.secretId || outcome.version !== key.version || outcome.subject !== key.subject) {
          return broken('key outcome does not match its intended secret');
        }
        intent.seen.add(outcome.item);
      }
      // Completed batches need no state, and another outcome for one is a duplicate.
      if (intent !== undefined && intent.seen.size === intent.keys.length) this.#intents.delete(intent.seq);
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
    return { ok: false, failedAtSeq: Number(overdue[0]!.seq), reason };
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
  const { intent } = detail;
  if (typeof intent !== 'string' || entry.relatedSeq === null) return 'key outcome has no intent identity';
  // Several secrets read at one place share one entry, each its item there.
  const many = detail.secrets;
  if (many !== undefined && (!Array.isArray(many) || many.length === 0)) return 'key outcome has no valid item list';
  const listed = many === undefined ? [{ ...detail, secretId: entry.secretId ?? detail.secretId }] : many.map(record);
  const items: Item[] = [];
  for (const one of listed) {
    if (one === null) return 'key outcome has no valid item list';
    const { item, secretId, version, subject } = one;
    if (typeof item !== 'number' || !Number.isSafeInteger(item) || item < 0) return 'key outcome has no valid item number';
    if (typeof secretId !== 'string' || typeof subject !== 'string') return 'key outcome has no secret identity';
    if (typeof version !== 'number' || !Number.isSafeInteger(version) || version < 1) return 'key outcome has no valid version';
    items.push({ item, secretId, version, subject });
  }
  return { intentId: intent, relatedSeq: entry.relatedSeq, items };
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
