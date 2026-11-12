import { entryHash, type StoredEntry } from '@coffre/core/audit';
import type { LogEntry, PairNotes } from '@coffre/core/merkle';
import { USES_IN_FLIGHT } from '@coffre/core/memory';
import { VOUCHED_AT_ONCE, type AuditCursorRow, type AuditEventRow, type CheckInput, type CheckState } from '@coffre/core/vault';
import type { Database } from '@coffre/db';

import { cursorVouched, eventColumns, eventVouched, type AuditCursor, type AuditEvent, type SignedCursor } from './audit-rows.ts';
import { keyringOf, type Keyring, type VerifierKeys, entryVouched, openUnder } from './keyring.ts';
import { changeEvent, readEvent } from './projection.ts';
import { derive, newestHeld, rangeAt, sealedCut, sealedRange, type ReadsStore } from './reads.ts';
import { UPGRADE_REQUESTS, type AnchorPayload } from './upgrade.ts';
import { checkTrees } from './verifier.ts';

// The audit's two checks. `checkAudit`, the page's and the beat's: flat, the newest checkpoint and what lies above it,
// whatever the log holds. `checkListed`, `coffre verify log`'s: the audit projection's listing held to the sealed log,
// one checkpoint's range a request.

/**
 * The most entries `check` reads above the newest signed checkpoint (`Vault.check` in @coffre/core/vault): past it, the checkpointer is late, and the check says `late` rather than read on. It is
 * `USES_IN_FLIGHT`, the uses an isolate holds in flight at once: the checkpointer seals every
 * `TICK_MS`, so a live log holds a handful above its newest checkpoint, and 1,250 is far past that while one page's
 * read of them stays one round trip. Nobody sets it.
 */
export const CHECK_TAIL_ENTRIES = USES_IN_FLIGHT;

/**
 * The audit page's check, flat (0.16, T277; D200; state-rows.md, sections 3 and 4): what the vault's `check` answers,
 * and `behind`, whether the database ended below a pair held outside, which the vault asks again a tick later (the
 * signer remembers a pair a moment before its row lands), as `verifyTrees` does.
 *
 * One statement (`checkRead`): the newest checkpoint, the entries of both chains above it, at most
 * `CHECK_TAIL_ENTRIES`, the rotations, the frozen log's anchor and its last entry. Then CPU alone: the pair's
 * signatures and the pairs held outside (`verifyLog`), each entry above it by its MAC and request, the rows the page
 * shows and its cursor by their MACs (audit-rows.ts, P1's), and the frozen log's last entry against the anchor. It
 * writes nothing. Its cost is the rows handed in and what lies above the newest checkpoint, whatever the log holds.
 *
 * Retention's floor is not read: below the newest checkpoint nothing is walked, and the cursor's `reads_from`, which
 * no MAC covers, is never taken (`FloorSealed`, formal/Reads.tla). The full walk (`coffre verify log`) takes it from the
 * sealed retention change.
 *
 * What it catches, for a database writer with no key (section 4): an entry above the checkpoint forged or altered (its
 * MAC), a checkpoint deleted or an older one served (`behind`: below the pair held outside), a row shown altered (its
 * MAC: `forged`), the cursor put back (`listedThrough` falls behind `checkpoint`; altered, its MAC), the frozen log cut
 * or extended (its last entry is not the anchor's). What it leaves to the recheck: an entry altered or deleted inside a
 * signed range, a projection row deleted.
 */
export type Checked = {
  state: CheckState;
  reason: string | null;
  checkpoint: { number: string; at: number } | null;
  listedThrough: { number: string; at: number };
  forged: number[];
  behind: boolean;
};

export type CheckOptions = {
  /** Pairs held outside the database, the signer's memory and a witness's (`VaultOptions.heldOutside`). */
  anchors: readonly PairNotes[];
  /**
   * Whether the vault's upgrade step has written the anchor (V1, T279; upgrade.ts): from then on the frozen log answers
   * to it, and a check that finds no anchor says `broken`. Before, the log has none, and `audit_log` still grows.
   */
  upgraded: boolean;
};

export async function checkAudit(db: Database, keys: VerifierKeys, input: CheckInput, options: CheckOptions): Promise<Checked> {
  const events: unknown = (input as { events?: unknown } | undefined)?.events;
  if (!Array.isArray(events) || events.length > VOUCHED_AT_ONCE) throw new Error(`check takes up to ${VOUCHED_AT_ONCE} rows`);
  const shown = events.map((row: unknown) => eventOf(row));
  const cursor = cursorOf((input as { cursor?: unknown }).cursor);

  const { walked, read, ring } = await checkTrees(db, keys, { anchors: options.anchors, above: CHECK_TAIL_ENTRIES });
  const forged = shown.flatMap((row, i) => (row === null || !eventVouched(ring, row) ? [i] : []));
  // The newest checkpoint, as its signatures open it: the walk's own when it found nothing wrong, else the row's, which
  // the beat's finding is named for (`findingEventId`).
  const opened = walked.checkpoint !== null ? walked.checkpoint : read.newest === null ? null : (await openUnder(ring, read.newest.notes))?.pair ?? null;
  const checkpoint = opened === null || BigInt(opened.upto) === 0n ? null : { number: String(opened.upto), at: opened.at };

  const broken: string[] = walked.problems.filter((p) => !walked.behind || !/^the database ends up to /.test(p));
  if (forged.length > 0) broken.push(`${forged.length} of the rows shown: not the projector's (their MAC does not hold)`);
  if (cursor === null || !cursorVouched(ring, cursor)) broken.push("the audit cursor is not the projector's (its MAC does not hold)");
  const frozen = frozenLog(read.anchor, read.last, ring, options.upgraded);
  if (frozen !== null) broken.push(frozen);
  const behind = walked.behind ? ['the database ends below the checkpoint its signer holds: checkpoints were deleted, or an older one is served'] : [];
  // The projector lists only what a checkpoint signed: a cursor past the newest one is a database rolled back below it.
  if (cursor !== null && checkpoint !== null && cursor.through > BigInt(checkpoint.number)) behind.push(`the projection lists through ${cursor.through}, past the newest checkpoint (${checkpoint.number})`);
  const [state, reasons]: [CheckState, string[]] = broken.length > 0 ? ['broken', broken] : behind.length > 0 ? ['behind', behind] : walked.capped ? ['late', [`more than ${CHECK_TAIL_ENTRIES} entries above the newest checkpoint: the checkpointer is late`]] : ['ok', []];
  const given = input.cursor as Partial<AuditCursorRow> | undefined;
  return {
    state,
    reason: reasons.length === 0 ? null : reasons.join('; '),
    checkpoint,
    listedThrough: cursor !== null ? { number: String(cursor.through), at: cursor.at } : { number: String(given?.through ?? '0'), at: Number(given?.at ?? 0) },
    forged,
    behind: walked.behind,
  };
}

/**
 * Why the frozen log is not what the upgrade anchored, or null when it is (state-rows.md, section 6): its last entry
 * is the anchor's, by seq and by its hash computed again from its columns, so a row altered keeps no stored hash that
 * passes. The anchor is the vault's change (its MAC, its request id). Before the upgrade there is no anchor, and the
 * log is not frozen yet: nothing to hold.
 */
export function frozenLog(anchor: LogEntry | null, last: StoredEntry | null, ring: Keyring, upgraded: boolean): string | null {
  if (anchor === null) return upgraded ? 'the frozen log has no anchor: the upgrade wrote one' : null;
  if (entryVouched(ring, anchor) !== 'held') return "the frozen log's anchor is not the vault's (its MAC does not hold)";
  // [at, request, object, actor, payload, seal, mac]
  const [request, payload] = [anchor.columns[1], anchor.columns[4]];
  const named = request === UPGRADE_REQUESTS.anchor && typeof payload === 'string' ? anchorOf(payload) : null;
  if (named === null) return `change ${anchor.number}: no anchor the upgrade writes`;
  if (last === null) return `the frozen log is empty; its anchor names seq ${named.seq}: it was cut`;
  if (last.seq !== named.seq) return `the frozen log ends at seq ${last.seq}; its anchor names ${named.seq}: it was ${last.seq < named.seq ? 'cut' : 'extended'}`;
  let hash: Buffer | null = null;
  try {
    hash = entryHash(last.prevHash, last, last.mac);
  } catch {}
  return hash !== null && hash.equals(named.hash) ? null : `the frozen log's last entry (seq ${last.seq}) is not the one its anchor names: it was altered`;
}

function anchorOf(payload: string): { seq: bigint; hash: Buffer } | null {
  try {
    const p = JSON.parse(payload) as Partial<AnchorPayload>;
    const seq = p.anchor?.seq;
    const hash = p.anchor?.hash;
    if (p.op !== 'upgrade.anchor' || typeof seq !== 'string' || !/^[0-9]{1,19}$/.test(seq) || typeof hash !== 'string' || !/^[0-9a-f]{64}$/.test(hash)) return null;
    return { seq: BigInt(seq), hash: Buffer.from(hash, 'hex') };
  } catch {
    return null;
  }
}

const DECIMAL = /^[0-9]{1,19}$/;
const nullable = (v: unknown): v is string | null => v === null || typeof v === 'string';

/** Bytes from base64, only if it is the canonical text of exactly `length` bytes: no padding games, no other alphabet. */
function base64(text: unknown, length: number): Buffer | null {
  if (typeof text !== 'string') return null;
  const bytes = Buffer.from(text, 'base64');
  return bytes.length === length && bytes.toString('base64') === text ? bytes : null;
}

/** A row the page handed in, as P1's `AuditEvent`; null for one no projector writes, which is then `forged`. */
function eventOf(raw: unknown): AuditEvent | null {
  if (typeof raw !== 'object' || raw === null) return null;
  const r = raw as Partial<Record<keyof AuditEventRow, unknown>>;
  const mac = base64(r.mac, 16);
  if (
    mac === null || !Number.isSafeInteger(r.at) || typeof r.number !== 'string' || !DECIMAL.test(r.number) || (r.log !== 14 && r.log !== 15 && r.log !== 16)
    || (r.author !== 'app' && r.author !== 'vault') || typeof r.action !== 'string' || typeof r.shown !== 'boolean' || typeof r.allowed !== 'boolean'
    || typeof r.actor !== 'string' || typeof r.detail !== 'string' || !Array.isArray(r.places) || !r.places.every((p) => typeof p === 'string')
    || !(r.related === null || (typeof r.related === 'string' && DECIMAL.test(r.related)))
    || ![r.code, r.subject, r.credential, r.project, r.environment, r.secret, r.version, r.requestId, r.operationId, r.sourceIp].every(nullable)
  ) return null;
  return {
    at: r.at as number, number: BigInt(r.number), log: r.log, author: r.author, action: r.action, shown: r.shown, allowed: r.allowed,
    code: r.code as string | null, actor: r.actor, subject: r.subject as string | null, credential: r.credential as string | null,
    project: r.project as string | null, environment: r.environment as string | null, secret: r.secret as string | null, version: r.version as string | null,
    places: r.places as string[], requestId: r.requestId as string | null, operationId: r.operationId as string | null,
    related: r.related === null ? null : BigInt(r.related as string), sourceIp: r.sourceIp as string | null, detail: r.detail, mac,
  };
}

/**
 * The cursor the page handed in, as P1's signed cursor; null for one the projector never writes. Only the five columns
 * its MAC covers: P1's interim `old_floor` and `old_top`, and retention's `reads_from`, carry none, and nothing here
 * reads them.
 */
function cursorOf(raw: unknown): SignedCursor | null {
  if (typeof raw !== 'object' || raw === null) return null;
  const r = raw as Partial<Record<keyof AuditCursorRow, unknown>>;
  const decimal = (v: unknown) => (typeof v === 'string' && DECIMAL.test(v) ? BigInt(v) : null);
  const [through, pair, oldFrom] = [decimal(r.through), decimal(r.pair), decimal(r.oldFrom)];
  const oldHash = typeof r.oldHash === 'string' && /^[0-9a-f]{64}$/.test(r.oldHash) ? Buffer.from(r.oldHash, 'hex') : null;
  const mac = r.mac === null ? null : base64(r.mac, 16);
  if (through === null || pair === null || oldFrom === null || oldHash === null || !Number.isSafeInteger(r.at) || (r.mac !== null && mac === null)) return null;
  return { through, pair, at: r.at as number, oldFrom, oldHash, mac };
}

// The audit projection's listing of the chains held to the sealed log: `coffre verify log`'s check, a
// checkpoint's range a request, never a page's. Each range is read whole and held to the trees (`sealedRange`), its
// uses and changes derived again as the projector derives them (`readEvent`, `changeEvent`), and each held to the row
// the projection lists for it, as far as the projector has gone: the range it stands in too, to its cursor. A row
// deleted, edited, renumbered, listed twice or off one of its places' pages, each is named. 0.14's chain is not held
// to its rows yet, the entries the app still appends to it included: a row of one of them, edited, shows `forged` on
// its page, but one deleted leaves every page unnoticed, while `audit_log`'s own check still passes.

/** What the check needs of the database (log-store.ts). */
export type CheckStore = ReadsStore & {
  auditCursor(): Promise<AuditCursor>;
  /**
   * The projection's rows of the chains numbered in `(after, upto]` at times in `[from, to]`, each with whether each of
   * its `places` has its row in `audit_event_places`, which the pages of that place read (`placed`).
   */
  listed(stretch: { after: bigint; upto: bigint; from: number; to: number }): Promise<(AuditEvent & { placed: boolean })[]>;
};

/** The most problems a stretch names; more are counted. */
const PROBLEMS_NAMED = 20;

/**
 * A stretch of the check, from the pair at `from`: the range that pair starts, or the retention cut's when it is past
 * `from`. Flat: a stretch reads one range however long the log. The check starts at retention's cut: below it only the
 * next day's stragglers are left, a few seconds of uses at each midnight, whose rows go unchecked until their day goes
 * (a known limit).
 */
export async function checkListed(store: CheckStore, keys: VerifierKeys, from: bigint): Promise<{ problems: string[]; through: bigint; listed: bigint; next: bigint | null }> {
  let cursor: AuditCursor;
  try {
    cursor = await store.auditCursor();
  } catch (error) {
    return { problems: [(error as Error).message], through: from, listed: 0n, next: null };
  }
  const stop = (problem: string) => ({ problems: [problem], through: from, listed: cursor.through, next: null });
  const ring = await keyringOf(keys, store);
  if (!cursorVouched(ring, cursor)) return stop(`the audit cursor, at ${cursor.through}, is not the vault's: it was moved around the projector`);
  const head = await newestHeld(store, ring, cursor);
  if (typeof head === 'string') return stop(head);
  if (head === null) return { problems: [], through: from, listed: cursor.through, next: null };
  let cut;
  try {
    cut = await sealedCut(store, head);
  } catch (error) {
    return stop((error as Error).message);
  }
  const at = cut !== null && cut.upto > from ? cut.upto : from;
  // The range the projector stands in is held as far as it has gone; past it, none.
  const last = at >= cursor.pair;
  if (last && (await store.pairs(cursor.pair, 1)).length === 0) return { problems: [], through: cursor.through, listed: cursor.through, next: null };
  let range;
  try {
    range = await rangeAt(store, ring, last ? cursor.pair : at);
    range = { ...range, entries: await sealedRange(store, ring, range.start, range.next) };
  } catch (error) {
    return stop(last ? `the projection is stopped at ${cursor.through}: ${(error as Error).message}` : (error as Error).message);
  }
  const { pair, entries, start } = range;
  const upto = last ? cursor.through : pair.upto;
  let problems: string[];
  try {
    problems = await listedAsSealed(store, ring, entries.filter((entry) => entry.number <= upto), { after: start?.upto ?? 0n, upto });
  } catch (error) {
    // A change a use is read from that does not hold: what stops the projector stops the check too, said.
    return stop((error as Error).message);
  }
  const named = problems.length <= PROBLEMS_NAMED ? problems : [...problems.slice(0, PROBLEMS_NAMED), `and ${problems.length - PROBLEMS_NAMED} more`];
  return { problems: named, through: upto, listed: cursor.through, next: last ? null : pair.upto };
}

/** What a range's entries, derived again, find wrong in the listing between `after` and `upto`. */
async function listedAsSealed(store: CheckStore, ring: Keyring, entries: readonly LogEntry[], range: { after: bigint; upto: bigint }): Promise<string[]> {
  const reads = await derive(store, ring, entries.filter((entry) => entry.tree === 'uses'));
  const derived = [
    ...reads.map(readEvent),
    ...entries.flatMap((entry) => (entry.tree === 'changes' ? [changeEvent(entry)].filter((row) => row !== null) : [])),
  ];
  if (derived.length === 0) return [];
  const problems: string[] = [];
  const named = (row: { log: number; number: bigint }) => `${row.log === 16 ? 'read' : 'change'} ${row.number}`;
  // The rows of the range's own times, by the primary key's range: after a stall a pair's floor lies far below its
  // entries, and the times between hold every later pair's too. A row planted at another time is no page's
  // either but as forged, by its MAC. A loop, not spread arguments: a range after an outage holds more entries than a
  // call takes arguments.
  let [from, to] = [Number.MAX_SAFE_INTEGER, 0];
  for (const row of derived) [from, to] = [Math.min(from, row.at), Math.max(to, row.at)];
  const listing = await store.listed({ after: range.after, upto: range.upto, from, to });
  const listed = new Map<string, AuditEvent & { placed: boolean }>();
  for (const row of listing) {
    const key = `${row.log}:${row.number}`;
    if (listed.has(key)) problems.push(`${named(row)} is listed twice`);
    listed.set(key, row);
  }
  for (const row of derived) {
    const key = `${row.log}:${row.number}`;
    const found = listed.get(key);
    listed.delete(key);
    if (found === undefined) problems.push(`${named(row)} is sealed but not listed`);
    // The same row, under a key that vouches at its number: one listed before a rotation keeps the replaced key's MAC.
    else if (!eventVouched(ring, found) || eventColumns(found) !== eventColumns(row)) problems.push(`${named(row)} is listed otherwise than the log sealed it`);
    // A place's row of it gone, that place's pages would leave it out unseen.
    else if (!found.placed) problems.push(`${named(row)} is off a place's pages: one of its places does not list it`);
  }
  for (const row of listed.values()) problems.push(`${named(row)} is listed, but the log seals no such entry`);
  return problems;
}
