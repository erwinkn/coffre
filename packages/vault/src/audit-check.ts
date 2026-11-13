import { USES_IN_FLIGHT } from '@coffre/core/memory';
import type { LogEntry } from '@coffre/core/merkle';

import { cursorVouched, eventColumns, eventVouched, type AuditCursor, type AuditEvent } from './audit-rows.ts';
import { keyringOf, type Keyring, type VerifierKeys } from './keyring.ts';
import { changeEvent, readEvent } from './projection.ts';
import { derive, newestHeld, rangeAt, sealedCut, sealedRange, type ReadsStore } from './reads.ts';

// The audit projection's listing of the chains held to the sealed log: `coffre verify log`'s check, a
// checkpoint's range a request, never a page's. Each range is read whole and held to the trees (`sealedRange`), its
// uses and changes derived again as the projector derives them (`readEvent`, `changeEvent`), and each held to the row
// the projection lists for it, as far as the projector has gone: the range it stands in too, to its cursor. A row
// deleted, edited, renumbered, listed twice or off one of its places' pages, each is named. 0.14's chain is not held
// to its rows yet, the entries the app still appends to it included: a row of one of them, edited, shows `forged` on
// its page, but one deleted leaves every page unnoticed, while `audit_log`'s own check still passes.

/**
 * The most entries `check` reads above the newest signed checkpoint (`Vault.check` in @coffre/core/vault): past it, the checkpointer is late, and the check says `late` rather than read on. It is
 * `USES_IN_FLIGHT`, the uses an isolate holds in flight at once: the checkpointer seals every
 * `TICK_MS`, so a live log holds a handful above its newest checkpoint, and 1,250 is far past that while one page's
 * read of them stays one round trip. Nobody sets it.
 */
export const CHECK_TAIL_ENTRIES = USES_IN_FLIGHT;

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
