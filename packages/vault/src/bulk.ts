import { USE_DEADLINE_MS } from '@coffre/core/vault';

import type { BulkLimit } from './config.ts';

export { USE_DEADLINE_MS };

/**
 * The bulk cap of 0.15 (R28, R52, docs/design/sealed-inputs.md): at most
 * `count` distinct keys per principal in any rolling `windowMs`, both the
 * log's policy object, as the deployment configured it.
 *
 * One row per principal and key holds `last`, when the key was last
 * counted, as the start of that use's refresh period (`periodOf`). A key
 * is in the principal's set at `t` while `last > t − window − refresh`; a
 * key in it passes; a key not in it passes only if fewer than `count`
 * other keys count, and then enters (`last := periodOf(t)`). A key's row
 * moves on only once it is from an earlier period than the use's, so a hot
 * key writes its row once a minute rather than on every use; `last` lags
 * by less than `refresh`, which the set's bound adds back. Uses that move
 * one key on at once write the same period, or the greatest is kept: the
 * row ends where the replay's does whichever commits first, so they never
 * wait for one another (T127). Other keys count over a longer bound,
 * `window + refresh + deadline + ahead`: uses are decided in number order,
 * not by their time, so a key that entered at a later `at` may already be
 * in when an earlier use is decided (TLC's finding, HotPathOneClock), up
 * to the deadline after it, or the minute a Worker's clock may run ahead
 * before it (HotPathOneBulkSkew, W228).
 *
 * Every request counts, whatever else refuses it but the cap: the log keeps
 * requests, not outcomes, and the use's one statement writes the row before
 * the vault decides. A key stays in the set up to `refresh` past its window,
 * never less, and counts against a new key up to `refresh + deadline +
 * ahead` past it.
 */

/** How far past the database's clock a use may be stamped (`ahead` refuses past it): no use is decided earlier than this before its `at`. */
export const USE_AHEAD_MS = 60_000;

/** How stale a key's row may get before a use moves it on: a minute, or a tenth of a shorter window, at least 1 ms. */
export function refreshMs(limit: BulkLimit): number {
  return Math.max(1, Math.min(60_000, Math.floor(limit.windowMs / 10)));
}

/** The start of `at`'s refresh period: what a use that writes its key's row writes. */
export function periodOf(at: number, refresh: number): number {
  return at - (((at % refresh) + refresh) % refresh);
}

/** A principal's rows: each key's `last`, ms since the epoch. */
export type BulkRows = Map<string, number>;

/** What a use reads of the cap: whether its key is in the set, and how many other keys count (up to `count`, as far as it reads). */
export type BulkRead = { inSet: boolean; others: number };

/**
 * The cap's rule for a request for `key` at `at`: what it reads, and the
 * `last` it writes, or null for none. Live, the use's statement applies it
 * to the `bulk` table, under the principal's lock to write: exclusive for a
 * key that enters the set, shared for one moved on; replayed, `bulkStep`
 * to the replay's rows.
 */
export function bulkRule(rows: ReadonlyMap<string, number>, key: string, at: number, limit: BulkLimit): BulkRead & { write: number | null } {
  const refresh = refreshMs(limit);
  const last = rows.get(key);
  const inSet = last !== undefined && last > at - limit.windowMs - refresh;
  let others = 0;
  if (!inSet) {
    for (const [other, t] of rows) {
      if (others >= limit.count) break;
      if (other !== key && t > at - limit.windowMs - refresh - USE_DEADLINE_MS - USE_AHEAD_MS) others += 1;
    }
  }
  const admitted = inSet || others < limit.count;
  const period = periodOf(at, refresh);
  const stale = last === undefined || last < period;
  return { inSet, others, write: admitted && stale ? period : null };
}

/** The rule applied: the rows moved on, and what the request read. */
export function bulkStep(rows: BulkRows, key: string, at: number, limit: BulkLimit): BulkRead {
  const { write, ...read } = bulkRule(rows, key, at, limit);
  if (write !== null) rows.set(key, write);
  return read;
}

/** Whether the cap refuses what a request read: a key not in the set, with `count` others already counted. */
export function overCap(read: BulkRead, limit: BulkLimit): boolean {
  return !read.inSet && read.others >= limit.count;
}
