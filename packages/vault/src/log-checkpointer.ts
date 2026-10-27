import { pairSigners } from '@coffre/core/merkle';

import { Checkpointer, logOrigin, type Alarm, type CheckpointStore, type Memory, type Witness } from './checkpointer.ts';
import { authentic, logMacKey } from './log-entry.ts';
import type { LogStore } from './log-store.ts';
import { DAY_MS, dayOf, retain } from './retention.ts';

/**
 * The checkpointer as a host runs it, on Node (`runCheckpointer`) or in its
 * Durable Object (`CheckpointerObject`): the trees' keys and the MAC key
 * from the vault's signing seed, the log's origin from that key, and every
 * alarm handed to `record` as well as returned by `alarms`, where whoever
 * watches the log reads them (R40's plugin): refused ticks, changes answered
 * unwitnessed (R51), a memory found behind the database.
 */
export type HostOptions = {
  store: CheckpointStore;
  /** The vault's signing seed: the first of `signingKeys`. */
  seed: Uint8Array;
  memory: Memory;
  witnesses?: readonly Witness[];
  /** Where each alarm is kept; it is also logged. */
  record?: (alarm: Alarm) => void | Promise<void>;
  now?: () => number;
};

export async function openLogCheckpointer(options: HostOptions): Promise<Checkpointer> {
  const signers = await pairSigners(await logOrigin(options.seed), options.seed);
  const now = options.now ?? Date.now;
  return Checkpointer.open(options.store, signers, {
    memory: options.memory,
    witnesses: options.witnesses,
    authentic: authentic(logMacKey(options.seed)),
    now,
    alert: (message) => {
      console.warn(`coffre audit: ${message}`);
      void Promise.resolve(options.record?.({ at: now(), message })).catch((error: Error) => console.warn(`coffre audit: the alarm could not be kept: ${error.message}`));
    },
  });
}

/** How often the checkpointer seals (R51, R54): a change waits at most about this long for a tick, and seals sooner if it asks. */
export const TICK_MS = 500;

/** An error as an alarm says it: the database's own reason, when a query wrapped it, rather than the query's text. */
export function reasonOf(error: unknown): string {
  const e = error as Error & { cause?: unknown };
  return e?.cause instanceof Error ? e.cause.message : (e?.message ?? String(error));
}

/** Days of uses made ahead of today's (and yesterday's, for a new database): uses stamped in a day with no partition fail. */
export const DAYS_AHEAD = 3;
/** How often retention runs: hourly, so that a day goes within the hour it is due, and a run that waits tries again. */
export const RETAIN_EVERY_MS = 3_600_000;
/** How often the bulk cap's old rows are pruned, at most `PRUNED` a time (R52's window, in `prune_bulk`). */
export const PRUNE_EVERY_MS = 60_000;
const PRUNED = 10_000;

/**
 * What a host runs after each tick (plan PR 7): the next days' partitions
 * made once a day, retention once an hour when `keepDays` is set, the bulk
 * cap's old rows pruned once a minute. A failure is an alarm, said once while
 * it stands; retention waiting for the log to move on is none.
 */
export function upkeep(cp: Checkpointer, store: LogStore, options: { keepDays: number | null; seed: Uint8Array; now?: () => number; alert: (message: string) => void }): () => Promise<void> {
  const now = options.now ?? Date.now;
  const macKey = logMacKey(options.seed);
  let madeFor: string | null = null;
  let retained = -Infinity;
  let pruned = -Infinity;
  let failed: string | null = null;
  return async () => {
    const t = now();
    try {
      if (madeFor !== dayOf(t)) {
        await store.makeDays(Array.from({ length: DAYS_AHEAD + 2 }, (_, i) => dayOf(t + (i - 1) * DAY_MS)));
        madeFor = dayOf(t);
      }
      if (t - pruned >= PRUNE_EVERY_MS) {
        pruned = t;
        await store.pruneBulk(PRUNED);
      }
      if (options.keepDays !== null && t - retained >= RETAIN_EVERY_MS) {
        retained = t;
        await retain(cp, store, { keepDays: options.keepDays, macKey, now });
      }
      failed = null;
    } catch (error) {
      const message = `the log's upkeep failed: ${reasonOf(error)}`;
      if (message !== failed) options.alert(message);
      failed = message;
    }
  };
}
