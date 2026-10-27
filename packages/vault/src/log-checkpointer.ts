import { pairSigners } from '@coffre/core/merkle';

import { Checkpointer, logOrigin, type Alarm, type CheckpointStore, type Memory, type Witness } from './checkpointer.ts';
import { authentic, logMacKey } from './log-entry.ts';

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
      void Promise.resolve(options.record?.({ at: now(), message })).catch(() => {});
    },
  });
}

/** How often the checkpointer seals (R51, R54): a change waits at most about this long for a tick, and seals sooner if it asks. */
export const TICK_MS = 500;
