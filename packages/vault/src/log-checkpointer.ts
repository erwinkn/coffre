import { randomUUID } from 'node:crypto';

import { pairSigners, pairVerifiers, type PairSigners, type PairVerifiers } from '@coffre/core/merkle';
import type { Database } from '@coffre/db';
import { migrated } from '@coffre/db/schema-version';

import { verifierKeys, type VerifierKeys } from './keyring.ts';
import { Checkpointer, FenceClosed, logOrigin, type Alarm, type CheckpointStore, type Fence, type Memory, type Witness } from './checkpointer.ts';
import { authentic, entryMac, KEY_OBJECT, logMacKey, rotationOf, rotationPayload, type LogMacKey } from './log-entry.ts';
import type { LogStore } from './log-store.ts';
import { DAY_MS, dayOf, retain } from './retention.ts';

/** One signing seed's keys of the log: its origin, the trees' signers and verifiers under it, and the entries' MAC key. */
export type LogKey = { origin: string; signers: PairSigners; verifiers: PairVerifiers; mac: LogMacKey };

export async function logKey(seed: Uint8Array): Promise<LogKey> {
  const origin = await logOrigin(seed);
  const signers = await pairSigners(origin, seed);
  return { origin, signers, verifiers: await pairVerifiers({ changes: signers.changes.verifierKey, uses: signers.uses.verifierKey }), mac: logMacKey(seed) };
}

/**
 * The vault's keys of the log, from its signing keys (`signingKeys`, the one
 * it signs with first): no two may share a MAC tag, which is how the
 * database tells a replaced key's entries from the current one's.
 */
export async function logKeys(seeds: readonly Uint8Array[]): Promise<{ current: LogKey; previous: LogKey[] }> {
  const [current, ...previous] = await Promise.all(seeds.map((seed) => logKey(seed)));
  if (current === undefined) throw new Error('the vault has no signing key');
  const clash = previous.find((key) => key.mac.tag.equals(current.mac.tag));
  if (clash !== undefined) throw new Error(`the signing key's log tag is that of a key it replaced (${clash.origin}): make another signing key`);
  const twins = previous.findIndex((key, i) => previous.slice(i + 1).some((other) => other.mac.tag.equals(key.mac.tag)));
  if (twins !== -1) throw new Error(`two keys the signing key replaced share a log tag (${previous[twins]!.origin}): the database could not tell their entries apart`);
  return { current, previous };
}

/**
 * The checkpointer as a host runs it, on Node (`runCheckpointer`) or in its
 * Durable Object (`CheckpointerObject`): the trees' keys and the MAC key
 * from each of the vault's signing keys, the log's origin from each, the log
 * moved on to the first when it is under another, and every alarm
 * handed to `record` as well as returned by `alarms`, where whoever watches
 * the log reads them: refused ticks, changes answered
 * unwitnessed, a memory found behind the database.
 */
export type HostOptions = {
  store: LogStore;
  /** The vault's signing keys (`ResolvedVaultConfig.signingKeys`): the one it signs with, then those it replaced. */
  signingKeys: readonly Uint8Array[];
  memory: Memory;
  witnesses?: readonly Witness[];
  /** Where each alarm is kept; it is also logged. */
  record?: (alarm: Alarm) => void | Promise<void>;
  now?: () => number;
  /** What closes it for good, when its host bounds the open; `TICK_BOUND_MS` otherwise, for the tests. */
  fence?: Fence;
  tickBoundMs?: number;
  /** The most entries a tick seals in one pair (`WINDOW_MAX` otherwise): a backlog is sealed a part at a time, for the tests. */
  windowMax?: number;
  /** How far behind its pair an entry's time may be (`FRESH_MS` otherwise), and retention's freshness bound: for the tests. */
  freshMs?: number;
};

export async function openLogCheckpointer(options: HostOptions): Promise<Checkpointer> {
  const { current, previous } = await logKeys(options.signingKeys);
  const now = options.now ?? Date.now;
  const store = options.store;
  return Checkpointer.open(store, current.signers, {
    memory: options.memory,
    witnesses: options.witnesses,
    authentic: authentic(current.mac),
    previous: previous.map((key) => ({ origin: key.origin, verifiers: key.verifiers, authentic: authentic(key.mac) })),
    rotations: {
      read: () => store.rotations(),
      of: rotationOf,
      async write(from) {
        const retired = previous.find((key) => key.origin === from);
        if (retired === undefined) throw new Error(`the log is under ${from}, a key the vault does not hold`);
        const [at, requestId] = [now(), randomUUID()];
        return store.rotate((number) => {
          // Its payload names its number, under its MAC (NumberInRotation).
          const row = { at, requestId, object: KEY_OBJECT, actor: 'system:vault', payload: rotationPayload(from, current.origin, number), seal: null };
          return { ...row, mac: entryMac(current.mac, { tree: 'changes', row }) };
        }, retired.mac.tag);
      },
    },
    now,
    ...(options.fence === undefined ? {} : { fence: options.fence }),
    ...(options.tickBoundMs === undefined ? {} : { tickBoundMs: options.tickBoundMs }),
    ...(options.windowMax === undefined ? {} : { windowMax: options.windowMax }),
    ...(options.freshMs === undefined ? {} : { freshMs: options.freshMs }),
    alert: (message) => {
      console.warn(`coffre audit: ${message}`);
      void Promise.resolve(options.record?.({ at: now(), message })).catch((error: Error) => console.warn(`coffre audit: the alarm could not be kept: ${error.message}`));
    },
  });
}

/** How often the checkpointer seals: a change waits at most about this long for a tick, and seals sooner if it asks. */
export const TICK_MS = 500;

/** An error as an alarm says it: the database's own reason, when a query wrapped it, rather than the query's text. */
export function reasonOf(error: unknown): string {
  const e = error as Error & { cause?: unknown };
  return e?.cause instanceof Error ? e.cause.message : (e?.message ?? String(error));
}

/**
 * Throws below this release's migrations, as before its `coffre migrate`: what the checkpointer seals, the days it
 * makes and the tables its projector fills are not yet this release's there, so on either platform it opens over
 * nothing, makes nothing and projects nothing until they are.
 */
export async function requireMigrated(db: Database): Promise<void> {
  if (!(await migrated(db))) throw new Error("the database is below this release's migrations: run coffre migrate");
}

/** Days of uses made ahead of today's (and yesterday's, for a new database): uses stamped in a day with no partition fail. */
export const DAYS_AHEAD = 3;
/** How often retention runs: hourly, so that a day goes within the hour it is due, and a run that waits tries again. */
export const RETAIN_EVERY_MS = 3_600_000;
/** How often the bulk cap's old rows are pruned, at most `PRUNED` a time (past the policy's bulk window, in `prune_bulk`). */
export const PRUNE_EVERY_MS = 60_000;
const PRUNED = 10_000;

/** How long retention may wait on one lock (a reader holding the uses, say) before that is an alarm. */
export const WAITING_ALARM_MS = DAY_MS;

/** The days of uses a host makes ahead at `t`: yesterday's (a new database), today's, and `DAYS_AHEAD` more. */
export const daysAround = (t: number) => Array.from({ length: DAYS_AHEAD + 2 }, (_, i) => dayOf(t + (i - 1) * DAY_MS));

/**
 * What a host runs after each tick: the next days' partitions
 * made once a day, retention once an hour when `keepDays` is set, the bulk
 * cap's old rows pruned once a minute. A failure is an alarm, said once while
 * it stands; retention waiting is none, but for a lock: one that has kept a
 * day waiting longer than `WAITING_ALARM_MS`. A quiet log, whose pairs do not
 * pass a day's end until something is logged, waits with no alarm.
 */
export function upkeep(cp: Checkpointer, store: LogStore, options: { keepDays: number | null; signingKeys: readonly Uint8Array[]; now?: () => number; alert: (message: string) => void }): () => Promise<void> {
  const now = options.now ?? Date.now;
  // The vault's log keys, the current first, those it replaced after (retention's cut and cursor: keyring.ts). Derived
  // once, on the first run that retains, and kept: settled values only.
  let keys: VerifierKeys | null = null;
  let madeFor: string | null = null;
  let retained = -Infinity;
  let pruned = -Infinity;
  let failed: string | null = null;
  // The day retention waits on, and since when.
  let waiting: { day: string; since: number } | null = null;
  return async () => {
    const t = now();
    try {
      if (madeFor !== dayOf(t)) {
        await store.makeDays(daysAround(t));
        madeFor = dayOf(t);
      }
      if (t - pruned >= PRUNE_EVERY_MS) {
        pruned = t;
        await store.pruneBulk(PRUNED);
      }
      if (options.keepDays !== null && t - retained >= RETAIN_EVERY_MS) {
        retained = t;
        keys ??= await verifierKeys(options.signingKeys);
        const run = await retain(cp, store, { keepDays: options.keepDays, keys, now });
        const day = run.waiting?.lock ? (run.waiting.day ?? 'the tiles') : null;
        if (day === null) waiting = null;
        else if (waiting?.day !== day) waiting = { day, since: t };
        else if (t - waiting.since >= WAITING_ALARM_MS) throw new Error(`retention has waited on ${day} since ${new Date(waiting.since).toISOString()}: ${run.waiting!.reason}`);
      }
      failed = null;
    } catch (error) {
      // Its checkpointer closed under it, given up on or replaced: the next one's upkeep does the work, and this is no
      // alarm.
      if (error instanceof FenceClosed || (error as { cause?: unknown })?.cause instanceof FenceClosed) return;
      const message = `the log's upkeep failed: ${reasonOf(error)}`;
      if (message !== failed) options.alert(message);
      failed = message;
    }
  };
}
