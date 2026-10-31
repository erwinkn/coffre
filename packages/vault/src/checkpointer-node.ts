import { appendFile, open, readFile, rename, stat, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';

import type { PairNotes } from '@coffre/core/merkle';
import type { Sealing } from '@coffre/core/vault';
import type { Database } from '@coffre/db';

import { Fence, heldIn, sealingOf, Stalled, TICK_BOUND_MS, Unsealed, within, type Alarm, type Checkpointer, type Memory, type SealThrough, type Witness } from './checkpointer.ts';
import { daysAround, openLogCheckpointer, reasonOf, TICK_MS, upkeep } from './log-checkpointer.ts';
import { Projector } from './reads.ts';
import { verifierKeys } from './verifier.ts';
import { logStore } from './log-store.ts';

/**
 * The 0.15 checkpointer on Node (docs/design/audit-tree.md): one process
 * seals the log every 500 ms, its memory a file beside the vault, synced
 * before the database has the pair it holds (RememberFirst). The vault's
 * process runs it (`keepCheckpointer`, node.ts). Nothing it awaits is
 * unbounded (T169): a tick past its bound stalls the checkpointer, and the
 * vault's process opens another.
 */

/** The signer's memory in a file: written whole, synced, renamed over the last, and the directory synced, so a power loss keeps it. */
export function fileMemory(path: string): Memory {
  return {
    last: () => readFile(path, 'utf8').catch((error: NodeJS.ErrnoException) => {
      if (error.code === 'ENOENT') return null;
      throw error;
    }),
    async remember(record) {
      const file = await open(`${path}.part`, 'w');
      try {
        await file.writeFile(record);
        await file.sync();
      } finally {
        await file.close();
      }
      await rename(`${path}.part`, path);
      const dir = await open(dirname(path), 'r');
      try {
        await dir.sync();
      } finally {
        await dir.close();
      }
    },
  };
}

export type RunningCheckpointer = {
  checkpointer: Checkpointer;
  /** For the change path (plan PR 4): seal now, then wait for the witnesses (R51). */
  sealThrough: SealThrough;
  /** The alarms raised since `since` (ms), oldest first, from the file beside the memory. */
  alarms(since?: number): Promise<Alarm[]>;
  /** The pair the signer remembers, from its file: what the vault's verifier holds its walks to (`VaultOptions.heldOutside`). */
  heldOutside(): Promise<PairNotes[]>;
  /** The reads' projection run until it stands at the newest pair (T166): for tests and tools, never on a request's path. */
  projected(): Promise<void>;
  /** Whether it seals (`Vault.sealing`): ticking, its last tick ended well, lately. */
  sealing(): Sealing;
  stop(): Promise<void>;
};

/** How long the runner waits on an open, the next days of uses, or the log's upkeep after a tick (T169). */
const OPEN_BOUND_MS = TICK_BOUND_MS;
const UPKEEP_BOUND_MS = 60_000;

/** A connection of the checkpointer's own (T169), which its runner cuts once it stalls: `openDatabase(url, { max })`. */
export type Session = { db: Database; cut(): Promise<void> };

/**
 * Opens the checkpointer over `database` (the vault's login) and ticks it
 * every `intervalMs`, a tick after the last one ends, each followed by the
 * log's upkeep (days made ahead, retention past `retainDays`, the bulk
 * cap's rows pruned). Each alarm is appended to `<memory>.alarms`, one JSON
 * line each. Given `connect` instead, over a session of its own, cut once
 * it stalls or stops, so that what it still awaits holds no connection of
 * the vault's (review r1).
 */
export async function runCheckpointer(options: {
  /** The vault's database, or `connect`, a session of its own. */
  database?: Database;
  connect?: () => Promise<Session>;
  seed: Uint8Array;
  /** The memory's file. */
  memory: string;
  witnesses?: readonly Witness[];
  intervalMs?: number;
  tileRange?: number;
  /** Full days of uses kept before today's; null keeps every day (retention.ts). */
  retainDays?: number | null;
  /** Told once its checkpointer stalls (T169), which ticks no more: `keepCheckpointer` opens another. */
  stalled?: (why: string) => void;
  /** `TICK_BOUND_MS`, which bounds the open and the next days too: for the tests. */
  tickBoundMs?: number;
  /** The memory over its file, `fileMemory` unless a test holds its writes. */
  memoryOf?: (path: string) => Memory;
}): Promise<RunningCheckpointer> {
  const alarmsPath = `${options.memory}.alarms`;
  let appending: Promise<void> = Promise.resolve();
  if ((options.connect === undefined) === (options.database === undefined)) throw new Error('the checkpointer runs over its database or a session it connects, one of the two');
  const session = options.connect === undefined ? null : await within(options.connect(), options.tickBoundMs ?? OPEN_BOUND_MS, 'connecting');
  const store = logStore(session?.db ?? options.database!, { tileRange: options.tileRange });
  const fence = new Fence();
  // The next days of uses first: a use needs its day's partition even if the checkpointer then refuses to open. Each
  // bounded (T169); an open past its bound fenced, so that it does nothing more once another opens.
  const checkpointer = await within(store.makeDays(daysAround(Date.now())), options.tickBoundMs ?? OPEN_BOUND_MS, 'making the next days of uses').then(() => within(openLogCheckpointer({
    store,
    seed: options.seed,
    memory: (options.memoryOf ?? fileMemory)(options.memory),
    witnesses: options.witnesses,
    record: (alarm) => record(alarm),
    fence,
    ...(options.tickBoundMs === undefined ? {} : { tickBoundMs: options.tickBoundMs }),
  }), options.tickBoundMs ?? OPEN_BOUND_MS, 'the open')).catch(async (error: unknown) => {
    // Fenced, its session cut, and its memory write in flight landed, before the keeper may open another over the same
    // file (review r1).
    await session?.cut().catch(() => {});
    await fence.close('its open failed');
    throw error;
  });
  /** In order, one after the other; a file grown past a megabyte keeps its last 30 days. */
  function record(alarm: Alarm): Promise<void> {
    appending = appending.then(async () => {
      await appendFile(alarmsPath, `${JSON.stringify(alarm)}\n`);
      if ((await stat(alarmsPath)).size > 1_000_000) {
        const kept = (await readAlarms(alarmsPath)).filter((a) => a.at >= alarm.at - 30 * 86_400_000);
        await writeFile(`${alarmsPath}.part`, kept.map((a) => `${JSON.stringify(a)}\n`).join(''));
        await rename(`${alarmsPath}.part`, alarmsPath);
      }
    }).catch((error: Error) => console.warn(`coffre audit: an alarm could not be kept: ${error.message}`));
    return appending;
  }
  // Behind the checkpointer's fence: an upkeep still running once it stalled does nothing beside the next one's.
  const keep = upkeep(checkpointer, fence.store(store), {
    keepDays: options.retainDays ?? null,
    seed: options.seed,
    alert: (message) => {
      console.warn(`coffre audit: ${message}`);
      void record({ at: Date.now(), message });
    },
  });
  // The reads' projection (T166), kicked after each tick and never waited on: a projection behind lags the audit pages,
  // never a seal (reads.ts).
  const keys = await verifierKeys([options.seed]);
  const projector = new Projector(store, keys, (message) => {
    console.warn(`coffre audit: ${message}`);
    void record({ at: Date.now(), message });
  });
  const interval = options.intervalMs ?? TICK_MS;
  let stopped = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let ticking: Promise<unknown> = Promise.resolve();
  // A tick that throws (a failed write may be a tamper signal: a tile changed under the signer) is an alarm, kept once.
  let failed: string | null = null;
  // The last tick that ended, for readiness; and whether the checkpointer stalled, which ends the loop.
  let last: { at: number; failures: string[] } | null = null;
  let stalled = false;
  // The upkeep, bounded: one past its bound goes on behind the next ticks, and none starts beside it. Its connection
  // is the vault's pool's, which the runner does not cut.
  let upkeeping: Promise<void> | null = null;
  const upkeepOnce = async () => {
    if (upkeeping !== null) return;
    const run = (upkeeping = keep().finally(() => {
      if (upkeeping === run) upkeeping = null;
    }));
    await within(run, UPKEEP_BOUND_MS, "the log's upkeep").catch((error: Error) => console.warn(`coffre audit: ${error.message}`));
  };
  // The upkeep after a tick that held; after one refused, only the next days (retention would fail on it, alarmed again).
  // A window sealed only in part (T169, WINDOW_MAX): the next tick at once, the upkeep once it has caught up.
  let more = false;
  const loop = () => {
    ticking = checkpointer.tick().then((t) => {
      failed = null;
      last = { at: Date.now(), failures: t.failures };
      projector.kick();
      more = t.more;
      return more ? undefined : upkeepOnce();
    }, async (error: Error) => {
      more = false;
      const message = `a checkpoint failed: ${reasonOf(error)}`;
      if (message !== failed) {
        failed = message;
        console.warn(`coffre audit: ${message}`);
        await record({ at: Date.now(), message });
      }
      // A checkpointer that stalled (T169) ticks no more: its keeper opens another.
      if (error instanceof Stalled) stalled = true;
      await within(store.makeDays(daysAround(Date.now())), options.tickBoundMs ?? OPEN_BOUND_MS, 'making the next days of uses').catch(() => {});
    }).finally(() => {
      if (stalled) options.stalled?.(failed!);
      else if (!stopped) timer = setTimeout(loop, more ? 0 : interval);
    });
  };
  loop();
  return {
    checkpointer,
    sealThrough: (number, deadline) => checkpointer.sealThrough(number, deadline),
    async heldOutside() {
      return heldIn(await fileMemory(options.memory).last());
    },
    async projected() {
      // A run goes a few steps: as many runs as the ranges above the cursor take, and no more than a hundred.
      for (let run = 0; run < 100; run += 1) {
        await projector.settled();
        projector.kick();
        await projector.settled();
        const [cursor, newest] = await Promise.all([store.readsCursor(), store.newest()]);
        if (newest === null || cursor.through >= newest.upto) return;
      }
      throw new Error("the reads' projection did not catch up with the newest pair");
    },
    sealing: () => sealingOf({ open: !stalled && !stopped, failed, last }),
    async alarms(since = 0) {
      await appending;
      return (await readAlarms(alarmsPath)).filter((a) => a.at >= since);
    },
    async stop() {
      stopped = true;
      clearTimeout(timer);
      // A stalled one's session cut first, so that what its tick awaits fails now (T169).
      if (stalled) await session?.cut().catch(() => {});
      await ticking;
      await projector.stop();
      // Closed, so that a handle kept after stop() never ticks beside a runner started over the same memory.
      await checkpointer.close();
      await session?.cut().catch(() => {});
    },
  };
}

/** The alarms in the file, a line each; a line a crash left torn is skipped. */
async function readAlarms(path: string): Promise<Alarm[]> {
  const text = await readFile(path, 'utf8').catch((error: NodeJS.ErrnoException) => {
    if (error.code === 'ENOENT') return '';
    throw error;
  });
  return text.split('\n').flatMap((line) => {
    try {
      return line.length > 0 ? [JSON.parse(line) as Alarm] : [];
    } catch {
      return [];
    }
  });
}

/** How long after a refused open the vault's checkpointer tries again (`keepCheckpointer`). */
const OPEN_AGAIN_MS = 10_000;

export type KeptCheckpointer = Pick<RunningCheckpointer, 'sealThrough' | 'heldOutside' | 'alarms' | 'sealing' | 'stop'>;

/**
 * The checkpointer as the vault's process keeps it: `runCheckpointer`, tried
 * again every `retryMs` while it cannot open (a log it refuses, as after a
 * restore, docs/restore.md; the database out of reach), each try making the
 * next days of uses first, so that uses go on; its failure an alarm, kept
 * once while it stands. Meanwhile a change's seal fails with why, as on
 * Workers, and the pair held outside is read from the file as ever. One
 * that stalls (T169) is stopped, fenced, and another opened a tick later.
 */
export async function keepCheckpointer(options: Parameters<typeof runCheckpointer>[0] & { retryMs?: number }): Promise<KeptCheckpointer> {
  let running: RunningCheckpointer | null = null;
  let failed: string | null = null;
  let stopped = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const alarmsPath = `${options.memory}.alarms`;
  // The runners that stalled, stopping: their memory writes in flight land before `stop` returns, so that nothing opened
  // after it over the same file has a newer pair overwritten (review r3).
  let retiring: Promise<void> = Promise.resolve();
  const tryOpen = async (): Promise<void> => {
    try {
      const opened: RunningCheckpointer = await runCheckpointer({
        ...options,
        // Its stop waits for the memory writes it sent (its fence); then another opens, as after a refused open.
        stalled: (why) => {
          if (running === opened) running = null;
          failed = why;
          const retired = opened.stop().catch(() => {});
          retiring = Promise.all([retiring, retired]).then(() => {});
          void retired.finally(() => {
            if (!stopped) timer = setTimeout(() => void (trying = tryOpen()), TICK_MS);
          });
        },
      });
      running = opened;
      failed = null;
    } catch (error) {
      const message = `the checkpointer cannot open: ${reasonOf(error)}`;
      if (message !== failed) {
        failed = message;
        console.warn(`coffre audit: ${message}`);
        await appendFile(alarmsPath, `${JSON.stringify({ at: Date.now(), message } satisfies Alarm)}\n`).catch((e: Error) => console.warn(`coffre audit: an alarm could not be kept: ${e.message}`));
      }
      if (!stopped) timer = setTimeout(() => void (trying = tryOpen()), options.retryMs ?? OPEN_AGAIN_MS);
    }
  };
  let trying = tryOpen();
  await trying;
  return {
    sealThrough: (number, deadline) => (running === null ? Promise.reject(new Unsealed(number, failed ?? 'the checkpointer is not open')) : running.sealThrough(number, deadline)),
    sealing: () => (running === null ? { ok: false, reason: failed ?? 'the checkpointer is not open' } : running.sealing()),
    async heldOutside() {
      return heldIn(await fileMemory(options.memory).last());
    },
    async alarms(since = 0) {
      return running === null ? (await readAlarms(alarmsPath)).filter((a) => a.at >= since) : running.alarms(since);
    },
    async stop() {
      stopped = true;
      clearTimeout(timer);
      await trying;
      await running?.stop();
      await retiring;
    },
  };
}
