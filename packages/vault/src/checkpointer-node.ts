import { appendFile, open, readFile, rename, stat, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';

import type { Database } from '@coffre/db';

import type { Alarm, Checkpointer, Memory, SealThrough, Witness } from './checkpointer.ts';
import { openLogCheckpointer, reasonOf, TICK_MS, upkeep } from './log-checkpointer.ts';
import { logStore } from './log-store.ts';

/**
 * The 0.15 checkpointer on Node (docs/design/audit-tree.md): one process
 * seals the log every 500 ms, its memory a file beside the vault, synced
 * before the database has the pair it holds (RememberFirst). Nothing starts
 * it until 0.15's log is switched on (plan PR 10).
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
  stop(): Promise<void>;
};

/**
 * Opens the checkpointer over `database` (the vault's login) and ticks it
 * every `intervalMs`, a tick after the last one ends, each followed by the
 * log's upkeep (days made ahead, retention past `retainDays`, the bulk
 * cap's rows pruned). Each alarm is appended to `<memory>.alarms`, one JSON
 * line each.
 */
export async function runCheckpointer(options: {
  database: Database;
  seed: Uint8Array;
  /** The memory's file. */
  memory: string;
  witnesses?: readonly Witness[];
  intervalMs?: number;
  tileRange?: number;
  /** Full days of uses kept before today's; null keeps every day (retention.ts). */
  retainDays?: number | null;
}): Promise<RunningCheckpointer> {
  const alarmsPath = `${options.memory}.alarms`;
  let appending: Promise<void> = Promise.resolve();
  const store = logStore(options.database, { tileRange: options.tileRange });
  const checkpointer = await openLogCheckpointer({
    store,
    seed: options.seed,
    memory: fileMemory(options.memory),
    witnesses: options.witnesses,
    record: (alarm) => record(alarm),
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
  const keep = upkeep(checkpointer, store, {
    keepDays: options.retainDays ?? null,
    seed: options.seed,
    alert: (message) => {
      console.warn(`coffre audit: ${message}`);
      void record({ at: Date.now(), message });
    },
  });
  const interval = options.intervalMs ?? TICK_MS;
  let stopped = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let ticking: Promise<unknown> = Promise.resolve();
  // A tick that throws (a failed write may be a tamper signal: a tile changed under the signer) is an alarm, kept once.
  let failed: string | null = null;
  const loop = () => {
    ticking = checkpointer.tick().then(() => void (failed = null), (error: Error) => {
      const message = `a checkpoint failed: ${reasonOf(error)}`;
      if (message === failed) return;
      failed = message;
      console.warn(`coffre audit: ${message}`);
      return record({ at: Date.now(), message });
    }).then(keep).finally(() => {
      if (!stopped) timer = setTimeout(loop, interval);
    });
  };
  loop();
  return {
    checkpointer,
    sealThrough: (number, deadline) => checkpointer.sealThrough(number, deadline),
    async alarms(since = 0) {
      await appending;
      return (await readAlarms(alarmsPath)).filter((a) => a.at >= since);
    },
    async stop() {
      stopped = true;
      clearTimeout(timer);
      await ticking;
      // Closed, so that a handle kept after stop() never ticks beside a runner started over the same memory.
      await checkpointer.close();
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
