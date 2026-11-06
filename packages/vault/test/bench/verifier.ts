// What the verifier's check costs a Worker (verifier.ts, `ABOVE_NEWEST`): the CPU of one check of 0.15's log in workerd,
// on a log of 50,000 sealed uses, at each count of entries above the newest pair `VERIFIER_BENCH_SIZES` names
// (0,250,500,1000,2000 by default; a count past the cap measures the capped check), `VERIFIER_BENCH_RUNS` checks each
// (40), less a request that does nothing, its median. The CPU is that of the workerd that runs the Worker, read from
// Linux's per-thread counters until they are quiet again (as packages/conformance/scripts/bench.ts reads them): its
// main thread's, where the isolate runs the request, and every thread's, V8's helpers (concurrent GC, compilation)
// with it. Not the Postgres it reads, another process, as Hyperdrive's origin is, nor wrangler's proxy, which no
// deployment runs. The Worker runs the verifier alone, no checkpointer: the entries above the pair stay there.
//
// Not part of the suite. Linux only. On the suite's Postgres, as a test file:
//
//   scripts/test-suite.sh --files packages/vault/test/bench/verifier.ts
//
// Prints each count's CPU, at the median, p90 and most, and a line fitted through the isolate thread's medians up to
// 2,000 or the cap: the check's fixed cost, an entry's, and the most entries it fits in 20 ms (verifier.ts says why).
import { randomBytes } from 'node:crypto';
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { setTimeout as sleep } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';

import { unstable_dev, type Unstable_DevWorker } from 'wrangler';

import { openLogCheckpointer } from '../../src/log-checkpointer.ts';
import { logMacKey } from '../../src/log-entry.ts';
import { logStore } from '../../src/log-store.ts';
import { ABOVE_NEWEST } from '../../src/verifier.ts';
import { variableMemory } from '../audit-tree.ts';
import { openTestDatabase, VAULT_URL, type TestDatabase } from '../database.ts';
import { logWriter } from '../log-entries.ts';

const SIZES = (process.env.VERIFIER_BENCH_SIZES ?? '0,250,500,1000,2000').split(',').map(Number);
const RUNS = Number(process.env.VERIFIER_BENCH_RUNS ?? 40);
/** The CPU the check at its cap is held to (verifier.ts, `ABOVE_NEWEST`). */
const BUDGET_MS = 20;

let db: TestDatabase;
let worker: Unstable_DevWorker;
let dir: string;
const seed = randomBytes(32);
const token = randomBytes(16).toString('hex');

before(async () => {
  db = await openTestDatabase();
  dir = mkdtempSync(join(tmpdir(), 'coffre-verifier-bench-'));
  writeFileSync(join(dir, 'wrangler.json'), JSON.stringify({
    name: 'coffre-verifier-bench',
    compatibility_date: '2026-08-06',
    compatibility_flags: ['nodejs_compat'],
    vars: { SIGNING_KEY: seed.toString('base64'), TOKEN: token },
    hyperdrive: [{ binding: 'VAULT_HYPERDRIVE', id: 'verifier-bench', localConnectionString: VAULT_URL }],
  }));
  process.env.WRANGLER_BUILD_CONDITIONS = 'coffre:source,workerd,worker,browser';
  worker = await unstable_dev(fileURLToPath(new URL('../workers/verifier-bench-worker.ts', import.meta.url)), {
    config: join(dir, 'wrangler.json'),
    local: true, ip: '127.0.0.1', port: 0, inspectorPort: 0, persist: false, logLevel: 'error',
    experimental: { disableExperimentalWarning: true, disableDevRegistry: true },
  });
});
after(async () => {
  await worker?.stop();
  await db?.close();
  if (dir) rmSync(dir, { recursive: true, force: true });
});

/**
 * The workerd that runs the Worker, of the two wrangler starts under this process: the one with the inspector the
 * bench asks for (`inspectorPort`), not the proxy before it, which no deployment runs. Their arguments differ in that
 * alone; anything else found fails the bench rather than measure the wrong one.
 */
function workerOf(): number {
  const parent = new Map<number, number>();
  const named = new Map<number, string>();
  for (const entry of readdirSync('/proc')) {
    if (!/^\d+$/.test(entry)) continue;
    let stat: string;
    try {
      stat = readFileSync(`/proc/${entry}/stat`, 'utf8');
    } catch {
      continue;
    }
    const close = stat.lastIndexOf(')');
    named.set(Number(entry), stat.slice(stat.indexOf('(') + 1, close));
    parent.set(Number(entry), Number(stat.slice(close + 2).split(' ')[1]));
  }
  const ours = (pid: number) => {
    for (let p = pid; p > 1; p = parent.get(p) ?? 0) if (p === process.pid) return true;
    return false;
  };
  const workerds = [...named].filter(([pid, name]) => name === 'workerd' && ours(pid)).map(([pid]) => pid);
  const args = (pid: number) => readFileSync(`/proc/${pid}/cmdline`, 'utf8').split('\0');
  const running = workerds.filter((pid) => args(pid).some((arg) => arg.startsWith('--inspector-addr=')));
  if (workerds.length !== 2 || running.length !== 1) {
    throw new Error(`expected wrangler's two workerd, one with an inspector: ${JSON.stringify(workerds.map((pid) => args(pid)))}`);
  }
  return running[0]!;
}

/**
 * Milliseconds on CPU so far of a process: its main thread's, where workerd runs the isolate's JavaScript, and
 * every thread's, V8's helpers (concurrent GC, compilation) with it. A thread that ended between listing and reading
 * is passed over, as it no longer runs; any other failure to read a counter fails the measurement
 * (packages/conformance/scripts/bench.ts reads them so).
 */
function cpu(pid: number): { main: number; all: number } {
  let main = 0;
  let all = 0;
  for (const task of readdirSync(`/proc/${pid}/task`)) {
    let schedstat: string;
    try {
      schedstat = readFileSync(`/proc/${pid}/task/${task}/schedstat`, 'utf8');
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT' || (error as NodeJS.ErrnoException).code === 'ESRCH') continue;
      throw error;
    }
    const ns = Number(schedstat.split(' ')[0]);
    if (!Number.isFinite(ns)) throw new Error(`unreadable CPU counter for thread ${task} of process ${pid}: ${schedstat}`);
    all += ns / 1e6;
    if (Number(task) === pid) main = ns / 1e6;
  }
  return { main, all };
}

/** The CPU `ask` costs `pid`, counted until it is quiet: 90 ms without a twentieth of a millisecond more. */
async function measure(pid: number, ask: () => Promise<unknown>): Promise<{ main: number; all: number }> {
  const before = cpu(pid);
  await ask();
  let last = cpu(pid);
  for (let quiet = 0; quiet < 3;) {
    await sleep(30);
    const now = cpu(pid);
    quiet = now.all - last.all < 0.05 ? quiet + 1 : 0;
    last = now;
  }
  return { main: last.main - before.main, all: last.all - before.all };
}

const pct = (values: number[], p: number) => [...values].sort((a, b) => a - b)[Math.min(values.length - 1, Math.floor((values.length - 1) * p))]!;

test("the verifier's check in workerd, by the entries above the newest pair", { timeout: 3_600_000 }, async () => {
  const log = logWriter(db.owner, logMacKey(seed));
  await log.empty();
  await log.days();
  const memory = variableMemory();
  const cp = await openLogCheckpointer({ store: logStore(db.vault), signingKeys: [seed], memory });
  // History below, sealed a tick at a time: the check reads none of it.
  for (let below = 0; below < 50_000; below += 5_000) {
    await log.uses(5_000);
    assert.ok((await cp.tick()).signed);
  }
  const ask = async (op: 'noop' | 'verify') => {
    const response = await worker.fetch('/', { method: 'POST', headers: { 'x-token': token }, body: JSON.stringify({ op, anchor: memory.record }), signal: AbortSignal.timeout(30_000) });
    const body = (await response.json()) as { ok?: boolean; unsealed?: number; capped?: boolean; error?: string };
    if (!response.ok) throw new Error(body.error ?? String(response.status));
    return body;
  };
  const pid = workerOf();
  const points: [number, number][] = [];
  let above = 0;
  for (const size of SIZES) {
    await log.uses(size - above);
    above = size;
    // Warm, as an isolate serving pages is.
    for (let i = 0; i < 5; i += 1) {
      const checked = await ask('verify');
      assert.equal(checked.unsealed, Math.min(size, ABOVE_NEWEST), JSON.stringify(checked));
    }
    const floor: { main: number; all: number }[] = [];
    const checks: { main: number; all: number }[] = [];
    for (let i = 0; i < RUNS; i += 1) {
      floor.push(await measure(pid, () => ask('noop')));
      checks.push(await measure(pid, () => ask('verify')));
    }
    const of = (which: 'main' | 'all', p: number) => pct(checks.map((c) => c[which]), p) - pct(floor.map((f) => f[which]), 0.5);
    points.push([size, of('main', 0.5)]);
    console.log(`${size} above the pair: the isolate's thread ${of('main', 0.5).toFixed(2)} ms at the median, ${of('main', 0.9).toFixed(2)} at p90, ${of('main', 1).toFixed(2)} at most; all of workerd's threads ${of('all', 0.5).toFixed(2)}, ${of('all', 0.9).toFixed(2)}, ${of('all', 1).toFixed(2)} (a request that does nothing, its median, taken off)`);
  }
  // A line through the counts up to 2,000 or the cap, by least squares: the check's fixed cost and an entry's.
  const near = points.filter(([size]) => size <= Math.min(2_000, ABOVE_NEWEST));
  if (near.length >= 2) {
    const n = near.length;
    const sx = near.reduce((s, [x]) => s + x, 0);
    const sy = near.reduce((s, [, y]) => s + y, 0);
    const sxx = near.reduce((s, [x]) => s + x * x, 0);
    const sxy = near.reduce((s, [x, y]) => s + x * y, 0);
    const perEntry = (n * sxy - sx * sy) / (n * sxx - sx * sx);
    const fixed = (sy - perEntry * sx) / n;
    console.log(`the isolate's thread, at the median, fitted through ${near.map(([size]) => size).join(', ')}: ${fixed.toFixed(2)} ms fixed, ${(perEntry * 1000).toFixed(1)} µs an entry; ${BUDGET_MS} ms fits ${Math.floor((BUDGET_MS - fixed) / perEntry)} entries; ABOVE_NEWEST is ${ABOVE_NEWEST}`);
  }
});
