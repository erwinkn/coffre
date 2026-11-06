// What the verifier's check costs a Worker (verifier.ts, `ABOVE_NEWEST`): the CPU of one check of 0.15's log in workerd,
// on a log of 50,000 sealed uses, at each count of entries above the newest pair `VERIFIER_BENCH_SIZES` names
// (0,250,500,1000,2000,4000 by default), the median and p90 of `VERIFIER_BENCH_RUNS` checks each (25), less the
// floor: a request that does nothing, the same number of times. A check's CPU is workerd's own, every thread's, read
// from Linux's per-thread counters until they are quiet again (as packages/conformance/scripts/bench.ts reads them);
// the Postgres it reads is another process, as Hyperdrive's origin is. The Worker runs the verifier alone, nothing
// else in its workerd, no checkpointer: the entries above the pair stay there.
//
// Not part of the suite. Linux only. On the suite's Postgres, as a test file:
//
//   scripts/test-suite.sh --files packages/vault/test/bench/verifier.ts
//
// Prints each count's CPU, a line fitted through them up to 2,000 (the fixed cost and the cost of an entry), and the
// most entries a check fits in R27's p99 bound, 20 ms, by that line.
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

const SIZES = (process.env.VERIFIER_BENCH_SIZES ?? '0,250,500,1000,2000,4000').split(',').map(Number);
const RUNS = Number(process.env.VERIFIER_BENCH_RUNS ?? 25);
/** R27's p99 bound on a request's CPU, which the check at its cap is held to (verifier.ts, `ABOVE_NEWEST`). */
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

/** The workerd processes this one started. */
function workerds(): number[] {
  const parent = new Map<number, number>();
  const named = new Map<number, string>();
  for (const entry of readdirSync('/proc')) {
    if (!/^\d+$/.test(entry)) continue;
    try {
      const stat = readFileSync(`/proc/${entry}/stat`, 'utf8');
      const close = stat.lastIndexOf(')');
      named.set(Number(entry), stat.slice(stat.indexOf('(') + 1, close));
      parent.set(Number(entry), Number(stat.slice(close + 2).split(' ')[1]));
    } catch {}
  }
  const ours = (pid: number) => {
    for (let p = pid; p > 1; p = parent.get(p) ?? 0) if (p === process.pid) return true;
    return false;
  };
  return [...named].filter(([pid, name]) => name === 'workerd' && ours(pid)).map(([pid]) => pid);
}

/** Milliseconds on CPU so far, every thread of `pids`. */
function cpu(pids: number[]): number {
  let ns = 0;
  for (const pid of pids) {
    for (const task of readdirSync(`/proc/${pid}/task`)) {
      try {
        ns += Number(readFileSync(`/proc/${pid}/task/${task}/schedstat`, 'utf8').split(' ')[0]);
      } catch {}
    }
  }
  return ns / 1e6;
}

/** The CPU `ask` costs `pids`, counted until they are quiet: 90 ms without a twentieth of a millisecond more. */
async function measure(pids: number[], ask: () => Promise<unknown>): Promise<number> {
  const before = cpu(pids);
  await ask();
  let last = cpu(pids);
  for (let quiet = 0; quiet < 3;) {
    await sleep(30);
    const now = cpu(pids);
    quiet = now - last < 0.05 ? quiet + 1 : 0;
    last = now;
  }
  return last - before;
}

const pct = (values: number[], p: number) => [...values].sort((a, b) => a - b)[Math.min(values.length - 1, Math.floor(values.length * p))]!;

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
  const pids = workerds();
  assert.ok(pids.length > 0, 'no workerd of ours found');
  const ask = async (op: 'noop' | 'verify') => {
    const response = await worker.fetch('/', { method: 'POST', headers: { 'x-token': token }, body: JSON.stringify({ op, anchor: memory.record }), signal: AbortSignal.timeout(30_000) });
    const body = (await response.json()) as { ok?: boolean; unsealed?: number; capped?: boolean; error?: string };
    if (!response.ok) throw new Error(body.error ?? String(response.status));
    return body;
  };
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
    const floor: number[] = [];
    const checks: number[] = [];
    for (let i = 0; i < RUNS; i += 1) {
      floor.push(await measure(pids, () => ask('noop')));
      checks.push(await measure(pids, () => ask('verify')));
    }
    const median = pct(checks, 0.5) - pct(floor, 0.5);
    points.push([size, median]);
    console.log(`${size} above the pair: ${median.toFixed(2)} ms CPU at the median, ${(pct(checks, 0.9) - pct(floor, 0.5)).toFixed(2)} at p90 (the floor, ${pct(floor, 0.5).toFixed(2)} ms, taken off)`);
  }
  // A line through the counts up to 2,000, by least squares: the check's fixed cost and an entry's.
  const near = points.filter(([size]) => size <= 2_000 && size <= ABOVE_NEWEST);
  if (near.length >= 2) {
    const n = near.length;
    const sx = near.reduce((s, [x]) => s + x, 0);
    const sy = near.reduce((s, [, y]) => s + y, 0);
    const sxx = near.reduce((s, [x]) => s + x * x, 0);
    const sxy = near.reduce((s, [x, y]) => s + x * y, 0);
    const perEntry = (n * sxy - sx * sy) / (n * sxx - sx * sx);
    const fixed = (sy - perEntry * sx) / n;
    console.log(`fitted up to 2,000: ${fixed.toFixed(2)} ms fixed, ${(perEntry * 1000).toFixed(1)} µs an entry; R27's p99 bound (${BUDGET_MS} ms) fits ${Math.floor((BUDGET_MS - fixed) / perEntry)} entries; ABOVE_NEWEST is ${ABOVE_NEWEST}`);
  }
});
