// What a workload's gate costs, in CPU, on Workers and in memory. In
// workerd, as on Cloudflare: a Worker request that asks the gate of its
// workload (test/workers/gates-worker.ts) against one that asks nothing,
// the floor, the difference being the gate's `fetch` from the Worker's side
// and the object's own work, each request a new proof and two counts. Then
// `GateState.admit` alone, in this process. Not part of the suite:
//
//   node --conditions=coffre:source packages/server/test/bench/gate.ts [--requests 2000]
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

import { unstable_dev } from 'wrangler';

import { GateState } from '../../src/gate.ts';

const { values } = parseArgs({ options: { requests: { type: 'string', default: '2000' } } });
const requests = Number(values.requests);

/** Every workerd this process started, and the CPU its threads have had, in milliseconds. */
function workerdCpu(): number {
  const parents = new Map<number, number>();
  const names = new Map<number, string>();
  for (const entry of readdirSync('/proc')) {
    if (!/^\d+$/.test(entry)) continue;
    try {
      const stat = readFileSync(`/proc/${entry}/stat`, 'utf8');
      names.set(Number(entry), stat.slice(stat.indexOf('(') + 1, stat.lastIndexOf(')')));
      parents.set(Number(entry), Number(stat.slice(stat.lastIndexOf(')') + 2).split(' ')[1]));
    } catch {
      continue;
    }
  }
  const ours = (pid: number): boolean => pid === process.pid || (parents.has(pid) && pid > 1 && ours(parents.get(pid)!));
  let ns = 0;
  for (const [pid, name] of names) {
    if (name !== 'workerd' || !ours(pid)) continue;
    for (const task of readdirSync(`/proc/${pid}/task`)) {
      try {
        ns += Number(readFileSync(`/proc/${pid}/task/${task}/schedstat`, 'utf8').split(' ')[0]);
      } catch {
        continue;
      }
    }
  }
  return ns / 1e6;
}

const dir = mkdtempSync(join(tmpdir(), 'coffre-gate-bench-'));
writeFileSync(join(dir, 'wrangler.json'), JSON.stringify({
  name: 'coffre-gate-bench',
  compatibility_date: '2026-08-06',
  compatibility_flags: ['nodejs_compat'],
  durable_objects: { bindings: [{ name: 'GATES', class_name: 'CoffreGates' }] },
  migrations: [{ tag: 'gates', new_sqlite_classes: ['CoffreGates'] }],
}));
process.env.WRANGLER_BUILD_CONDITIONS = 'coffre:source,workerd,worker,browser';
const worker = await unstable_dev(fileURLToPath(new URL('../workers/gates-worker.ts', import.meta.url)), {
  config: join(dir, 'wrangler.json'),
  local: true, ip: '127.0.0.1', port: 0, inspectorPort: 0, persist: false, logLevel: 'error',
  experimental: { disableExperimentalWarning: true, disableDevRegistry: true },
});
const counts = [{ key: 'stripe', windowMs: 60_000, most: 1e9 }, { key: 'stripe', windowMs: 86_400_000, most: 1e9 }];
try {
  const ask = async (body: unknown) => (await worker.fetch('http://gate/', { method: 'POST', body: JSON.stringify(body) })).json() as Promise<{ nonce?: string; ok?: boolean }>;
  const { nonce } = await ask({ principal: 'token:api', nonce: true });
  let n = 0;
  const proof = () => ({ principal: 'token:api', replay: { session: 's', jti: `jti-${String(n++).padStart(18, '0')}`, nonce }, counts });
  const per = async (body: () => unknown) => {
    for (let i = 0; i < 200; i++) await ask(body());
    const before = workerdCpu();
    for (let i = 0; i < requests; i++) await ask(body());
    return (workerdCpu() - before) / requests;
  };
  const floor = await per(() => ({}));
  const gated = await per(proof);
  const check = await ask(proof());
  if (check.ok !== true) throw new Error(`the gate refused the bench: ${JSON.stringify(check)}`);
  console.log(`workerd, ${requests} requests each, warm, CPU per request: floor ${(floor * 1000).toFixed(0)} µs, asking the gate ${(gated * 1000).toFixed(0)} µs, the gate ${((gated - floor) * 1000).toFixed(0)} µs`);
} finally {
  await worker.stop();
  rmSync(dir, { recursive: true, force: true });
}

const gate = new GateState(Date.now(), Number.MAX_SAFE_INTEGER);
const nonce = gate.nonce(Date.now());
const started = process.cpuUsage();
const many = 200_000;
for (let i = 0; i < many; i++) gate.admit({ replay: { jti: `jti-${String(i).padStart(18, '0')}`, nonce }, counts }, Date.now());
const spent = process.cpuUsage(started);
console.log(`GateState.admit in Node, ${many} proofs with two counts: ${(((spent.user + spent.system) / many)).toFixed(2)} µs each, ${many} jtis held`);
