// What a tick costs the checkpointer at R44's 1,000 entries a second and a
// 500 ms tick (docs/design/audit-tree.md, "Numbers"): 500 entries, one in a
// hundred a change, MACs checked, leaves hashed, both trees grown, two notes
// signed. With the signer's memory held in a variable, then in a file synced
// before the database write (the Node memory: file, rename, directory, each
// fsynced), so the memory's own cost shows apart.
//
//   node --conditions=coffre:source packages/vault/scripts/audit-tree-bench.ts [ticks] [dir]
import { open, readFile, rename, rm } from 'node:fs/promises';
import { join } from 'node:path';

import { Checkpointer, type Memory } from '../src/checkpointer.ts';
import { authentic, keys, MemoryStore, variableMemory } from '../test/audit-tree.ts';

const ticks = Number(process.argv[2] ?? 400);
const dir = process.argv[3] ?? process.cwd();

function fileMemory(path: string): Memory {
  return {
    last: () => readFile(path, 'utf8').catch(() => null),
    async remember(record) {
      const file = await open(`${path}.part`, 'w');
      await file.writeFile(record);
      await file.sync();
      await file.close();
      await rename(`${path}.part`, path);
      const parent = await open(dir, 'r');
      await parent.sync();
      await parent.close();
    },
  };
}

const quantile = (xs: number[], q: number) => [...xs].sort((a, b) => a - b)[Math.min(xs.length - 1, Math.floor(q * xs.length))]!;

const memoryFile = join(dir, `audit-memory-${process.pid}`);
for (const [name, memory] of [['variable', variableMemory()], ['file, fsynced', fileMemory(memoryFile)]] as const) {
  const k = await keys(3);
  const store = new MemoryStore(k.macKey);
  const cpu: number[] = [];
  const wall: number[] = [];
  const remember: number[] = [];
  const timed: Memory = { last: () => memory.last(), remember: async (r) => { const t = performance.now(); await memory.remember(r); remember.push(performance.now() - t); } };
  const measured = await Checkpointer.open(store, k.signers, { memory: timed, authentic: authentic(k.macKey) });
  for (let t = 0; t < ticks; t += 1) {
    for (let i = 0; i < 500; i += 1) store.append(i % 100 === 0 ? 'changes' : 'uses', `r-${t}-${i}`, '{"secret":"6f1d4b8e-0b0c-4a2e-8a51-1c2d3e4f5a6b"}');
    const c0 = process.cpuUsage();
    const w0 = performance.now();
    const tick = await measured.tick();
    wall.push(performance.now() - w0);
    const c = process.cpuUsage(c0);
    cpu.push((c.user + c.system) / 1000);
    if (!tick.signed) throw new Error(tick.failures.join('; '));
    // The store keeps only the window, so its scan stays out of what is measured.
    store.log = [];
  }
  const skip = Math.floor(ticks / 10);
  const [c, w, r] = [cpu.slice(skip), wall.slice(skip), remember.slice(skip)];
  console.log(`${name}: a tick of 500, CPU p50 ${quantile(c, 0.5).toFixed(2)} / p99 ${quantile(c, 0.99).toFixed(2)} ms; wall p50 ${quantile(w, 0.5).toFixed(2)} / p99 ${quantile(w, 0.99).toFixed(2)} ms; memory write p50 ${quantile(r, 0.5).toFixed(3)} / p99 ${quantile(r, 0.99).toFixed(3)} ms; ${(memory as { record?: string }).record?.length ?? (await memory.last())?.length} B remembered`);
}
await rm(memoryFile, { force: true });
await rm(`${memoryFile}.part`, { force: true });
