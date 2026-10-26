// What the seal rule costs a change (W209): load.ts appends uses at `--rate`
// in a process of its own, the checkpointer ticks every `--every` ms, and
// `--changes` changes run one after another, each answering once sealed (and
// witnessed, with `--witness`). Prints the change's latency (commit, seal,
// total) and how many were witnessed within `--deadline`.
//
//   node experiments/merkle/change-bench.ts --url postgresql://… [--witness <url>] [--deadline 2000] [--label x]
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { parseArgs } from 'node:util';

import pg from 'pg';

import { changeAndSeal, type ChangeAnswer } from './src/change.ts';
import { Checkpointer, createLog, keysFrom, leafOf } from './src/log.ts';
import { fileMemory } from './src/memory.ts';
import { openNote, parseCheckpoint, verifierFrom } from './src/note.ts';
import { verifyInclusion } from './src/tree.ts';
import { httpWitness } from './src/witness.ts';

const { values } = parseArgs({ options: {
  url: { type: 'string' }, rate: { type: 'string', default: '1000' }, every: { type: 'string', default: '500' }, changes: { type: 'string', default: '40' },
  witness: { type: 'string' }, deadline: { type: 'string', default: '2000' }, label: { type: 'string', default: '' },
} });
const url = values.url!;
const keys = await keysFrom('w209-synthetic');
const verifier = await verifierFrom(keys.signer.verifierKey);
const pool = new pg.Pool({ connectionString: url, max: 4 });
await createLog(pool);
const scratch = mkdtempSync(join(homedir(), 'scratch', 'w209', 'change-'));
const cp = await Checkpointer.open(pool, keys, { memory: fileMemory(join(scratch, 'memory')), witnesses: values.witness === undefined ? [] : [httpWitness('do-witness', values.witness)] });
const changes = Number(values.changes);
const load = spawn(process.execPath, [new URL('./load.ts', import.meta.url).pathname, '--url', url, '--rate', values.rate, '--seconds', String(Math.ceil(changes * 0.6) + 10)], { stdio: ['ignore', 'ignore', 'inherit'] });
await new Promise((r) => setTimeout(r, 2000));
let ticking = true;
const ticker = (async () => {
  while (ticking) {
    await new Promise((r) => setTimeout(r, Number(values.every)));
    await cp.tick().catch(() => {});
  }
})();
const answers: ChangeAnswer[] = [];
for (let i = 0; i < changes; i += 1) {
  await new Promise((r) => setTimeout(r, 100 + Math.random() * 400));
  const a = await changeAndSeal(pool, keys, cp, { at: Date.now(), principal: `svc-${i}`, credential: null, kind: 'change', requestId: `change-${i}`, payload: '{"action":"access.revoke"}', seal: Buffer.alloc(32, i) }, Number(values.deadline));
  const head = parseCheckpoint((await openNote(a.proof.checkpoint, verifier))!);
  if (!verifyInclusion(leafOf(a.proof.entry), a.proof.index, head.size, a.proof.proof, head.root)) throw new Error('a change answered with a proof that does not verify');
  answers.push(a);
}
ticking = false;
await ticker;
load.kill();
const pct = (xs: number[], p: number) => [...xs].sort((a, b) => a - b)[Math.min(xs.length - 1, Math.ceil((p / 100) * xs.length) - 1)]!;
const f = (k: 'commitMs' | 'sealMs' | 'totalMs') => `${pct(answers.map((a) => a[k]), 50).toFixed(0)}/${pct(answers.map((a) => a[k]), 99).toFixed(0)}`;
const failures = [...new Set(answers.flatMap((a) => a.failures.map((x) => x.replace(/\d+ leaves at \d+/g, '…'))))];
console.log(`${values.label.padEnd(14)} ${changes} changes under ${values.rate} uses/s, tick ${values.every} ms: commit p50/p99 ${f('commitMs')} ms, seal+witness ${f('sealMs')} ms, total ${f('totalMs')} ms; witnessed ${values.witness === undefined ? 'n/a (none set up)' : `${answers.filter((a) => a.witnessed === true).length}/${changes}`}${failures.length > 0 ? `; ${failures.slice(0, 2).join('; ')}` : ''}`);
rmSync(scratch, { recursive: true, force: true });
await pool.end();
process.exit(0);
