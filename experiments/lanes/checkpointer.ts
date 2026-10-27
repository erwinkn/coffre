// The simple design's checkpointer (W201), alone: a checkpoint every
// `--every` ms for `--seconds`, against the database directly, while a load
// runs elsewhere (on Cloudflare, it would be a Durable Object's alarm; what it
// costs the database is the same). Prints what the checkpoints cost.
// --variant one (W208) checkpoints seed-one.ts's log (src/one.ts).
//
//   node experiments/lanes/checkpointer.ts --url postgresql://… --variant seq|head|one [--every 1000] [--seconds 60]
import { parseArgs } from 'node:util';

import pg from 'pg';

import { keysFrom } from './src/model.ts';
import * as one from './src/one.ts';
import { checkpoint, loadCheckpointState, type Checkpoint } from './src/simple.ts';

const { values } = parseArgs({
  options: {
    url: { type: 'string' },
    variant: { type: 'string', default: 'seq' },
    every: { type: 'string', default: '1000' },
    seconds: { type: 'string', default: '60' },
    seed: { type: 'string', default: 'w194-synthetic' },
  },
});
const mode = values.variant as 'head' | 'seq' | 'one';
const keys = keysFrom(values.seed);
const client = new pg.Client({ connectionString: values.url });
await client.connect();
const state = mode === 'one' ? null : await loadCheckpointState(client);
const oneState = mode === 'one' ? await one.loadCheckpointState(client) : null;
const done: (Checkpoint | one.Checkpoint)[] = [];
const until = Date.now() + Number(values.seconds) * 1000;
while (Date.now() < until) {
  await new Promise((resolve) => setTimeout(resolve, Number(values.every)));
  done.push(mode === 'one' ? await one.checkpoint(client, keys, oneState!) : await checkpoint(client, keys, mode, state!));
}
await client.end();
const sorted = (xs: number[]) => xs.sort((a, b) => a - b);
const db = sorted(done.map((c) => c.dbMs));
const verify = sorted(done.map((c) => c.verifyMs));
const entries = done.reduce((s, c) => s + c.entries, 0);
const signed = done.filter((c) => c.signed).length;
const failures = done.flatMap((c) => c.failures);
console.log(`checkpoints ${signed} signed of ${done.length} ticks, ${entries} entries (${(entries / Math.max(1, signed)).toFixed(0)} each), db p50/max ${db[Math.floor(db.length / 2)]?.toFixed(1)}/${db.at(-1)?.toFixed(1)} ms, verify+sign p50/max ${verify[Math.floor(verify.length / 2)]?.toFixed(1)}/${verify.at(-1)?.toFixed(1)} ms, ${failures.length === 0 ? 'all verified' : `FAILURES ${failures.slice(0, 5).join(', ')}`}`);
