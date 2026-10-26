// Fill a fresh log: `--entries` appends, 40 at a time, a checkpoint every
// `--every` of them, a day change at `--day-every` (0: none).
//
//   node experiments/merkle/fill.ts --url postgresql://… [--entries 70000] [--every 997] [--day-every 0]
import { parseArgs } from 'node:util';

import pg from 'pg';

import { append, Checkpointer, createLog, keysFrom } from './src/log.ts';

const { values } = parseArgs({ options: {
  url: { type: 'string' }, entries: { type: 'string', default: '70000' }, every: { type: 'string', default: '997' },
  'day-every': { type: 'string', default: '0' }, fresh: { type: 'boolean', default: true },
} });
const pool = new pg.Pool({ connectionString: values.url, max: 40 });
const keys = await keysFrom('w209-synthetic');
if (values.fresh) {
  await createLog(pool);
}
const cp = await Checkpointer.open(pool, keys);
const total = Number(values.entries);
const every = Number(values.every);
const dayEvery = Number(values['day-every']);
let day = 0;
const started = performance.now();
for (let done = 0; done < total;) {
  const batch = Math.min(every, total - done);
  await Promise.all(Array.from({ length: 40 }, async (_, w) => {
    for (let i = w; i < batch; i += 40) {
      const n = done + i;
      await append(pool, keys, { at: Date.now(), principal: `svc-${n % 100}`, credential: `cred-${n % 100}`, kind: 'use', requestId: `fill-${n}`, payload: '{"secret":"DFNS_KEY"}' });
    }
  }));
  done += batch;
  if (dayEvery > 0 && Math.floor(done / dayEvery) > day) {
    day += 1;
    await pool.query('SELECT new_day($1)', [day]);
    await cp.tick({ nextDay: day });
  } else {
    await cp.tick();
  }
}
await cp.tick();
console.log(`${total} entries, tree of ${cp.size}, in ${((performance.now() - started) / 1000).toFixed(1)} s`);
await pool.end();
