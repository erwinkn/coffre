// W212: how many uses straddle each `at`-day boundary when a single sequence
// orders the log (every shape but `day`). #365's own log, laid out by `at` with
// days `--day-ms` long, takes `--rate` appends a second (load.ts, a process of
// its own) while a checkpointer seals every 500 ms. For each day boundary it
// counts the stragglers: uses of the next day numbered below the day's cut, the
// first checkpoint at or above the day's highest number. Retention leaves those
// unprotected until their own day goes (#365, review r8). It also prints the
// WAL the appends and checkpoints write together, per tick.
//
//   node experiments/merkle/shapes/midnight.ts --url postgresql://… [--seconds 120] [--day-ms 5000]
import { spawn } from 'node:child_process';
import { parseArgs } from 'node:util';

import pg from 'pg';

import { Checkpointer, createLog, keysFrom } from '../src/log.ts';

const { values } = parseArgs({ options: {
  url: { type: 'string' }, seconds: { type: 'string', default: '120' }, 'day-ms': { type: 'string', default: '5000' }, rate: { type: 'string', default: '1000' },
} });
const url = values.url!;
const dayMs = Number(values['day-ms']);
const db = new pg.Client({ connectionString: url });
await db.connect();
await createLog(db, 'at', dayMs);
const first = Math.floor(Date.now() / dayMs);
const last = Math.floor((Date.now() + (Number(values.seconds) + 30) * 1000) / dayMs);
for (let d = first; d <= last; d += 1) await db.query('SELECT new_day($1)', [d]);
const keys = await keysFrom('w209-synthetic');
const cp = await Checkpointer.open(db, keys);

const load = spawn(process.execPath, [new URL('../load.ts', import.meta.url).pathname, '--url', url, '--rate', values.rate, '--seconds', values.seconds], { stdio: ['ignore', 'pipe', 'inherit'] });
let out = '';
load.stdout.on('data', (d) => { out += d; });
const lsn = async () => (await db.query('SELECT pg_current_wal_insert_lsn()::text AS l')).rows[0].l as string;
const wal0 = await lsn();
let ticks = 0;
let running = true;
load.on('exit', () => { running = false; });
const t0 = performance.now();
for (let n = 1; running; n += 1) {
  await new Promise((r) => setTimeout(r, Math.max(0, t0 + n * 500 - performance.now())));
  await cp.tick();
  ticks += 1;
}
// Everything the appends and the checkpoints wrote, per tick: the whole log's WAL, of which the tiles are a part.
const { rows: [wal] } = await db.query('SELECT pg_wal_lsn_diff($2, $1)::bigint AS d', [wal0, await lsn()]);
await cp.tick();

// For each whole day: its highest number, its cut, and the next day's uses below the cut.
const { rows } = await db.query(`
  WITH days AS (SELECT at / $1 AS day, max(number) AS top, count(*) AS uses FROM audit_uses GROUP BY 1),
  cuts AS (SELECT d.day, d.uses, (SELECT min(c.upto) FROM checkpoints c WHERE c.upto >= d.top) AS cut FROM days d)
  SELECT c.day, c.uses::int, (SELECT count(*) FROM audit_uses a WHERE a.at >= (c.day + 1) * $1 AND a.number <= c.cut)::int AS stragglers
  FROM cuts c WHERE c.cut IS NOT NULL AND c.day > (SELECT min(day) FROM days) AND c.day < (SELECT max(day) FROM days) - 1 ORDER BY 1`, [dayMs]);
const s = rows.map((r) => r.stragglers as number).sort((a, b) => a - b);
const pct = (p: number) => s[Math.min(s.length - 1, Math.ceil((p / 100) * s.length) - 1)];
console.log(JSON.stringify({
  boundaries: s.length, walPerTick: Number(wal.d) / ticks, load: JSON.parse(out.trim().split('\n').at(-1)!), stragglers: { p50: pct(50), p90: pct(90), max: s.at(-1), mean: s.reduce((a, b) => a + b, 0) / s.length },
}));
await db.end();
