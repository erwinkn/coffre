// An open loop of appends (W209): `--rate` a second, Poisson, for `--seconds`,
// through a pool of `--pool` connections, each one statement (append_entry).
// Prints one JSON line: what was served, how fast, what failed. Run by bench.ts
// as a process of its own, so the checkpointer's CPU is measured alone.
import { parseArgs } from 'node:util';

import pg from 'pg';

import { append, keysFrom } from './src/log.ts';

const { values } = parseArgs({ options: {
  url: { type: 'string' }, rate: { type: 'string', default: '1000' }, seconds: { type: 'string', default: '20' }, pool: { type: 'string', default: '40' },
} });
const RATE = Number(values.rate);
const SECONDS = Number(values.seconds);
const keys = await keysFrom('w209-synthetic');
const pool = new pg.Pool({ connectionString: values.url, max: Number(values.pool), connectionTimeoutMillis: 1000 });
pool.on('error', () => {});
await Promise.all(Array.from({ length: Number(values.pool) }, () => pool.query('SELECT 1')));
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
const lat: number[] = [];
const errors = new Map<string, number>();
const pending: Promise<void>[] = [];
const start = performance.now();
let next = 0;
let n = 0;
while (next < SECONDS * 1000) {
  const wait = start + next - performance.now();
  if (wait > 0) await sleep(wait);
  const sent = performance.now();
  const i = n++;
  pending.push(append(pool, keys, {
    at: Date.now(), principal: `svc-${i % 100}`, credential: `cred-${i % 100}`, kind: 'use', requestId: `load-${process.pid}-${i}`,
    payload: JSON.stringify({ secret: 'DFNS_KEY', environment: 'production', decision: 'allow' }),
  }).then(() => { lat.push(performance.now() - sent); }, (e: Error) => { errors.set(e.message.slice(0, 50), (errors.get(e.message.slice(0, 50)) ?? 0) + 1); }));
  next += -Math.log(1 - Math.random()) * (1000 / RATE);
}
await Promise.all(pending);
const elapsed = (performance.now() - start) / 1000;
lat.sort((a, b) => a - b);
const pct = (p: number) => lat[Math.min(lat.length - 1, Math.ceil((p / 100) * lat.length) - 1)] ?? NaN;
console.log(JSON.stringify({ sent: n, ok: lat.length, perSecond: lat.length / elapsed, p50: pct(50), p99: pct(99), p999: pct(99.9), max: lat.at(-1), errors: Object.fromEntries(errors) }));
await pool.end();
