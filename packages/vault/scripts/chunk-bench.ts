// T169: a backlog after a stall, sealed a part a tick (WINDOW_MAX) through
// one connection as the checkpointer's object holds it, behind a proxy
// that adds Hyperdrive's round trip (~20 ms on Cloudflare, A396). Prints
// each tick's wall time, its barrier and window read, its write, and the
// plans of the window read and of the probe for the lowest `at` left above
// a part, at the start of the backlog. On a Postgres of your own, never the
// shared one: it empties the log's tables of the database the URLs name.
//
//   node --conditions=coffre:source packages/vault/scripts/chunk-bench.ts <owner url> <vault url> [backlog] [rtt ms]
import { randomBytes, randomUUID } from 'node:crypto';

import { createDatabase } from '@coffre/db';
import { postgresClient } from '@coffre/db/connect';
import { HyperdrivePool } from '@coffre/db/hyperdrive';
import { sql } from 'drizzle-orm';

import { WINDOW_MAX } from '../src/checkpointer.ts';
import { openLogCheckpointer } from '../src/log-checkpointer.ts';
import { entryMac, logMacKey } from '../src/log-entry.ts';
import { logStore, postgresWindow } from '../src/log-store.ts';
import { stallProxy } from '../test/stall-proxy.ts';
import { variableMemory } from '../test/audit-tree.ts';

const [ownerUrl, vaultUrl, backlogArg, rttArg] = process.argv.slice(2);
if (ownerUrl === undefined || vaultUrl === undefined) throw new Error('usage: chunk-bench.ts <owner url> <vault url> [backlog] [rtt ms]');
const backlog = Number(backlogArg ?? 240_000);
const rtt = Number(rttArg ?? 20);

const owner = postgresClient(ownerUrl, { max: 4 });
for (const table of ['log_checkpoints', 'log_tiles', 'log_changes', 'log_uses']) await owner.unsafe(`DELETE FROM ${table}`);
await owner.unsafe(`UPDATE log_fence SET at_floor = $1`, [Date.now() - 3000]);
const day = (ms: number) => new Date(ms).toISOString().slice(0, 10);
await owner.unsafe('SELECT make_day($1::date), make_day($2::date)', [day(Date.now()), day(Date.now() + 86_400_000)]);

const seed = randomBytes(32);
const macKey = logMacKey(seed);
const proxy = await stallProxy(vaultUrl, { delayMs: rtt / 2 });
const pool = new HyperdrivePool(proxy.url, { closeIdleMs: 60_000 });
const store = logStore(createDatabase(pool));
const cp = await openLogCheckpointer({ store, seed, memory: variableMemory() });
await cp.tick();
const floor = cp.pair.pair.floor;
const base = Date.now() - 2500;

// The backlog, as a stall leaves it: uses stamped over a few seconds, at or above the floor the signer holds.
const t0 = Date.now();
for (let done = 0; done < backlog; done += 5000) {
  const n = Math.min(5000, backlog - done);
  const at: string[] = [], rid: string[] = [], cred: string[] = [], sec: string[] = [], mac: Buffer[] = [];
  for (let i = 0; i < n; i += 1) {
    const row = { at: base + Math.floor(((done + i) / backlog) * 2500), requestId: BigInt.asIntN(64, randomBytes(8).readBigUInt64BE()), credential: randomUUID(), secret: randomUUID(), purpose: 1, place: null };
    at.push(String(row.at)); rid.push(String(row.requestId)); cred.push(row.credential); sec.push(row.secret);
    mac.push(entryMac(macKey, { tree: 'uses', row }));
  }
  await owner.unsafe(`INSERT INTO log_uses (number, at, request_id, credential, secret, purpose, mac, place)
    SELECT nextval('log_number'), a, r, c, s, 1, m, NULL FROM unnest($1::bigint[], $2::bigint[], $3::uuid[], $4::uuid[], $5::bytea[]) AS x (a, r, c, s, m)`,
    [at, rid, cred, sec, mac] as never);
}
console.log(`backlog: ${backlog} uses in ${Date.now() - t0} ms; round trip ${rtt} ms`);
await new Promise((resolve) => setTimeout(resolve, 3500));

// The plans, at the start of the backlog: the window read by number, and the probe past its first part.
const db = createDatabase(owner);
const after = cp.pair.pair.upto;
const [{ upto }] = await owner.unsafe(`SELECT pg_sequence_last_value('log_number')::text AS upto`) as unknown as [{ upto: string }];
const explain = async (label: string, query: ReturnType<typeof sql>) => {
  const rows = (await db.execute(sql`EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) ${query}`)) as unknown as { 'QUERY PLAN': [{ Plan: { 'Actual Rows': number }; 'Execution Time': number }] }[];
  const plan = rows[0]!['QUERY PLAN'][0]!;
  console.log(`${label}: ${plan['Execution Time'].toFixed(1)} ms, ${plan.Plan['Actual Rows']} rows`);
};
await explain('window read, first part', postgresWindow(after, BigInt(upto), sql`${floor}::bigint`, undefined, WINDOW_MAX + 1, true));
const k = after + BigInt(WINDOW_MAX);
await explain('probe past it', sql`SELECT min(u.at) FROM log_uses u WHERE u.at >= ${floor}::bigint AND u.number > ${k} AND u.number <= ${BigInt(upto)}`);

// The ticks, each timed.
const ticks: { wall: number; close: number; write: number; entries: number }[] = [];
const start = performance.now();
for (;;) {
  const t1 = performance.now();
  const t = await cp.tick();
  ticks.push({ wall: performance.now() - t1, close: t.closeMs, write: t.writeMs, entries: t.entries });
  if (t.failures.length > 0) throw new Error(t.failures.join('; '));
  if (!t.more) break;
}
const total = performance.now() - start;
const sorted = (xs: number[]) => [...xs].sort((a, b) => a - b);
const pct = (xs: number[], p: number) => sorted(xs)[Math.min(xs.length - 1, Math.floor(p * xs.length))]!;
console.log(`drained in ${ticks.length} ticks, ${(total / 1000).toFixed(1)} s`);
console.log(`tick wall ms: first ${ticks[0]!.wall.toFixed(0)}, p50 ${pct(ticks.map((t) => t.wall), 0.5).toFixed(0)}, max ${Math.max(...ticks.map((t) => t.wall)).toFixed(0)}`);
console.log(`barrier + window ms: first ${ticks[0]!.close.toFixed(0)}, p50 ${pct(ticks.map((t) => t.close), 0.5).toFixed(0)}, max ${Math.max(...ticks.map((t) => t.close)).toFixed(0)}`);
console.log(`write ms: p50 ${pct(ticks.map((t) => t.write), 0.5).toFixed(0)}, max ${Math.max(...ticks.map((t) => t.write)).toFixed(0)}`);
await pool.end();
await proxy.close();
await owner.end();
