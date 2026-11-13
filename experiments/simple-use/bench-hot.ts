// The hot calls of experiments/simple-use/hot.sql at a fixed rate, measured as packages/vault/scripts/bench-use.ts
// measures `use_credential`: Postgres CPU per use from the container's cgroup, buffers per use from
// pg_stat_statements, through postgres.js with unnamed statements. Run on a database bench-use.ts seeded.
//
//   node --conditions=coffre:source experiments/simple-use/bench-hot.ts --owner <url> --hot <url> --container <name> \
//     --form hot|ride|moved|move|move-moved|write [--rate 1000] [--seconds 10] [--pool 16]
//
// hot: every call writes its entry. ride: each pair's first call writes, every later one rides that entry.
// write: today's function, decided, writing every call (the baseline for hot).
// moved: the log's newest change is not the isolate's, so every call probes the decision's objects (none changed).
// move: every call moves its key's cap period (`use_move`), under the principal's cap lock shared, the log unmoved.
// move-moved: the same with the log moved, so every call also probes the decision's objects.
import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { parseArgs } from 'node:util';

import { postgresClient } from '@coffre/db/connect';

const { values: args } = parseArgs({
  options: {
    owner: { type: 'string' }, hot: { type: 'string' }, container: { type: 'string' }, form: { type: 'string', default: 'hot' },
    function: { type: 'string', default: 'use_hot' }, rate: { type: 'string', default: '1000' }, seconds: { type: 'string', default: '10' },
    pool: { type: 'string', default: '16' }, pairs: { type: 'string', default: '1000' },
  },
});
const owner = postgresClient(args.owner!, { max: 2 });
const q = async <T = Record<string, unknown>>(text: string, values: unknown[] = []) => [...await owner.unsafe(text, values as never[])] as T[];
const cgroupUsec = () => Number(/usage_usec (\d+)/.exec(execFileSync('docker', ['exec', args.container!, 'cat', '/sys/fs/cgroup/cpu.stat'], { encoding: 'utf8' }))![1]);

type Pair = { credential: string; principal: string; secret: string; version: string; objects: string };
// The same pairs as bench-use.ts's cached form, with the objects a decision on them reads: the credential, its
// principal, roles, policy, the key, its environment, and that environment's parent slot (none here).
const asked = (await q<Pair>(`SELECT c.id AS credential, c.principal, s.id AS secret, s.current_version_id AS version,
    ARRAY[log_object('credential', c.id::text), log_object('principal', c.principal), log_object('roles', 'instance'), log_object('policy', 'instance'),
          log_object('secret', s.id::text), log_object('environment', s.environment_id::text)]::uuid[]::text AS objects
  FROM credentials c JOIN grants g ON g.principal = c.principal JOIN secrets s ON s.environment_id = g.environment_id AND s.current_version_id IS NOT NULL`))
  .sort(() => Math.random() - 0.5).slice(0, Number(args.pairs));
// moved: the isolate decided at the change before the newest one, which still exists with its MAC.
const [newest, previous] = await q<{ number: string; mac: Buffer }>('SELECT number, mac FROM log_changes ORDER BY number DESC LIMIT 2');
const moving = args.form === 'move' || args.form === 'move-moved';
const known = args.form === 'moved' || args.form === 'move-moved' ? previous! : newest!;
const asOf = known.number;
// move: each pair's key in the principal's set, from a period every call moves past.
if (moving) {
  await q(`INSERT INTO bulk_cap (principal, secret, last) SELECT * FROM unnest($1::text[], $2::uuid[], $3::bigint[])
    ON CONFLICT (principal, secret) DO UPDATE SET last = EXCLUDED.last`, [asked.map((p) => p.principal), asked.map((p) => p.secret), asked.map(() => String(Date.now() - 1000))]);
}
const hot = postgresClient(args.hot!, { max: Number(args.pool) });
const entry = `ROW(NULL, $1::bigint, $2::bigint, $3::uuid, $4::uuid, 4::smallint, $5::bytea, NULL::uuid, NULL::text, true)::log_uses`;
const write = `SELECT state, number FROM ${args.function}(${entry}, $6::uuid, $7::bigint, $8::bytea, $9::uuid[], $10::bigint)`;
const move = `SELECT state, number FROM use_move(${entry}, $6::uuid, $7::bigint, $8::bytea, $9::uuid[], $10::bigint, $11::text, $12::bigint, 910000)`;
const ride = `SELECT state FROM use_ride(ROW($1::bigint, $2::bigint, $3::bigint, $4::uuid, $5::uuid, 4::smallint, NULL::bytea, NULL::uuid, NULL::text, true)::log_uses,
  $6::bigint, $7::uuid, $8::bigint, $9::bytea, $10::uuid[], $11::bigint)`;
// write: today's function (`--function use_credential|use_credential_0082`) on a decided use, every call writing its entry.
const today = `SELECT r->>'state' AS state, r->>'number' AS number FROM ${args.function}($1::uuid, $2::uuid, $3::bigint, $4::bigint, 4::smallint, NULL, $5::bytea,
  $6::bigint, NULL, NULL, NULL, $7::bigint, $8::bytea, 1000, 900000, p_decided => true) r`;
const covers = new Map<Pair, { number: string; at: number; request: string }>();

async function call(pair: Pair): Promise<string | null> {
  const at = Date.now();
  const cover = args.form === 'ride' ? covers.get(pair) : undefined;
  if (cover !== undefined) {
    const [row] = await hot.unsafe(ride, [cover.number, String(cover.at), cover.request, pair.credential, pair.secret, String(at), pair.version, asOf, known.mac, pair.objects, String(at + 3000)] as never[]);
    return (row!.state as string | null) ?? null;
  }
  const request = (randomBytes(8).readBigUInt64BE() >> 1n).toString();
  if (args.form === 'write') {
    const [row] = await hot.unsafe(today, [pair.credential, pair.secret, request, String(at), randomBytes(16), String(at + 3000), asOf, known.mac] as never[]);
    return (row!.state as string | null) ?? null;
  }
  const [row] = moving
    ? await hot.unsafe(move, [String(at), request, pair.credential, pair.secret, randomBytes(16), pair.version, asOf, known.mac, pair.objects, String(at + 3000), pair.principal, String(at)] as never[])
    : await hot.unsafe(write, [String(at), request, pair.credential, pair.secret, randomBytes(16), pair.version, asOf, known.mac, pair.objects, String(at + 3000)] as never[]);
  if (row!.number != null) covers.set(pair, { number: String(row!.number), at, request });
  return (row!.state as string | null) ?? null;
}

// Every connection's plans made, and in `ride` every pair's cover written, before the measured run.
await Promise.all(Array.from({ length: Number(args.pool) * 2 }, (_, i) => call(asked[i % asked.length]!)));
for (let i = 0; i < asked.length; i += 20) await Promise.all(asked.slice(i, i + 20).map(call));
await q('SELECT pg_stat_statements_reset()');
const before = cgroupUsec();
const started = Date.now();
let sent = 0, done = 0, failed = 0;
const latencies: number[] = [];
const inflight = new Set<Promise<void>>();
const rate = Number(args.rate);
while (Date.now() - started < Number(args.seconds) * 1000) {
  const due = Math.floor(((Date.now() - started) / 1000) * rate);
  for (; sent < due; sent += 1) {
    const t0 = performance.now();
    const p = call(asked[Math.floor(Math.random() * asked.length)]!).then(
      (state) => { if (state !== null) failed += 1; done += 1; latencies.push(performance.now() - t0); },
      () => { failed += 1; },
    ).finally(() => inflight.delete(p));
    inflight.add(p);
  }
  await new Promise((resolve) => setTimeout(resolve, 2));
}
await Promise.all(inflight);
const elapsed = (Date.now() - started) / 1000;
const usec = cgroupUsec() - before;
const name = args.form === 'ride' ? 'use_ride' : moving ? 'use_move' : args.function!;
const [stats] = await q<{ calls: string; blocks: string; ms: string }>(`SELECT sum(calls) AS calls, sum(shared_blks_hit + shared_blks_read) AS blocks, sum(total_exec_time) AS ms
  FROM pg_stat_statements WHERE toplevel AND query LIKE '%FROM ${name}(%'`);
latencies.sort((a, b) => a - b);
const pct = (p: number) => latencies[Math.floor((latencies.length - 1) * p)]?.toFixed(2);
console.log(JSON.stringify({
  form: args.form, function: name, served: Math.round(done / elapsed), failed, cpuMsPerUse: Number((usec / 1000 / done).toFixed(3)),
  buffersPerUse: Number((Number(stats!.blocks) / Number(stats!.calls)).toFixed(1)), serverMsPerUse: Number((Number(stats!.ms) / Number(stats!.calls)).toFixed(3)),
  p50: pct(0.5), p99: pct(0.99),
}));
await hot.end();
await owner.end();
