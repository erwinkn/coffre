// The simple hot path (W201) under an open loop, from Node: uses arrive at
// `--rate` a second (Poisson) for `--seconds`, each from one of
// `--principals` in turn, through a pool of `--pool` connections (Hyperdrive's
// origin pool: a statement holds a connection for its round trip and its
// server time, as Hyperdrive's transaction mode does), to a Postgres that a
// relay puts `--rtt` away. A checkpoint every `--checkpoint-ms`.
//
// Prints what succeeded and how fast, what failed and why, statements per
// use, Postgres's CPU (its container's cgroup) per use, and each statement's
// mean time and buffers (pg_stat_statements). --revoke-at <s> revokes svc-0's
// grant that far in, and counts every svc-0 use sent after the answer that
// was still allowed (must be 0). --hold-snapshot keeps a REPEATABLE READ
// transaction open for the whole run, as a backup's pg_dump does.
//
//   node experiments/lanes/bench-simple.ts --url postgresql://… --variant seq --rate 1000 [--seconds 20] [--principals 100] [--pool 40]
//     [--cgroup /sys/fs/cgroup/…/cpu.stat] [--revoke-at 10] [--checkpoint-ms 1000] [--label x]
import { readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';

import pg from 'pg';

import { keysFrom } from './src/model.ts';
import { change, checkpoint, nameStatements, use, type CheckpointState, type Variant } from './src/simple.ts';

const { values } = parseArgs({
  options: {
    url: { type: 'string' },
    admin: { type: 'string' },
    variant: { type: 'string', default: 'seq' },
    rate: { type: 'string', default: '100' },
    seconds: { type: 'string', default: '20' },
    principals: { type: 'string', default: '100' },
    pool: { type: 'string', default: '40' },
    seed: { type: 'string', default: 'w194-synthetic' },
    cgroup: { type: 'string' },
    'revoke-at': { type: 'string' },
    'checkpoint-ms': { type: 'string', default: '1000' },
    // How long a use waits for a connection before it is refused 503: the pool's queue bound.
    'queue-ms': { type: 'string', default: '1000' },
    'hold-snapshot': { type: 'boolean', default: false },
    // Named (prepared) statements on the hot path.
    named: { type: 'boolean', default: false },
    label: { type: 'string', default: '' },
  },
});
if (values.url === undefined) throw new Error('--url names the database (through the relay)');
const VARIANT = values.variant as Variant;
const RATE = Number(values.rate);
const SECONDS = Number(values.seconds);
const PRINCIPALS = Number(values.principals);
const ENVIRONMENT = '00000000-0000-4000-8000-000000000001';
const SECRET = '00000000-0000-4000-8000-0000000000a1';
const keys = keysFrom(values.seed);

nameStatements(values.named);
// Changes have a pool of their own, as the vault's own Hyperdrive binding would be: a revocation never waits behind uses for a connection.
const control = new pg.Pool({ connectionString: values.url, max: 2 });
control.on('error', () => {});
const pool = new pg.Pool({ connectionString: values.url, max: Number(values.pool), connectionTimeoutMillis: Number(values['queue-ms']) });
pool.on('error', () => {});
// Statistics and checkpoints go straight to the database, outside the pool under test.
const admin = new pg.Client({ connectionString: values.admin ?? values.url });
await admin.connect();
// Open every connection first: Hyperdrive's are open already.
await Promise.all(Array.from({ length: Number(values.pool) }, () => pool.query('SELECT 1')));
await admin.query('SELECT pg_stat_statements_reset()');

let snapshotHolder: pg.Client | null = null;
if (values['hold-snapshot']) {
  snapshotHolder = new pg.Client({ connectionString: values.admin ?? values.url });
  await snapshotHolder.connect();
  await snapshotHolder.query('BEGIN ISOLATION LEVEL REPEATABLE READ');
  await snapshotHolder.query('SELECT count(*) FROM audit_head');
}

const cpu = () => (values.cgroup === undefined ? NaN : Number(/usage_usec (\d+)/.exec(readFileSync(values.cgroup, 'utf8'))![1]));
const percentile = (sorted: number[], p: number) => (sorted.length === 0 ? NaN : sorted[Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1)]!);
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

type Run = { sent: number; ms: number; status: number; code: string; statements: number; tries: number; principal: string };
const runs: Run[] = [];
const pending: Promise<void>[] = [];

// Checkpoints, from their own connection, every --checkpoint-ms.
const checkpoints: Awaited<ReturnType<typeof checkpoint>>[] = [];
let checkpointing = true;
const { rows: [h] } = await admin.query('SELECT (next_seq - 1)::text AS upto, floor::text AS floor FROM audit_head');
const state: CheckpointState = { upto: VARIANT === 'seq' ? h.floor : h.upto, hash: Buffer.alloc(32), seen: [], tip: null };
const mode = VARIANT === 'cas' ? null : VARIANT;
const checkpointer = (async () => {
  const every = Number(values['checkpoint-ms']);
  while (checkpointing && mode !== null && every > 0) {
    await sleep(every);
    if (!checkpointing) break;
    checkpoints.push(await checkpoint(admin, keys, mode, state));
  }
})();

let revocation: { ms: number; at: number } | null = null;
const revokeAt = values['revoke-at'] === undefined ? null : Number(values['revoke-at']) * 1000;
let revoking = false;

const cpuBefore = cpu();
const start = performance.now();
let n = 0;
let next = 0;
while (next < SECONDS * 1000) {
  const wait = start + next - performance.now();
  if (wait > 0) await sleep(wait);
  if (revokeAt !== null && !revoking && performance.now() - start >= revokeAt) {
    revoking = true;
    const began = performance.now();
    pending.push(change(control, keys, mode ?? 'head', 'svc-0', false, ENVIRONMENT).then(() => {
      revocation = { ms: performance.now() - began, at: performance.now() - start };
    }, (error: Error) => console.log(`  revocation FAILED: ${error.message}`)));
  }
  const principal = `svc-${n % PRINCIPALS}`;
  const sent = performance.now() - start;
  n += 1;
  const requestId = `r${n}`;
  pending.push(
    use(pool, keys, VARIANT, { principal, credential: `cred-${principal}`, environmentId: ENVIRONMENT, secretId: SECRET, requestId }).then(
      (a) => {
        runs.push({ sent, ms: performance.now() - start - sent, status: a.ok ? 200 : a.retryAfter === undefined ? 403 : 503, code: a.ok ? 'ok' : a.code, statements: a.statements, tries: a.tries, principal });
      },
      (error: Error & { code?: string }) => {
        // A connection not had in time, or a lock or statement that ran out: 503 with Retry-After, at once.
        const busy = /timeout exceeded when trying to connect/.test(error.message) || error.code === '55P03' || error.code === '57014';
        runs.push({ sent, ms: performance.now() - start - sent, status: busy ? 503 : 500, code: error.code ?? error.message.slice(0, 40), statements: 0, tries: 0, principal });
      },
    ),
  );
  next += -Math.log(1 - Math.random()) * (1000 / RATE);
}
await Promise.all(pending);
const elapsed = (performance.now() - start) / 1000;
const cpuAfter = cpu();
checkpointing = false;
await checkpointer;

const ok = runs.filter((r) => r.status === 200);
const lat = ok.map((r) => r.ms).sort((a, b) => a - b);
const failed = new Map<string, number>();
for (const r of runs) if (r.status !== 200) failed.set(`${r.status} ${r.code}`, (failed.get(`${r.status} ${r.code}`) ?? 0) + 1);
const refused = runs.filter((r) => r.status === 503).map((r) => r.ms).sort((a, b) => a - b);
const fifth = (from: number) => ok.filter((r) => r.sent >= from && r.sent < from + (SECONDS * 1000) / 5).map((r) => r.ms).sort((a, b) => a - b);
const statements = runs.reduce((sum, r) => sum + r.statements, 0) / Math.max(1, runs.length);
const retried = runs.filter((r) => r.tries > 1).length;
const pgCpuMs = (cpuAfter - cpuBefore) / 1000;

console.log([
  values.label.padEnd(12), `${VARIANT}${values.named ? '+named' : ''}`.padEnd(10), `${String(RATE).padStart(5)}/s`, `${PRINCIPALS}p`,
  `ok ${(ok.length / elapsed).toFixed(1).padStart(7)}/s`,
  `p50 ${percentile(lat, 50).toFixed(1)}`, `p99 ${percentile(lat, 99).toFixed(1)}`, `max ${(lat.at(-1) ?? NaN).toFixed(0)} ms`,
  `stmts ${statements.toFixed(2)}`, `retried ${retried}`,
  `pg cpu ${(pgCpuMs / elapsed / 10).toFixed(0)}% of a core (${(pgCpuMs / Math.max(1, runs.length)).toFixed(3)} ms/use)`,
  `1st/5th p50 ${percentile(fifth(0), 50).toFixed(1)}/${percentile(fifth((SECONDS * 4000) / 5), 50).toFixed(1)}`,
  `failed ${runs.length - ok.length}${failed.size === 0 ? '' : ` ${JSON.stringify(Object.fromEntries(failed))}`}`,
  refused.length === 0 ? '' : `503 p50/p99 ${percentile(refused, 50).toFixed(0)}/${percentile(refused, 99).toFixed(0)} ms`,
].join('  '));

if (checkpoints.length > 0) {
  const db = checkpoints.map((c) => c.dbMs).sort((a, b) => a - b);
  const verify = checkpoints.map((c) => c.verifyMs).sort((a, b) => a - b);
  const entries = checkpoints.reduce((s, c) => s + c.entries, 0);
  const failures = checkpoints.flatMap((c) => c.failures);
  console.log(`  checkpoints: ${checkpoints.length}, ${entries} entries (${(entries / checkpoints.length).toFixed(0)} each), db p50/max ${percentile(db, 50).toFixed(1)}/${db.at(-1)!.toFixed(1)} ms, verify+sign p50/max ${percentile(verify, 50).toFixed(1)}/${verify.at(-1)!.toFixed(1)} ms (${(verify.reduce((a, b) => a + b, 0) / Math.max(1, entries) * 1000).toFixed(1)} µs/entry), ${failures.length === 0 ? 'all verified' : `FAILURES ${failures.slice(0, 5).join(', ')}`}`);
}

if (revocation !== null) {
  const r = revocation as { ms: number; at: number };
  const after = runs.filter((x) => x.principal === 'svc-0' && x.sent > r.at);
  const allowed = after.filter((x) => x.status === 200).length;
  const codes = new Map<string, number>();
  for (const x of after) if (x.status !== 200) codes.set(x.code, (codes.get(x.code) ?? 0) + 1);
  console.log(`  revocation: took ${r.ms.toFixed(1)} ms; svc-0 uses sent after its answer: ${after.length}, allowed: ${allowed} (must be 0); refused ${JSON.stringify(Object.fromEntries(codes))}`);
  await change(control, keys, mode ?? 'head', 'svc-0', true, ENVIRONMENT);
}

// Each statement's mean server time and buffers, the busiest first.
const { rows: stats } = await admin.query(`
  SELECT calls, round(mean_exec_time::numeric, 3) AS mean_ms, round((shared_blks_hit + shared_blks_read)::numeric / calls, 1) AS buffers,
    round(wal_records::numeric / calls, 1) AS wal, left(regexp_replace(query, '\\s+', ' ', 'g'), 70) AS query
  FROM pg_stat_statements WHERE calls >= 10 AND query NOT LIKE '%pg_stat_statements%' ORDER BY total_exec_time DESC LIMIT 6`);
for (const s of stats) console.log(`  ${String(s.calls).padStart(8)} × ${String(s.mean_ms).padStart(7)} ms  ${String(s.buffers).padStart(5)} buf  ${String(s.wal).padStart(4)} wal  ${s.query}`);

if (snapshotHolder !== null) await snapshotHolder.end();
await admin.end();
await pool.end();
await control.end();
