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
// --variant one (W208) runs src/one.ts on seed-one.ts's database: one call
// per use. --cap bounds the uses in flight (an isolate's admission control:
// above it a use is refused 503 at once, without a statement); --deadline-ms
// answers 503 a use not done by then, and `one`'s call does nothing if it
// starts later than that (the pool or Hyperdrive held it). --outcomes writes
// each use's answer, for verify-one.ts's replay.
//
//   node experiments/lanes/bench-simple.ts --url postgresql://… --variant seq --rate 1000 [--seconds 20] [--principals 100] [--pool 40]
//     [--cgroup /sys/fs/cgroup/…/cpu.stat] [--revoke-at 10] [--checkpoint-ms 1000] [--label x]
import { readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';

import pg from 'pg';

import { keysFrom } from './src/model.ts';
import { randomUUID } from 'node:crypto';
import { writeFileSync } from 'node:fs';

import * as one from './src/one.ts';
import { change, checkpoint, loadCheckpointState, nameStatements, use, type Variant } from './src/simple.ts';

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
    // What the revocation takes away: svc-0's grant, or its credential.
    'revoke-kind': { type: 'string', default: 'grant' },
    // The relay's pid, to report its CPU: a bottleneck of the rig, not of the design.
    'relay-pid': { type: 'string' },
    // Named (prepared) statements on the hot path.
    named: { type: 'boolean', default: false },
    label: { type: 'string', default: '' },
    // Admission control: uses in flight at most (0: none), and the deadline of a use, in ms.
    cap: { type: 'string', default: '0' },
    'deadline-ms': { type: 'string' },
    // Where each use's answer goes, as JSON lines, for verify-one.ts.
    outcomes: { type: 'string' },
    // The revocation through the uses' pool, not a pool of its own: what a Hyperdrive config for changes saves.
    'control-shared': { type: 'boolean', default: false },
    // `one`: at this many seconds, a day's partition made ahead and the oldest detached and dropped, under load.
    'maintain-at': { type: 'string' },
    // `one`, fewer rows: covers held for this many ms, and the share of uses that go without (as distinct reads would).
    'cover-ms': { type: 'string' },
    distinct: { type: 'string', default: '0' },
  },
});
if (values.url === undefined) throw new Error('--url names the database (through the relay)');
const VARIANT = values.variant as Variant | 'one';
const ONE = VARIANT === 'one';
const CAP = Number(values.cap);
const DEADLINE = values['deadline-ms'] === undefined ? undefined : Number(values['deadline-ms']);
const RUN = randomUUID().slice(0, 8);
const covers: one.Covers | undefined = values['cover-ms'] === undefined ? undefined : { window: Number(values['cover-ms']), held: new Map() };
const DISTINCT = Number(values.distinct);
const RATE = Number(values.rate);
const SECONDS = Number(values.seconds);
const PRINCIPALS = Number(values.principals);
const ENVIRONMENT = '00000000-0000-4000-8000-000000000001';
const SECRET = '00000000-0000-4000-8000-0000000000a1';
const keys = keysFrom(values.seed);

nameStatements(values.named);
one.nameStatements(values.named);
// Changes have a pool of their own, as the vault's own Hyperdrive binding would be: a revocation never waits behind uses for a connection.
const pool = new pg.Pool({ connectionString: values.url, max: Number(values.pool), connectionTimeoutMillis: Number(values['queue-ms']) });
pool.on('error', () => {});
const control = values['control-shared'] ? pool : new pg.Pool({ connectionString: values.url, max: 2 });
control.on('error', () => {});
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

type Run = { sent: number; ms: number; status: number; code: string; statements: number; tries: number; principal: string; requestId: string; number?: string; covered?: true };
const runs: Run[] = [];
const pending: Promise<void>[] = [];

// Checkpoints, from their own connection, every --checkpoint-ms.
const checkpoints: { dbMs: number; verifyMs: number; entries: number; signed: boolean; failures: string[] }[] = [];
let checkpointing = true;
const state = ONE ? null : await loadCheckpointState(admin);
const oneState = ONE ? await one.loadCheckpointState(admin) : null;
const mode = VARIANT === 'cas' || ONE ? null : VARIANT;
const kind = values['revoke-kind'] as 'grant' | 'credential';
const checkpointer = (async () => {
  const every = Number(values['checkpoint-ms']);
  while (checkpointing && (mode !== null || ONE) && every > 0) {
    await sleep(every);
    if (!checkpointing) break;
    checkpoints.push(ONE ? await one.checkpoint(admin, keys, oneState!) : await checkpoint(admin, keys, mode!, state!));
  }
})();

let revocation: { ms: number; at: number; seq: string } | null = null;
// Retention under load (`one`): tomorrow's tomorrow's partition made, the oldest detached concurrently and dropped.
const maintainAt = values['maintain-at'] === undefined ? null : Number(values['maintain-at']) * 1000;
let maintaining = false;
let maintenance: string | null = null;
async function maintain(at: number): Promise<void> {
  const ddl = new pg.Client({ connectionString: values.admin ?? values.url });
  await ddl.connect();
  const timed = async (sql: string) => { const t = performance.now(); await ddl.query(sql); return (performance.now() - t).toFixed(0); };
  const ahead = new Date(Date.now() + 3 * 86_400_000).toISOString().slice(0, 10);
  const made = await timed(`SELECT make_day('${ahead}')`);
  const { rows: [oldest] } = await ddl.query(`SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid WHERE i.inhparent = 'entries_uses'::regclass ORDER BY c.relname LIMIT 1`);
  const { rows: [{ n }] } = await ddl.query(`SELECT count(*)::int AS n FROM ${oldest.relname}`);
  const detached = await timed(`ALTER TABLE entries_uses DETACH PARTITION ${oldest.relname} CONCURRENTLY`);
  const dropped = await timed(`DROP TABLE ${oldest.relname}`);
  await ddl.end();
  maintenance = `at ${(at / 1000).toFixed(0)} s: made ${ahead}'s partition in ${made} ms; detached ${oldest.relname} (${n} entries) in ${detached} ms, dropped in ${dropped} ms`;
}
const revokeAt = values['revoke-at'] === undefined ? null : Number(values['revoke-at']) * 1000;
let revoking = false;

// The rig's own CPU: this process (the load and the vault's work) and the relay.
const relayCpu = () => {
  if (values['relay-pid'] === undefined) return NaN;
  const fields = readFileSync(`/proc/${values['relay-pid']}/stat`, 'utf8').split(') ')[1]!.split(' ');
  return (Number(fields[11]) + Number(fields[12])) * 10; // utime + stime, in ms at 100 ticks a second
};
const relayBefore = relayCpu();
const selfBefore = process.cpuUsage();
// How many uses wait for a connection, sampled every 50 ms.
const waiting: number[] = [];
const sampler = setInterval(() => waiting.push(pool.waitingCount), 50);
let inFlight = 0;
let inFlightMax = 0;
const LATE = Symbol('late');
const revokeOp: one.Op = kind === 'credential' ? { op: 'credential.revoke', credential: 'cred-svc-0' } : { op: 'access.revoke', environment: ENVIRONMENT };
const restoreOp: one.Op = kind === 'credential' ? { op: 'credential.restore', credential: 'cred-svc-0' } : { op: 'access.grant', environment: ENVIRONMENT, role: 'viewer' };
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
    const revoked = ONE
      ? one.change(control, keys, 'svc-0', revokeOp).then((done) => ({ seq: done.number }))
      : change(control, keys, mode ?? 'head', 'svc-0', false, ENVIRONMENT, kind);
    pending.push(revoked.then((done) => {
      revocation = { ms: performance.now() - began, at: performance.now() - start, seq: done.seq };
    }, (error: Error) => console.log(`  revocation FAILED: ${error.message}`)));
  }
  if (maintainAt !== null && !maintaining && performance.now() - start >= maintainAt) {
    maintaining = true;
    const at = performance.now() - start;
    pending.push(maintain(at).catch((error: Error) => { maintenance = `FAILED: ${error.message}`; }));
  }
  const principal = `svc-${n % PRINCIPALS}`;
  const sent = performance.now() - start;
  n += 1;
  const requestId = `${RUN}-${n}`;
  if (CAP > 0 && inFlight >= CAP) {
    // Admission control: refused at once, no statement sent.
    runs.push({ sent, ms: performance.now() - start - sent, status: 503, code: 'overloaded', statements: 0, tries: 0, principal, requestId });
  } else {
    inFlight += 1;
    inFlightMax = Math.max(inFlightMax, inFlight);
    const input = { principal, credential: `cred-${principal}`, environmentId: ENVIRONMENT, secretId: SECRET, requestId };
    const call = (ONE ? one.use(pool, keys, input, DEADLINE === undefined ? undefined : Date.now() + DEADLINE, Math.random() < DISTINCT ? undefined : covers) : use(pool, keys, VARIANT as Variant, input)) as Promise<
      { ok: true; statements: number; tries?: number; number?: string; covered?: true } | { ok: false; code: string; retryAfter?: number; statements: number; tries?: number; number?: string }
    >;
    // The slot is held until the call is done, answered or not: it bounds the work in flight, not the answers.
    const done = call.finally(() => { inFlight -= 1; });
    pending.push(
      (DEADLINE === undefined ? done : Promise.race([done, sleep(DEADLINE).then((): typeof LATE => LATE)])).then(
        (a) => {
          if (a === LATE) {
            runs.push({ sent, ms: performance.now() - start - sent, status: 503, code: 'deadline', statements: 0, tries: 0, principal, requestId });
            return;
          }
          runs.push({ sent, ms: performance.now() - start - sent, status: a.ok ? 200 : a.retryAfter === undefined ? 403 : 503, code: a.ok ? (a.covered ? 'covered' : 'ok') : a.code, statements: a.statements, tries: a.tries ?? 1, principal, requestId, number: a.number, covered: a.ok ? a.covered : undefined });
        },
        (error: Error & { code?: string }) => {
          // A connection not had in time, or a lock or statement that ran out: 503 with Retry-After, at once.
          const busy = /timeout exceeded when trying to connect/.test(error.message) || error.code === '55P03' || error.code === '57014';
          runs.push({ sent, ms: performance.now() - start - sent, status: busy ? 503 : 500, code: error.code ?? error.message.slice(0, 40), statements: 0, tries: 0, principal, requestId });
        },
      ),
    );
    // A call the deadline answered still runs to its end: wait for it too.
    if (DEADLINE !== undefined) pending.push(done.then(() => {}, () => {}));
  }
  next += -Math.log(1 - Math.random()) * (1000 / RATE);
}
await Promise.all(pending);
const elapsed = (performance.now() - start) / 1000;
const cpuAfter = cpu();
clearInterval(sampler);
const self = process.cpuUsage(selfBefore);
const relayMs = relayCpu() - relayBefore;
checkpointing = false;
await checkpointer;

const ok = runs.filter((r) => r.status === 200);
const repeats = runs.filter((r) => r.covered).length;
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
  `stmts ${statements.toFixed(2)}`, `retried ${retried}`, ...(covers === undefined ? [] : [`entries/use ${((runs.length - repeats) / Math.max(1, runs.length)).toFixed(3)} (${repeats} on a cover)`]),
  `pg cpu ${(pgCpuMs / elapsed / 10).toFixed(0)}% of a core (${(pgCpuMs / Math.max(1, runs.length)).toFixed(3)} ms/use)`,
  `1st/5th p50 ${percentile(fifth(0), 50).toFixed(1)}/${percentile(fifth((SECONDS * 4000) / 5), 50).toFixed(1)}`,
  `failed ${runs.length - ok.length}${failed.size === 0 ? '' : ` ${JSON.stringify(Object.fromEntries(failed))}`}`,
  refused.length === 0 ? '' : `503 p50/p99 ${percentile(refused, 50).toFixed(0)}/${percentile(refused, 99).toFixed(0)} ms`,
].join('  '));

if (values.outcomes !== undefined) writeFileSync(values.outcomes, runs.map((r) => JSON.stringify({ requestId: r.requestId, status: r.status, code: r.code, number: r.number ?? null, covered: r.covered ?? false })).join('\n') + '\n');
console.log(`  rig: load generator ${((self.user + self.system) / 1000 / elapsed / 10).toFixed(0)}% of a core, relay ${(relayMs / elapsed / 10).toFixed(0)}% of a core; uses waiting for a connection mean ${(waiting.reduce((a, b) => a + b, 0) / Math.max(1, waiting.length)).toFixed(0)}, max ${Math.max(0, ...waiting)}${CAP > 0 ? `; in flight max ${inFlightMax} (cap ${CAP})` : ''}`);

if (checkpoints.length > 0) {
  const db = checkpoints.map((c) => c.dbMs).sort((a, b) => a - b);
  const verify = checkpoints.map((c) => c.verifyMs).sort((a, b) => a - b);
  const entries = checkpoints.reduce((s, c) => s + c.entries, 0);
  const failures = checkpoints.flatMap((c) => c.failures);
  const signed = checkpoints.filter((c) => c.signed).length;
  console.log(`  checkpoints: ${signed} signed of ${checkpoints.length} ticks, ${entries} entries (${(entries / Math.max(1, signed)).toFixed(0)} each), db p50/max ${percentile(db, 50).toFixed(1)}/${db.at(-1)!.toFixed(1)} ms, verify+sign p50/max ${percentile(verify, 50).toFixed(1)}/${verify.at(-1)!.toFixed(1)} ms (${(verify.reduce((a, b) => a + b, 0) / Math.max(1, entries) * 1000).toFixed(1)} µs/entry), ${failures.length === 0 ? 'all verified' : `FAILURES ${failures.slice(0, 5).join(', ')}`}`);
}

if (maintenance !== null) {
  // Latency around it: the uses sent in the 5 s from it, against the run's.
  const window = ok.filter((r) => r.sent >= maintainAt! && r.sent < maintainAt! + 5000).map((r) => r.ms).sort((a, b) => a - b);
  console.log(`  retention ${maintenance}; uses sent in the 5 s from then: p50 ${percentile(window, 50).toFixed(1)}, p99 ${percentile(window, 99).toFixed(1)}, max ${(window.at(-1) ?? NaN).toFixed(0)} ms`);
}

if (revocation !== null) {
  const r = revocation as { ms: number; at: number; seq: string };
  const after = runs.filter((x) => x.principal === 'svc-0' && x.sent > r.at);
  const allowed = after.filter((x) => x.status === 200).length;
  const codes = new Map<string, number>();
  for (const x of after) if (x.status !== 200) codes.set(x.code, (codes.get(x.code) ?? 0) + 1);
  console.log(`  revocation (${kind}): took ${r.ms.toFixed(1)} ms; svc-0 uses sent after its answer: ${after.length}, allowed: ${allowed} (must be 0); refused ${JSON.stringify(Object.fromEntries(codes))}`);
  // The case the count above cannot see: a use that read before the revocation and appended after it. In the log,
  // no use by svc-0 allowed at a revision before the revocation's may have been written after the revocation was.
  const inFlight = runs.filter((x) => x.principal === 'svc-0' && x.sent < r.at && x.sent + x.ms > r.at - r.ms).length;
  if (ONE) {
    // `one`: no use numbered before the revocation was written after it, and none numbered after it was allowed.
    const { rows: [audit] } = await admin.query(
      `SELECT count(*) FILTER (WHERE u.number < c.number AND u.written_at > c.written_at)::int AS late,
              count(*) FILTER (WHERE u.number < c.number)::int AS before
       FROM entries u, entries c WHERE c.number = $1 AND u.principal = 'svc-0' AND u.kind = 'use' AND u.request_id LIKE $2`,
      [r.seq, `${RUN}-%`],
    );
    const allowedAfter = runs.filter((x) => x.principal === 'svc-0' && x.status === 200 && x.number !== undefined && BigInt(x.number) > BigInt(r.seq)).length;
    console.log(`  revocation, in the log: svc-0 uses in flight while it ran: ${inFlight}; entries numbered before it ${audit.before}, of which written after it ${audit.late} (must be 0); numbered after it and allowed ${allowedAfter} (must be 0)`);
    await one.change(control, keys, 'svc-0', restoreOp);
  } else {
    const { rows: [audit] } = await admin.query(
      `SELECT count(*) FILTER (WHERE u.revision < c.revision AND u.written_at > c.written_at)::int AS late,
              count(*) FILTER (WHERE u.revision >= c.revision)::int AS after,
              count(*) FILTER (WHERE u.revision < c.revision)::int AS before
       FROM audit u, audit c WHERE c.seq = $1 AND u.subject = 'svc-0' AND u.action = 'secret.use' AND u.decision = 'allow'`,
      [r.seq],
    );
    console.log(`  revocation, in the log: svc-0 uses in flight while it ran: ${inFlight}; allowed entries before it ${audit.before}, of which written after it ${audit.late} (must be 0); allowed at or after its revision ${audit.after} (must be 0)`);
    await change(control, keys, mode ?? 'head', 'svc-0', true, ENVIRONMENT, kind);
  }
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
if (control !== pool) await control.end();
