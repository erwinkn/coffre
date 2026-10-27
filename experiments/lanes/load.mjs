// An open-loop load on the prototype: requests arrive at `--rate` a second
// (Poisson) for `--seconds`, whether or not the earlier ones are done, each
// from one of `--principals` principals in turn. Prints the latency
// percentiles of what succeeded, what failed and how fast, and whether
// latency grew from the first fifth of the run to the last: a queue that
// grows.
//
// --revoke-at <s> takes svc-0's grant away that far into the run (POST
// /revoke), and counts every use by svc-0 sent after the revocation's
// answer that still succeeded: each one a use ordered after a revocation,
// which must be refused. The grant is given back after the run.
//
// W211: --secrets <n> sends k=<j>, each principal's uses going round n keys;
// request ids are random 63-bit numbers (`one`'s). --tick-path <path>
// --tick-ms <ms> POSTs there every tick-ms, one at a time, through the run (the
// checkpointer, on the changes' Hyperdrive config, which it keeps warm).
//
//   node experiments/lanes/load.mjs --base https://… --path /use/v2 [--rate 100] [--seconds 30] [--principals 50]
import http from 'node:http';
import https from 'node:https';
import { randomBytes } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { parseArgs } from 'node:util';

const { values } = parseArgs({
  options: {
    base: { type: 'string' },
    path: { type: 'string', default: '/use/v2' },
    query: { type: 'string', default: '' },
    rate: { type: 'string', default: '50' },
    seconds: { type: 'string', default: '20' },
    principals: { type: 'string', default: '50' },
    offset: { type: 'string', default: '0' },
    'revoke-at': { type: 'string' },
    mode: { type: 'string', default: 'lanes' },
    // Where a revocation and the grant given back after go, for protocols with their own (v5: /v5/revoke, /v5/grant).
    'revoke-path': { type: 'string' },
    'grant-path': { type: 'string' },
    timeout: { type: 'string', default: '20000' },
    // W208: each use's answer, as JSON lines keyed by its request id (sent as r=), for verify-one.ts.
    outcomes: { type: 'string' },
    label: { type: 'string', default: '' },
    secrets: { type: 'string', default: '1' },
    'tick-path': { type: 'string' },
    'tick-ms': { type: 'string', default: '1000' },
  },
});
const BASE = new URL(values.base);
const RATE = Number(values.rate);
const SECONDS = Number(values.seconds);
const PRINCIPALS = Number(values.principals);
const OFFSET = Number(values.offset);
const TIMEOUT = Number(values.timeout);
const lib = BASE.protocol === 'https:' ? https : http;
const agent = new lib.Agent({ keepAlive: true, maxSockets: 2048 });

/** One request: its status, latency, the Worker's own total and statements, and Retry-After. */
function call(method, path) {
  return new Promise((resolve) => {
    const started = performance.now();
    const req = lib.request(new URL(path, BASE), { method, agent, timeout: TIMEOUT }, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => (body += chunk));
      res.on('end', () => {
        const timing = Object.fromEntries((res.headers['server-timing'] ?? '').split(',').filter(Boolean).map((part) => {
          const [name, dur] = part.trim().split(';dur=');
          return [name, Number(dur)];
        }));
        let code;
        try {
          const parsed = JSON.parse(body);
          code = parsed.code === 'error' ? String(parsed.message).slice(0, 40) : parsed.code;
        } catch {
          code = body.slice(0, 40);
        }
        resolve({ status: res.statusCode, ms: performance.now() - started, timing, code, retryAfter: res.headers['retry-after'], body });
      });
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', (error) => resolve({ status: 0, ms: performance.now() - started, timing: {}, code: error.message.slice(0, 40) }));
    req.end();
  });
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const percentile = (sorted, p) => (sorted.length === 0 ? NaN : sorted[Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1)]);

const runs = [];
const pending = [];
let revokedAt = null;
let revocation = null;
const start = performance.now();
let n = 0;
let next = 0;
const revokeAt = values['revoke-at'] === undefined ? null : Number(values['revoke-at']) * 1000;
const sep = values.path.includes('?') ? '&' : '?';
const SECRETS = Number(values.secrets);
// A request id: random, 63 bits (one.ts's newRequestId).
const requestIdOf = () => (randomBytes(8).readBigUInt64BE() >> 1n).toString();
// The checkpointer: one tick at a time, every --tick-ms, until the run's last request is sent.
const ticks = [];
let ticking = values['tick-path'] !== undefined;
const ticker = (async () => {
  while (ticking) {
    await sleep(Number(values['tick-ms']));
    if (!ticking) break;
    const r = await call('POST', values['tick-path']);
    ticks.push(r);
  }
})();
const withP = (path) => `${path}${path.includes('?') ? '&' : '?'}p=svc-0`;
while (next < SECONDS * 1000) {
  const wait = start + next - performance.now();
  if (wait > 0) await sleep(wait);
  if (revokeAt !== null && revocation === null && performance.now() - start >= revokeAt) {
    revocation = call('POST', values['revoke-path'] === undefined ? `/revoke?p=svc-0&mode=${values.mode}` : withP(values['revoke-path'])).then((r) => {
      revokedAt = performance.now() - start;
      return r;
    });
  }
  const principal = `svc-${OFFSET + (n % PRINCIPALS)}`;
  const sent = performance.now() - start;
  n += 1;
  const requestId = requestIdOf();
  const key = Math.floor((n - 1) / PRINCIPALS) % SECRETS;
  pending.push(call('GET', `${values.path}${sep}p=${principal}${values.query}&k=${key}&r=${requestId}`).then((r) => runs.push({ ...r, sent, principal, requestId })));
  next += -Math.log(1 - Math.random()) * (1000 / RATE);
}
ticking = false;
await Promise.all(pending);
await ticker;
const elapsed = (performance.now() - start) / 1000;

const ok = runs.filter((r) => r.status === 200);
const lat = ok.map((r) => r.ms).sort((a, b) => a - b);
const server = ok.map((r) => r.timing.total).filter((v) => !Number.isNaN(v)).sort((a, b) => a - b);
const failed = new Map();
for (const r of runs) if (r.status !== 200) failed.set(`${r.status} ${r.code}`, (failed.get(`${r.status} ${r.code}`) ?? 0) + 1);
const refusedFast = runs.filter((r) => r.status === 503).map((r) => r.ms).sort((a, b) => a - b);
const fifth = (from) => runs.filter((r) => r.status === 200 && r.sent >= from && r.sent < from + (SECONDS * 1000) / 5).map((r) => r.ms).sort((a, b) => a - b);
const statements = ok.length === 0 ? NaN : ok.reduce((sum, r) => sum + (r.timing.statements ?? 0), 0) / ok.length;

const line = [
  values.label.padEnd(10),
  `${values.path}${values.query}`.padEnd(18),
  `${String(RATE).padStart(4)}/s`,
  `${String(PRINCIPALS).padStart(3)}p`,
  `ok ${(ok.length / elapsed).toFixed(1).padStart(6)}/s`,
  `p50 ${percentile(lat, 50).toFixed(0).padStart(5)}`,
  `p99 ${percentile(lat, 99).toFixed(0).padStart(5)}`,
  `max ${(lat.at(-1) ?? NaN).toFixed(0).padStart(5)} ms`,
  `worker p50/p99 ${percentile(server, 50).toFixed(0)}/${percentile(server, 99).toFixed(0)}`,
  `stmts ${statements.toFixed(1)}`,
  ...(runs.some((r) => r.code === 'covered') ? [`entries/use ${(1 - runs.filter((r) => r.code === 'covered').length / runs.length).toFixed(3)}`] : []),
  `1st/5th p50 ${percentile(fifth(0), 50).toFixed(0)}/${percentile(fifth((SECONDS * 4000) / 5), 50).toFixed(0)}`,
  `failed ${runs.length - ok.length}${failed.size === 0 ? '' : ` ${JSON.stringify(Object.fromEntries(failed))}`}`,
  refusedFast.length === 0 ? '' : `503 p99 ${percentile(refusedFast, 99).toFixed(0)} ms`,
].join('  ');
console.log(line);
if (values.outcomes !== undefined) writeFileSync(values.outcomes, runs.map((r) => JSON.stringify({ requestId: r.requestId, status: r.status, code: r.code ?? (r.status === 200 ? 'ok' : ''), ...(r.code === 'covered' ? { covered: true, number: JSON.parse(r.body).seq } : {}) })).join('\n') + '\n');
// Each statement's time at the Worker, where it says (s1, s2: the first and second statement).
const steps = ['s1', 's2', 's3'].map((name) => [name, ok.map((r) => r.timing[name]).filter((v) => v !== undefined && !Number.isNaN(v)).sort((a, b) => a - b)]).filter(([, v]) => v.length > 0);
const mean = (v) => v.reduce((a, b) => a + b, 0) / v.length;
if (steps.length > 0) console.log(`  statements at the worker: ${steps.map(([name, v]) => `${name} mean ${mean(v).toFixed(1)}, p50/p90/p99 ${percentile(v, 50)}/${percentile(v, 90)}/${percentile(v, 99)} ms`).join(', ')}`);

if (ticks.length > 0) {
  const ms = ticks.map((t) => t.ms).sort((a, b) => a - b);
  const bad = ticks.filter((t) => t.status !== 200);
  console.log(`  ticks: ${ticks.length}, p50/max ${percentile(ms, 50).toFixed(0)}/${ms.at(-1).toFixed(0)} ms${bad.length === 0 ? ', all signed' : `, ${bad.length} FAILED: ${bad.slice(0, 2).map((t) => t.body).join('; ')}`}`);
}
if (revocation !== null) {
  const r = await revocation;
  const after = runs.filter((x) => x.principal === 'svc-0' && revokedAt !== null && x.sent > revokedAt);
  const violations = after.filter((x) => x.status === 200);
  console.log(`  revocation: ${r.status} at ${revokedAt?.toFixed(0)} ms (took ${r.ms.toFixed(0)} ms); svc-0 uses sent after it: ${after.length}, allowed: ${violations.length} (must be 0); refused: ${JSON.stringify(Object.fromEntries(after.filter((x) => x.status !== 200).reduce((m, x) => m.set(`${x.status} ${x.code}`, (m.get(`${x.status} ${x.code}`) ?? 0) + 1), new Map())))}`);
  await call('POST', values['grant-path'] === undefined ? `/grant?p=svc-0&mode=${values.mode}` : withP(values['grant-path']));
}
agent.destroy();
