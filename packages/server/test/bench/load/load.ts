// Open-loop load: requests sent at a fixed rate whatever the answers, each
// timed from when it was due, not when it went out, so a server that falls
// behind is charged for the queue it makes (no coordinated omission).
//
//   node load.ts --url http://127.0.0.1:57130 --rate 300 [--warmup 10] [--duration 60] [--token bench-ci-token] [--keys 100]
//
// One single-key reveal each, `POST /api/reveals {"path":"bench/prod/KEY_<n>"}`,
// the keys taken in turn. Prints one JSON line: the measured window's
// latencies, its answers by status and error code, and how late the sends
// themselves were (the generator's own health).
import { Agent, request } from 'node:http';
import { readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';

import { bodyDigest, createProof, type PublicJwk } from '@coffre/client/dpop';

const { values } = parseArgs({
  options: {
    url: { type: 'string' },
    rate: { type: 'string' },
    warmup: { type: 'string', default: '10' },
    duration: { type: 'string', default: '60' },
    token: { type: 'string', default: 'bench-ci-token' },
    keys: { type: 'string', default: '100' },
    path: { type: 'string', default: '/api/reveals' },
    place: { type: 'string', default: 'bench/prod' },
    timeout: { type: 'string', default: '30' },
    // The generator's connections: a fixed keep-alive pool. A request due while every one is busy is shed by the
    // client (counted, never sent), so arrivals stay open-loop and the generator never piles connections on.
    connections: { type: 'string', default: '256' },
    // reveal: POST /api/reveals, one key; the proxy run's (W422): handle-full, GET /use/market/apis/echo/ping, and
    // handle-stable, GET /use/echo/ping, each with the handle; workload, GET /use/echo/ping by the sessions in turn,
    // each request with a proof of its own under its service's latest nonce.
    mode: { type: 'string', default: 'reveal' },
    callers: { type: 'string' },
    // Marks at these seconds into the measured window, for the driver's outage: stop, then start.
    at: { type: 'string', default: '' },
  },
});
const mode = values.mode!;
const rate = Number(values.rate);
const [warmup, duration, keys, timeoutMs] = [Number(values.warmup), Number(values.duration), Number(values.keys), Number(values.timeout) * 1000];
const connections = Number(values.connections);
const agent = new Agent({ keepAlive: true, maxSockets: connections, maxFreeSockets: connections });

type Result = { due: number; ms: number; status: number; code: string | null };
const results: Result[] = [];
let lateMax = 0;
let lateSum = 0;
let inflight = 0;
let inflightMax = 0;

type Callers = { handle: string; sessions: { service: string; token: string; jwk: PublicJwk; privateJwk: JsonWebKey }[] };
const callers = values.callers === undefined ? null : (JSON.parse(readFileSync(values.callers, 'utf8')) as Callers);
const sessions = callers === null ? [] : await Promise.all(callers.sessions.map(async (s) => ({ ...s, key: { privateKey: await crypto.subtle.importKey('jwk', s.privateJwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']), jwk: s.jwk } })));
/** Each service's gate's nonce, as its latest answer gave it. */
const nonces = new Map<string, string>();
const emptyDigest = mode === 'workload' ? await bodyDigest(new Uint8Array()) : '';
const PUBLIC = 'https://secrets.acme.example';

/** The request `i`: its path, method, headers and body, and for a session, the service whose nonce its answer carries. */
async function build(i: number): Promise<{ path: string; method: string; headers: Record<string, string>; body: string | null; service?: string }> {
  if (mode === 'reveal') {
    const body = JSON.stringify({ path: `${values.place}/KEY_${i % keys}` });
    return { path: values.path!, method: 'POST', body, headers: { authorization: `Bearer ${values.token}`, 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(body)) } };
  }
  if (mode === 'handle-full') return { path: '/use/market/apis/echo/ping', method: 'GET', body: null, headers: { authorization: `Bearer ${callers!.handle}` } };
  if (mode === 'handle-stable') return { path: '/use/echo/ping', method: 'GET', body: null, headers: { authorization: `Bearer ${callers!.handle}` } };
  const session = sessions[i % sessions.length]!;
  const nonce = nonces.get(session.service);
  const content = { headers: { 'x-request': 'one' }, body: emptyDigest };
  const dpop = await createProof(session.key, { method: 'GET', url: `${PUBLIC}/use/echo/ping`, token: session.token, content, ...(nonce === undefined ? {} : { nonce }) });
  return { path: '/use/echo/ping', method: 'GET', body: null, service: session.service, headers: { authorization: `DPoP ${session.token}`, dpop, ...content.headers } };
}

function send(i: number, due: number): void {
  void build(i).then((built) => fire(built, due), (error) => results.push({ due, ms: performance.now() - due, status: -1, code: `build: ${String(error)}` }));
}

function fire(built: Awaited<ReturnType<typeof build>>, due: number): void {
  const { body } = built;
  const late = performance.now() - due;
  lateMax = Math.max(lateMax, late);
  lateSum += late;
  if (inflight >= connections) {
    results.push({ due, ms: 0, status: 0, code: 'shed' });
    return;
  }
  inflight += 1;
  inflightMax = Math.max(inflightMax, inflight);
  let done = false;
  const finish = (status: number, code: string | null) => {
    if (done) return;
    done = true;
    inflight -= 1;
    results.push({ due, ms: performance.now() - due, status, code });
  };
  const req = request(new URL(built.path, values.url), { method: built.method, agent, headers: built.headers }, (res) => {
    const nonce = res.headers['dpop-nonce'];
    if (built.service !== undefined && typeof nonce === 'string') nonces.set(built.service, nonce);
    const chunks: Buffer[] = [];
    res.on('data', (chunk: Buffer) => chunks.push(chunk));
    res.on('end', () => {
      const status = res.statusCode ?? 0;
      let code: string | null = null;
      const text = Buffer.concat(chunks).toString('utf8');
      if (status !== 200) code = /"(?:code|reason)"\s*:\s*"([^"]+)"/.exec(text)?.[1] ?? /"error"\s*:\s*"([^"]+)"/.exec(text)?.[1] ?? text.slice(0, 60);
      finish(status, code);
    });
    res.on('error', (error) => finish(-1, `response: ${error.message}`));
  });
  req.setTimeout(timeoutMs, () => req.destroy(new Error('timeout')));
  req.on('error', (error) => finish(-1, (error as NodeJS.ErrnoException).code ?? error.message));
  req.end(body ?? undefined);
}

const total = Math.round(rate * (warmup + duration));
const start = performance.now() + 50;
// Marks for whoever reads the counters around the measured window: its start, and its last send.
setTimeout(() => console.log(JSON.stringify({ mark: 'start' })), start + warmup * 1000 - performance.now());
for (const second of values.at!.split(',').filter(Boolean).map(Number)) setTimeout(() => console.log(JSON.stringify({ mark: 'at', second })), start + (warmup + second) * 1000 - performance.now());
let next = 0;
await new Promise<void>((resolve) => {
  const tick = () => {
    const now = performance.now();
    while (next < total && start + (next * 1000) / rate <= now) {
      send(next, start + (next * 1000) / rate);
      next += 1;
    }
    if (next < total) setImmediate(tick);
    else {
      console.log(JSON.stringify({ mark: 'end' }));
      resolve();
    }
  };
  tick();
});
// Every request answered, or timed out.
while (results.length < total) await new Promise((resolve) => setTimeout(resolve, 50));
agent.destroy();

const measuredFrom = start + warmup * 1000;
const measured = results.filter((r) => r.due >= measuredFrom);
// Latency over the requests sent; those the client shed are counted apart.
const ms = measured.filter((r) => r.status !== 0).map((r) => r.ms).sort((a, b) => a - b);
const at = (q: number) => (ms.length === 0 ? null : Math.round(ms[Math.min(ms.length - 1, Math.floor(q * ms.length))]! * 100) / 100);
const tally = (of: (r: Result) => string | null) => {
  const counts: Record<string, number> = {};
  for (const r of measured) {
    const key = of(r);
    if (key !== null) counts[key] = (counts[key] ?? 0) + 1;
  }
  return counts;
};
// Per second of the measured window: answers, and the slowest.
const seconds = Array.from({ length: duration }, (_, s) => {
  const of = measured.filter((r) => r.status !== 0 && Math.floor((r.due - measuredFrom) / 1000) === s);
  const shed = measured.filter((r) => r.status === 0 && Math.floor((r.due - measuredFrom) / 1000) === s).length;
  const codes: Record<string, number> = {};
  for (const r of of) if (r.status !== 200) codes[`${r.status} ${r.code}`] = (codes[`${r.status} ${r.code}`] ?? 0) + 1;
  return { n: of.length, shed, errors: of.filter((r) => r.status !== 200).length, codes, p50: of.length === 0 ? null : Math.round([...of.map((r) => r.ms)].sort((a, b) => a - b)[Math.floor(0.5 * of.length)]!), p99: of.length === 0 ? null : Math.round([...of.map((r) => r.ms)].sort((a, b) => a - b)[Math.floor(0.99 * of.length)]!) };
});
console.log(JSON.stringify({
  rate, warmup, duration, connections, due: total, measured: measured.length, shed: measured.filter((r) => r.status === 0).length,
  p50: at(0.5), p90: at(0.9), p99: at(0.99), p999: at(0.999), max: at(1),
  statuses: tally((r) => String(r.status)), codes: tally((r) => (r.status === 200 ? null : `${r.status} ${r.code}`)),
  sendLateMaxMs: Math.round(lateMax), sendLateMeanMs: Math.round((lateSum / total) * 100) / 100, inflightMax,
  seconds,
}));
