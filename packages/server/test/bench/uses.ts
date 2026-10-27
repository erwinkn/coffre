// Uses at a steady rate beside ci.ts's sign-ins (T123, R58): `use_credential`
// called as 0.15's hot path's login, each call one round trip through a relay
// of its own (`farPostgres`), on a thread of its own so that the sign-ins'
// work never delays a use's timer. Each use is timed from when it was due
// to its answer, a wait for a connection included, as a Worker's request
// waits for Hyperdrive's. The main thread names a phase (`phase`), and gets
// each phase's numbers back (`report`): p50, p99 and max, and the uses
// refused: an answer of the database's own (`late`, `ahead`,
// `unconfigured`) or an error (a lock or statement timeout). With `cold`,
// that many uses a second more each open a connection of their own, a new
// backend whose first call plans the statement, make their one call and
// close it, timed from when they were due to their answer; the others are
// counted apart from them. Not a test.
import { createHmac, hkdfSync, randomBytes } from 'node:crypto';
import { parentPort, workerData } from 'node:worker_threads';

import { macData } from '@coffre/core/merkle';
import { postgresClient } from '@coffre/db/connect';

import { farPostgres, percentile } from './far.ts';

export type UseLoad = { url: string; rtt: number; rate: number; pool: number; cold: number; credentials: string[]; secrets: string[]; seed: Uint8Array };
export type UsePhase = {
  phase: string;
  sent: number;
  p50: number;
  p90: number;
  p99: number;
  p999: number;
  max: number;
  slow: number;
  refused: Record<string, number>;
  /** The uses each on a new backend (`cold`), apart from the others above: how many, their p50 and max. */
  cold: number;
  coldP50: number;
  coldMax: number;
};

const load = workerData as UseLoad;
// Each entry MACed as the checkpointer checks it, which seals nothing past one that fails (packages/vault/src/log-entry.ts).
const macKey = Buffer.from(hkdfSync('sha256', load.seed, new Uint8Array(0), 'coffre.log.mac.v1', 32));
const mac = (row: { at: number; requestId: bigint; credential: string; secret: string; purpose: number }) =>
  createHmac('sha256', macKey).update(macData('uses', [BigInt(row.at), row.requestId, row.credential, row.secret, row.purpose, null])).digest().subarray(0, 16);
const far = await farPostgres(load.url, load.rtt);
// Kept open, as Hyperdrive keeps its own.
const pool = postgresClient(far.url, { max: load.pool });
// Every connection open before the first phase: as many statements at once as the pool has connections.
await Promise.all(Array.from({ length: load.pool }, () => pool.unsafe('SELECT pg_sleep(0.05)')));

type Phase = { phase: string; latencies: number[]; cold: number[]; refused: Map<string, number>; sent: number };
const phases: Phase[] = [];
let current = null as Phase | null;
let running = true;
const inflight = new Set<Promise<void>>();

/** One use, on the pool's connections, or on a new connection of its own (`cold`). */
const use = async (phase: Phase, due: number, cold = false) => {
  const row = { at: Date.now(), requestId: randomBytes(8).readBigUInt64BE() >> 1n, credential: load.credentials[Math.floor(Math.random() * load.credentials.length)]!, secret: load.secrets[Math.floor(Math.random() * load.secrets.length)]!, purpose: 4 };
  const own = cold ? postgresClient(far.url, { max: 1 }) : pool;
  try {
    const rows = await own.unsafe<{ use: { state: string | null } }[]>(
      'SELECT use_credential($1, $2, $3, $4, 4::smallint, NULL, $5, $6) AS use',
      [row.credential, row.secret, row.requestId.toString(), String(row.at), mac(row), String(row.at + 3000)],
    );
    const state = rows[0]!.use.state;
    if (state !== null) phase.refused.set(state, (phase.refused.get(state) ?? 0) + 1);
  } catch (error) {
    const code = String((error as { code?: string }).code ?? (error as Error).message);
    phase.refused.set(code, (phase.refused.get(code) ?? 0) + 1);
  } finally {
    (cold ? phase.cold : phase.latencies).push(performance.now() - due);
    if (cold) await own.end();
  }
};

const sender = (async () => {
  let start = performance.now();
  let sent = 0;
  let coldSent = 0;
  let of: Phase | null = null;
  while (running) {
    if (current !== of) {
      of = current;
      start = performance.now();
      sent = 0;
      coldSent = 0;
    }
    if (of !== null) {
      const due = Math.floor(((performance.now() - start) / 1000) * load.rate);
      for (; sent < due; sent += 1) {
        of.sent += 1;
        const p = use(of, start + (sent * 1000) / load.rate).finally(() => inflight.delete(p));
        inflight.add(p);
      }
      const coldDue = Math.floor(((performance.now() - start) / 1000) * load.cold);
      for (; coldSent < coldDue; coldSent += 1) {
        const p = use(of, start + (coldSent * 1000) / load.cold, true).finally(() => inflight.delete(p));
        inflight.add(p);
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 1));
  }
})();

const summary = ({ phase, latencies, cold, refused, sent }: Phase): UsePhase => {
  const sorted = [...latencies].sort((a, b) => a - b);
  const colds = [...cold].sort((a, b) => a - b);
  // Slow: past two round trips, a use that waited on something.
  const slow = sorted.filter((ms) => ms > 2 * load.rtt).length / Math.max(1, sorted.length);
  return { phase, sent, p50: percentile(sorted, 50), p90: percentile(sorted, 90), p99: percentile(sorted, 99), p999: percentile(sorted, 99.9), max: sorted.at(-1) ?? 0, slow,
    refused: Object.fromEntries(refused), cold: colds.length, coldP50: colds.length === 0 ? 0 : percentile(colds, 50), coldMax: colds.at(-1) ?? 0 };
};

parentPort!.on('message', async (message: { phase?: string | null; report?: true }) => {
  if (message.phase !== undefined) {
    // A phase named again goes on where it left off: a level's rounds, say.
    current = message.phase === null ? null : phases.find(({ phase }) => phase === message.phase) ?? null;
    if (message.phase !== null && current === null) phases.push((current = { phase: message.phase, latencies: [], cold: [], refused: new Map(), sent: 0 }));
    parentPort!.postMessage({ ok: true });
  }
  if (message.report) {
    current = null;
    running = false;
    await sender;
    await Promise.all(inflight);
    await pool.end();
    await far.close();
    parentPort!.postMessage({ phases: phases.map(summary) });
  }
});
parentPort!.postMessage({ ready: true });
