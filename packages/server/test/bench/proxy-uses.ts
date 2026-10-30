// `/use` at a steady rate beside ci.ts's sign-ins (PR 5b, R44, R58): the credential proxy's inject on a person's handle,
// through the whole app, as a Node deployment serves it: one runtime, the vault in process, each Postgres connection one
// round trip away through a relay of its own (`farPostgres`), on a thread of its own so that the sign-ins' work never
// delays a request's timer. The proxy keeps no value (`cacheSeconds: 0`): every request opens its key, 0.14's unwrap or
// 0.15's use, the hot path at its worst. Each request is timed from when it was due to its answer, and counted refused
// unless the upstream got the real key. The main thread names a phase (`phase`) and gets each phase's numbers back
// (`report`), as uses.ts's. Not a test.
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { parentPort, workerData } from 'node:worker_threads';

import { github, signin } from '@coffre/core/identity';
import { createDatabase } from '@coffre/db';
import { postgresClient } from '@coffre/db/connect';
import { localVault } from '@coffre/vault/node';

import { resolveConfig } from '../../src/config.ts';
import { checkPlugins } from '../../src/plugins.ts';
import { credentialProxy, header } from '../../src/plugins/credential-proxy.ts';
import { createRuntime } from '../../src/runtime.ts';
import { answer, type Pages } from '../start-fixture.ts';
import { farPostgres } from './far.ts';

/** A phase as one thread saw it: each request's latency, the refusals, and the thread's CPU, µs. The main thread merges threads. */
export type ProxyPhase = { phase: string; sent: number; latencies: number[]; refused: Record<string, number>; cpuUs: number };

export type ProxyLoad = {
  log: '0.14' | '0.15';
  urls: { app: string; vault: string; hot: string };
  rtt: number;
  rate: number;
  /** Each pool's connections: the app's, the vault's and the hot path's. */
  pools: { app: number; vault: number; hot: number };
  handles: string[];
  path: string;
  value: string;
  kek: string;
  owner: string;
  chainKey: string;
  origin: string;
  /** The proxy's `cacheSeconds`: 0, every request opens its key; its default, 60, as a deployment runs it. */
  cacheSeconds: number;
  /** The stable URL, `/use/<credential>/…`, as an app's own config names it (R14), which asks first which environment the handle was made for; else the environment's. */
  stable: boolean;
  /**
   * 0.15's vault's map of names (T145, `UseLimits.names`), its cap: 0, every request's use reads its names first, then is made,
   * the worst case; under the handles a thread sends, each picked at random, that share of them misses. Unset, its
   * default, and the handles in turn: every request warm.
   */
  names?: number;
};

const load = workerData as ProxyLoad;
const [farApp, farVault, farHot] = await Promise.all([farPostgres(load.urls.app, load.rtt), farPostgres(load.urls.vault, load.rtt), farPostgres(load.urls.hot, load.rtt)]);
// Kept open, as Hyperdrive keeps its own, every connection made before the first phase.
const sizes = [load.pools.app, load.pools.vault, load.pools.hot];
const pools = [farApp, farVault, farHot].map((far, i) => postgresClient(far.url, { max: sizes[i] }));
// As many statements at once as each pool has connections: every one open.
await Promise.all(pools.flatMap((pool, i) => Array.from({ length: sizes[i]! }, () => pool.unsafe('SELECT pg_sleep(0.05)'))));
const [appPool, vaultPool, hotPool] = pools as [ReturnType<typeof postgresClient>, ReturnType<typeof postgresClient>, ReturnType<typeof postgresClient>];

const upstream = createServer((request, response) => {
  response.writeHead(request.headers['x-api-key'] === load.value ? 200 : 403);
  response.end();
});
await new Promise<void>((resolve) => upstream.listen(0, '127.0.0.1', resolve));

const vault = await localVault(
  { database: createDatabase(vaultPool), ...(load.log === '0.15' ? { hotDatabase: createDatabase(hotPool) } : {}), kek: { id: 'test-kek-1', key: load.kek }, owners: [load.owner], bulkLimit: { count: 1_000_000, windowMinutes: 1 } },
  // This thread changes nothing but the policy at its start: the main thread's checkpointer seals it on its next tick.
  load.log === '0.15' ? { log: '0.15', sealThrough: async () => ({}) as never, ...(load.names === undefined ? {} : { uses: { names: load.names } }) } : {},
);
const config = resolveConfig({
  publicUrl: load.origin,
  vault,
  auth: signin({ providers: [github({ clientId: 'a', clientSecret: 'b' })] }),
  auditChainKey: load.chainKey,
  plugins: [credentialProxy({
    credentials: { api: { upstream: `http://127.0.0.1:${(upstream.address() as AddressInfo).port}/v1`, inject: header('x-api-key', '{API_KEY}') } },
    insecureUpstreams: true,
    cacheSeconds: load.cacheSeconds,
  })],
});
const runtime = createRuntime(config, createDatabase(appPool), vault, { json: async (url) => { throw new Error(`no fetch of ${url.href} here`); } });
runtime.plugins = checkPlugins(config.plugins);
const ui = {} as Pages;

type Phase = { phase: string; latencies: number[]; refused: Map<string, number>; sent: number; cpuUs: number };
let cpuFrom: number | null = null;
const threadCpu = () => { const { user, system } = process.threadCpuUsage(); return user + system; };
const phases: Phase[] = [];
let current = null as Phase | null;
let running = true;
const inflight = new Set<Promise<void>>();
let next = 0;

const use = async (phase: Phase, due: number) => {
  // At random under a map smaller than the handles: in turn, each would be the one just dropped.
  const handle = load.handles[load.names === undefined ? next++ % load.handles.length : Math.floor(Math.random() * load.handles.length)]!;
  try {
    // As an app's own config names them (R14): the stable URL with the API's path after it, `/use/<credential>/v1/…`.
    const url = load.stable ? `${load.origin}/use/api/v1/thing` : `${load.origin}/use/${load.path}/api/v1/thing`;
    const response = await answer(new Request(url, { headers: { 'x-api-key': handle } }), runtime, ui, '203.0.113.7');
    if (response.status !== 200) {
      const why = `${response.status} ${(await response.text()).slice(0, 80)}`;
      phase.refused.set(why, (phase.refused.get(why) ?? 0) + 1);
    } else await response.arrayBuffer();
  } catch (error) {
    const why = String((error as Error).message).slice(0, 80);
    phase.refused.set(why, (phase.refused.get(why) ?? 0) + 1);
  } finally {
    phase.latencies.push(performance.now() - due);
  }
};

const sender = (async () => {
  let start = performance.now();
  let sent = 0;
  let of: Phase | null = null;
  while (running) {
    if (current !== of) {
      of = current;
      start = performance.now();
      sent = 0;
    }
    if (of !== null) {
      const due = Math.floor(((performance.now() - start) / 1000) * load.rate);
      for (; sent < due; sent += 1) {
        of.sent += 1;
        const p = use(of, start + (sent * 1000) / load.rate).finally(() => inflight.delete(p));
        inflight.add(p);
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 1));
  }
})();

const summary = ({ phase, latencies, refused, sent, cpuUs }: Phase): ProxyPhase => ({ phase, sent, latencies, refused: Object.fromEntries(refused), cpuUs });

parentPort!.on('message', async (message: { phase?: string | null; report?: true }) => {
  if (message.phase !== undefined) {
    if (current !== null && cpuFrom !== null) current.cpuUs += threadCpu() - cpuFrom;
    current = message.phase === null ? null : phases.find(({ phase }) => phase === message.phase) ?? null;
    if (message.phase !== null && current === null) phases.push((current = { phase: message.phase, latencies: [], refused: new Map(), sent: 0, cpuUs: 0 }));
    cpuFrom = current === null ? null : threadCpu();
    parentPort!.postMessage({ ok: true });
  }
  if (message.report) {
    current = null;
    running = false;
    await sender;
    await Promise.all(inflight);
    await vault.close();
    await Promise.all(pools.map((pool) => pool.end()));
    await Promise.all([farApp, farVault, farHot].map((far) => far.close()));
    await new Promise<void>((resolve) => upstream.close(() => resolve()));
    parentPort!.postMessage({ phases: phases.map(summary) });
  }
});
parentPort!.postMessage({ ready: true });
