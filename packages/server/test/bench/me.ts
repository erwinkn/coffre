// What showing a caller costs under load, as on Workers: `GET /api/me`,
// which the CLI and every page's client ask, and a page's shell render
// (`me`, `auth` and the project list through `pageClient`, at once). Each
// request has a Postgres connection to itself (`HyperdrivePool`) and each
// vault call another, a warm isolate's, every statement a round trip to a
// database far away (`farPostgres`). Hyperdrive keeps its connections to
// Postgres open between requests, so each concurrent request reuses one:
// the CPU is the statements', not a backend's start and its login. It reports each level's wall time,
// p50 and p99, its statements on each side, its vault calls and, with
// `--cgroup`, the Postgres container's CPU per request (cpu.stat's
// usage_usec over the requests sent).
// Not part of the suite. On a migrated scratch database, as `pnpm test` makes:
//
//   COFFRE_TEST_DATABASE=<db> node --conditions=coffre:source packages/server/test/bench/me.ts \
//     [--rtt 20] [--requests 400] [--concurrency 1,10,40] [--cgroup /sys/fs/cgroup/system.slice/docker-<id>.scope]
import { randomBytes, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parseArgs } from 'node:util';

import { github, signin } from '@coffre/core/identity';
import type { Vault } from '@coffre/core/vault';
import { createDatabase, type Client } from '@coffre/db';
import { HyperdrivePool } from '@coffre/db/hyperdrive';
import { localVault, type LocalVault } from '@coffre/vault/node';

import { resolveConfig } from '../../src/config.ts';
import { pageClient } from '../../src/fetch-api.ts';
import { createRuntime, type CoffreRuntime } from '../../src/runtime.ts';
import { clientFor, contextFor, openTestDatabase, resetDatabase, testDeps, testVault } from '../api-fixture.ts';
import { answer, type Pages } from '../start-fixture.ts';
import { TEST_RUNTIME_DATABASE_URL, TEST_VAULT_DATABASE_URL } from '../db/connections.ts';
import { watched } from '../db/postgres-pool.ts';
import { farPostgres, percentile } from './far.ts';

const { values } = parseArgs({
  options: {
    rtt: { type: 'string', default: '20' },
    requests: { type: 'string', default: '400' },
    concurrency: { type: 'string', default: '1,10,40' },
    cgroup: { type: 'string' },
  },
});
const RTT = Number(values.rtt);
const cpuUsec = () => (values.cgroup === undefined ? 0 : Number(/usage_usec (\d+)/.exec(readFileSync(join(values.cgroup, 'cpu.stat'), 'utf8'))![1]));

const ORIGIN = 'https://secrets.acme.example';
const ROOT = 'admin@acme.example';
const DEV = 'dev@acme.example';

type Cost = { app: number; vault: number; vaultCalls: number };
const newCost = (): Cost => ({ app: 0, vault: 0, vaultCalls: 0 });

/** A connection's pool, counting each statement it runs on `cost`. */
class CountedPool {
  readonly #pool: HyperdrivePool;
  readonly client: Client;
  cost: Cost = newCost();

  constructor(pool: HyperdrivePool, side: 'app' | 'vault') {
    this.#pool = pool;
    this.client = watched(pool, () => {
      this.cost[side] += 1;
    });
  }

  end() {
    return this.#pool.end();
  }
}

const db = await openTestDatabase();
const [farApp, farVault] = await Promise.all([farPostgres(TEST_RUNTIME_DATABASE_URL, RTT), farPostgres(TEST_VAULT_DATABASE_URL, RTT)]);
const idle: { vault: LocalVault; pool: CountedPool }[] = [];
/** The app's connections, one a request at a time, kept between requests as Hyperdrive keeps its own. */
const connections: CountedPool[] = [];
try {
  await resetDatabase(db.owner);
  const kek = randomBytes(32);
  const deps = testDeps(db.runtime, [ROOT], { vault: testVault([ROOT], {}, { kek }) });
  /** The vault as a request reaches it on Workers: each call on a warm isolate of its own, with a connection of its own. */
  const vaultFor = (cost: Cost): Vault => new Proxy({} as Vault, {
    get: (_, name: string) => async (...args: unknown[]) => {
      const instance = idle.pop() ?? await (async () => {
        const pool = new CountedPool(new HyperdrivePool(farVault.url), 'vault');
        return { pool, vault: await localVault({ database: createDatabase(pool.client), kek: { id: 'test-kek-1', key: kek.toString('base64') }, owners: [ROOT] }, { log: '0.14' }) };
      })();
      instance.pool.cost = cost;
      cost.vaultCalls += 1;
      try {
        return await (instance.vault[name as keyof Vault] as (...args: unknown[]) => Promise<unknown>)(...args);
      } finally {
        instance.pool.cost = newCost();
        idle.push(instance);
      }
    },
  });
  const config = resolveConfig({ publicUrl: ORIGIN, vault: vaultFor(newCost()), auth: signin({ providers: [github({ clientId: 'a', clientSecret: 'b' })] }), auditChainKey: deps.chainKey.toString('base64') });
  const setup = createRuntime(config, deps.db, deps.vault, { json: async () => ({}) });

  // An instance of some size: DEV holds a grant in a few of its projects, among many they do not reach.
  const root = clientFor(deps, ROOT);
  for (let n = 0; n < 20; n++) {
    await root.projects.create(`p${n}`, { name: `Project ${n}` });
    for (const environment of ['dev', 'staging', 'prod']) await root.environments.create(`p${n}/${environment}`, { name: environment });
  }
  await root.environments.protect('p0/prod');
  await root.members.add(`user:${DEV}`);
  await root.access.set(`user:${DEV}`, { 'p0/dev': 'developer', p1: 'viewer', 'p2/staging': 'viewer' });
  const started = await setup.signin!.startDevice({ clientLabel: 'laptop', sourceIp: null });
  await setup.signin!.decideDevice(await contextFor({ ...deps, signin: setup.signin! }, DEV), started.userCode, true);
  const polled = await setup.signin!.pollDevice(started.deviceCode, { requestId: randomUUID(), sourceIp: null });
  if (polled.status !== 'approved') throw new Error('the device login was not approved');
  const token = polled.credential.token;

  /** One request, as on Workers: its own runtime, on a connection of its own while it runs. */
  const timed = async (run: (runtime: CoffreRuntime) => Promise<void>): Promise<{ ms: number; cost: Cost }> => {
    const cost = newCost();
    let pool = connections.pop();
    if (pool === undefined) {
      pool = new CountedPool(new HyperdrivePool(farApp.url), 'app');
      await pool.client.unsafe('select 1');
    }
    pool.cost = cost;
    const runtime = createRuntime(config, createDatabase(pool.client), vaultFor(cost), { json: async () => ({}) }, () => undefined);
    const begun = performance.now();
    try {
      await run(runtime);
      return { ms: performance.now() - begun, cost };
    } finally {
      pool.cost = newCost();
      connections.push(pool);
    }
  };
  const scenarios: Record<string, (runtime: CoffreRuntime) => Promise<void>> = {
    'GET /api/me': async (runtime) => {
      const response = await answer(new Request(`${ORIGIN}/api/me`, { headers: { authorization: `Bearer ${token}` } }), runtime, {} as Pages, '203.0.113.9');
      if (!response.ok) throw new Error(`${response.status} ${await response.text()}`);
      await response.json();
    },
    "a page's shell render": async (runtime) => {
      const client = pageClient(new Request(`${ORIGIN}/projects`, { headers: { cookie: `__Host-coffre_session=${token}` } }), runtime, null);
      await Promise.all([client.me(), client.auth(), client.projects.list()]);
    },
  };

  console.log(`rtt ${RTT} ms, ${values.requests} requests a level; as ${DEV}, who reaches 3 of 20 projects`);
  for (const [name, run] of Object.entries(scenarios)) {
    // Warm: as many connections as the widest level, each with its statements planned once, as a busy instance's are.
    const widest = Math.max(...values.concurrency!.split(',').map(Number));
    for (let round = 0; round < 3; round++) await Promise.all(Array.from({ length: widest }, () => timed(run)));
    for (const concurrency of values.concurrency!.split(',').map(Number)) {
      const total = Number(values.requests);
      const results: { ms: number; cost: Cost }[] = [];
      const cpuBefore = cpuUsec();
      const begun = performance.now();
      let next = 0;
      await Promise.all(Array.from({ length: concurrency }, async () => {
        while (next < total) {
          next += 1;
          results.push(await timed(run));
        }
      }));
      const seconds = (performance.now() - begun) / 1000;
      const cpu = cpuUsec() - cpuBefore;
      const sorted = results.map((result) => result.ms).sort((a, b) => a - b);
      const [first] = results;
      console.log(
        `${name.padEnd(22)} ×${String(concurrency).padStart(3)}  ${(results.length / seconds).toFixed(0).padStart(4)}/s  p50 ${percentile(sorted, 50).toFixed(1)} ms  p99 ${percentile(sorted, 99).toFixed(1)} ms`
        + `  statements app ${first!.cost.app} vault ${first!.cost.vault}, vault calls ${first!.cost.vaultCalls}`
        + `${values.cgroup === undefined ? '' : `  Postgres CPU ${(cpu / 1000 / results.length).toFixed(2)} ms/request`}`,
      );
    }
  }
} finally {
  await Promise.allSettled(idle.map(({ pool }) => pool.end()));
  await Promise.allSettled(connections.map((pool) => pool.end()));
  await Promise.allSettled([farApp.close(), farVault.close()]);
  await db.close();
}
