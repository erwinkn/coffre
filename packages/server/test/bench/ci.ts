// What a CI run's three requests cost under concurrent load, as on Workers:
// the Action's sign-in (`POST /api/auth/oidc`), its list (`GET
// /api/secrets/<env>`) and its reveal of 7 keys (`POST /api/reveals`), each
// request on a Postgres connection of its own and each vault call on
// another (`HyperdrivePool`), every statement a round trip to a database
// far away. As in packages/vault/test/bench/decisions.ts, a relay delays
// each chunk by half the round trip either way, so a lock held across
// round trips is held as long as it would be through Hyperdrive. Several
// jobs of one run sign in as one service at once, as a market Build's do.
// It reports each phase's wall time, p50 and p99, its statements, and the
// time its statements spent in the database beyond the round trip:
// waiting on locks, almost all of it, and which statements waited.
// Not part of the suite. On a migrated scratch database, as `pnpm test` makes:
//
//   COFFRE_TEST_DATABASE=<db> node --conditions=coffre:source packages/server/test/bench/ci.ts \
//     [--rtt 20] [--rounds 5] [--jobs 1,3,10]
import { generateKeyPairSync, randomBytes, sign as signWith } from 'node:crypto';
import { connect, createServer, type Server } from 'node:net';
import { parseArgs } from 'node:util';

import { github, signin } from '@coffre/core/identity';
import type { Vault } from '@coffre/core/vault';
import { createDatabase } from '@coffre/db';
import { HyperdrivePool } from '@coffre/db/hyperdrive';
import { localVault, type LocalVault } from '@coffre/vault/node';

import { resolveConfig } from '../../src/config.ts';
import { createRuntime } from '../../src/runtime.ts';
import { processLimits } from '../../src/workloads/limits.ts';
import { FetchRefused, type WorkloadTransport } from '../../src/workloads/transport.ts';
import { auditWatch } from '../../src/plugins/audit-watch.ts';
import { clientFor, contextFor, openTestDatabase, resetDatabase, testDeps, testVault } from '../api-fixture.ts';
import { answer, type Pages } from '../start-fixture.ts';
import { TEST_RUNTIME_DATABASE_URL, TEST_VAULT_DATABASE_URL } from '../db/connections.ts';

const { values } = parseArgs({
  options: {
    rtt: { type: 'string', default: '20' },
    rounds: { type: 'string', default: '5' },
    jobs: { type: 'string', default: '1,3,10' },
  },
});
const RTT = Number(values.rtt);
const ROUNDS = Number(values.rounds);
const JOBS = values.jobs.split(',').map(Number);

const ORIGIN = 'https://secrets.acme.example';
const ROOT = 'admin@acme.example';
const SERVICE = 'ci-build';
const MEMBER = `token:${SERVICE}`;
const ISSUER = 'https://token.actions.githubusercontent.com';
const KEYS = `${ISSUER}/.well-known/jwks`;
const CLAIMS = { repository_owner_id: '9919', repository_id: '41532', workflow_ref: 'acme/market/.github/workflows/build.yml@refs/heads/dev', ref: 'refs/heads/dev', event_name: 'push' };
const SEVEN = ['CLOUDFLARE_API_TOKEN', 'SCALEWAY_SECRET_KEY', 'R2_ACCESS_KEY_ID', 'R2_SECRET_ACCESS_KEY', 'SOURCE_REGISTRY_KEY', 'GITHUB_RELEASE_APP_CLIENT_ID', 'GITHUB_RELEASE_APP_PRIVATE_KEY'];

/** Postgres as Hyperdrive serves it from far away: each chunk delayed by half the round trip, each way. */
async function farPostgres(at: string, rtt: number): Promise<{ url: string; close(): Promise<void> }> {
  const target = new URL(at);
  const server: Server = createServer((client) => {
    const upstream = connect(Number(target.port), target.hostname);
    const relay = (from: NodeJS.ReadableStream, to: NodeJS.WritableStream) => from.on('data', (chunk) => setTimeout(() => to.write(chunk), rtt / 2));
    relay(client, upstream);
    relay(upstream, client);
    const end = () => {
      client.destroy();
      upstream.destroy();
    };
    client.on('close', end).on('error', end);
    upstream.on('close', end).on('error', end);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const url = new URL(at);
  url.port = String((server.address() as { port: number }).port);
  return { url: url.toString(), close: () => new Promise((resolve) => server.close(() => resolve())) };
}

/** What a phase ran: its statements on the app's connection and the vault's, and how long they took beyond the round trip each, by statement. */
type Cost = { app: number; vault: number; vaultCalls: number; waitedMs: number; waits: Map<string, number> };
const newCost = (): Cost => ({ app: 0, vault: 0, vaultCalls: 0, waitedMs: 0, waits: new Map() });

/** A connection's pool, timing each statement it runs on `cost()`, a transaction's included; its class name ends in `Pool`, as Drizzle needs. */
class TimedPool {
  readonly #pool: HyperdrivePool;
  readonly #side: 'app' | 'vault';
  cost: Cost = newCost();

  constructor(pool: HyperdrivePool, side: 'app' | 'vault') {
    this.#pool = pool;
    this.#side = side;
  }

  async #time(query: (...args: unknown[]) => Promise<unknown>, args: unknown[]): Promise<unknown> {
    const started = performance.now();
    try {
      return await query(...args);
    } finally {
      const waited = Math.max(0, performance.now() - started - RTT);
      const cost = this.cost;
      cost[this.#side] += 1;
      cost.waitedMs += waited;
      if (waited > 2) {
        const text = typeof args[0] === 'string' ? args[0] : String((args[0] as { text?: string })?.text ?? '?');
        const what = `${this.#side}: ${text.replace(/\s+/g, ' ').trim().slice(0, 70)}`;
        cost.waits.set(what, (cost.waits.get(what) ?? 0) + waited);
      }
    }
  }

  query = ((...args: unknown[]) => this.#time(this.#pool.query as never, args)) as HyperdrivePool['query'];

  async connect() {
    const client = await this.#pool.connect();
    return { query: ((...args: unknown[]) => this.#time(client.query as never, args)) as typeof client.query, release: client.release };
  }

  end() {
    return this.#pool.end();
  }
}

const db = await openTestDatabase();
const [farApp, farVault] = await Promise.all([farPostgres(TEST_RUNTIME_DATABASE_URL, RTT), farPostgres(TEST_VAULT_DATABASE_URL, RTT)]);
const idle: { vault: LocalVault; pool: TimedPool }[] = [];
try {
  await resetDatabase(db.owner);
  const kek = randomBytes(32);
  const deps = testDeps(db.runtime, [ROOT], { vault: testVault([ROOT], { bulkLimit: { count: 1_000_000, windowMinutes: 1 } }, { kek }) });
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'rs-1', alg: 'RS256', use: 'sig' };
  const part = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
  const token = () => {
    const now = Math.floor(Date.now() / 1000);
    const input = `${part({ alg: 'RS256', kid: 'rs-1', typ: 'JWT' })}.${part({ iss: ISSUER, aud: ORIGIN, sub: 'repo:acme/market:ref:refs/heads/dev', iat: now - 5, exp: now + 295, jti: crypto.randomUUID(), run_id: '7001', sha: 'f'.repeat(40), repository: 'acme/market', ...CLAIMS })}`;
    return `${input}.${signWith('sha256', Buffer.from(input), privateKey).toString('base64url')}`;
  };
  const transport: WorkloadTransport = {
    json: async (url) => {
      const published = new Map<string, unknown>([[`${ISSUER}/.well-known/openid-configuration`, { issuer: ISSUER, jwks_uri: KEYS }], [KEYS, { keys: [jwk] }]]);
      if (!published.has(url.href)) throw new FetchRefused(url, 'answered 404');
      return published.get(url.href);
    },
  };

  /**
   * The vault as a request reaches it on Workers: each call on a warm
   * isolate of its own, with a connection of its own, its statements
   * counted on the request's cost.
   */
  const vaultFor = (cost: Cost): Vault => new Proxy({} as Vault, {
    get: (_, name: string) => async (...args: unknown[]) => {
      const instance = idle.pop() ?? await (async () => {
        const pool = new TimedPool(new HyperdrivePool(farVault.url), 'vault');
        return { pool, vault: await localVault({ database: createDatabase(pool), kek: { id: 'test-kek-1', key: kek.toString('base64') }, owners: [ROOT], bulkLimit: { count: 1_000_000, windowMinutes: 1 } }) };
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

  const config = resolveConfig({
    publicUrl: ORIGIN,
    vault: vaultFor(newCost()),
    auth: signin({ providers: [github({ clientId: 'a', clientSecret: 'b' })], workloads: { limits: processLimits({ perSource: 1_000_000, total: 1_000_000 }) } }),
    auditChainKey: deps.chainKey.toString('base64'),
    plugins: [auditWatch({ anchor: deps.anchor })],
  });
  const setup = createRuntime(config, deps.db, deps.vault, transport);
  const root = clientFor(deps, ROOT);
  await root.projects.create('ci', { name: 'CI' });
  await root.environments.create('ci/dev', { name: 'dev' });
  await root.secrets.set('ci/dev', Object.fromEntries(SEVEN.map((key) => [key, `${key.toLowerCase()}-value`])));
  await root.members.add(MEMBER);
  await root.access.set(MEMBER, { 'ci/dev': 'viewer' });
  let binding: string | null = null;
  /** A binding of its own for each level, so no level meets the last one's per-minute limit. */
  const bind = async () => {
    const made = await setup.workloads!.bind(await contextFor(deps, ROOT), SERVICE, { profile: 'github', issuer: null, claims: CLAIMS, label: 'build', replaces: binding === null ? [] : [binding] }, { dryRun: false });
    if (!('binding' in made)) throw new Error('bind');
    binding = made.binding.id;
  };

  const ui = {} as Pages;
  /** One request, as on Workers: its own runtime and connection, timed once connected, its background work finished after its answer. */
  const request = async (make: () => Request): Promise<{ ms: number; cost: Cost; body: unknown }> => {
    const cost = newCost();
    const pool = new TimedPool(new HyperdrivePool(farApp.url), 'app');
    const background: Promise<unknown>[] = [];
    (await pool.connect()).release();
    pool.cost = cost;
    const runtime = createRuntime(config, createDatabase(pool), vaultFor(cost), transport, (promise) => void background.push(promise));
    const started = performance.now();
    try {
      const response = await answer(make(), runtime, ui, '203.0.113.9');
      const ms = performance.now() - started;
      if (!response.ok) throw new Error(`${response.status} ${await response.text()}`);
      return { ms, cost, body: await response.json() };
    } finally {
      await Promise.allSettled(background);
      await pool.end();
    }
  };
  /** One CI job: its sign-in, its list and its reveal, one after the other. */
  const job = async () => {
    const oidc = await request(() => new Request(`${ORIGIN}/api/auth/oidc`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ service: MEMBER, token: token() }) }));
    const { token: credential } = oidc.body as { token: string };
    const authorization = `Bearer ${credential}`;
    const list = await request(() => new Request(`${ORIGIN}/api/secrets/ci/dev`, { headers: { authorization } }));
    const reveal = await request(() => new Request(`${ORIGIN}/api/reveals`, { method: 'POST', headers: { authorization, 'content-type': 'application/json' }, body: JSON.stringify({ path: 'ci/dev', keys: SEVEN }) }));
    return { oidc, list, reveal };
  };

  const percentile = (sorted: number[], p: number) => sorted[Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1)]!;
  console.log(`rtt ${RTT} ms, ${ROUNDS} rounds a level, each job: sign-in, list, reveal of ${SEVEN.length} keys, all as ${MEMBER}`);
  // Warm: the issuer's keys fetched, the vault's isolates settled, as after the first run of the day.
  await bind();
  await job();
  for (const jobs of JOBS) {
    await bind();
    const phases = { oidc: [] as { ms: number; cost: Cost }[], list: [] as { ms: number; cost: Cost }[], reveal: [] as { ms: number; cost: Cost }[] };
    for (let round = 0; round < ROUNDS; round += 1) {
      for (const done of await Promise.all(Array.from({ length: jobs }, job))) {
        for (const phase of ['oidc', 'list', 'reveal'] as const) phases[phase].push(done[phase]);
      }
    }
    for (const [phase, runs] of Object.entries(phases)) {
      const ms = runs.map((run) => run.ms).sort((a, b) => a - b);
      const mean = (pick: (cost: Cost) => number) => (runs.reduce((sum, run) => sum + pick(run.cost), 0) / runs.length).toFixed(1);
      const waits = new Map<string, number>();
      for (const run of runs) for (const [what, waited] of run.cost.waits) waits.set(what, (waits.get(what) ?? 0) + waited);
      console.log(
        `${String(jobs).padStart(2)} jobs ${phase.padEnd(6)} p50 ${percentile(ms, 50).toFixed(0).padStart(5)} ms  p99 ${percentile(ms, 99).toFixed(0).padStart(5)} ms  ` +
          `statements app ${mean((c) => c.app)} vault ${mean((c) => c.vault)} (${mean((c) => c.vaultCalls)} calls)  waited ${mean((c) => c.waitedMs)} ms`,
      );
      for (const [what, waited] of [...waits].sort((a, b) => b[1] - a[1]).slice(0, 3)) console.log(`         ${(waited / runs.length).toFixed(0).padStart(5)} ms/run  ${what}`);
    }
  }
} finally {
  await Promise.all(idle.map(({ vault, pool }) => vault.close().then(() => pool.end())));
  await Promise.all([farApp.close(), farVault.close()]);
  await db.close();
}
