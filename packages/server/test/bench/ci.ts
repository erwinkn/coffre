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
// waiting on locks, almost all of it, and which statements waited. A
// binding issues at most 60 credentials a minute, so the service is bound
// afresh before a round would pass that, and a level runs at most 60 jobs
// at once. With 5 to 15 runs a level, its p99 is its slowest run.
// With `--log 0.15`, the vault keeps 0.15's log: the sign-in's credential is a change of it, which a Node
// checkpointer seals before the sign-in answers (R51; docs/design/0.15-plan.md, "As built: PR 4b"), over its own
// connection, near; and each vault call has the hot path's login too, so that a job's reveal is 0.15's uses, as a
// deployment's is (T145: without it, 0.14's unwrap queued on the log's head).
// With `--uses <rate>`, uses run beside, that many a second, each one `use_credential` call through a relay of its
// own (uses.ts), and it reports their latency and refusals for each level, `0` jobs a level of uses alone (`--idle`
// seconds): what a sign-in costs the hot path (R58). `--signin-only` leaves each job's list and reveal out.
// With `--proxy <rate>` instead, the uses beside are the whole app's `/use`, the credential proxy on 100 people's
// handles (proxy-uses.ts, PR 5b): 0.14's unwrap or, with `--log 0.15`, 0.15's use. `--proxy-cache <s>` is the proxy's
// `cacheSeconds` (0, the default here: every request opens its key); `--proxy-stable` sends each to the stable URL;
// `--proxy-names <n>` caps 0.15's vault's map of names at n a thread, its handles picked at random (0: every request cold).
// `--proxy-fork` makes every handle for ci/feature, a fork of ci/dev that inherits its `API_KEY` (T165): what a fork's
// `/use` costs, by the vault's one call by name or, before T165, by the app's own path.
// `--cgroup <dir>`, the Postgres container's cgroup, adds its CPU per use of each level (cpu.stat's usage_usec over
// the uses sent), and the same by login: the app's (`runtime`), the vault's, the hot path's (`vault_hot`), the server's own.
// `--principals` spreads the uses over that many services (1: one hot principal, T127), `--keys` gives ci/dev that many
// keys (7 by default, the reveal's), and `--use-cold <n>` makes n uses a second more, each on a new connection of its
// own, a new backend whose first call plans the statement (T131): reported apart from the others. `--window` is
// the cap's window in minutes (1 by default; its rows move on every tenth of it), its count a million.
// `--issue` makes each job a service token's issue by the Owner instead (T149, PR 2), the vault weighing it: what a burst
// of issues costs beside the uses. `--legacy` hides from the app that the vault issues tokens and signs in (`about()`
// says neither): the app's own transactions under 0.14's head, as before T149, to compare with.
// `--bindings <n>` spreads a level's jobs over n bindings of the one service, each a workflow of its own: a binding
// takes at most 60 sign-ins a minute, so 100 at once are two bindings' (with 0.15's log, each serializes on its row).
// Not part of the suite. On a migrated scratch database, as `pnpm test` makes:
//
//   COFFRE_TEST_DATABASE=<db> node --conditions=coffre:source packages/server/test/bench/ci.ts \
//     [--rtt 20] [--rounds 5] [--jobs 1,3,10] [--log 0.15] [--uses 1000 | --proxy 1000] [--use-pool 100] [--idle 5]
//     [--principals 100] [--keys 7] [--use-cold 0] [--window 1] [--signin-only] [--proxy-cache 60] [--proxy-stable] [--proxy-names 0] [--proxy-fork]
//     [--cgroup /sys/fs/cgroup/system.slice/docker-<id>.scope]
import { generateKeyPairSync, randomBytes, sign as signWith } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import { Worker } from 'node:worker_threads';

import { github, signin } from '@coffre/core/identity';
import type { Vault } from '@coffre/core/vault';
import { createDatabase, type Client } from '@coffre/db';
import { postgresClient } from '@coffre/db/connect';
import { HyperdrivePool } from '@coffre/db/hyperdrive';
import { derivedSigningKey } from '@coffre/vault';
import { localVault, runCheckpointer, type LocalVault, type RunningCheckpointer } from '@coffre/vault/node';
import { sql } from 'drizzle-orm';

import { resolveConfig } from '../../src/config.ts';
import { EXCHANGES_PER_BINDING_MINUTE, exchangeLimit } from '../../src/api/workloads.ts';
import { createRuntime } from '../../src/runtime.ts';
import { processLimits } from '../../src/workloads/limits.ts';
import { FetchRefused, type WorkloadTransport } from '../../src/workloads/transport.ts';
import { auditWatch } from '../../src/plugins/audit-watch.ts';
import { clientFor, contextFor, openTestDatabase, resetDatabase, testDeps, testVault } from '../api-fixture.ts';
import { answer, type Pages } from '../start-fixture.ts';
import { TEST_HOT_DATABASE_URL, TEST_RUNTIME_DATABASE_URL, TEST_VAULT_DATABASE_URL } from '../db/connections.ts';
import { farPostgres, percentile } from './far.ts';
import type { ProxyLoad, ProxyPhase } from './proxy-uses.ts';
import type { UseLoad, UsePhase } from './uses.ts';
import { watched } from '../db/postgres-pool.ts';

const { values } = parseArgs({
  options: {
    rtt: { type: 'string', default: '20' },
    rounds: { type: 'string', default: '5' },
    jobs: { type: 'string', default: '1,3,10' },
    log: { type: 'string', default: '0.14' },
    uses: { type: 'string', default: '0' },
    idle: { type: 'string', default: '5' },
    warm: { type: 'string', default: '3' },
    'use-pool': { type: 'string', default: '100' },
    principals: { type: 'string', default: '100' },
    'use-cold': { type: 'string', default: '0' },
    keys: { type: 'string', default: '7' },
    window: { type: 'string', default: '1' },
    'signin-only': { type: 'boolean', default: false },
    issue: { type: 'boolean', default: false },
    legacy: { type: 'boolean', default: false },
    proxy: { type: 'string', default: '0' },
    threads: { type: 'string', default: '4' },
    'proxy-cache': { type: 'string', default: '0' },
    'proxy-stable': { type: 'boolean', default: false },
    'proxy-fork': { type: 'boolean', default: false },
    'proxy-names': { type: 'string' },
    cgroup: { type: 'string' },
    bindings: { type: 'string', default: '1' },
  },
});
const RTT = Number(values.rtt);
const ROUNDS = Number(values.rounds);
const JOBS = values.jobs.split(',').map(Number);
const USES = Number(values.uses);
const SIGNIN_ONLY = values['signin-only'];
const ISSUE = values.issue;
const PROXY = Number(values.proxy);
/**
 * The Postgres container's CPU so far, in µs, when `--cgroup` names its cgroup: whole, and by login, each of its
 * backends' own (`/proc/<pid>/stat`, in clock ticks of 10 ms) summed by the login its title names, `other` for the
 * server's own processes. Every backend ever seen counts, at its last reading (`seen`, read every 100 ms): one that
 * ends, as a CI job's connection or a cold use's does, keeps its CPU but for its last 100 ms.
 */
type CpuNow = { total: number; logins: Map<string, number> };
/** Each backend seen, by pid and start time (a pid used again is another), with its login and CPU when last read. */
const seen = new Map<string, { login: string; usec: number }>();
const sampleCpu = () => {
  if (values.cgroup === undefined) return;
  for (const pid of readFileSync(join(values.cgroup, 'cgroup.procs'), 'utf8').split('\n').filter(Boolean)) {
    try {
      const title = readFileSync(`/proc/${pid}/cmdline`, 'utf8').replace(/\0/g, ' ');
      const stat = readFileSync(`/proc/${pid}/stat`, 'utf8');
      // utime, stime and starttime, its 14th, 15th and 22nd fields: the 12th, 13th and 20th after its command's parenthesis.
      const fields = stat.slice(stat.lastIndexOf(')') + 2).split(' ');
      const login = /^postgres: (\w+) /.exec(title)?.[1] ?? 'other';
      seen.set(`${pid}/${fields[19]}`, { login, usec: (Number(fields[11]) + Number(fields[12])) * 10_000 });
    } catch {
      // Gone meanwhile: its last reading stands.
    }
  }
};
const sampling = values.cgroup === undefined ? null : setInterval(sampleCpu, 100);
sampling?.unref();
const cpuNow = (): CpuNow => {
  const logins = new Map<string, number>();
  if (values.cgroup === undefined) return { total: 0, logins };
  const total = Number(/usage_usec (\d+)/.exec(readFileSync(join(values.cgroup, 'cpu.stat'), 'utf8'))![1]);
  sampleCpu();
  for (const { login, usec } of seen.values()) logins.set(login, (logins.get(login) ?? 0) + usec);
  return { total, logins };
};
const cpuSince = (from: CpuNow, to: CpuNow): CpuNow => ({
  total: to.total - from.total,
  logins: new Map([...to.logins].map(([login, usec]) => [login, usec - (from.logins.get(login) ?? 0)])),
});
const cpuAdd = (a: CpuNow | undefined, b: CpuNow): CpuNow => a === undefined ? b : {
  total: a.total + b.total,
  logins: new Map([...new Set([...a.logins.keys(), ...b.logins.keys()])].map((login) => [login, (a.logins.get(login) ?? 0) + (b.logins.get(login) ?? 0)])),
};
/** A phase's Postgres CPU per use, whole and by login: the app's (`coffre_runtime`), the vault's, the hot path's, and what none holds. */
const cpuShown = (used: CpuNow | undefined, sent: number): string => {
  if (used === undefined || values.cgroup === undefined) return '';
  const per = (usec: number) => (usec / 1000 / Math.max(1, sent)).toFixed(2);
  const logins = [...used.logins].filter(([, usec]) => usec > 0).sort(([a], [b]) => (a < b ? -1 : 1)).map(([login, usec]) => `${login.replace(/^coffre_/, '')} ${per(usec)}`);
  // What no backend's reading holds: the kernel's work for the container, and backends that lived between two readings.
  const unattributed = used.total - [...used.logins.values()].reduce((sum, usec) => sum + Math.max(0, usec), 0);
  return `  Postgres CPU ${per(used.total)} ms/use (${logins.join(', ')}, unattributed ${per(unattributed)})`;
};
const BULK = { count: 1_000_000, windowMinutes: Number(values.window) };

const ORIGIN = 'https://secrets.acme.example';
const ROOT = 'admin@acme.example';
const SERVICE = 'ci-build';
const MEMBER = `token:${SERVICE}`;
const ISSUER = 'https://token.actions.githubusercontent.com';
const KEYS = `${ISSUER}/.well-known/jwks`;
const CLAIMS = { repository_owner_id: '9919', repository_id: '41532', workflow_ref: 'acme/market/.github/workflows/build.yml@refs/heads/dev', ref: 'refs/heads/dev', event_name: 'push' };
/** The claims of workflow `n`'s runs: the first is `CLAIMS`, each other a workflow of its own, which a binding of its own takes. */
const claimsOf = (n: number) => (n === 0 ? CLAIMS : { ...CLAIMS, workflow_ref: `acme/market/.github/workflows/build-${n}.yml@refs/heads/dev` });
const BINDINGS = Number(values.bindings);
// An isolate takes 32 sign-ins at once, then answers 429; a burst of more spreads over isolates, each its own 32, which
// this one process stands in for: what they share is the database, here as there (their CPU this process's, pessimistic).
exchangeLimit.inFlight = Math.max(exchangeLimit.inFlight, ...JOBS);
const SEVEN = ['CLOUDFLARE_API_TOKEN', 'SCALEWAY_SECRET_KEY', 'R2_ACCESS_KEY_ID', 'R2_SECRET_ACCESS_KEY', 'SOURCE_REGISTRY_KEY', 'GITHUB_RELEASE_APP_CLIENT_ID', 'GITHUB_RELEASE_APP_PRIVATE_KEY'];

/** What a phase ran: its statements on the app's connection and the vault's, and how long they took beyond the round trip each, by statement. */
type Cost = { app: number; vault: number; vaultCalls: number; waitedMs: number; waits: Map<string, number> };
const newCost = (): Cost => ({ app: 0, vault: 0, vaultCalls: 0, waitedMs: 0, waits: new Map() });

/** A connection's pool, timing each statement it runs on `cost`, a transaction's included. */
class TimedPool {
  readonly #pool: HyperdrivePool;
  /** The pool as the database runs on it, timed. */
  readonly client: Client;
  cost: Cost = newCost();

  constructor(pool: HyperdrivePool, side: 'app' | 'vault') {
    this.#pool = pool;
    this.client = watched(pool, ({ text, ms }) => {
      const waited = Math.max(0, ms - RTT);
      const cost = this.cost;
      cost[side] += 1;
      cost.waitedMs += waited;
      if (waited > 2) {
        const what = `${side}: ${text.replace(/\s+/g, ' ').trim().slice(0, 70)}`;
        cost.waits.set(what, (cost.waits.get(what) ?? 0) + waited);
      }
    });
  }

  end() {
    return this.#pool.end();
  }
}

const db = await openTestDatabase();
const [farApp, farVault, farHot] = await Promise.all([
  farPostgres(TEST_RUNTIME_DATABASE_URL, RTT), farPostgres(TEST_VAULT_DATABASE_URL, RTT), farPostgres(TEST_HOT_DATABASE_URL, RTT),
]);
const idle: { vault: LocalVault; pool: TimedPool; hot: TimedPool | null }[] = [];
const checkpointerPool = postgresClient(TEST_VAULT_DATABASE_URL, { max: 4 });
const memory = mkdtempSync(join(tmpdir(), 'coffre-ci-bench-'));
let checkpointer: RunningCheckpointer | null = null;
let loader: Worker | null = null;
let proxies: Worker[] = [];
try {
  await resetDatabase(db.owner);
  const kek = randomBytes(32);
  if (values.log === '0.15') {
    await db.owner.execute(sql`DELETE FROM log_checkpoints`);
    await db.owner.execute(sql`DELETE FROM log_tiles`);
    await db.owner.execute(sql`DELETE FROM log_uses`);
    await db.owner.execute(sql`UPDATE log_fence SET at_floor = ${Date.now() - 3000}`);
    checkpointer = await runCheckpointer({ database: createDatabase(checkpointerPool), seed: derivedSigningKey(kek), memory: join(memory, 'memory') });
  }
  const log = checkpointer === null ? { log: '0.14' as const } : { log: '0.15' as const, sealThrough: checkpointer.sealThrough, heldOutside: checkpointer.heldOutside };
  const deps = testDeps(db.runtime, [ROOT], { vault: testVault([ROOT], { bulkLimit: BULK }, { kek }, {}, log) });
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'rs-1', alg: 'RS256', use: 'sig' };
  const part = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
  const token = (workflow = 0) => {
    const now = Math.floor(Date.now() / 1000);
    const input = `${part({ alg: 'RS256', kid: 'rs-1', typ: 'JWT' })}.${part({ iss: ISSUER, aud: ORIGIN, sub: 'repo:acme/market:ref:refs/heads/dev', iat: now - 5, exp: now + 295, jti: crypto.randomUUID(), run_id: '7001', sha: 'f'.repeat(40), repository: 'acme/market', ...claimsOf(workflow) })}`;
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
  let about: unknown = null;
  const vaultFor = (cost: Cost): Vault => new Proxy({} as Vault, {
    get: (_, name: string) => async (...args: unknown[]) => {
      // What the vault says of itself, once: a deployment's runtime keeps its vault for the isolate, and asks it once.
      if (name === 'about' && about !== null) return about;
      const instance = idle.pop() ?? await (async () => {
        const pool = new TimedPool(new HyperdrivePool(farVault.url), 'vault');
        const hot = values.log === '0.15' ? new TimedPool(new HyperdrivePool(farHot.url), 'vault') : null;
        const vault = await localVault({
          database: createDatabase(pool.client), ...(hot === null ? {} : { hotDatabase: createDatabase(hot.client) }),
          kek: { id: 'test-kek-1', key: kek.toString('base64') }, owners: [ROOT], bulkLimit: BULK,
        }, log);
        return { pool, hot, vault };
      })();
      instance.pool.cost = cost;
      if (instance.hot !== null) instance.hot.cost = cost;
      cost.vaultCalls += 1;
      try {
        let answered = await (instance.vault[name as keyof Vault] as (...args: unknown[]) => Promise<unknown>)(...args);
        if (name === 'about' && values.legacy) {
          const { credentials: _, issues: __, binds: ___, ...before } = answered as Record<string, unknown>;
          answered = before;
        }
        if (name === 'about') about = answered;
        return answered;
      } finally {
        instance.pool.cost = newCost();
        if (instance.hot !== null) instance.hot.cost = newCost();
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
  const keys = [...SEVEN, ...Array.from({ length: Math.max(0, Number(values.keys) - SEVEN.length) }, (_, n) => `MORE_${n}`)];
  await root.secrets.set('ci/dev', Object.fromEntries(keys.map((key) => [key, `${key.toLowerCase()}-value`])));
  await root.members.add(MEMBER);
  await root.access.set(MEMBER, { 'ci/dev': 'viewer' });
  /** Each workflow's binding, and the sign-ins it has left this minute: a round that would pass them binds afresh, replacing it. */
  const bindings = Array.from({ length: BINDINGS }, () => ({ id: null as string | null, left: 0 }));
  const bind = async (n: number) => {
    const held = bindings[n]!;
    const made = await setup.workloads!.bind(await contextFor(deps, ROOT), SERVICE, { profile: 'github', issuer: null, claims: claimsOf(n), label: `build-${n}`, replaces: held.id === null ? [] : [held.id] }, { dryRun: false });
    if (!('binding' in made)) throw new Error('bind');
    held.id = made.binding.id;
    held.left = EXCHANGES_PER_BINDING_MINUTE;
  };
  /** `jobs` sign-ins, job i through binding i mod `--bindings`, each binding with them left. */
  const room = async (jobs: number) => {
    // An issue signs nothing in through a binding.
    if (ISSUE) return;
    for (let n = 0; n < BINDINGS; n += 1) {
      const share = Math.ceil((jobs - n) / BINDINGS);
      if (share > EXCHANGES_PER_BINDING_MINUTE) throw new Error(`a binding takes at most ${EXCHANGES_PER_BINDING_MINUTE} sign-ins a minute: run at most that many jobs a binding at once`);
      if (bindings[n]!.left < share) await bind(n);
      bindings[n]!.left -= share;
    }
  };

  const ui = {} as Pages;
  /** One request, as on Workers: its own runtime and connection, timed once connected, its background work finished after its answer. */
  const request = async (make: () => Request): Promise<{ ms: number; cost: Cost; body: unknown }> => {
    const cost = newCost();
    const pool = new TimedPool(new HyperdrivePool(farApp.url), 'app');
    const background: Promise<unknown>[] = [];
    await pool.client.unsafe('select 1');
    pool.cost = cost;
    const runtime = createRuntime(config, createDatabase(pool.client), vaultFor(cost), transport, (promise) => void background.push(promise));
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
  /** One CI job: its sign-in, its list and its reveal, one after the other; or, with `--signin-only`, its sign-in. */
  const owner = await contextFor(deps, ROOT);
  /** A service token's issue by the Owner, on a runtime and a connection of its own, as `request` makes one. */
  const issueOne = async (): Promise<{ ms: number; cost: Cost; body: unknown }> => {
    const cost = newCost();
    const pool = new TimedPool(new HyperdrivePool(farApp.url), 'app');
    await pool.client.unsafe('select 1');
    pool.cost = cost;
    const runtime = createRuntime(config, createDatabase(pool.client), vaultFor(cost), transport);
    const started = performance.now();
    try {
      const body = await runtime.signin!.issueServiceToken(owner, SERVICE, { label: 'bench', expiresInDays: 1 });
      return { ms: performance.now() - started, cost, body };
    } finally {
      await pool.end();
    }
  };
  const job = async (n = 0) => {
    if (ISSUE) return { issue: await issueOne() };
    const oidc = await request(() => new Request(`${ORIGIN}/api/auth/oidc`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ service: MEMBER, token: token(n % BINDINGS) }) }));
    if (SIGNIN_ONLY) return { oidc };
    const { token: credential } = oidc.body as { token: string };
    const authorization = `Bearer ${credential}`;
    const list = await request(() => new Request(`${ORIGIN}/api/secrets/ci/dev`, { headers: { authorization } }));
    const reveal = await request(() => new Request(`${ORIGIN}/api/reveals`, { method: 'POST', headers: { authorization, 'content-type': 'application/json' }, body: JSON.stringify({ path: 'ci/dev', keys: SEVEN }) }));
    return { oidc, list, reveal };
  };

  console.log(`rtt ${RTT} ms, ${ROUNDS} rounds a level, each job: ${ISSUE
    ? `a service token's issue to ${MEMBER} by ${ROOT}${values.legacy ? ', as the app issued it before T149' : ''}`
    : `sign-in${SIGNIN_ONLY ? '' : `, list, reveal of ${SEVEN.length} keys`}, all as ${MEMBER}`}`);
  // Warm: the issuer's keys fetched, the vault's isolates settled, as after the first run of the day.
  await room(1);
  await job();
  // Uses beside, `--uses` a second (uses.ts), as 0.15's hot path makes them.
  if (USES > 0) {
    const today = Date.now();
    await db.owner.execute(sql`SELECT make_day(${new Date(today).toISOString().slice(0, 10)}::date), make_day(${new Date(today + 86_400_000).toISOString().slice(0, 10)}::date)`);
    // A fleet's uses: `--principals` services' credentials (100 by default), each of the seven keys. What the vault then
    // decides on them does not change what the statement costs.
    const credentials: string[] = [];
    for (let n = 0; n < Number(values.principals); n += 1) {
      const principal = `token:fleet-${n}`;
      const id = crypto.randomUUID();
      await db.owner.execute(sql`INSERT INTO vault_members (principal, status, generation, created_at, created_by, status_changed_at, status_changed_by, access_seq, mac)
        VALUES (${principal}, 'active', 0, ${Date.now()}, 'system:bench', ${Date.now()}, 'system:bench', 0, ${Buffer.alloc(32)})`);
      await db.owner.execute(sql`INSERT INTO credentials (id, kind, auth_mac, token_hash, token_hint, generation, principal, created_by, expires_at)
        VALUES (${id}, 'service', ${Buffer.alloc(32)}, ${randomBytes(32)}, 'h', 0, ${principal}, 'system:bench', ${new Date(Date.now() + 86_400_000)})`);
      credentials.push(id);
    }
    const secrets = (await db.owner.execute<{ id: string }>(sql`SELECT id FROM secrets`)).map(({ id }) => id);
    const load: UseLoad = { url: TEST_HOT_DATABASE_URL, rtt: RTT, rate: USES, pool: Number(values['use-pool']), cold: Number(values['use-cold']), credentials, secrets, seed: derivedSigningKey(kek) };
    loader = new Worker(new URL('./uses.ts', import.meta.url), { workerData: load });
    await new Promise((resolve) => loader!.once('message', resolve));
  }
  // `/use` beside, `--proxy` a second (proxy-uses.ts): 100 people, each a Developer of ci/dev with a handle of their own,
  // so that no one principal's bulk row serializes them, as with `--uses`.
  if (PROXY > 0) {
    const handles: string[] = [];
    const place = values['proxy-fork'] ? 'ci/feature' : 'ci/dev';
    if (values['proxy-fork']) await root.environments.create('ci/feature', { from: 'dev', inherit: true });
    for (let n = 0; n < 100; n += 1) {
      const email = `person-${n}@acme.example`;
      await root.members.add(`user:${email}`);
      await root.access.set(`user:${email}`, { 'ci/dev': 'developer', ...(values['proxy-fork'] ? { 'ci/feature': 'developer' as const } : {}) });
      const started = await setup.signin!.startDevice({ clientLabel: 'laptop', sourceIp: null });
      await setup.signin!.decideDevice(await contextFor(deps, email), started.userCode, true);
      const polled = await setup.signin!.pollDevice(started.deviceCode, { requestId: crypto.randomUUID(), sourceIp: null });
      if (polled.status !== 'approved') throw new Error('not approved');
      const made = await answer(new Request(`${ORIGIN}/api/handles`, { method: 'POST', headers: { authorization: `Bearer ${polled.credential.token}`, 'content-type': 'application/json' }, body: JSON.stringify({ label: 'run', paths: [place] }) }), setup, ui, null);
      handles.push(((await made.json()) as { token: string }).token);
    }
    const load: ProxyLoad = {
      log: values.log === '0.15' ? '0.15' : '0.14', urls: { app: TEST_RUNTIME_DATABASE_URL, vault: TEST_VAULT_DATABASE_URL, hot: TEST_HOT_DATABASE_URL }, rtt: RTT, rate: PROXY,
      pools: { app: Number(values['use-pool']), vault: 8, hot: 16 }, handles, path: place, value: `${SEVEN[0]!.toLowerCase()}-value`, kek: kek.toString('base64'), owner: ROOT, chainKey: deps.chainKey.toString('base64'), origin: ORIGIN,
      cacheSeconds: Number(values['proxy-cache']),
      stable: values['proxy-stable'],
      ...(values['proxy-names'] === undefined ? {} : { names: Number(values['proxy-names']) }),
    };
    // The proxy injects `API_KEY`: ci/dev's first key under that name.
    await root.secrets.set('ci/dev', { API_KEY: load.value });
    // Several threads, each an app and a vault of its own, as Workers runs many isolates: one Node thread is the
    // bottleneck well below 1,000 requests a second, as the thread CPU per request below says.
    const threads = Number(values.threads);
    proxies = await Promise.all(Array.from({ length: threads }, async (_, n) => {
      const worker = new Worker(new URL('./proxy-uses.ts', import.meta.url), { workerData: { ...load, rate: PROXY / threads, handles: handles.filter((_, i) => i % threads === n) } });
      await new Promise((resolve) => worker.once('message', resolve));
      return worker;
    }));
  }
  /** Postgres's CPU in each named phase, µs, over the uses it sent. */
  const cpu = new Map<string, CpuNow>();
  let cpuFrom: { phase: string; at: CpuNow } | null = null;
  /** The uses from now on count toward `phase`, or none (null): the binding's renewal between rounds is no sign-in's. */
  const usesIn = async (phase: string | null) => {
    if (proxies.length > 0) {
      if (cpuFrom !== null) cpu.set(cpuFrom.phase, cpuAdd(cpu.get(cpuFrom.phase), cpuSince(cpuFrom.at, cpuNow())));
      cpuFrom = phase === null ? null : { phase, at: cpuNow() };
      await Promise.all(proxies.map(async (worker) => {
        worker.postMessage({ phase });
        await new Promise((resolve) => worker.once('message', resolve));
      }));
      return;
    }
    if (loader === null) return;
    if (cpuFrom !== null) cpu.set(cpuFrom.phase, cpuAdd(cpu.get(cpuFrom.phase), cpuSince(cpuFrom.at, cpuNow())));
    cpuFrom = phase === null ? null : { phase, at: cpuNow() };
    loader.postMessage({ phase });
    await new Promise((resolve) => loader!.once('message', resolve));
  };
  // Every connection's plans made, and every key's bulk row written, before the first level.
  // `--warm` seconds: long enough that each pooled connection has planned its statements, as Hyperdrive's have.
  await usesIn('warm');
  await new Promise((resolve) => setTimeout(resolve, Number(values.warm) * 1000));
  await usesIn(null);
  for (const jobs of JOBS) {
    if (jobs === 0) {
      // Uses alone: the baseline the others are held to.
      await usesIn('0 jobs');
      await new Promise((resolve) => setTimeout(resolve, Number(values.idle) * 1000));
      await usesIn(null);
      continue;
    }
    const phases = { oidc: [] as { ms: number; cost: Cost }[], issue: [] as { ms: number; cost: Cost }[], list: [] as { ms: number; cost: Cost }[], reveal: [] as { ms: number; cost: Cost }[] };
    for (let round = 0; round < ROUNDS; round += 1) {
      await room(jobs);
      await usesIn(`${jobs} jobs`);
      for (const done of await Promise.all(Array.from({ length: jobs }, (_, n) => job(n)))) {
        const ran = done as { [K in keyof typeof phases]?: { ms: number; cost: Cost } };
        for (const phase of ['oidc', 'issue', 'list', 'reveal'] as const) {
          const run = ran[phase];
          if (run !== undefined) phases[phase].push(run);
        }
      }
      await usesIn(null);
    }
    for (const [phase, runs] of Object.entries(phases)) {
      if (runs.length === 0) continue;
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
  if (proxies.length > 0) {
    const reports = await Promise.all(proxies.map((worker) => {
      worker.postMessage({ report: true });
      return new Promise<ProxyPhase[]>((resolve) => worker.on('message', (message: { phases?: ProxyPhase[] }) => message.phases && resolve(message.phases)));
    }));
    console.log(`/use, ${PROXY}/s beside over ${proxies.length} threads, the whole app on ${values.log}'s log (ms; refused: any answer but the upstream's 200, and errors):`);
    for (const name of reports[0]!.map(({ phase }) => phase).filter((phase) => phase !== 'warm')) {
      const each = reports.map((phases) => phases.find(({ phase }) => phase === name)!);
      const sorted = each.flatMap(({ latencies }) => latencies).sort((a, b) => a - b);
      const sent = each.reduce((sum, { sent: n }) => sum + n, 0);
      const refused = new Map<string, number>();
      for (const { refused: by } of each) for (const [why, n] of Object.entries(by)) refused.set(why, (refused.get(why) ?? 0) + n);
      const app = each.reduce((sum, { cpuUs }) => sum + cpuUs, 0) / 1000 / Math.max(1, sent);
      const used = cpu.get(name);
      console.log(
        `  ${name.padEnd(8)} ${String(sent).padStart(6)} uses  p50 ${percentile(sorted, 50).toFixed(1).padStart(6)}  p90 ${percentile(sorted, 90).toFixed(1).padStart(6)}  p99 ${percentile(sorted, 99).toFixed(1).padStart(6)}  ` +
          `max ${sorted.at(-1)!.toFixed(1).padStart(7)}  app CPU ${app.toFixed(2)} ms/use${cpuShown(used, sent)}  refused: ${[...refused].map(([why, n]) => `${why} ${n}`).join(', ') || 'none'}`,
      );
    }
  }
  if (loader !== null) {
    loader.postMessage({ report: true });
    const { phases } = await new Promise<{ phases: UsePhase[] }>((resolve) => loader!.on('message', (message: { phases?: UsePhase[] }) => message.phases && resolve(message as { phases: UsePhase[] })));
    console.log(`uses, ${USES}/s beside, each one round trip (ms; refused: the database's own answers and errors):`);
    for (const use of phases.filter(({ phase }) => phase !== 'warm')) {
      const refused = Object.entries(use.refused).map(([why, n]) => `${why} ${n}`).join(', ') || 'none';
      const used = cpu.get(use.phase);
      console.log(
        `  ${use.phase.padEnd(8)} ${String(use.sent).padStart(6)} uses  p50 ${use.p50.toFixed(1).padStart(6)}  p90 ${use.p90.toFixed(1).padStart(6)}  p99 ${use.p99.toFixed(1).padStart(6)}  p99.9 ${use.p999.toFixed(1).padStart(6)}  ` +
          `max ${use.max.toFixed(1).padStart(7)}  past 2 rtt ${(use.slow * 100).toFixed(1).padStart(5)}%` +
          `${cpuShown(used, use.sent)}  refused: ${refused}` +
          (use.cold === 0 ? '' : `  beside ${use.cold} each on a new backend: p50 ${use.coldP50.toFixed(1)}, max ${use.coldMax.toFixed(1)}`),
      );
    }
  }
} finally {
  if (sampling !== null) clearInterval(sampling);
  await loader?.terminate();
  await Promise.all(proxies.map((worker) => worker.terminate()));
  await Promise.all(idle.map(({ vault, pool, hot }) => vault.close().then(() => Promise.all([pool.end(), hot?.end()]))));
  await Promise.all([farApp.close(), farVault.close(), farHot.close()]);
  await checkpointer?.stop();
  await checkpointerPool.end();
  rmSync(memory, { recursive: true, force: true });
  await db.close();
}
