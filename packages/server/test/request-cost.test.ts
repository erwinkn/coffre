// What a request costs, exactly, and that it does not grow with the
// instance. On Workers' Free plan, an invocation has 10 ms of CPU; each
// statement is a round trip through Hyperdrive, and each connection, the
// app's or one vault call's, costs a TLS socket and a SCRAM login. So each
// hot request has a budget of statements and connections it meets exactly,
// and runs the same statements, reading the same rows, on a log of a few
// entries as on one of thousands, among a handful of members or hundreds,
// after one change to the policy or many.
// `pnpm bench:workers` measures the CPU itself (packages/conformance/scripts/bench.ts).
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import * as hegel from '@hegeldev/hegel';
import * as gs from '@hegeldev/hegel/generators';

import { createClient, type CoffreClient } from '@coffre/client';
import { bodyDigest, createProof, generateProofKey, thumbprint } from '@coffre/client/dpop';
import { generateToken, github, hashToken, signin, tokenHint, type Gate } from '@coffre/core/identity';
import { createDatabase } from '@coffre/db';
import { appendEntries } from '@coffre/db/log';
import { localVault } from '@coffre/vault/node';
import type pg from 'pg';

import { SigninService } from '../src/api/signin.ts';
import { insertBinding, memberStanding, places } from '../src/db/queries.ts';
import { insertSession } from '../src/db/workloads.ts';
import { fetchApi } from '../src/fetch-api.ts';
import { auditReadiness, writeAuditHeartbeat } from '../src/heartbeat.ts';
import { appLogKey, CHAIN_WALK } from '../src/db/audit.ts';
import { bindingRoute, checkPlugins, pluginRoute } from '../src/plugins.ts';
import { credentialProxy, header } from '../src/plugins/credential-proxy.ts';
import type { CoffreRuntime } from '../src/runtime.ts';
import { processLimits } from '../src/workloads/limits.ts';
import { clientFor, contextFor, openTestDatabase, resetDatabase, waitUntil, type FixtureDeps } from './api-fixture.ts';
import { TEST_RUNTIME_DATABASE_URL, TEST_VAULT_DATABASE_URL } from './db/connections.ts';
import { propertySettings } from '../../../scripts/property-settings.ts';
import { postgresOnly } from './db/engine.ts';
import { testPostgresPool } from './db/postgres-pool.ts';

const ORIGIN = 'https://secrets.acme.example';
const ROOT = 'admin@acme.example';
const READER = 'reader@acme.example';
const SERVICE = 'token:ci-web';
const POSTGRES = postgresOnly("counts what the app's and the vault's Postgres connections run");
const auth = signin({ providers: [github({ clientId: 'gh-id', clientSecret: 'gh-secret' })] }).resolve(ORIGIN);

type Count = { statements: number; rows: number };

/** A pool that counts the statements run on it, a transaction's included, and the rows they answered. Drizzle checks out a client for a transaction from a class named `…Pool`. */
class CountingPool {
  readonly #pool: pg.Pool;
  readonly count: Count = { statements: 0, rows: 0 };

  constructor(pool: pg.Pool) {
    this.#pool = pool;
  }

  async #counted(query: pg.Pool['query'] | pg.PoolClient['query'], args: unknown[]): Promise<unknown> {
    const answered = await (query as (...queryArgs: unknown[]) => Promise<pg.QueryResult>)(...args);
    this.count.statements += 1;
    this.count.rows += answered.rows?.length ?? 0;
    return answered;
  }

  query = ((...args: unknown[]) => this.#counted(this.#pool.query.bind(this.#pool), args)) as pg.Pool['query'];

  async connect() {
    const client = await this.#pool.connect();
    return {
      query: ((...args: unknown[]) => this.#counted(client.query.bind(client), args)) as pg.PoolClient['query'],
      release: () => client.release(),
    };
  }

  end() {
    return this.#pool.end();
  }
}

/** What a request ran: statements and rows on the app's connection and on the vault's, and how many calls the vault answered, each a connection of its own on Workers. */
type Cost = { app: Count; vault: Count; vaultCalls: number };

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let app: CountingPool;
let vaultPool: CountingPool;
let vaultCalls = 0;
let root: CoffreClient;
let reader: CoffreClient;
let service: CoffreClient;
/** A workload's request, as its SDK sends it to the credential proxy: a fresh proof each time. */
let workload: () => Promise<void>;
/** The same through a Cloudflare service binding, its caller the binding's `props`. */
let bound: () => Promise<void>;
/** The scheduled beat, and `/readyz`'s check, on the counted connections. */
let beat: () => Promise<boolean>;
let ready: () => Promise<{ ok: boolean }>;
/** `count` entries of the app's appended at once, as many requests would write them. */
let append: (count: number) => Promise<void>;

/** A client that calls the API as a CLI or a CI run does, its token checked on each request. */
function bearer(runtime: CoffreRuntime, token: string): CoffreClient {
  return createClient({ url: ORIGIN, headers: () => ({ authorization: `Bearer ${token}` }), transport: (request) => fetchApi(request, runtime, { sourceIp: null }) });
}

before(async () => {
  if (POSTGRES.skip) return;
  db = await openTestDatabase();
  await resetDatabase(db.owner);
  app = new CountingPool(testPostgresPool(TEST_RUNTIME_DATABASE_URL));
  vaultPool = new CountingPool(testPostgresPool(TEST_VAULT_DATABASE_URL));
  const opened = await localVault({
    database: createDatabase(vaultPool),
    kek: { id: 'test-kek-1', key: randomBytes(32).toString('base64') },
    owners: [ROOT],
  });
  // Every call the app makes of the vault: on Workers, each its own invocation and connection.
  const vault = new Proxy(opened as unknown as FixtureDeps['vault'], {
    get(target, key) {
      const value: unknown = Reflect.get(target, key, target);
      if (typeof value !== 'function') return value;
      return (...args: unknown[]) => {
        vaultCalls += 1;
        return (value as (...args: unknown[]) => unknown).apply(target, args);
      };
    },
  });
  if (auth.mode !== 'signin') throw new Error('unreachable');
  const base: FixtureDeps = { db: createDatabase(app), vault, chainKey: randomBytes(32) };
  beat = () => writeAuditHeartbeat(base.db, base.chainKey, vault, { warn: () => assert.fail('the beat warned') });
  ready = () => auditReadiness(base.db, vault, base.chainKey);
  append = async (count) => {
    for (let left = count; left > 0; left -= 1000) {
      const entries = Array.from({ length: Math.min(1000, left) }, () => ({ actor: 'system:load', action: 'secret.read', decision: 'allow' as const, metadata: '{}' }));
      await db.owner.transaction((tx) => appendEntries(tx, appLogKey(base.chainKey), entries));
    }
  };
  const signinService = new SigninService({ ...base, signin: auth.signin });
  const deps: FixtureDeps = { ...base, signin: signinService };
  const runtime: CoffreRuntime = {
    db: deps.db, vault, chainKey: deps.chainKey, signin: signinService, workloads: null, mcp: null, auth, publicUrl: ORIGIN,
    verifier: signinService, waitUntil, schema: { migrated: true }, rotateAfterDays: 365, plugins: [],
  };
  root = clientFor(deps, ROOT);
  await root.projects.create('market', { name: 'Market' });
  for (const path of ['market/dev', 'market/prod', 'market/busy']) await root.environments.create(path, { name: path });
  await root.secrets.set('market/dev', { API_KEY: 'fake-api-key', DATABASE_URL: 'postgres://fake' });
  await root.members.add(`user:${READER}`);
  await root.access.set(`user:${READER}`, { 'market/dev': 'viewer' });
  await root.members.add(SERVICE);
  await root.access.set(SERVICE, { 'market/dev': 'viewer' });
  // One change to the policy, so that there is a newest to read before there are many.
  await root.environments.protect('market/prod');

  // The reader's CLI session, from an approved device login, and the service's token, as a CI run holds them.
  const started = await signinService.startDevice({ clientLabel: 'laptop', sourceIp: null });
  await signinService.decideDevice(await contextFor(deps, READER), started.userCode, true);
  const polled = await signinService.pollDevice(started.deviceCode, { requestId: randomUUID(), sourceIp: null });
  if (polled.status !== 'approved') throw new Error('the device login was not approved');
  reader = bearer(runtime, polled.credential.token);
  service = bearer(runtime, (await root.tokens.issue(SERVICE, { label: 'ci', expiresInDays: 1 })).token);

  // A workload's key-bound session of the service, as `/api/auth/workload` makes one, and a plugin that asks for it as the proxy does.
  const standing = (await memberStanding(deps.db, SERVICE))!;
  const bindingId = randomUUID();
  await insertBinding(deps.db, deps.chainKey, {
    id: bindingId, principal: SERVICE, generation: standing.generation, profile: 'kubernetes', issuer: 'https://cluster.acme.example', jwksUri: 'https://cluster.acme.example/keys',
    jwks: null, claims: '{"sub":"x"}', scope: null, policy: '{}', label: null, createdBy: ROOT,
  });
  const dev = (await places(deps.db)).find((project) => project.slug === 'market')!.environments.find((environment) => environment.slug === 'dev')!.id;
  const key = await generateProofKey();
  const token = generateToken('workload');
  const now = Date.now();
  await insertSession(deps.db, deps.chainKey, {
    id: randomUUID(), kind: 'workload', tokenHash: hashToken(token), tokenHint: tokenHint(token), generation: standing.generation, principal: SERVICE, identityId: null,
    label: null, createdBy: `binding:${bindingId}`, expiresAt: new Date(now + 3_600_000), revokedAt: null, scope: null,
    places: JSON.stringify([{ environmentId: dev, personal: false }]), jkt: await thumbprint(key.jwk), notAfter: new Date(now + 86_400_000),
    ancestors: null, constraints: null, enrollmentId: null, approvedAt: null, approvedBy: null,
  });
  const gate: Gate = { nonce: async () => 'g1.cost', admit: async () => ({ ok: true, nonce: 'g1.cost' }) };
  // Its last use, written once in five minutes after the answer: waited for, so it lands on its own request's count.
  const background: Promise<unknown>[] = [];
  const proxied = {
    ...runtime,
    waitUntil: (promise: Promise<unknown>) => void background.push(promise),
    auth: signin({ providers: [github({ clientId: 'gh-id', clientSecret: 'gh-secret' })], workloads: { limits: processLimits({ perSource: 10, total: 10 }) } }).resolve(ORIGIN),
    gates: () => gate,
    // The credential proxy itself, its upstream an egress that answers at once: the request costs only what coffre does.
    plugins: checkPlugins([credentialProxy({
      credentials: { stripe: { upstream: 'https://api.stripe.example', inject: header('authorization', 'Bearer {API_KEY}'), egress: { fetch: async () => new Response(null, { status: 204 }) } } },
    })]),
  } satisfies CoffreRuntime;
  workload = async () => {
    const url = `${ORIGIN}/use/stripe/v1/charges`;
    const body = 'amount=2000';
    const headers = { 'content-type': 'application/x-www-form-urlencoded' };
    const proof = await createProof(key, { method: 'POST', url, token, nonce: 'g1.cost', content: { headers, body: await bodyDigest(body) } });
    const answered = await pluginRoute(new Request(url, { method: 'POST', headers: { ...headers, authorization: `DPoP ${token}`, dpop: proof }, body }), proxied, null);
    if (answered?.status !== 204) throw new Error(`the proxy's workload was refused: ${await answered?.text()}`);
    await Promise.all(background.splice(0));
  };
  await insertBinding(deps.db, deps.chainKey, {
    id: randomUUID(), principal: SERVICE, generation: standing.generation, profile: 'cloudflare', issuer: 'urn:coffre:cloudflare', jwksUri: 'urn:coffre:cloudflare',
    jwks: null, claims: '{}', scope: null, policy: '{}', label: null, createdBy: ROOT,
  });
  bound = async () => {
    const answered = await bindingRoute(new Request(`${ORIGIN}/use/market/dev/stripe/v1/charges`, { method: 'POST', body: 'amount=2000' }), proxied, SERVICE);
    if (answered?.status !== 204) throw new Error(`the binding's call was refused: ${await answered?.text()}`);
    await Promise.all(background.splice(0));
  };
});

after(async () => {
  if (POSTGRES.skip) return;
  await resetDatabase(db.owner);
  await Promise.all([app.end(), vaultPool.end(), db.close()]);
});

async function cost(request: () => Promise<unknown>): Promise<Cost> {
  const before = { app: { ...app.count }, vault: { ...vaultPool.count }, vaultCalls };
  await request();
  const since = (now: Count, then: Count) => ({ statements: now.statements - then.statements, rows: now.rows - then.rows });
  return { app: since(app.count, before.app), vault: since(vaultPool.count, before.vault), vaultCalls: vaultCalls - before.vaultCalls };
}

/**
 * Each hot request, and what it costs warm: its statements on the app's
 * connection and the vault's, and the vault's calls. A workload's request
 * at the proxy: one statement, and nothing of the vault's.
 *
 * A reveal: the credential, with the newest policy change; the path; the
 * environment's rows; once the vault has released, the credential and its
 * member again (`credentialStill`). The vault's `access`: one statement. Its `unwrap`:
 * the versions, then BEGIN, its lock timeout, the reader's row locked,
 * the head locked with everything the decision reads, the entries and the
 * head in one statement, COMMIT.
 */
const requests: Record<string, { request: () => Promise<unknown>; budget: { app: number; vault: number; vaultCalls: number } }> = {
  'a reveal of one key': { request: () => reader.secrets.reveal('market/dev/API_KEY'), budget: { app: 4, vault: 8, vaultCalls: 2 } },
  'a reveal of an environment': { request: () => reader.secrets.reveal('market/dev'), budget: { app: 4, vault: 8, vaultCalls: 2 } },
  'an export, as a service': { request: () => service.secrets.reveal('market/dev'), budget: { app: 4, vault: 8, vaultCalls: 2 } },
  "a request's check of its caller": { request: () => reader.me(), budget: { app: 2, vault: 2, vaultCalls: 2 } },
  // Section 5.3's one statement: the session, its member, binding, ancestors and freezes; the vault is not asked, its
  // decision warm in the proxy's cache.
  "a workload's request at the proxy": { request: () => workload(), budget: { app: 1, vault: 0, vaultCalls: 0 } },
  // A Cloudflare call naming its environment: its binding, member, place and freezes in one statement; the vault's decision warm.
  "a Cloudflare call at the proxy": { request: () => bound(), budget: { app: 1, vault: 0, vaultCalls: 0 } },
};

test('each hot request runs exactly its budget of statements, on as many connections', POSTGRES, async () => {
  // Once first, for what the vault does once per process.
  for (const { request } of Object.values(requests)) await request();
  for (const [name, { request, budget }] of Object.entries(requests)) {
    const spent = await cost(request);
    assert.deepEqual({ app: spent.app.statements, vault: spent.vault.statements, vaultCalls: spent.vaultCalls }, budget, name);
  }
});

test('a request runs the same statements, and reads the same rows, however large the log, the members and the policy grow', POSTGRES, async () => {
  for (const { request } of Object.values(requests)) await request();
  const small: Record<string, Cost> = {};
  for (const [name, { request }] of Object.entries(requests)) small[name] = await cost(request);

  // The log grown by writes elsewhere, each an entry of the app's and one of the vault's.
  for (let i = 0; i < 150; i++) await root.secrets.set('market/busy', { [`KEY_${i % 20}`]: `fake-${i}` });
  // Members, each with a grant, and the reader's own access changed back and forth: entries about them.
  for (let i = 0; i < 40; i++) {
    await root.members.add(`user:member-${i}@acme.example`);
    await root.access.set(`user:member-${i}@acme.example`, { 'market/dev': 'viewer' });
  }
  for (let i = 0; i < 40; i++) await root.access.set(`user:${READER}`, { 'market/dev': i % 2 === 0 ? 'developer' : 'viewer' });
  // The policy changed, again and again: prod unprotected, then protected again.
  for (let i = 0; i < 40; i++) await root.environments.protect('market/prod', i % 2 === 1);

  for (const [name, { request }] of Object.entries(requests)) {
    assert.deepEqual(await cost(request), small[name], `${name} ran more statements or read more rows once the instance grew`);
  }
});

test("a caller's check reads nothing of a project they reach nothing in", POSTGRES, async () => {
  await reader.me();
  const before = await cost(() => reader.me());
  await root.projects.create('elsewhere', { name: 'Elsewhere' });
  for (const environment of ['dev', 'prod', 'qa']) await root.environments.create(`elsewhere/${environment}`, { name: environment });
  await root.secrets.set('elsewhere/dev', { A: 'fake-a', B: 'fake-b' });
  assert.deepEqual(await cost(() => reader.me()), before);
});

/**
 * The instance grown every way at once, in an order Hegel draws: other
 * environments written, other projects and their forks made, members granted, the
 * reader's own role flipped, environments protected and not, roles edited
 * and made, references made into the environment the requests read, keys
 * made sensitive, tokens issued. Whatever it grew by, each request costs
 * what it did before.
 */
const growth = gs.record({
  kind: gs.sampledFrom(['write', 'project', 'fork', 'member', 'flip', 'protect', 'role', 'reference', 'sensitive', 'token'] as const),
  place: gs.integers({ minValue: 0, maxValue: 7 }),
  count: gs.integers({ minValue: 1, maxValue: 12 }),
  on: gs.booleans(),
});
const growthSettings = propertySettings(4, 10);

test(`a request costs the same after any growth of the instance, seed ${growthSettings.seed}`, POSTGRES, async () => {
  for (const { request } of Object.values(requests)) await request();
  const small: Record<string, Cost> = {};
  for (const [name, { request }] of Object.entries(requests)) small[name] = await cost(request);
  // Places made so far: names from a counter, since the instance keeps what every case made. So Hegel's replay of a
  // failing case runs on a larger instance, and may pass, which it reports as flaky: the first failure is printed whole.
  const made = { projects: [] as string[], environments: ['market/busy', 'market/prod'], keys: [] as string[] };
  let n = 0;
  await hegel.testAsync(async (tc) => {
    const steps = tc.draw(gs.arrays(growth, { minSize: 1, maxSize: 8 }));
    for (const step of steps) {
      const at = made.environments[step.place % made.environments.length]!;
      const id = n++;
      switch (step.kind) {
        case 'write': {
          const keys = Object.fromEntries(Array.from({ length: step.count }, (_, i) => [`GROWN_${id}_${i}`, `fake-${id}-${i}`]));
          await root.secrets.set(at, keys);
          made.keys.push(...Object.keys(keys).map((key) => `${at}/${key}`));
          break;
        }
        case 'project': {
          await root.projects.create(`grown-${id}`, { name: `Grown ${id}` });
          for (const environment of ['dev', 'prod']) await root.environments.create(`grown-${id}/${environment}`, { name: environment });
          made.projects.push(`grown-${id}`);
          made.environments.push(`grown-${id}/dev`, `grown-${id}/prod`);
          break;
        }
        case 'fork': {
          // In another project than market: a caller reads the environments of the projects they reach, its forks among them.
          const [project, from] = at.split('/');
          if (project === 'market') break;
          await root.environments.create(`${project}/fork-${id}`, { name: `Fork ${id}`, from });
          made.environments.push(`${project}/fork-${id}`);
          break;
        }
        case 'member': {
          const member = `user:grown-${id}@acme.example`;
          await root.members.add(member);
          await root.access.set(member, { [step.on ? 'market/dev' : at]: step.count % 2 === 0 ? 'viewer' : 'developer' });
          break;
        }
        case 'flip':
          await root.access.set(`user:${READER}`, { 'market/dev': step.on ? 'developer' : 'viewer' });
          break;
        case 'protect':
          // Never market/dev, which the reader reads: protected, a viewer there only uses.
          await root.environments.protect(at, step.on);
          break;
        case 'role':
          await root.roles.set(step.on ? `grown-${step.count % 3}` : 'auditor', {
            name: `Grown ${step.count}`, description: '', permissions: step.count % 2 === 0 ? ['audit.read'] : ['audit.read', 'secret.read', 'secret.use'], protected: ['audit.read'],
          }, step.on ? undefined : { instance: true });
          break;
        case 'reference':
          await root.secrets.set(at, { [`REFERS_${id}`]: { ref: step.on ? 'market/dev/API_KEY' : 'market/dev/DATABASE_URL' } });
          break;
        case 'sensitive': {
          const grown = made.keys.filter((path) => !path.startsWith('market/dev/'));
          if (grown.length === 0) break;
          const path = grown[step.count % grown.length]!;
          const slash = path.lastIndexOf('/');
          await root.secrets.set(path.slice(0, slash), { [path.slice(slash + 1)]: { sensitivity: step.on ? 'sensitive' : 'secret' } });
          break;
        }
        case 'token':
          await (step.on
            ? root.tokens.issue(SERVICE, { label: `grown-${id}`, expiresInDays: 1 })
            : root.tokens.issue(`user:${ROOT}`, { label: `grown-${id}`, expiresInMinutes: 60, scope: { [at]: 'viewer' } }));
          break;
      }
    }
    for (const [name, { request }] of Object.entries(requests)) {
      const spent = await cost(request);
      const why = `${name} ran more statements or read more rows once the instance grew by ${JSON.stringify(steps)}: ${JSON.stringify(spent)}, not ${JSON.stringify(small[name])}`;
      if (JSON.stringify(spent) !== JSON.stringify(small[name])) console.error(why);
      assert.deepEqual(spent, small[name], why);
    }
  }, growthSettings);
});

test("readiness reads the entries since the newest beat's walk began, however long the log", POSTGRES, async () => {
  // An hour of beats, the most a resume reads back.
  for (let i = 0; i < 12; i++) await beat();
  assert.equal((await ready()).ok, true);
  const small = await cost(ready);
  // The log grown by writes, then a beat that walks them: readiness walks from where the next beat would.
  for (let i = 0; i < 150; i++) await root.secrets.set('market/busy', { [`READY_${i % 20}`]: `fake-${i}` });
  await beat();
  assert.equal((await ready()).ok, true);
  assert.deepEqual(await cost(ready), small, 'readiness ran more statements or read more rows once the log grew');
});

test('readiness reads no more than one walk of entries since the newest beat, and is red past it', POSTGRES, async () => {
  await beat();
  // Twice a walk's worth of writes since the newest beat, as a beat far behind a busy log would find.
  await append(2 * CHAIN_WALK);
  const spent = await cost(async () => assert.equal((await ready()).ok, false));
  // Each entry walked is two rows: its size, then itself (`withinBytes`, `auditRange`).
  assert.ok(spent.app.rows <= 2 * CHAIN_WALK + 100, `readiness read ${spent.app.rows} rows`);
});
