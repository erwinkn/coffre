// The Cloudflare binding (docs/design/workload-access.md, section 9.2), in
// workerd, as two Workers of an account run it: coffre's
// (test/workers/workload-coffre-worker.ts), which exports `CoffreWorkload`,
// and an app's (test/workers/workload-caller-worker.ts), which binds it
// several times, each binding's props its own. Props are the caller's
// proof: a binding without props naming a service, or naming one with no
// live cloudflare binding, gets nothing. The data is the suite's, seeded
// from Node with the vault's and the log's keys, which coffre's Worker is
// given too. Postgres only, as that Worker reaches its database over
// Hyperdrive.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { github, signin } from '@coffre/core/identity';
import { eq } from 'drizzle-orm';
import { createTestHarness, type TestHarness } from 'wrangler';

import { allowed, audited } from '../src/api/context.ts';
import { propsService } from '../src/cloudflare-workload.ts';
import { resolveConfig } from '../src/config.ts';
import { createRuntime, type CoffreRuntime } from '../src/runtime.ts';
import { processLimits } from '../src/workloads/limits.ts';
import { fetchTransport } from '../src/workloads/transport.ts';
import { clientFor, contextFor, holdSomething, openTestDatabase, resetDatabase, testDeps, type FixtureDeps } from './api-fixture.ts';
import { TEST_RUNTIME_DATABASE_URL, TEST_VAULT_DATABASE_URL } from './db/connections.ts';
import { TEST_ENGINE } from './db/engine.ts';
import { environments } from './db/tables.ts';

const skip = TEST_ENGINE !== 'postgres' ? "coffre's Worker reaches its database over Hyperdrive, Postgres" : false;
const COFFRE = 'coffre-workload-test';
const ORIGIN = 'https://secrets.acme.example';
const ROOT = 'admin@acme.example';
const SERVICE = 'edge-api';
const MEMBER = `token:${SERVICE}`;

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;
let runtime: CoffreRuntime;
let dir: string;
let harness: TestHarness;

before(async () => {
  if (skip) return;
  db = await openTestDatabase();
  await resetDatabase(db.owner);
  deps = testDeps(db.runtime, [ROOT]);
  runtime = createRuntime(
    resolveConfig({
      publicUrl: ORIGIN,
      vault: deps.vault,
      auth: signin({ providers: [github({ clientId: 'a', clientSecret: 'b' })], workloads: { limits: processLimits({ perSource: 1000, total: 1000 }) } }),
      auditChainKey: deps.chainKey.toString('base64'),
    }),
    deps.db,
    deps.vault,
    fetchTransport(),
  );
  deps.signin = runtime.signin!;
  // The service, holding a value in market/prod, the one place it reaches.
  assert.equal((await deps.vault.admit({ actor: `user:${ROOT}`, principal: MEMBER })).ok, true);
  await holdSomething(db.owner, deps.vault, MEMBER, `user:${ROOT}`);
  const root = clientFor(deps, ROOT);
  await root.projects.create('market', { name: 'Market' });
  await root.environments.create('market/prod', { name: 'prod' });
  await root.secrets.set('market/prod', { STRIPE_SECRET_KEY: 'sk_live_1' });
  await root.access.set(MEMBER, { 'market/prod': 'viewer' });
  harness = await boot();
});

after(async () => {
  await harness?.close();
  if (dir !== undefined) rmSync(dir, { recursive: true, force: true });
  if (db !== undefined) {
    await resetDatabase(db.owner);
    await db.close();
  }
});

/** The two Workers: coffre's is given the instance's keys. */
async function boot(): Promise<TestHarness> {
  dir = mkdtempSync(join(tmpdir(), 'coffre-workload-'));
  const worker = (name: string) => fileURLToPath(new URL(`./workers/${name}`, import.meta.url));
  const binding = (name: string, props?: Record<string, unknown>) => ({ binding: name, service: COFFRE, entrypoint: 'CoffreWorkload', ...(props === undefined ? {} : { props }) });
  writeFileSync(
    join(dir, 'coffre.json'),
    JSON.stringify({
      name: COFFRE,
      main: worker('workload-coffre-worker.ts'),
      compatibility_date: '2026-08-06',
      compatibility_flags: ['nodejs_compat'],
      vars: { APP_KEY: deps.chainKey.toString('base64'), VAULT_KEY: (deps.vault as unknown as { kek: Buffer }).kek.toString('base64') },
      hyperdrive: [
        { binding: 'HYPERDRIVE', id: 'coffre-app', localConnectionString: TEST_RUNTIME_DATABASE_URL },
        { binding: 'VAULT_HYPERDRIVE', id: 'coffre-vault', localConnectionString: TEST_VAULT_DATABASE_URL },
      ],
      services: [{ binding: 'VAULT', service: COFFRE, entrypoint: 'Vault' }],
    }),
  );
  writeFileSync(
    join(dir, 'caller.json'),
    JSON.stringify({
      name: 'coffre-workload-caller',
      main: worker('workload-caller-worker.ts'),
      compatibility_date: '2026-08-06',
      services: [
        binding('COFFRE', { service: SERVICE }),
        binding('UNBOUND', { service: 'ghost' }),
        binding('NO_PROPS'),
        binding('EXTRA', { service: SERVICE, place: 'market/prod' }),
        binding('NUMBER', { service: 42 }),
      ],
    }),
  );
  // Bundled from the packages' sources, as the tests read them.
  process.env.WRANGLER_BUILD_CONDITIONS = 'coffre:source,workerd,worker,browser';
  const started = createTestHarness({ root: dir, workers: [{ configPath: join(dir, 'caller.json') }, { configPath: join(dir, 'coffre.json') }] });
  await started.listen();
  return started;
}

type Called = { status?: number; body?: string; answer?: Record<string, unknown>; threw?: string };

/** What the caller's call through `binding` returned, or threw. */
async function call(binding: string, op: string, more: Record<string, string> = {}): Promise<Called> {
  const answered = await harness.fetch(`/?${new URLSearchParams({ binding, op, ...more })}`);
  assert.equal(answered.status, 200, await answered.clone().text());
  return (await answered.json()) as Called;
}

const reason = (called: Called) => (JSON.parse(called.body ?? '{}') as { reason?: string }).reason;

/** A freeze or its lift, as `POST /api/freezes` logs it. */
async function freeze(target: string, action: 'workload.freeze' | 'workload.unfreeze' = 'workload.freeze') {
  const ctx = { caller: { principal: { type: 'user', id: ROOT } }, requestId: randomUUID(), sourceIp: null } as never;
  await audited({ db: deps.db, chainKey: deps.chainKey }, async (_tx, log) => {
    log.push(allowed(ctx, action, { metadata: { target } }));
  });
}

test('props name a service, exactly: `edge-api` or `token:edge-api`, and no other field', () => {
  assert.equal(propsService({ service: 'edge-api' }), 'token:edge-api');
  assert.equal(propsService({ service: 'token:edge-api' }), 'token:edge-api');
  for (const props of [undefined, null, 'edge-api', ['edge-api'], {}, { service: 42 }, { service: '' }, { service: 'Edge-API' }, { service: 'edge api' }, { service: 'user:ada@acme.example' }, { service: 'token:' }, { service: 'edge-api', place: 'market/prod' }, { Service: 'edge-api' }]) {
    assert.equal(propsService(props), null, JSON.stringify(props));
  }
});

/** A cloudflare binding of the service, made by the Owner, for `run`; unbound after, whatever happens. */
async function bound<T>(label: string, run: (id: string) => Promise<T>): Promise<T> {
  const made = await runtime.workloads!.bind(await contextFor(deps, ROOT), SERVICE, { profile: 'cloudflare', issuer: null, claims: {} as never, label, replaces: [], policy: {} }, { dryRun: false });
  assert.ok('binding' in made);
  try {
    return await run(made.binding.id);
  } finally {
    await runtime.workloads!.unbind(await contextFor(deps, ROOT), SERVICE, made.binding.id).catch(() => undefined);
  }
}

test("a Worker is its service through the service's cloudflare binding, and nothing without one: bound, frozen, unbound", { skip, timeout: 180_000 }, async () => {
  // No binding yet: the props name a service, which nothing trusts.
  const before = await call('COFFRE', 'fetch');
  assert.equal(before.status, 401, before.body ?? '');
  await bound('edge', async (id) => {
    // Bound: the call is the service's, as the binding, with no proof and nothing between.
    const answered = await call('COFFRE', 'fetch', { path: '/use?credential=stripe' });
    assert.equal(answered.status, 200, answered.body ?? '');
    assert.deepEqual((JSON.parse(answered.body!) as { caller: unknown }).caller, { principal: MEMBER, credentialId: `binding:${id}`, profile: 'cloudflare', hdr: null, sourceIp: null });
    // Another service's props, with no binding of its own, still get nothing.
    assert.equal((await call('UNBOUND', 'fetch')).status, 401);

    // Frozen: the binding, then the credential it uses; each lifted.
    await freeze(`binding:${id}`);
    assert.equal(reason(await call('COFFRE', 'fetch', { path: '/use?credential=stripe' })), 'frozen');
    await freeze(`binding:${id}`, 'workload.unfreeze');
    assert.equal((await call('COFFRE', 'fetch', { path: '/use?credential=stripe' })).status, 200);
    const place = (await db.owner.select().from(environments).where(eq(environments.slug, 'prod')))[0]!.id;
    await freeze(`credential:${place}/stripe`);
    assert.equal(reason(await call('COFFRE', 'fetch', { path: '/use?credential=stripe' })), 'frozen');
    assert.equal((await call('COFFRE', 'fetch', { path: '/use?credential=openai' })).status, 200, 'another credential is not frozen');
    await freeze(`credential:${place}/stripe`, 'workload.unfreeze');

    // Unbound: the next call gets nothing.
    await runtime.workloads!.unbind(await contextFor(deps, ROOT), SERVICE, id);
    assert.equal((await call('COFFRE', 'fetch')).status, 401);
  });
});

test('a bound Worker uses the values its service holds, through the vault, as the proxy will', { skip, timeout: 180_000 }, async () => {
  await bound('edge-use', async () => {
    const answered = await call('COFFRE', 'fetch', { path: '/use?credential=stripe&key=STRIPE_SECRET_KEY' });
    assert.equal(answered.status, 200, `${answered.body} ${JSON.stringify(harness.getLogs().filter((log) => log.level === 'error').slice(-2))}`);
    assert.equal((JSON.parse(answered.body!) as { value: string }).value, 'sk_live_1');
  });
});

test('a binding without props naming a service gets nothing, through fetch or any RPC method', { skip, timeout: 180_000 }, async () => {
  for (const binding of ['NO_PROPS', 'EXTRA', 'NUMBER']) {
    const fetched = await call(binding, 'fetch');
    assert.equal(fetched.status, 401, `${binding}: ${fetched.body}`);
    assert.equal(reason(fetched), 'props');
    for (const op of ['sign', 'verify', 'presign']) {
      const answered = await call(binding, op);
      assert.equal(answered.answer, undefined, `${binding} ${op} got ${JSON.stringify(answered.answer)}`);
      assert.match(answered.threw ?? '', /without props naming its service/, `${binding} ${op}`);
    }
  }
});

test("a binding reaches the proxy's paths only, never the API, sign-in or the pages", { skip, timeout: 180_000 }, async () => {
  for (const path of ['/api/members', '/auth/login', '/', '/useless', '/mcp', '/use/../api/members']) {
    const answered = await call('COFFRE', 'fetch', { path });
    assert.equal(answered.status, 404, `${path}: ${answered.body}`);
  }
});

test('each RPC method is a POST to /use, or to the place it names, as its service', { skip, timeout: 180_000 }, async () => {
  await bound('edge-rpc', async (id) => {
    const sent = {
      sign: { sign: { credential: 'dfns-key', message: 'Y2hhbGxlbmdl' } },
      verify: { verify: { credential: 'stripe-webhook', message: 'Y2hhbGxlbmdl', signature: 'v1=00' } },
      presign: { presign: { credential: 's3', path: '/bucket/key' } },
    };
    for (const [op, body] of Object.entries(sent)) {
      const answered = await call('COFFRE', op, { message: 'challenge', signature: 'v1=00' });
      assert.equal(answered.threw, undefined, `${op}: ${answered.threw}`);
      assert.deepEqual(answered.answer!.body, body, op);
      assert.equal((answered.answer!.caller as { credentialId: string }).credentialId, `binding:${id}`);
      const unbound = await call('UNBOUND', op);
      assert.equal(unbound.answer, undefined, `UNBOUND ${op}`);
      assert.match(unbound.threw ?? '', /no live cloudflare binding/, `UNBOUND ${op}`);
    }
    for (const place of ['market', 'market/prod/extra', '/prod']) {
      const answered = await call('COFFRE', 'sign', { place });
      assert.match(answered.threw ?? '', /place names an environment/, place);
    }
  });
});
