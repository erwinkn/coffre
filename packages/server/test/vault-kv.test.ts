// The Vault KV adapter (`@coffre/server/plugins/vault-kv`), as External
// Secrets Operator reaches it: the requests its Vault provider makes, through
// HashiCorp's Go client (`hashicorp/vault/api` v1.22.0, which ESO v2.13.0
// pins), each answered by coffre in process, on the 0.16 contract. A read is
// the API's reveal as the token's holder (`PluginContext.api`): one `use`,
// and no statement of the app's. And the plugin mechanism around it: paths
// checked at configuration. 0.14.7's cases, where they still hold; its
// sign-in, vault-kv-login.test.ts.
import assert from 'node:assert/strict';
import { after, beforeEach, test } from 'node:test';

import { CoffreError } from '@coffre/client';
import { cloudflareAccess } from '@coffre/core/identity';
import { rowsOf } from '@coffre/db/dialect';
import { credential, emptyDatabase, environment, grant, identity, instance, principal, project, rewrite, role, rows, secret, user, value, write } from '@coffre/vault/testing';
import { sql } from 'drizzle-orm';

import { checkPlugins, pluginRoute, type CoffrePlugin } from '../src/plugins.ts';
import { vaultKv } from '../src/plugins/vault-kv.ts';
import type { CoffreRuntime } from '../src/runtime.ts';
import { openApp, SESSION, type TestApp } from './app-fixture.ts';

/**
 * Beside the adapter, a plugin of the test's own that makes several API calls
 * on one request, as `PluginContext.api` lets a plugin: who the token is, the
 * projects it reaches, and who it is again. Its answer says what it saw, or
 * the refusal, as a `CoffreError`.
 */
const probe: CoffrePlugin = {
  name: 'probe',
  routes: {
    prefix: '/probe',
    fetch: async (request, coffre) => {
      const api = coffre.api(request.headers.get('x-token') ?? '');
      try {
        const me = await api.me();
        const { projects } = await api.projects.list();
        const again = await api.me();
        return Response.json({ registered: [me.registered, again.registered], projects: projects.map((one) => one.slug) });
      } catch (error) {
        if (!(error instanceof CoffreError)) throw error;
        return Response.json({ status: error.status, code: error.code, reason: error.reason ?? null }, { status: 418 });
      }
    },
  },
};
const plugins = [vaultKv(), probe];
const app = await openApp({ plugins });
const { world } = app;
after(() => app.close());

const [root, dev] = [user('root'), user('dev')];
const [ESO, EU, OLD] = ['token:eso', 'token:eu', 'token:old'];
const PROD = { DATABASE_URL: 'postgres://prod', STRIPE_KEY: 'sk_live_prod' };
const STAGING = { DATABASE_URL: 'postgres://staging' };
const HIDDEN = 'sk_hidden_staging';
const PERSONAL = `coffre_pat_${'p'.repeat(43)}`;
const BROWSER = `coffre_web_${'w'.repeat(43)}`;
/** Credentials the API takes from no one: root's handle and MCP client's token, and ESO's workload session, each live. */
const HANDLE = `coffre_use_${'h'.repeat(43)}`;
const MCP = `coffre_mcp_${'m'.repeat(43)}`;
const WORKLOAD = `coffre_wl_${'k'.repeat(43)}`;
/** ESO's token ends then: lookup-self says what it has left. */
const ENDS = new Date(Date.now() + 30 * 86_400_000);

/**
 * market: prod, its fork prod-eu, which inherits, and staging, with a
 * sensitive key and Dev's personal config of it. ESO, a service account,
 * views prod and prod-eu; eu, prod-eu alone; old was removed. Dev views
 * market, and has a CLI session and a personal token scoped to staging;
 * root, the Owner, a browser session. Each service token is scoped to
 * where its account views.
 */
let stripe: ReturnType<typeof secret>;
beforeEach(async () => {
  await emptyDatabase(world.owner);
  for (const kept of [world.memory.reads, world.memory.callers, world.memory.logged, world.memory.touched, world.refused]) kept.clear();
  const market = project('market');
  const prod = environment(market, 'prod');
  const eu = environment(market, 'prod-eu', { parentId: prod.id });
  const staging = environment(market, 'staging');
  const devs = environment(market, 'staging-dev', { parentId: staging.id, owner: dev });
  stripe = await value(world, secret(prod, 'STRIPE_KEY'), PROD.STRIPE_KEY, { sensitive: true });
  const github = identity(root);
  // A service token reaches what it was made for, as Viewer, sensitive values included, as an Owner issues one.
  const scoped = (...at: { id: string }[]) => ({ scope: JSON.stringify(at.map((place) => ({ projectId: market.id, environmentId: place.id, role: 'viewer', sensitive: true }))) });
  await write(
    world,
    ...rows('policy', instance()),
    ...rows('projects', market),
    ...rows('environments', prod, eu, staging, devs),
    ...rows(
      'secrets',
      await value(world, secret(prod, 'DATABASE_URL'), PROD.DATABASE_URL),
      stripe,
      await value(world, secret(eu, 'REGION'), 'eu-west-1'),
      await value(world, secret(staging, 'DATABASE_URL'), STAGING.DATABASE_URL),
      await value(world, secret(staging, 'HIDDEN'), HIDDEN, { sensitive: true }),
      await value(world, secret(devs, 'DATABASE_URL'), 'postgres://localhost/dev'),
    ),
    ...rows('roles', role(false, 'viewer', ['secret.read'], []), role(true, 'owner', ['secret.read', 'secret.write']), role(true, 'member', [])),
    ...rows('principals', principal(root, { role: 'owner' }), principal(dev), principal(ESO), principal(EU), principal(OLD, { status: 'removed' })),
    ...rows('grants', grant(ESO, 'viewer', { environment: prod }), grant(ESO, 'viewer', { environment: eu }), grant(EU, 'viewer', { environment: eu }), grant(dev, 'viewer', { project: market })),
    ...rows('identities', github),
    ...rows(
      'credentials',
      credential('eso-token', ESO, { expiresAt: ENDS, ...scoped(prod, eu) }),
      credential('eu-token', EU, scoped(eu)),
      credential('old-token', OLD, scoped(prod)),
      credential('dev-cli', dev),
      credential(PERSONAL, dev, { kind: 'personal', scope: JSON.stringify([{ projectId: market.id, environmentId: staging.id, role: 'viewer' }]) }),
      credential(BROWSER, root, { kind: 'browser', identityId: github.id }),
      credential(HANDLE, root, { kind: 'handle', ...scoped(prod), places: JSON.stringify([{ environmentId: prod.id, personal: false }]) }),
      credential(MCP, root, { kind: 'mcp', client: JSON.stringify({ id: 'https://claude.ai/client.json', host: 'claude.ai', registration: 'cimd', redirectUri: 'https://claude.ai/callback', scopes: 'read' }) }),
      credential(WORKLOAD, ESO, { kind: 'workload', jkt: 'eso-key', ...scoped(prod) }),
    ),
  );
  // The database's migrations are known from the first request on: none of a test's counts is that question.
  await app.request('/livez');
  await app.request('/api/me', { headers: { authorization: 'Bearer nobody' } });
  app.calls.length = 0;
});

type Vault = { data: (Record<string, unknown> & { data?: Record<string, string> }) | null; errors?: string[]; warnings?: string[] | null } & Record<string, unknown>;

/** What HashiCorp's Go client sends with every request: its token, and `X-Vault-Request`. */
function vault(path: string, token: string | null = 'eso-token', init: RequestInit & { headers?: Record<string, string> } = {}, through: TestApp = app) {
  return through.request(`/v1/${path}`, {
    ...init,
    headers: { 'x-vault-request': 'true', 'user-agent': 'Go-http-client/1.1', ...(token === null ? {} : { 'x-vault-token': token }), ...init.headers },
  });
}
const body = async (response: Response | Promise<Response>) => (await (await response).json()) as Vault;
const read = async (path: string, token?: string | null) => (await body(vault(`secret/data/${path}`, token))).data?.data;
/** What one request cost: the vault's calls it made, and the app's statements. */
async function cost<T>(run: () => Promise<T>): Promise<[T, string[], number]> {
  const [calls, statements] = [app.calls.length, app.statements];
  const result = await run();
  return [result, app.calls.slice(calls), app.statements - statements];
}
/** A body that counts its reads: a request built on it is read only if something pulls it. */
function counted(text: string) {
  let pulls = 0;
  const body = new ReadableStream<Uint8Array>({ pull: (sink) => void (pulls++, sink.enqueue(new TextEncoder().encode(text)), sink.close()) }, { highWaterMark: 0 });
  return { init: { method: 'PUT', body, duplex: 'half' } as RequestInit & { headers?: Record<string, string> }, pulls: () => pulls };
}
const logged = async () => (await rowsOf<{ body: string }>(world.owner, sql`SELECT body FROM log_pending ORDER BY id`)).map((row) => row.body);

test("ESO's store check and reads: lookup-self, then an environment, the API's reveal as the token, in one `use` and no statement of the app's", async () => {
  // SecretStore validation: ESO's checkToken asserts `type` is a string and `ttl` a number, and reads `expire_time`.
  const [self, asked] = await cost(() => body(vault('auth/token/lookup-self')));
  // `GET /api/me`, as the token: the vault asked about it once.
  assert.deepEqual(asked, ['caller']);
  assert.equal(self.data!.type, 'service');
  assert.equal(self.data!.display_name, ESO);
  assert.equal(self.data!.expire_time, ENDS.toISOString());
  assert.ok(Math.abs((self.data!.ttl as number) - 30 * 86_400) < 60, String(self.data!.ttl));
  assert.equal('namespace_path' in self.data!, false, 'Terraform refuses a token in a namespace');

  // dataFrom.extract and data[].remoteRef: one read of the environment, the property picked by ESO itself.
  const [response, calls, statements] = await cost(() => vault('secret/data/market/prod'));
  assert.deepEqual([response.status, calls, statements], [200, ['use'], 0]);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  const { data, renewable, lease_duration, warnings } = await body(response);
  // A service account is handed a sensitive value, and nothing is left out.
  assert.deepEqual({ ...data!.data }, PROD);
  assert.deepEqual([renewable, lease_duration, warnings], [false, 0, null]);
  const metadata = data!.metadata as { version: number; custom_metadata: { coffre_version: string } };
  assert.equal(metadata.version, 0);
  // The environment's own version, as the API's reveal answers it.
  const api = (await (await app.request('/api/reveals', { method: 'POST', headers: { authorization: 'Bearer eso-token' }, body: JSON.stringify({ path: 'market/prod' }) })).json()) as { version: string };
  assert.equal(metadata.custom_metadata.coffre_version, api.version);
  // The vault's entry for the read: an environment's, as an export's.
  const entries = await logged();
  assert.ok(entries.some((entry) => entry.includes('"purpose":"run"') && entry.includes('STRIPE_KEY')), entries.join('\n'));
});

test('one value, by its key', async () => {
  const [response, calls, statements] = await cost(() => vault('secret/data/market/prod/STRIPE_KEY'));
  assert.deepEqual([calls, statements], [['use'], 0]);
  assert.deepEqual({ ...(await body(response)).data!.data }, { STRIPE_KEY: PROD.STRIPE_KEY });
});

test("an environment the token cannot read, or one that is not there, is Vault's 403, with no value; a key that is not there is 404, which ESO reads as gone", async () => {
  // The vault says neither which (`no_access`), so 0.14.7's 404 for an environment is a 403 now: ESO deletes nothing on it.
  for (const path of ['market/staging', 'market/nowhere']) {
    const denied = await vault(`secret/data/${path}`);
    assert.equal(denied.status, 403, path);
    const text = await denied.text();
    assert.match(text, /permission denied/);
    assert.equal(text.includes(STAGING.DATABASE_URL), false);
  }
  const missing = await vault('secret/data/market/prod/NOPE');
  assert.equal(missing.status, 404);
  assert.deepEqual(await missing.json(), { errors: [] });
});

test('the token is X-Vault-Token alone: none, a wrong one, or a browser session cookie are each refused', async () => {
  assert.equal((await vault('secret/data/market/prod', null)).status, 403);
  assert.equal((await vault('auth/token/lookup-self', `coffre_svc_${'A'.repeat(43)}`)).status, 403);
  // The Owner's browser, sent from coffre's own origin: the cookie is never read here.
  const page = { cookie: `${SESSION}=${BROWSER}`, 'sec-fetch-site': 'same-origin' };
  const cookie = await vault('secret/data/market/prod', null, { headers: page });
  assert.equal(cookie.status, 403);
  assert.equal((await cookie.text()).includes(PROD.DATABASE_URL), false);
});

test("a person's read leaves the sensitive keys out, and Vault's warnings name them, never their values; the key alone is refused", async () => {
  const response = await vault('secret/data/market/staging', 'dev-cli');
  assert.equal(response.status, 200);
  const text = await response.text();
  assert.equal(text.includes(HIDDEN), false);
  const { data, warnings } = JSON.parse(text) as Vault;
  assert.deepEqual(data!.data, STAGING);
  assert.deepEqual(warnings, ['left out, sensitive, which no person is handed: HIDDEN']);
  // Never 404, which ESO would read as the secret gone.
  assert.equal((await vault('secret/data/market/staging/HIDDEN', 'dev-cli')).status, 403);
});

test("a fork that inherits reads its parent's values live, as the API's reveal does, and only with read on the parent", async () => {
  assert.deepEqual({ ...(await read('market/prod-eu')) }, { ...PROD, REGION: 'eu-west-1' });
  await rewrite(world, stripe, 'sk_live_rotated');
  world.memory.reads.clear();
  assert.deepEqual({ ...(await read('market/prod-eu/STRIPE_KEY')) }, { STRIPE_KEY: 'sk_live_rotated' });
  // Read on the fork alone: its inherited keys are refused, and nothing is revealed.
  const refused = await vault('secret/data/market/prod-eu', 'eu-token');
  assert.equal(refused.status, 403);
  assert.equal((await refused.text()).includes('eu-west-1'), false);
});

test("`<project>/<env>@me` is the caller's personal config over the environment, as the API reads it", async () => {
  assert.deepEqual({ ...(await read('market/staging@me', 'dev-cli')) }, { DATABASE_URL: 'postgres://localhost/dev' });
  // Everyone else's `@me`, without one of their own, is the environment itself.
  assert.deepEqual({ ...(await read('market/prod@me')) }, PROD);
});

test("a person's personal token reads within its scope, and lookup-self answers for it", async () => {
  assert.equal((await body(vault('auth/token/lookup-self', PERSONAL))).data!.display_name, dev);
  assert.deepEqual({ ...(await read('market/staging', PERSONAL)) }, STAGING);
  assert.equal((await vault('secret/data/market/prod', PERSONAL)).status, 403);
});

test('read only: every other method is 405, and changes nothing', async () => {
  for (const method of ['PUT', 'POST', 'PATCH', 'DELETE']) {
    const [response, calls] = await cost(() => vault('secret/data/market/prod', 'eso-token', { method, body: JSON.stringify({ data: { STRIPE_KEY: 'x' } }) }));
    assert.deepEqual([response.status, calls], [405, []], method);
  }
  assert.deepEqual({ ...(await read('market/prod')) }, PROD);
});

test('what coffre does not serve says so, before the vault is asked, and never as 404 on a path a client meant as a secret', async () => {
  const [statuses, calls, statements] = await cost(async () => {
    const status = async (path: string, headers: Record<string, string> = {}) => (await vault(path, 'eso-token', { headers })).status;
    return [
      // A version's, or a snapshot's values, which coffre has not: never answered with today's.
      await status('secret/data/market/prod?version=2'),
      await status('secret/data/market/prod?read_snapshot_id=snap-1'),
      // ESO's dataFrom.find, as HashiCorp's client sends LIST: a 404 here would read as every secret gone.
      await status('secret/data/market/prod?list=true'),
      await status('secret/metadata/market/?list=true'),
      await status('secret/metadata/?list=true'),
      // Too short or too deep names no environment: a configuration mistake, which must not delete ESO's target.
      await status('secret/data/market'),
      await status('secret/data/market/prod/KEY/more'),
      await status('secret/data/market/prod', { 'x-vault-namespace': 'team-a' }),
      // metadataPolicy: Fetch, another mount, a path coffre does not serve.
      await status('secret/metadata/market/prod'),
      await status('kv/data/market/prod'),
      // `vault kv get -wrap-ttl=5m` expects a wrapping token, never the values themselves.
      await status('secret/data/market/prod', { 'x-vault-wrap-ttl': '5m' }),
    ];
  });
  assert.deepEqual([statuses, calls, statements], [[400, 400, 405, 405, 405, 400, 400, 400, 400, 400, 400], [], 0]);
  // `auth/token/lookup`, which takes another's token: 400 once the token is checked.
  assert.equal((await vault('auth/token/lookup')).status, 400);
  // vault-action sends an empty namespace with every request.
  assert.equal((await vault('secret/data/market/prod', 'eso-token', { headers: { 'x-vault-namespace': '' } })).status, 200);
});

test("`vault kv get` and vals learn the mount's version first, without a token", async () => {
  const { data } = await body(vault('sys/internal/ui/mounts/secret/market/prod', null));
  assert.equal(data!.path, 'secret/');
  assert.equal((data!.options as { version: string }).version, '2');
  assert.equal((await vault('sys/internal/ui/mounts/kv/market/prod', null)).status, 403);
});

test("`PluginContext.api`: a plugin's several API calls on one request ask the vault who the token is once, for all of them", async () => {
  const [response, calls, statements] = await cost(() => app.request('/probe', { headers: { 'x-token': 'eso-token' } }));
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { registered: [true, true], projects: ['market'] });
  assert.deepEqual(calls, ['caller']);
  // Each call's own statements, as over HTTP: the shared caller saves the vault's asking, not the app's reads.
  const [, alone, separately] = await cost(async () => {
    for (const path of ['/api/me', '/api/projects', '/api/me']) await app.request(path, { headers: { authorization: 'Bearer eso-token' } });
  });
  assert.deepEqual([alone, statements], [['caller', 'caller', 'caller'], separately]);
});

test('a handle, an MCP client\'s token and a workload\'s session sent through `PluginContext.api` are each refused, as the API refuses them, before the vault', async () => {
  for (const [token, status, code, reason] of [
    [HANDLE, 403, 'forbidden', 'handle'],
    [MCP, 401, 'unauthenticated', null],
    [WORKLOAD, 401, 'unauthenticated', 'workload'],
  ] as const) {
    const [probed, calls, statements] = await cost(async () => [await app.request('/probe', { headers: { 'x-token': token } }), await vault('secret/data/market/prod', token), await vault('auth/token/lookup-self', token)] as const);
    const [direct, read, self] = probed;
    assert.deepEqual([direct.status, await direct.json()], [418, { status, code, reason }], token);
    // Vault's 403, with no value.
    for (const refusal of [read, self]) {
      assert.equal(refusal.status, 403, token);
      const text = await refusal.text();
      assert.match(text, /permission denied/);
      assert.equal(text.includes(PROD.DATABASE_URL), false);
    }
    assert.deepEqual([calls, statements], [[], 0], token);
  }
});

test('a token whose account was removed is refused at lookup-self and at reads', async () => {
  assert.equal((await vault('auth/token/lookup-self', 'old-token')).status, 403);
  assert.equal((await vault('secret/data/market/prod', 'old-token')).status, 403);
});

test('an instance that trusts no workloads signs nothing in: 400, never 404, which no read names', async () => {
  const login = counted(JSON.stringify({ role: 'eso', jwt: 'x.y.z' }));
  const [none, calls, statements] = await cost(() => vault('auth/kubernetes/login', null, login.init));
  assert.equal(none.status, 400);
  assert.match((await none.json() as Vault).errors![0]!, /trusts no workloads/);
  // Refused before its body is read, or anything asked.
  assert.deepEqual([login.pulls(), calls, statements], [0, [], 0]);
});

test("behind Cloudflare Access, which 0.16.0 serves to browsers alone, a token is refused as the API's bearer is: before the vault, never a value", async () => {
  const behind = await openApp({ auth: cloudflareAccess({ teamDomain: 'acme.cloudflareaccess.com', audience: 'a'.repeat(64) }), plugins });
  try {
    for (const [path, init] of [
      ['secret/data/market/prod', {}],
      ['auth/token/lookup-self', {}],
      ['auth/token/revoke-self', { method: 'PUT' }],
      ['auth/kubernetes/login', { method: 'PUT', body: JSON.stringify({ role: 'eso', jwt: 'x.y.z' }) }],
    ] as const) {
      const response = await vault(path, 'eso-token', init, behind);
      assert.ok([400, 401, 403].includes(response.status), `${path}: ${response.status}`);
      assert.equal((await response.text()).includes(PROD.DATABASE_URL), false);
    }
    // A login's body is never read: the exchange is refused first.
    const login = counted(JSON.stringify({ role: 'eso', jwt: 'x.y.z' }));
    assert.equal((await vault('auth/kubernetes/login', null, login.init, behind)).status, 400);
    assert.equal(login.pulls(), 0);
    assert.deepEqual(behind.calls, []);
  } finally {
    await behind.close();
  }
});

test('plugins are checked at configuration: names, prefixes, and paths coffre or another plugin answers', () => {
  const at = (name: string, prefix: string): CoffrePlugin => ({ name, routes: { prefix, fetch: async () => new Response() } });
  assert.throws(() => checkPlugins([at('a', '/api')]), /overlaps \/api, which coffre answers/);
  assert.throws(() => checkPlugins([at('a', '/api/vault')]), /overlaps \/api/);
  assert.throws(() => checkPlugins([at('a', '/v1'), at('b', '/v1/sys')]), /overlaps \/v1, which another plugin takes/);
  assert.throws(() => checkPlugins([at('a', '/v1'), at('a', '/v2')]), /two plugins are named a/);
  assert.throws(() => checkPlugins([at('a', '/v1/')]), /without a trailing slash/);
  assert.throws(() => checkPlugins([at('Vault', '/v1')]), /lowercase/);
  assert.throws(() => vaultKv({ mount: 'kv/team' }), /one path segment/);
  // Vault's own roots: `auth/data/market/prod/login` would be a login.
  assert.throws(() => vaultKv({ mount: 'auth' }), /Vault's own path/);
  assert.throws(() => vaultKv({ mount: 'sys' }), /Vault's own path/);
  assert.equal(checkPlugins([at('a', '/v1'), at('b', '/v10'), { name: 'quiet' }]).length, 3);
});

test("paths no plugin takes stay the pages'", () => {
  const runtime = { plugins: checkPlugins(plugins) } as unknown as CoffreRuntime;
  assert.equal(pluginRoute(new Request('https://secrets.acme.example/v10/x'), runtime, null), null);
  assert.equal(pluginRoute(new Request('https://secrets.acme.example/v1x'), runtime, null), null);
});
