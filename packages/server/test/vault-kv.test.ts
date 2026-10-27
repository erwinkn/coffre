// The Vault KV v2 adapter (`@coffre/server/plugins/vault-kv`), as External
// Secrets Operator reaches it: the requests its Vault provider makes, through
// HashiCorp's Go client (`hashicorp/vault/api` v1.22.0, which ESO v2.13.0
// pins), each answered by coffre in process. And the plugin mechanism around
// it: paths checked at configuration, and a plugin's API as the token's holder.
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

import { contextFor, clientFor, keyIds, LOG, usesLogged } from './api-fixture.ts';
import { browserFor, db, deps, entries, fromPage, ROOT, route, runtime, sessionFor, useMcp, DEV } from './mcp-fixture.ts';
import { coffreRoute } from '../src/app.ts';
import type { CoffreRuntime } from '../src/runtime.ts';
import { checkPlugins, type CoffrePlugin } from '../src/plugins.ts';
import { vaultKv } from '../src/plugins/vault-kv.ts';

const PROD = { DATABASE_URL: `postgres://prod-${randomBytes(6).toString('hex')}`, STRIPE_KEY: `sk_live_${randomBytes(6).toString('hex')}` };
const STAGING = { DATABASE_URL: `postgres://staging-${randomBytes(6).toString('hex')}` };
let eso: string;

useMcp(async () => {
  runtime.plugins = checkPlugins([vaultKv()]);
  const root = clientFor(deps, ROOT);
  await root.members.add(`user:${DEV}`);
  await root.members.add('token:eso');
  await root.projects.create('market');
  await root.environments.create('market/prod');
  await root.environments.create('market/staging');
  await root.secrets.set('market/prod', PROD);
  await root.secrets.set('market/staging', STAGING);
  await root.access.set('token:eso', { 'market/prod': 'viewer' });
  eso = (await runtime.signin!.issueServiceToken(await contextFor(deps, ROOT), 'eso', { label: 'external-secrets', expiresInDays: 30 })).token;
});

/** What HashiCorp's Go client sends with every request: its token, and `X-Vault-Request`. */
function vault(path: string, token: string | null = eso, init: RequestInit & { headers?: Record<string, string> } = {}) {
  return route(`/v1/${path}`, {
    ...init,
    headers: { 'x-vault-request': 'true', 'user-agent': 'Go-http-client/1.1', ...(token === null ? {} : { 'x-vault-token': token }), ...init.headers },
  });
}

async function body(response: Response) {
  return (await response.json()) as { data: Record<string, unknown> & { data?: Record<string, string> }; errors?: string[] } & Record<string, unknown>;
}

test("ESO's store check and reads: lookup-self, then an environment, logged as one read of its keys by the token", async () => {
  // SecretStore validation: ESO's checkToken asserts `type` is a string and `ttl` a number, and reads `expire_time`.
  const self = await body(await vault('auth/token/lookup-self'));
  assert.equal(self.data.type, 'service');
  // What the token has left, as `GET /api/me` says it: 30 days, less the moments the test took.
  const me = (await (await route('/api/me', { headers: { authorization: `Bearer ${eso}` } })).json()) as { credentialExpiresAt: string };
  assert.equal(self.data.expire_time, me.credentialExpiresAt);
  assert.ok(Math.abs(Date.parse(me.credentialExpiresAt) - Date.now() - 30 * 86_400_000) < 60_000);
  assert.ok(Math.abs((self.data.ttl as number) - 30 * 86_400) < 60);
  assert.equal(self.data.display_name, 'token:eso');
  assert.equal('namespace_path' in self.data, false, "Terraform refuses a token in a namespace");

  // dataFrom.extract and data[].remoteRef: one read of the environment, the property picked by ESO itself.
  const read = await vault('secret/data/market/prod');
  assert.equal(read.status, 200);
  assert.equal(read.headers.get('cache-control'), 'no-store');
  const { data, renewable, lease_duration } = await body(read);
  assert.deepEqual(data.data, PROD);
  assert.deepEqual([renewable, lease_duration], [false, 0]);
  const metadata = data.metadata as { version: number; custom_metadata: { coffre_version: string } };
  assert.equal(metadata.version, 0);
  // The environment's own version, as `GET /api/projects/market/prod/version` answers it, without a read.
  assert.equal(metadata.custom_metadata.coffre_version, (await clientFor(deps, ROOT).environments.version('market/prod')).version);

  // One entry for the environment, naming every key it opened (#242). Under 0.15's log, a use of each, on the token.
  if (LOG === '0.14') {
    const reads = (await entries('secret.read')).filter((entry) => entry.decision === 'allow');
    assert.deepEqual(reads.map((entry) => entry.actor), ['token:eso']);
    assert.equal(JSON.stringify(reads[0]!.metadata.secrets).includes('STRIPE_KEY'), true);
  } else {
    const uses = await usesLogged(db.owner);
    assert.equal(new Set(uses.map((use) => use.credential)).size, 1, 'one credential, the token');
    const stripe = await keyIds(db.owner, 'STRIPE_KEY');
    assert.ok(uses.some((use) => stripe.includes(use.secret)));
  }
});

test('one value, by its key', async () => {
  const { data } = await body(await vault('secret/data/market/prod/STRIPE_KEY'));
  assert.deepEqual(data.data, { STRIPE_KEY: PROD.STRIPE_KEY });
});

test("an environment the token cannot read is Vault's 403, with no value; one that does not exist is 404, which ESO reads as gone", async () => {
  const denied = await vault('secret/data/market/staging');
  assert.equal(denied.status, 403);
  const text = await denied.text();
  assert.match(text, /permission denied/);
  assert.equal(text.includes(STAGING.DATABASE_URL), false);

  const missing = await vault('secret/data/market/nowhere');
  assert.equal(missing.status, 404);
  assert.deepEqual(await missing.json(), { errors: [] });
  assert.equal((await vault('secret/data/market/prod/NOPE')).status, 404);
});

test('the token is X-Vault-Token alone: none, a wrong one, or a browser session cookie are each refused', async () => {
  assert.equal((await vault('secret/data/market/prod', null)).status, 403);
  assert.equal((await vault('auth/token/lookup-self', `coffre_svc_${'A'.repeat(43)}`)).status, 403);
  // A signed-in Owner's browser, sent from coffre's own origin: the cookie is never read here.
  const page = fromPage(await browserFor(ROOT));
  const cookie = await vault('secret/data/market/prod', null, { headers: page });
  assert.equal(cookie.status, 403);
  assert.equal((await cookie.text()).includes(PROD.DATABASE_URL), false);
});

test("a person's CLI session reads what they may, as they would with `coffre export`", async () => {
  await clientFor(deps, ROOT).access.set(`user:${DEV}`, { 'market/staging': 'viewer' });
  const { data } = await body(await vault('secret/data/market/staging', await sessionFor(DEV)));
  assert.deepEqual(data.data, STAGING);
});

test("a person's read of an environment leaves its sensitive keys out, and Vault's warnings name them, never their values", async () => {
  const root = clientFor(deps, ROOT);
  const hidden = `sk_hidden_${randomBytes(6).toString('hex')}`;
  await root.secrets.set('market/staging', { OPEN: 'open', HIDDEN: { value: hidden, sensitivity: 'sensitive' } });
  await root.access.set(`user:${DEV}`, { 'market/staging': 'viewer' });
  const read = await vault('secret/data/market/staging', await sessionFor(DEV));
  assert.equal(read.status, 200);
  const text = await read.text();
  assert.equal(text.includes(hidden), false);
  const { data, warnings } = JSON.parse(text) as { data: { data: Record<string, string> }; warnings: string[] };
  assert.deepEqual(data.data, { ...STAGING, OPEN: 'open' });
  assert.deepEqual(warnings, ['left out, sensitive, which no person is handed: HIDDEN']);
  // The key alone is refused, never 404, which ESO would read as the secret gone.
  assert.equal((await vault('secret/data/market/staging/HIDDEN', await sessionFor(DEV))).status, 403);
  // A service account is handed it, and nothing is left out.
  await root.access.set('token:eso', { 'market/staging': 'viewer' });
  const both = (await runtime.signin!.issueServiceToken(await contextFor(deps, ROOT), 'eso', { label: 'staging', expiresInDays: 1 })).token;
  const service = await body(await vault('secret/data/market/staging', both));
  assert.equal(service.data.data!.HIDDEN, hidden);
  assert.equal(service.warnings, null);
});

test("a fork that inherits reads its parent's values live, as the API's reveal does, and only with read on the parent", async () => {
  const root = clientFor(deps, ROOT);
  await root.environments.create('market/prod-eu', { from: 'prod', inherit: true });
  await root.secrets.set('market/prod-eu', { REGION: 'eu-west-1' });
  await root.access.set('token:eso', { 'market/prod-eu': 'viewer' });
  // A token reaches what its account held when it was made: this one, both.
  const both = (await runtime.signin!.issueServiceToken(await contextFor(deps, ROOT), 'eso', { label: 'eu', expiresInDays: 1 })).token;
  assert.deepEqual((await body(await vault('secret/data/market/prod-eu', both))).data.data, { ...PROD, REGION: 'eu-west-1' });
  await root.secrets.set('market/prod', { STRIPE_KEY: 'sk_live_rotated' });
  assert.equal((await body(await vault('secret/data/market/prod-eu/STRIPE_KEY', both))).data.data!.STRIPE_KEY, 'sk_live_rotated');
  // Read on the fork alone: its inherited keys are refused (R8), and nothing is revealed.
  await root.access.set('token:eso', { 'market/prod': null });
  const refused = await vault('secret/data/market/prod-eu', both);
  assert.equal(refused.status, 403);
  assert.equal((await refused.text()).includes('eu-west-1'), false);
});

test("`<project>/<env>@me` is the caller's personal config over the environment, as the API reads it (R8)", async () => {
  await clientFor(deps, ROOT).access.set(`user:${DEV}`, { 'market/staging': 'viewer' });
  await clientFor(deps, DEV).secrets.set('market/staging@me', { DATABASE_URL: 'postgres://localhost/dev' });
  const session = await sessionFor(DEV);
  assert.deepEqual((await body(await vault('secret/data/market/staging@me', session))).data.data, { DATABASE_URL: 'postgres://localhost/dev' });
  // Everyone else's `@me` without one of their own is the environment itself.
  await clientFor(deps, ROOT).access.set('token:eso', { 'market/staging': 'viewer' });
  const both = (await runtime.signin!.issueServiceToken(await contextFor(deps, ROOT), 'eso', { label: 'staging', expiresInDays: 1 })).token;
  assert.deepEqual((await body(await vault('secret/data/market/staging@me', both))).data.data, STAGING);
});

test("a person's personal token reads within its scope, and lookup-self answers for it", async () => {
  await clientFor(deps, ROOT).access.set(`user:${DEV}`, { market: 'viewer' });
  const issued = await runtime.signin!.issuePersonalToken(await contextFor(deps, DEV), { label: 'vault-cli', expiresInMinutes: 60, scope: { 'market/staging': 'viewer' } });
  assert.match(issued.token, /^coffre_pat_/);
  assert.equal((await body(await vault('auth/token/lookup-self', issued.token))).data.display_name, `user:${DEV}`);
  assert.deepEqual((await body(await vault('secret/data/market/staging', issued.token))).data.data, STAGING);
  assert.equal((await vault('secret/data/market/prod', issued.token)).status, 403);
});

test('read only: every other method is 405, and changes nothing', async () => {
  for (const method of ['PUT', 'POST', 'PATCH', 'DELETE']) {
    const response = await vault('secret/data/market/prod', eso, { method, body: JSON.stringify({ data: { STRIPE_KEY: 'x' } }) });
    assert.equal(response.status, 405, method);
  }
  const { data } = await body(await vault('secret/data/market/prod'));
  assert.deepEqual(data.data, PROD);
});

test('what coffre does not serve says so, and never as 404 on a path a client meant as a secret', async () => {
  assert.equal((await vault('secret/data/market/prod?version=2')).status, 400);
  // A snapshot's values, which coffre has not: refused before anything is read, never answered with today's.
  assert.equal((await vault('secret/data/market/prod?read_snapshot_id=snap-1')).status, 400);
  assert.deepEqual(await entries('secret.read'), []);
  assert.equal((await vault('secret/data/market/prod?list=true')).status, 405);
  // ESO's dataFrom.find, as HashiCorp's client sends LIST: a 404 here would read as every secret gone.
  assert.equal((await vault('secret/metadata/market/?list=true')).status, 405);
  assert.equal((await vault('secret/metadata/?list=true')).status, 405);
  // Too short or too deep names no environment: a configuration mistake, which must not delete ESO's target.
  assert.equal((await vault('secret/data/market')).status, 400);
  assert.equal((await vault('secret/data/market/prod/KEY/more')).status, 400);
  assert.equal((await vault('secret/data/market/prod', eso, { headers: { 'x-vault-namespace': 'team-a' } })).status, 400);
  // vault-action sends an empty namespace with every request.
  assert.equal((await vault('secret/data/market/prod', eso, { headers: { 'x-vault-namespace': '' } })).status, 200);
  // metadataPolicy: Fetch, another mount, any path coffre does not serve: 400, never 404.
  assert.equal((await vault('secret/metadata/market/prod')).status, 400);
  assert.equal((await vault('kv/data/market/prod')).status, 400);
  assert.equal((await vault('auth/token/lookup')).status, 400);
  // `vault kv get -wrap-ttl=5m` expects a wrapping token, never the values themselves.
  const wrapped = await vault('secret/data/market/prod', eso, { headers: { 'x-vault-wrap-ttl': '5m' } });
  assert.equal(wrapped.status, 400);
  assert.equal((await wrapped.text()).includes(PROD.DATABASE_URL), false);
});

test("behind Cloudflare Access, a plugin's token is Access's assertion, which the API reads from its own header", async () => {
  const access = {
    ...runtime,
    auth: { mode: 'cloudflare', access: { issuer: 'https://acme.cloudflareaccess.com', jwksUrl: 'https://acme.cloudflareaccess.com/cdn-cgi/access/certs', audience: 'coffre-aud' } },
    signin: null,
    verifier: {
      verify: async (token: string) => {
        if (token !== 'assertion-for-eso') throw new Error('not an assertion');
        return { type: 'service', id: 'eso', commonName: 'eso' };
      },
    },
  } as unknown as CoffreRuntime;
  const ask = (token: string) =>
    coffreRoute(new Request('https://secrets.acme.example/v1/secret/data/market/prod', { headers: { 'x-vault-token': token } }), access, null).then((response) => response!);
  assert.deepEqual((await body(await ask('assertion-for-eso'))).data.data, PROD);
  // Access's assertion is not coffre's credential: no expiry to say, as Vault says of a token that never expires.
  const self = await coffreRoute(new Request('https://secrets.acme.example/v1/auth/token/lookup-self', { headers: { 'x-vault-token': 'assertion-for-eso' } }), access, null);
  const { data } = await body(self!);
  assert.deepEqual([data.ttl, data.expire_time], [0, null]);
  assert.equal((await ask('forged')).status, 403);
});

test("`vault kv get` and vals learn the mount's version first, without a token", async () => {
  const { data } = await body(await vault('sys/internal/ui/mounts/secret/market/prod', null));
  assert.equal(data.path, 'secret/');
  assert.equal((data.options as { version: string }).version, '2');
  assert.equal((await vault('sys/internal/ui/mounts/kv/market/prod', null)).status, 403);
});

test('a token whose account was removed is refused at lookup-self and at reads', async () => {
  await clientFor(deps, ROOT).members.remove('token:eso');
  assert.equal((await vault('auth/token/lookup-self')).status, 403);
  assert.equal((await vault('secret/data/market/prod')).status, 403);
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

test("paths no plugin takes stay the pages'", async () => {
  assert.equal(await coffreRoute(new Request('https://secrets.acme.example/v10/x'), runtime, null), null);
  assert.equal(await coffreRoute(new Request('https://secrets.acme.example/v1x'), runtime, null), null);
});
