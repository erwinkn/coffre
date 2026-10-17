// The Vault KV v2 adapter (`@coffre/server/plugins/vault-kv`), as External
// Secrets Operator reaches it: the requests its Vault provider makes, through
// HashiCorp's Go client (`hashicorp/vault/api` v1.22.0, which ESO v2.13.0
// pins), each answered by coffre in process. And the plugin mechanism around
// it: paths checked at configuration, and a plugin's API as the token's holder.
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

import { contextFor, clientFor } from './api-fixture.ts';
import { browserFor, deps, entries, fromPage, ROOT, route, runtime, sessionFor, useMcp, DEV } from './mcp-fixture.ts';
import { coffreRoute } from '../src/app.ts';
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

test("ESO's store check and reads: lookup-self, then an environment, with every value logged as read by the token", async () => {
  // SecretStore validation: ESO's checkToken asserts `type` is a string and `ttl` a number, and reads `expire_time`.
  const self = await body(await vault('auth/token/lookup-self'));
  assert.equal(self.data.type, 'service');
  assert.equal(self.data.ttl, 0);
  assert.equal(self.data.expire_time, null);
  assert.equal(self.data.display_name, 'token:eso');
  assert.equal('namespace_path' in self.data, false, "Terraform refuses a token in a namespace");

  // dataFrom.extract and data[].remoteRef: one read of the environment, the property picked by ESO itself.
  const read = await vault('secret/data/market/prod');
  assert.equal(read.status, 200);
  assert.equal(read.headers.get('cache-control'), 'no-store');
  const { data, renewable, lease_duration } = await body(read);
  assert.deepEqual(data.data, PROD);
  assert.deepEqual([renewable, lease_duration], [false, 0]);
  assert.equal((data.metadata as { version: number }).version, 0);

  const reads = (await entries('secret.read')).filter((entry) => entry.decision === 'allow');
  assert.deepEqual(reads.map((entry) => entry.actor).sort(), ['token:eso', 'token:eso']);
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
  assert.equal((await vault('secret/data/market/prod?list=true')).status, 405);
  // Too short or too deep names no environment: a configuration mistake, which must not delete ESO's target.
  assert.equal((await vault('secret/data/market')).status, 400);
  assert.equal((await vault('secret/data/market/prod/KEY/more')).status, 400);
  assert.equal((await vault('secret/data/market/prod', eso, { headers: { 'x-vault-namespace': 'team-a' } })).status, 400);
  // vault-action sends an empty namespace with every request.
  assert.equal((await vault('secret/data/market/prod', eso, { headers: { 'x-vault-namespace': '' } })).status, 200);
  assert.equal((await vault('secret/metadata/market/prod')).status, 404);
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
  assert.equal(checkPlugins([at('a', '/v1'), at('b', '/v10'), { name: 'quiet' }]).length, 3);
});

test("paths no plugin takes stay the pages'", async () => {
  assert.equal(await coffreRoute(new Request('https://secrets.acme.example/v10/x'), runtime, null), null);
  assert.equal(await coffreRoute(new Request('https://secrets.acme.example/v1x'), runtime, null), null);
});
