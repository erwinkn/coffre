// A plugin's check of a handle (`PluginContext.handle`) with 0.15's uses (T135): the vault asked about its person, as
// ever, and in a fetch, handed to the use of the same handle that follows, which then asks nothing again. Someone
// removed meanwhile, their credentials not swept yet, is refused: by the credential proxy's stable URL for a handle of
// two environments, which names neither, cached or not; by a plugin that only asks whether a handle stands; and by one
// that uses another person's handle after it. And `use`'s answer lists every key the environment holds unless the
// plugin asks for its keys `only`; a plain value used long after the check, on access as it is then. The same on 0.14's
// log and on SQLite, which hand nothing on.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

import { CoffreError } from '@coffre/client';
import { github, signin } from '@coffre/core/identity';

import { resolveConfig } from '../src/config.ts';
import { checkPlugins, pluginRoute, type CoffrePlugin } from '../src/plugins.ts';
import { credentialProxy, header } from '../src/plugins/credential-proxy.ts';
import { createRuntime, type CoffreRuntime } from '../src/runtime.ts';
import { clientFor, contextFor, LOG, openTestDatabase, resetDatabase, sealedNow, testDeps, testVault, type FixtureDeps } from './api-fixture.ts';
import { logFence } from './db/tables.ts';

const ORIGIN = 'https://secrets.acme.example';
const ROOT = 'admin@acme.example';
const DEV = 'dev@acme.example';

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;
let runtime: CoffreRuntime;
/** A handle made for market/dev alone, and one made for market/dev and market/staging. */
let one: string;
let two: string;
/** Someone else's handle, of market/dev, who stays a member; and a third person's of two environments, for the cached proxy. */
let other: string;
let cachedTwo: string;
const OTHER = 'other@acme.example';
const THIRD = 'third@acme.example';
const FOURTH = 'fourth@acme.example';
const FIFTH = 'fifth@acme.example';
/** FIFTH's handle, of market/dev. */
let fifth: string;
/** What happens between a check and its use (`/probe/later`). */
let between: () => Promise<void> = async () => undefined;
/** FOURTH's handle, of market/dev. */
let fourth: string;

/** A plugin that asks whether a handle stands (`/probe/handle`), or uses market/dev's API_KEY (`/probe/use`, `?only`). */
const credentials = { api: { upstream: 'https://api.example', inject: header('x-api-key', '{API_KEY}'), egress: { fetch: async () => new Response(null, { status: 204 }) } } };

const probe: CoffrePlugin = {
  name: 'probe',
  routes: {
    prefix: '/probe',
    fetch: async (request, coffre) => {
      const url = new URL(request.url);
      const handle = request.headers.get('x-handle')!;
      try {
        if (url.pathname === '/probe/handle') return Response.json(await coffre.handle(handle));
        // A handle checked, then, whatever happens meanwhile (`between`: a long upload), its plain value used.
        if (url.pathname === '/probe/later') {
          await coffre.handle(handle);
          await between();
          const used = await coffre.use(handle, { path: 'market/dev', keys: ['REGION'], purpose: 'use', logged: {}, only: true });
          return Response.json({ keys: used.keys });
        }
        // A handle checked, then another one used: what goes back is the first's.
        if (url.pathname === '/probe/then') {
          const checked = await coffre.handle(handle);
          await coffre.use(request.headers.get('x-other')!, { path: 'market/dev', keys: ['API_KEY'], purpose: 'use', logged: {}, only: true });
          return Response.json(checked);
        }
        const used = await coffre.use(handle, { path: 'market/dev', keys: ['API_KEY'], purpose: 'use', logged: {}, ...(url.searchParams.has('only') ? { only: true } : {}) });
        return Response.json({ keys: used.keys });
      } catch (error) {
        if (error instanceof CoffreError) return Response.json({ error: error.code }, { status: error.status });
        throw error;
      }
    },
  },
};

before(async () => {
  db = await openTestDatabase();
  await resetDatabase(db.owner);
  await db.owner.update(logFence).set({ atFloor: Date.now() - 60_000 });
  deps = testDeps(db.runtime, [ROOT], { vault: testVault([ROOT], {}, { kek: randomBytes(32) }, {}, LOG === '0.15' ? { log: '0.15', sealThrough: sealedNow } : {}) });
  const config = resolveConfig({
    publicUrl: ORIGIN,
    vault: deps.vault,
    auth: signin({ providers: [github({ clientId: 'a', clientSecret: 'b' })] }),
    auditChainKey: deps.chainKey.toString('base64'),
    plugins: [probe, credentialProxy({ credentials, cacheSeconds: 0 })],
  });
  runtime = createRuntime(config, deps.db, deps.vault, { json: async (url) => { throw new Error(`no fetch of ${url.href} here`); } });
  runtime.plugins = checkPlugins(config.plugins);
  const root = clientFor(deps, ROOT);
  await root.projects.create('market', { name: 'Market' });
  for (const path of ['market/dev', 'market/staging']) await root.environments.create(path);
  await root.secrets.set('market/dev', { API_KEY: 'sk_dev_0123456789', OTHER: 'other', REGION: { value: 'eu-west-3', plain: true } });
  await root.secrets.set('market/staging', { API_KEY: 'sk_staging_0123456789' });
  await root.members.add(`user:${DEV}`);
  await root.access.set(`user:${DEV}`, { market: 'developer' });
  const issue = async (person: string, paths: string[]) => (await runtime.signin!.issueHandle({ ...(await contextFor(deps, person)), personalToken: null }, { label: 'run', expiresInMinutes: 600, paths })).token;
  one = await issue(DEV, ['market/dev']);
  two = await issue(DEV, ['market/dev', 'market/staging']);
  for (const person of [OTHER, THIRD, FOURTH, FIFTH]) {
    await root.members.add(`user:${person}`);
    await root.access.set(`user:${person}`, { market: 'developer' });
  }
  other = await issue(OTHER, ['market/dev']);
  cachedTwo = await issue(THIRD, ['market/dev', 'market/staging']);
  fourth = await issue(FOURTH, ['market/dev']);
  fifth = await issue(FIFTH, ['market/dev']);
});

after(async () => {
  await resetDatabase(db.owner);
  await db.close();
});

/** A request to the probe, which reads the handle from `x-handle`, or to the proxy, which takes it where the key goes. */
const fetched = (path: string, handle: string, at: CoffreRuntime = runtime) =>
  pluginRoute(new Request(`${ORIGIN}${path}`, { headers: path.startsWith('/probe') ? { 'x-handle': handle, 'x-other': other } : { 'x-api-key': handle } }), at, '203.0.113.7')!;

/** The proxy as a deployment runs it, its cache on: the environments a handle was made for, and their values, kept 60 s. */
function caching(): CoffreRuntime {
  return { ...runtime, plugins: checkPlugins([credentialProxy({ credentials })]) };
}

test("a use answers every key the environment holds, or with `only`, those it asked for", async () => {
  assert.deepEqual(await (await fetched('/probe/use', one)).json(), { keys: ['API_KEY', 'OTHER', 'REGION'] });
  assert.deepEqual(await (await fetched('/probe/use?only', one)).json(), { keys: ['API_KEY'] });
});

test('a check of a handle that no use follows has the vault check its person: removed, not swept, they are refused', async () => {
  // Their answer kept from requests that read: each fetch below may decide on it.
  const warmed = await fetched('/use/market/dev/api/v1/charges', one);
  assert.equal(warmed.status, 204, await warmed.clone().text());
  assert.equal((await fetched('/probe/handle', one)).status, 200);
  // The stable URL of a handle made for two environments asks which, and names both: no use.
  const asked = await fetched('/use/api/v1/charges', two);
  assert.equal(asked.status, 409);
  assert.match(await asked.text(), /market\/staging/);
  // Removed in the vault; the app's sweep of their credentials has not run.
  const removed = await deps.vault.remove({ actor: `user:${ROOT}`, principal: `user:${DEV}` });
  assert.equal(removed.ok, true);
  for (const [path, handle] of [['/probe/handle', one], ['/use/api/v1/charges', two]] as const) {
    const answer = await fetched(path, handle);
    const body = await answer.text();
    assert.ok(answer.status === 401 || answer.status === 403, `${path}: ${answer.status} ${body}`);
    assert.doesNotMatch(body, /staging/, `${path} names no environment`);
  }
});

test("a check of one handle is no other's: one used after it vouches for nothing about the first", async () => {
  // Both answers kept, from uses; then FOURTH removed, not swept. OTHER stands.
  assert.equal((await fetched('/probe/use?only', other)).status, 200);
  assert.equal((await fetched('/probe/use?only', fourth)).status, 200);
  assert.equal((await deps.vault.remove({ actor: `user:${ROOT}`, principal: `user:${FOURTH}` })).ok, true);
  const answer = await fetched('/probe/then', fourth);
  assert.ok(answer.status === 401 || answer.status === 403, `${answer.status} ${await answer.text()}`);
});

test("a proxy that keeps a handle's environments keeps none a refused check named", async () => {
  const at = caching();
  // Their answer kept, from a use.
  assert.equal((await fetched('/use/market/dev/api/v1/charges', other, at)).status, 204);
  const warmed = await fetched('/use/market/dev/api/v1/charges', cachedTwo, at);
  assert.equal(warmed.status, 204, await warmed.clone().text());
  assert.equal((await deps.vault.remove({ actor: `user:${ROOT}`, principal: `user:${THIRD}` })).ok, true);
  // Asked again and again: each is refused, and none names the environments.
  for (let i = 0; i < 3; i++) {
    const answer = await fetched('/use/api/v1/charges', cachedTwo, at);
    const body = await answer.text();
    assert.ok(answer.status === 401 || answer.status === 403, `request ${i}: ${answer.status} ${body}`);
    assert.doesNotMatch(body, /staging/);
  }
});

test("a plain value used after the handle's check is used on the person's access as it is then: a grant lost meanwhile refuses it", async () => {
  const root = clientFor(deps, ROOT);
  assert.equal((await fetched('/probe/later', fifth)).status, 200);
  between = () => root.access.set(`user:${FIFTH}`, { market: null }).then(() => undefined);
  try {
    const answer = await fetched('/probe/later', fifth);
    assert.equal(answer.status, 403, await answer.text());
  } finally {
    between = async () => undefined;
  }
});
