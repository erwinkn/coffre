// `secret.use` (docs/design/credential-proxy.md, section 2): reading a value
// hands it back; using one does not, as the credential proxy fills in a
// person's placeholders. Every role that reads uses too, and a
// Contributor uses and writes without ever reading: it lists the keys, sets
// values, and runs its app on placeholders. What a person gets is the
// narrower of their role and the key's sensitivity. The vault decides use
// by its own grants: a read to `use` takes `secret.use`, any other `secret.read`.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

import { ROLES, roleGrants } from '@coffre/core/access';
import { createClient, type CoffreClient } from '@coffre/client';

import { replayStored } from '@coffre/vault/node';
import { clientFor, LOG, usesLogged } from './api-fixture.ts';
import { db, deps, entries, ORIGIN, ROOT, route, runtime, sessionFor, useMcp } from './mcp-fixture.ts';
import { coffreRoute } from '../src/app.ts';
import { checkPlugins } from '../src/plugins.ts';
import { credentialProxy, header } from '../src/plugins/credential-proxy.ts';

const API_KEY = 'sk_live_real_0123456789abcdef';
const WEBHOOK = 'whsec_0123456789abcdef';
const CONTRIBUTOR = 'contributor@acme.example';

/** A fake API that says whether it got the real key. */
let upstream: Server;
let upstreamUrl: string;

before(async () => {
  upstream = createServer((request, response) => {
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify({ real: request.headers['x-api-key'] === API_KEY }));
  });
  await new Promise<void>((resolve) => upstream.listen(0, '127.0.0.1', resolve));
  upstreamUrl = `http://127.0.0.1:${(upstream.address() as AddressInfo).port}`;
});

after(() => new Promise<void>((resolve) => upstream.close(() => resolve())));

let root: CoffreClient;

useMcp(async () => {
  runtime.plugins = checkPlugins([credentialProxy({
    credentials: { api: { upstream: `${upstreamUrl}/v1`, inject: header('x-api-key', '{API_KEY}') } },
    insecureUpstreams: true,
  })]);
  root = clientFor(deps, ROOT);
  await root.members.add(`user:${CONTRIBUTOR}`);
  await root.projects.create('market');
  await root.environments.create('market/dev');
  await root.secrets.set('market/dev', { API_KEY, WEBHOOK, REGION: { value: 'eu-west-3', plain: true } });
  await root.access.set(`user:${CONTRIBUTOR}`, { 'market/dev': 'contributor' });
});

/** The API as whoever `token` is, over coffre's own routes. */
function bearer(token: string): CoffreClient {
  return createClient({ url: ORIGIN, headers: () => ({ authorization: `Bearer ${token}` }), transport: (request) => coffreRoute(request, runtime, '203.0.113.7').then((response) => response!) });
}

async function refusal(promise: Promise<unknown>): Promise<{ status: number; reason: string | null; message: string }> {
  try {
    await promise;
  } catch (error) {
    const { status, reason, message } = error as { status: number; reason?: string; message: string };
    return { status, reason: reason ?? null, message };
  }
  throw new Error('it was not refused');
}

test('every role that reads uses too; a Contributor uses and writes, and reads nothing', () => {
  for (const [role, { permissions }] of Object.entries(ROLES)) {
    if ((permissions as readonly string[]).includes('secret.read')) assert.ok(roleGrants(role as keyof typeof ROLES, 'secret.use'), `${role} reads, and so uses`);
  }
  assert.deepEqual([...ROLES.contributor.permissions], ['secret.use', 'secret.write']);
});

test('a Contributor lists the keys and writes values, and is refused every value, by the app and by the vault', async () => {
  const contributor = clientFor(deps, CONTRIBUTOR);
  const listed = await contributor.secrets.list('market/dev');
  assert.deepEqual(listed.permissions, ['secret.use', 'secret.write']);
  assert.deepEqual(listed.keys.map((entry) => [entry.key, entry.value]), [['API_KEY', null], ['REGION', 'eu-west-3'], ['WEBHOOK', null]]);
  assert.equal((await contributor.secrets.history('market/dev/API_KEY')).versions.length, 1);
  assert.ok(typeof (await contributor.environments.version('market/dev')).version === 'string');
  // A value of their own, written without reading the one before.
  assert.deepEqual((await contributor.secrets.set('market/dev', { WEBHOOK: 'whsec_rotated_0123456789' })).keys, { WEBHOOK: { version: 2, sensitivity: 'secret' } });
  for (const path of ['market/dev', 'market/dev/WEBHOOK']) {
    const refused = await refusal(contributor.secrets.reveal(path));
    assert.equal(refused.status, 403, path);
    assert.match(refused.message, /without reading them \(secret\.use\)/);
  }
  const listedProjects = (await contributor.projects.list()).projects.find((project) => project.slug === 'market')!;
  assert.equal(listedProjects.environments.find((environment) => environment.slug === 'dev')!.accessible, true);
});

test("a Contributor's run gets placeholders and the plain values, never a secret's; the proxy fills in the real key", async () => {
  const session = await sessionFor(CONTRIBUTOR);
  const handle = await bearer(session).handles.create({ label: 'coffre run market/dev', paths: ['market/dev'] });
  // The handle reaches what its person holds there, use, and nothing they do not.
  assert.deepEqual(handle.scope, { 'market/dev': 'contributor' });
  const response = await route('/use/market/dev', { headers: { authorization: `Bearer ${handle.token}` } });
  assert.equal(response.status, 200, await response.clone().text());
  const plan = (await response.json()) as { env: Record<string, string>; left: string[] };
  assert.deepEqual(plan.env, { API_KEY: handle.token, REGION: 'eu-west-3' });
  assert.deepEqual(plan.left, ['WEBHOOK'], 'a secret its person may not read: left out');
  const answer = await route('/use/market/dev/api/thing', { headers: { 'x-api-key': handle.token } });
  assert.equal(answer.status, 200);
  assert.deepEqual(await answer.json(), { real: true });
  // The vault's read was to use, which the Contributor's grant holds: under 0.15's log, uses, each allowed as the
  // replay of the log says.
  if (LOG === '0.15') {
    const used = await usesLogged(db.owner);
    assert.ok(used.length > 0 && used.every((use) => use.purpose === 4), JSON.stringify(used));
    assert.deepEqual([...(await replayStored(db.owner, [deps.vault.signingKey])).decided.values()].filter((code) => code !== null), []);
    return;
  }
  const used = (await entries('secret.read')).filter((entry) => entry.author === 'vault' && entry.actor === `user:${CONTRIBUTOR}`);
  assert.ok(used.length > 0 && used.every((entry) => entry.decision === 'allow' && entry.metadata.purpose === 'use'), JSON.stringify(used.map((entry) => [entry.decision, entry.metadata.purpose])));
});

test("the vault holds a read to use to secret.use, and any other to secret.read, whatever the app asked", async () => {
  const listed = await root.secrets.list('market/dev');
  const version = listed.keys.find((entry) => entry.key === 'API_KEY')!.versionId!;
  const ask = (purpose: 'use' | 'reveal' | 'expose') => deps.vault.unwrap({ principal: `user:${CONTRIBUTOR}`, purpose, items: [{ secretVersionId: version }] });
  assert.equal((await ask('use')).ok, true);
  for (const purpose of ['reveal', 'expose'] as const) {
    const refused = await ask(purpose);
    assert.equal(!refused.ok && refused.refusal.code, 'no_grant', purpose);
  }
});

test("a Contributor's personal config is theirs to read: they use the environment it configures", async () => {
  const contributor = clientFor(deps, CONTRIBUTOR);
  await contributor.secrets.set('market/dev@me', { WEBHOOK: 'whsec_mine_0123456789' });
  assert.equal((await contributor.secrets.reveal('market/dev@me/WEBHOOK')).values.WEBHOOK, 'whsec_mine_0123456789');
});

test("a Contributor's dev@me lists their own value readable, and dev's inherited ones, told of, not", async () => {
  const contributor = clientFor(deps, CONTRIBUTOR);
  await contributor.secrets.set('market/dev@me', { WEBHOOK: 'whsec_mine_0123456789' });
  const listed = new Map((await contributor.secrets.list('market/dev@me')).keys.map((entry) => [entry.key, entry]));
  // Dev's key, its version and age told, as to a lister of dev; its value read only by a reader of dev.
  const inherited = listed.get('API_KEY')!;
  assert.deepEqual([inherited.parent?.state, inherited.version, inherited.readable], ['inherited', 1, false]);
  assert.equal((await refusal(contributor.secrets.reveal('market/dev@me/API_KEY'))).status, 403);
  // A plain value is listed, and is its own read.
  assert.deepEqual([listed.get('REGION')!.value, listed.get('REGION')!.readable], ['eu-west-3', true]);
  const own = listed.get('WEBHOOK')!;
  assert.deepEqual([own.parent?.state, own.readable], ['overridden', true]);
  // A reader of dev reads both, in their own dev@me.
  await root.secrets.set('market/dev@me', { WEBHOOK: 'whsec_root_0123456789' });
  const rootListed = new Map((await root.secrets.list('market/dev@me')).keys.map((entry) => [entry.key, entry.readable]));
  assert.deepEqual([rootListed.get('API_KEY'), rootListed.get('WEBHOOK')], [true, true]);
});

test('a personal token of a Contributor names contributor, and reaches no read', async () => {
  const session = await sessionFor(CONTRIBUTOR);
  const viewer = await refusal(bearer(session).tokens.issue(`user:${CONTRIBUTOR}`, { label: 'agent', expiresInMinutes: 60, scope: { 'market/dev': 'viewer' } }));
  assert.equal(viewer.status, 403);
  const token = await bearer(session).tokens.issue(`user:${CONTRIBUTOR}`, { label: 'agent', expiresInMinutes: 60, scope: { 'market/dev': 'contributor' } });
  const agent = bearer(token.token);
  assert.deepEqual((await agent.secrets.list('market/dev')).keys.map((entry) => entry.key), ['API_KEY', 'REGION', 'WEBHOOK']);
  assert.equal((await refusal(agent.secrets.reveal('market/dev/API_KEY'))).status, 403);
});

test("a Contributor's handle reads their own values in dev@me, and nothing of dev's", async () => {
  const contributor = clientFor(deps, CONTRIBUTOR);
  await contributor.secrets.set('market/dev@me', { WEBHOOK: 'whsec_mine_0123456789' });
  const handle = await bearer(await sessionFor(CONTRIBUTOR)).handles.create({ label: 'coffre run market/dev@me', paths: ['market/dev@me'] });
  const response = await route('/use/market/dev@me', { headers: { authorization: `Bearer ${handle.token}` } });
  assert.equal(response.status, 200, await response.clone().text());
  const plan = (await response.json()) as { env: Record<string, string>; left: string[] };
  assert.deepEqual(plan.env, { API_KEY: handle.token, REGION: 'eu-west-3', WEBHOOK: 'whsec_mine_0123456789' });
  assert.deepEqual(plan.left, []);
});

test("a Contributor of a fork and its parent is told the parent's plain values and versions, and lists the references it reads", async () => {
  await root.environments.create('market/dev-eu', { from: 'dev', inherit: true });
  await root.environments.create('market/base');
  await root.secrets.set('market/base', { SHARED: 'shared_0123456789' });
  await root.secrets.set('market/dev', { ALIAS: { ref: 'market/base/SHARED' } });
  await root.access.set(`user:${CONTRIBUTOR}`, { 'market/dev': 'contributor', 'market/dev-eu': 'contributor' });
  const contributor = clientFor(deps, CONTRIBUTOR);
  const region = (await contributor.secrets.list('market/dev-eu')).keys.find((entry) => entry.key === 'REGION')!;
  assert.deepEqual([region.value, region.version], ['eu-west-3', 1]);
  const references = await contributor.references.list('market/dev');
  assert.deepEqual(references.references.map((reference) => reference.holder), ['market/dev/ALIAS']);
});

test("a token that only uses a place, its owner's grant narrowed since, still makes a handle there", async () => {
  await root.access.set(`user:${CONTRIBUTOR}`, { 'market/dev': 'viewer' });
  const session = await sessionFor(CONTRIBUTOR);
  const token = await bearer(session).tokens.issue(`user:${CONTRIBUTOR}`, { label: 'agent', expiresInMinutes: 60, scope: { 'market/dev': 'viewer' } });
  await root.access.set(`user:${CONTRIBUTOR}`, { 'market/dev': 'contributor' });
  const handle = await bearer(token.token).handles.create({ label: 'coffre run market/dev', paths: ['market/dev'] });
  assert.deepEqual(handle.scope, { 'market/dev': 'contributor' });
});

test("a Contributor of both ends of a reference may open its source", async () => {
  await root.environments.create('market/base');
  await root.secrets.set('market/base', { SHARED: 'shared_0123456789' });
  await root.secrets.set('market/dev', { ALIAS: { ref: 'market/base/SHARED' } });
  await root.access.set(`user:${CONTRIBUTOR}`, { 'market/dev': 'contributor', 'market/base': 'contributor' });
  const alias = (await clientFor(deps, CONTRIBUTOR).secrets.list('market/dev')).keys.find((entry) => entry.key === 'ALIAS')!;
  assert.equal(alias.reference?.canOpenSource, true);
});

test("a Viewer of base who contributes to its fork dev reads none of base's secrets through dev, and overrides them", async () => {
  await root.environments.create('market/base');
  await root.secrets.set('market/base', { SHARED: 'shared_0123456789', ZONE: { value: 'eu', plain: true } });
  await root.environments.create('market/dev-base', { from: 'base', inherit: true });
  await root.access.set(`user:${CONTRIBUTOR}`, { 'market/base': 'viewer', 'market/dev-base': 'contributor' });
  const contributor = clientFor(deps, CONTRIBUTOR);
  const listed = new Map((await contributor.secrets.list('market/dev-base')).keys.map((entry) => [entry.key, entry]));
  // A read of dev-base needs read on dev-base, and on base for what it inherits: the first is missing.
  const shared = listed.get('SHARED')!;
  assert.deepEqual([shared.parent?.state, shared.readable], ['inherited', false]);
  assert.equal((await refusal(contributor.secrets.reveal('market/dev-base/SHARED'))).status, 403);
  assert.equal((await contributor.secrets.reveal('market/base/SHARED')).values.SHARED, 'shared_0123456789');
  assert.deepEqual([listed.get('ZONE')!.value, listed.get('ZONE')!.readable], ['eu', true]);
  // Override: a value of dev-base's own, written unread.
  assert.deepEqual((await contributor.secrets.set('market/dev-base', { SHARED: 'shared_dev_0123456789' })).keys, { SHARED: { version: 1, sensitivity: 'secret' } });
  const overridden = (await contributor.secrets.list('market/dev-base')).keys.find((entry) => entry.key === 'SHARED')!;
  assert.deepEqual([overridden.parent?.state, overridden.readable], ['overridden', false]);
});
