// Values of a person's own (docs/design/credential-proxy.md, section 2): in
// an environment the deployment lists under `generate`, a person's use reads
// their personal config of it, and the plan names each key their app would
// go without, a sensitive one no credential uses, that a recipe made, for
// `coffre run` to make a value of their own by it, once, in that personal
// config. Each write replaces the version
// the plan read, so of two runs at once one writes and the other is refused.
//
// 0.14.7's assertions, on 0.16 (docs/design/0.16.md, "The proxy"): the plan
// is the vault's peek, which says each key's version id and recipe, and one
// use; the map costs nothing more. The writes are the API's, as `coffre run`
// makes them (`PATCH /secrets/<project>/<env>@me`).
import assert from 'node:assert/strict';
import { after, beforeEach, test } from 'node:test';

import { generateToken } from '@coffre/core/identity';
import { rowsOf } from '@coffre/db/dialect';
import { credential, emptyDatabase, environment, grant, instance, principal, project, role, rows, secret, value, write } from '@coffre/vault/testing';
import { sql } from 'drizzle-orm';

import { basic, credentialProxy, header, type Egress } from '../src/plugins/credential-proxy.ts';
import { openApp } from './app-fixture.ts';

const API_KEY = 'sk_local_shared_0123456789';
const DEV = 'user:dev@acme.example';
const KID_ONLY = 'user:kid@acme.example';

/** A fake API that says which key it got. */
const egress: Egress = {
  async fetch(_input, init) {
    return Response.json({ shared: new Headers(init.headers).get('x-api-key') === API_KEY });
  },
};

const app = await openApp({
  plugins: [credentialProxy({
    credentials: {
      api: { upstream: 'https://api.example/v1', inject: header('x-api-key', '{API_KEY}'), egress },
      twilio: { upstream: 'https://api.twilio.example/2010-04-01', inject: basic('{TWILIO_SID}', '{TWILIO_TOKEN}'), egress },
    },
    generate: { 'market/local': 'all', 'market/listed': ['SEAL_KEY'], 'market/kid': 'all' },
  })],
});
const { world } = app;
after(() => app.close());

const market = project('market');
const local = environment(market, 'local');
const listed = environment(market, 'listed');
const dev = environment(market, 'dev');
// A fork of local, read by someone who does not read local: what it inherits is not theirs to be told of.
const kid = environment(market, 'kid', { parentId: local.id });

/** Each person's token, as `coffre login <url> --token` leaves it. */
const tokens = { dev: generateToken('personal'), kid: generateToken('personal') };

/** Every environment's keys, as 0.14.7's test wrote them: two a recipe made, sensitive, one typed, and what the app reads or a credential covers. */
function held(place: { id: string; projectId: string }) {
  return [
    { ...value(world, secret(place, 'SEAL_KEY'), 'shared-seal-key-0123456789', { sensitive: true }), recipe: 'bytes:32:hex' },
    { ...value(world, secret(place, 'WEBHOOK_SECRET'), 'shared-webhook-0123456789', { sensitive: true }), recipe: 'bytes:24:base62' },
    value(world, secret(place, 'TYPED'), 'typed-by-hand-0123456789', { sensitive: true }),
    value(world, secret(place, 'TESTNET_KEY'), 'testnet-key-0123456789'),
    value(world, secret(place, 'REGION'), 'eu-west-3', { plain: true }),
    value(world, secret(place, 'API_KEY'), API_KEY),
    value(world, secret(place, 'TWILIO_SID'), 'AC0123456789', { plain: true }),
    value(world, secret(place, 'TWILIO_TOKEN'), 'twilio_token_0123456789'),
  ];
}

beforeEach(async () => {
  await emptyDatabase(world.owner);
  for (const kept of [world.memory.reads, world.memory.callers, world.memory.logged, world.memory.touched, world.refused]) kept.clear();
  await write(
    world,
    ...rows('policy', instance()),
    ...rows('roles', role(true, 'owner', ['secret.read']), role(true, 'member', []), role(false, 'developer', ['secret.read', 'secret.use', 'secret.write'])),
    ...rows('projects', market),
    ...rows('environments', local, listed, dev, kid),
    ...rows('principals', principal(DEV), principal(KID_ONLY)),
    ...rows('grants', grant(DEV, 'developer', { project: market }), grant(KID_ONLY, 'developer', { environment: kid })),
    ...rows('secrets', ...held(local), ...held(listed), ...held(dev)),
    ...rows('credentials',
      credential(tokens.dev, DEV, { kind: 'personal', scope: JSON.stringify([{ projectId: market.id, environmentId: null, role: 'developer' }]) }),
      credential(tokens.kid, KID_ONLY, { kind: 'personal', scope: JSON.stringify([{ projectId: market.id, environmentId: kid.id, role: 'developer' }]) })),
  );
  await world.owner.execute(sql`DELETE FROM log_pending`);
});

type Body = { reason?: string; message?: string } & Record<string, unknown>;
async function api(token: string, method: string, path: string, body?: unknown): Promise<[number, Body]> {
  const response = await app.request(`/api${path}`, { method, headers: { authorization: `Bearer ${token}` }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  return [response.status, (await response.json()) as Body];
}

/** A handle of the person's, as `coffre run` makes one. */
async function handleFor(token: string, path: string): Promise<string> {
  const [status, made] = await api(token, 'POST', '/handles', { label: `coffre run ${path}`, paths: [path] });
  assert.equal(status, 200, JSON.stringify(made));
  return made.token as string;
}

type Plan = { environment: string; env: Record<string, string>; left: string[]; generate?: Record<string, { recipe: string; replaces: string; sensitivity: 'secret' }> };

async function planFor(path: string, handle: string): Promise<Plan> {
  const response = await app.request(`/use/${path}`, { headers: { authorization: `Bearer ${handle}` } });
  assert.equal(response.status, 200, await response.clone().text());
  return (await response.json()) as Plan;
}

/** Each key's version id, as the API lists it: what a write `replaces`. */
async function versionIds(path: string): Promise<Record<string, string>> {
  const [status, listed] = await api(tokens.dev, 'GET', `/secrets/${path}`);
  assert.equal(status, 200, JSON.stringify(listed));
  return Object.fromEntries((listed.keys as { key: string; versionId: string }[]).map((entry) => [entry.key, entry.versionId]));
}

test('the plan names what a recipe made and the app would go without; a run writes it, once, and the plan reads it from then on', async () => {
  const handle = await handleFor(tokens.dev, 'market/local');
  const ids = await versionIds('market/local');
  // What the map costs: nothing past any plan's peek and use, and no statement of the app's.
  const [calls, statements] = [app.calls.length, app.statements];
  const first = await planFor('market/local', handle);
  assert.deepEqual([app.calls.slice(calls), app.statements - statements], [['peek', 'use'], 0]);
  // Neither a typed key, nor one its person reads, plain or a credential's: those reach the app, or have no recipe. Each
  // a secret, which the app is given: saying nothing, the person's own value would be as sensitive as the key it overrides.
  assert.deepEqual(first.generate, {
    SEAL_KEY: { recipe: 'bytes:32:hex', replaces: ids.SEAL_KEY, sensitivity: 'secret' },
    WEBHOOK_SECRET: { recipe: 'bytes:24:base62', replaces: ids.WEBHOOK_SECRET, sensitivity: 'secret' },
  });
  assert.deepEqual(first.left, ['SEAL_KEY', 'TYPED', 'WEBHOOK_SECRET']);

  // As `coffre run` writes them, with the person's session, into their personal config.
  const write = {
    SEAL_KEY: { value: 'a'.repeat(64), generated: { recipe: 'bytes:32:hex' }, replaces: ids.SEAL_KEY!, sensitivity: 'secret' as const },
    WEBHOOK_SECRET: { value: 'devs-own-webhook-0123', generated: { recipe: 'bytes:24' }, replaces: ids.WEBHOOK_SECRET!, sensitivity: 'secret' as const },
  };
  // Two runs at once: one writes, the other is refused, and reads the plan again.
  const raced = await Promise.all([api(tokens.dev, 'PATCH', '/secrets/market/local@me', write), api(tokens.dev, 'PATCH', '/secrets/market/local@me', { ...write, SEAL_KEY: { ...write.SEAL_KEY, value: 'b'.repeat(64) } })]);
  assert.deepEqual(raced.map(([status]) => status).sort(), [200, 409], JSON.stringify(raced));
  const lost = raced.find(([status]) => status === 409)![1];
  assert.equal(lost.reason, 'stale');
  const won = raced[0]![0] === 200 ? 'a' : 'b';

  const second = await planFor('market/local', handle);
  assert.equal(second.environment, 'market/local@me');
  assert.deepEqual(second.generate, {});
  assert.equal(second.env.SEAL_KEY, won.repeat(64));
  assert.equal(second.env.WEBHOOK_SECRET, 'devs-own-webhook-0123');
  // A secret its person reads reaches the app through their personal config as it does through the environment; their own
  // values, generated over sensitive ones, are secrets they read.
  assert.equal(second.env.TESTNET_KEY, 'testnet-key-0123456789');
  assert.equal(second.env.REGION, 'eu-west-3');
  assert.deepEqual(second.left, ['TYPED']);
  // Each write is in the log as one, with its recipe.
  const bodies = await rowsOf<{ body: string }>(world.owner, sql`SELECT body FROM log_pending UNION ALL SELECT body FROM log`);
  const writes = bodies.map(({ body }) => JSON.parse(body) as { action: string; actor: string; decision?: string; detail: { keys?: { key: string; recipe?: string }[] } })
    .filter((entry) => entry.action === 'secret.write' && entry.actor === DEV && entry.detail.keys !== undefined);
  assert.deepEqual(writes.flatMap((entry) => entry.detail.keys!.map((line) => [line.key, line.recipe])).sort(), [['SEAL_KEY', 'bytes:32:hex'], ['WEBHOOK_SECRET', 'bytes:24:base62']]);
});

// R18's second step, making one's own value sensitive in place with no new value (`{ SEAL_KEY: { sensitivity:
// 'sensitive' } }`), needs the nature change W418 builds next: 0.14.7's test of it ("a person's own generated value
// they made sensitive is theirs: never made again, and the app goes without it (R18)") is ported with it. The plan's
// side of R18, a person's own sensitive value never generated again, is the test after this one.
test.todo("a person's own generated value they made sensitive is theirs: never made again, and the app goes without it (R18)");

test("a person's own value written sensitive is theirs: never made again, and the app goes without it; what they inherit sensitive still is (R18)", async () => {
  const handle = await handleFor(tokens.dev, 'market/local');
  const ids = await versionIds('market/local');
  const [status, body] = await api(tokens.dev, 'PATCH', '/secrets/market/local@me', { SEAL_KEY: { value: 'c'.repeat(64), generated: { recipe: 'bytes:32:hex' }, replaces: ids.SEAL_KEY!, sensitivity: 'sensitive' } });
  assert.equal(status, 200, JSON.stringify(body));
  const plan = await planFor('market/local', handle);
  assert.equal(plan.environment, 'market/local@me');
  assert.equal(plan.generate?.SEAL_KEY, undefined);
  assert.ok(plan.left.includes('SEAL_KEY'));
  // WEBHOOK_SECRET, local's sensitive value it inherits, is still made the person's own.
  assert.deepEqual(plan.generate?.WEBHOOK_SECRET, { recipe: 'bytes:24:base62', replaces: ids.WEBHOOK_SECRET, sensitivity: 'secret' });
});

test("a person's use of a generating environment reads their personal config: their own key is the one sent", async () => {
  const handle = await handleFor(tokens.dev, 'market/local');
  const forwarded = (path: string, key: string) => app.request(`/use/${path}`, { headers: { 'x-api-key': key } }).then((response) => response.json());
  assert.deepEqual(await forwarded('market/local/api/thing', handle), { shared: true });
  assert.equal((await api(tokens.dev, 'PATCH', '/secrets/market/local@me', { API_KEY: 'sk_devs_own_0123456789' }))[0], 200);
  // The vault's memory holds a handle's rows for two seconds (`memorySeconds`): a fresh handle reads again.
  const fresh = await handleFor(tokens.dev, 'market/local');
  assert.deepEqual(await forwarded('market/local/api/thing', fresh), { shared: false });
  // The stable URL, which the handle's environment names, reads through the personal config alike.
  assert.deepEqual(await forwarded('api/thing', fresh), { shared: false });
  // dev generates nothing: its own values, and nobody's personal config, as before.
  assert.equal((await api(tokens.dev, 'PATCH', '/secrets/market/dev@me', { API_KEY: 'sk_devs_own_0123456789' }))[0], 200);
  const devHandle = await handleFor(tokens.dev, 'market/dev');
  assert.deepEqual(await forwarded('market/dev/api/thing', devHandle), { shared: true });
});

test('a list of keys generates those alone, and an environment not listed generates nothing', async () => {
  const [status, made] = await api(tokens.dev, 'POST', '/handles', { label: 'coffre run', paths: ['market/listed', 'market/dev'] });
  assert.equal(status, 200, JSON.stringify(made));
  const handle = made.token as string;
  assert.deepEqual(Object.keys((await planFor('market/listed', handle)).generate ?? {}), ['SEAL_KEY']);
  assert.equal((await planFor('market/dev', handle)).generate, undefined);
});

test('generate names environments by path and keys by name, or the configuration is refused', () => {
  assert.throws(() => credentialProxy({ credentials: {}, generate: { 'market/local@me': 'all' } }), /generate names environments by path/);
  assert.throws(() => credentialProxy({ credentials: {}, generate: { 'market/local': ['not a key'] } }), /generate\['market\/local'\] is 'all' or a list of keys/);
});

test("a parent's version and recipe are told only to its readers: nothing is generated from what the reader may not know of", async () => {
  const handle = await handleFor(tokens.kid, 'market/kid');
  const plan = await planFor('market/kid', handle);
  assert.deepEqual(plan.generate, {});
  // Its own sensitive key a recipe made is generated, as anywhere.
  await write(world, ...rows('secrets', { ...value(world, secret(kid, 'OWN_KEY'), 'kid-own-0123456789', { sensitive: true }), recipe: 'bytes:16:hex' }));
  assert.deepEqual(Object.keys((await planFor('market/kid', handle)).generate ?? {}), ['OWN_KEY']);
});

test('a plain value reaches the app as it is through a personal config of its environment, once one is made', async () => {
  const handle = await handleFor(tokens.dev, 'market/local');
  assert.equal((await planFor('market/local', handle)).env.TWILIO_SID, 'AC0123456789');
  assert.equal((await api(tokens.dev, 'PATCH', '/secrets/market/local@me', { SOMETHING_MINE: 'mine-0123456789' }))[0], 200);
  const through = await planFor('market/local', handle);
  assert.equal(through.environment, 'market/local@me');
  assert.equal(through.env.TWILIO_SID, 'AC0123456789');
  assert.equal(through.env.TWILIO_TOKEN, handle);
});

test("a value the person writes of their own is in the very next plan, which reads now, never the vault's memory of the last", async () => {
  const handle = await handleFor(tokens.dev, 'market/local');
  // A personal config first, so that both plans ask the vault the same keys of it.
  assert.equal((await api(tokens.dev, 'PATCH', '/secrets/market/local@me', { SOMETHING_MINE: 'mine-0123456789' }))[0], 200);
  assert.equal((await planFor('market/local', handle)).env.TESTNET_KEY, 'testnet-key-0123456789');
  assert.equal((await api(tokens.dev, 'PATCH', '/secrets/market/local@me', { TESTNET_KEY: 'devs-own-testnet-0123' }))[0], 200);
  assert.equal((await planFor('market/local', handle)).env.TESTNET_KEY, 'devs-own-testnet-0123');
});

test('a recipe the server does not know, or a key pair\'s, is never one a plan makes a value by', async () => {
  // As a row says it, sealed: a recipe of a later release, say, which this one cannot make.
  await write(world, ...rows('secrets', { ...value(world, secret(local, 'LATER_KEY'), 'later-0123456789', { sensitive: true }), recipe: 'bytes:9999:hex' }));
  // A key pair's half: made only with its other half, which a plan does not name, so `coffre run` would refuse to start (0.14.7 left it out).
  await write(world, ...rows('secrets', { ...value(world, secret(local, 'SIGN_PRIVATE_KEY'), 'private-0123456789', { sensitive: true }), recipe: 'ecdsa:p-256' }));
  await write(world, ...rows('secrets', { ...value(world, secret(local, 'SHARE_KEY'), 'share-0123456789', { sensitive: true }), recipe: 'ecdh:p-384' }));
  const plan = await planFor('market/local', await handleFor(tokens.dev, 'market/local'));
  assert.deepEqual([Object.keys(plan.generate ?? {}), plan.left], [['SEAL_KEY', 'WEBHOOK_SECRET'], ['LATER_KEY', 'SEAL_KEY', 'SHARE_KEY', 'SIGN_PRIVATE_KEY', 'TYPED', 'WEBHOOK_SECRET']]);
});
