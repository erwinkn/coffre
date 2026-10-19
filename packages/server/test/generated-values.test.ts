// Values of a person's own (docs/design/credential-proxy.md, section 2): in
// an environment the deployment lists under `generate`, a person's use reads
// their personal config of it, and the plan names each key their app would
// go without, a sensitive one no credential uses, that a recipe made, for
// `coffre run` to make a value of their own by it, once, in that personal
// config. Each write replaces the version
// the plan read, so of two runs at once one writes and the other is refused.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

import { createClient, type CoffreClient } from '@coffre/client';

import { clientFor } from './api-fixture.ts';
import { deps, DEV, entries, ORIGIN, ROOT, route, runtime, sessionFor, useMcp } from './mcp-fixture.ts';
import { coffreRoute } from '../src/app.ts';
import { checkPlugins } from '../src/plugins.ts';
import { basic, credentialProxy, header } from '../src/plugins/credential-proxy.ts';

const API_KEY = 'sk_local_shared_0123456789';
const KID_ONLY = 'kid@acme.example';

/** A fake API that says which key it got. */
let upstream: Server;
let upstreamUrl: string;

before(async () => {
  upstream = createServer((request, response) => {
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify({ shared: request.headers['x-api-key'] === API_KEY }));
  });
  await new Promise<void>((resolve) => upstream.listen(0, '127.0.0.1', resolve));
  upstreamUrl = `http://127.0.0.1:${(upstream.address() as AddressInfo).port}`;
});

after(() => new Promise<void>((resolve) => upstream.close(() => resolve())));

let root: CoffreClient;

useMcp(
  async () => {
    runtime.plugins = checkPlugins([credentialProxy({
      credentials: {
        api: { upstream: `${upstreamUrl}/v1`, inject: header('x-api-key', '{API_KEY}') },
        twilio: { upstream: `${upstreamUrl}/twilio`, inject: basic('{TWILIO_SID}', '{TWILIO_TOKEN}') },
      },
      generate: { 'market/local': 'all', 'market/listed': ['SEAL_KEY'], 'market/kid': 'all' },
      insecureUpstreams: true,
    })]);
    root = clientFor(deps, ROOT);
    await root.members.add(`user:${DEV}`);
    await root.projects.create('market');
    for (const environment of ['local', 'listed', 'dev']) {
      await root.environments.create(`market/${environment}`);
      await root.secrets.set(`market/${environment}`, {
        SEAL_KEY: { value: 'shared-seal-key-0123456789', generated: { recipe: 'bytes:32:hex' }, sensitivity: 'sensitive' },
        WEBHOOK_SECRET: { value: 'shared-webhook-0123456789', generated: { recipe: 'bytes:24' }, sensitivity: 'sensitive' },
        TYPED: { value: 'typed-by-hand-0123456789', sensitivity: 'sensitive' },
        TESTNET_KEY: 'testnet-key-0123456789',
        REGION: { value: 'eu-west-3', plain: true },
        API_KEY,
        TWILIO_SID: { value: 'AC0123456789', plain: true },
        TWILIO_TOKEN: 'twilio_token_0123456789',
      });
    }
    // A fork of local, read by someone who does not read local: what it inherits is not theirs to be told of.
    await root.environments.create('market/kid', { from: 'local', inherit: true });
    await root.members.add(`user:${KID_ONLY}`);
    await root.access.set(`user:${KID_ONLY}`, { 'market/kid': 'developer' });
    await root.access.set(`user:${DEV}`, { market: 'developer' });
  },
);

function bearer(token: string): CoffreClient {
  return createClient({ url: ORIGIN, headers: () => ({ authorization: `Bearer ${token}` }), transport: (request) => coffreRoute(request, runtime, '203.0.113.7').then((response) => response!) });
}

type Plan = { environment: string; env: Record<string, string>; left: string[]; generate?: Record<string, { recipe: string; replaces: string; sensitivity: 'secret' }> };

async function planFor(path: string, handle: string): Promise<Plan> {
  const response = await route(`/use/${path}`, { headers: { authorization: `Bearer ${handle}` } });
  assert.equal(response.status, 200, await response.clone().text());
  return (await response.json()) as Plan;
}

const versionIds = async (path: string) => Object.fromEntries((await root.secrets.list(path)).keys.map((entry) => [entry.key, entry.versionId]));

test('the plan names what a recipe made and the app would go without; a run writes it, once, and the plan reads it from then on', async () => {
  const dev = bearer(await sessionFor(DEV));
  const handle = (await dev.handles.create({ label: 'coffre run market/local', paths: ['market/local'] })).token;
  const ids = await versionIds('market/local');
  const first = await planFor('market/local', handle);
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
  const raced = await Promise.allSettled([dev.secrets.set('market/local@me', write), dev.secrets.set('market/local@me', { ...write, SEAL_KEY: { ...write.SEAL_KEY, value: 'b'.repeat(64) } })]);
  assert.deepEqual(raced.map((each) => each.status).sort(), ['fulfilled', 'rejected']);
  const lost = (raced.find((each) => each.status === 'rejected') as PromiseRejectedResult).reason as { status: number; reason: string };
  assert.deepEqual([lost.status, lost.reason], [409, 'stale']);
  const won = raced[0]!.status === 'fulfilled' ? 'a' : 'b';

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
  const writes = (await entries('secret.write')).filter((entry) => entry.actor === `user:${DEV}`);
  assert.deepEqual(writes.map((entry) => [entry.metadata.key, entry.metadata.recipe]).sort(), [['SEAL_KEY', 'bytes:32:hex'], ['WEBHOOK_SECRET', 'bytes:24:base62']]);
});

test("a person's own generated value they made sensitive is theirs: never made again, and the app goes without it (R18)", async () => {
  const dev = bearer(await sessionFor(DEV));
  const handle = (await dev.handles.create({ label: 'coffre run market/local', paths: ['market/local'] })).token;
  const ids = await versionIds('market/local');
  await dev.secrets.set('market/local@me', { SEAL_KEY: { value: 'c'.repeat(64), generated: { recipe: 'bytes:32:hex' }, replaces: ids.SEAL_KEY!, sensitivity: 'secret' } });
  await dev.secrets.set('market/local@me', { SEAL_KEY: { sensitivity: 'sensitive' } });
  const plan = await planFor('market/local', handle);
  assert.equal(plan.environment, 'market/local@me');
  assert.equal(plan.generate?.SEAL_KEY, undefined);
  assert.ok(plan.left.includes('SEAL_KEY'));
  // WEBHOOK_SECRET, local's sensitive value it inherits, is still made the person's own.
  assert.ok(plan.generate?.WEBHOOK_SECRET !== undefined);
  // Written saying nothing, as a CLI before 0.10 writes it, it is as sensitive as local's: the person's own, left out the same.
  await dev.secrets.set('market/local@me', { WEBHOOK_SECRET: { value: 'devs-own-webhook-0123', generated: { recipe: 'bytes:24' }, replaces: ids.WEBHOOK_SECRET! } });
  const after = await planFor('market/local', handle);
  assert.deepEqual([after.generate?.WEBHOOK_SECRET, after.left.includes('WEBHOOK_SECRET')], [undefined, true]);
});

test("a person's use of a generating environment reads their personal config: their own key is the one sent", async () => {
  const dev = bearer(await sessionFor(DEV));
  const handle = (await dev.handles.create({ label: 'coffre run market/local', paths: ['market/local'] })).token;
  assert.deepEqual(await (await route('/use/market/local/api/thing', { headers: { 'x-api-key': handle } })).json(), { shared: true });
  await dev.secrets.set('market/local@me', { API_KEY: 'sk_devs_own_0123456789' });
  // The cache holds the handle's last opening for a minute: a fresh handle reads again.
  const fresh = (await dev.handles.create({ label: 'coffre run market/local', paths: ['market/local'] })).token;
  assert.deepEqual(await (await route('/use/market/local/api/thing', { headers: { 'x-api-key': fresh } })).json(), { shared: false });
  // The stable URL, which the handle's environment names, reads through the personal config alike.
  assert.deepEqual(await (await route('/use/api/thing', { headers: { 'x-api-key': fresh } })).json(), { shared: false });
  // dev generates nothing: its own values, and nobody's personal config, as before.
  await dev.secrets.set('market/dev@me', { API_KEY: 'sk_devs_own_0123456789' });
  const devHandle = (await dev.handles.create({ label: 'coffre run market/dev', paths: ['market/dev'] })).token;
  assert.deepEqual(await (await route('/use/market/dev/api/thing', { headers: { 'x-api-key': devHandle } })).json(), { shared: true });
});

test('a list of keys generates those alone, and an environment not listed generates nothing', async () => {
  const handle = (await bearer(await sessionFor(DEV)).handles.create({ label: 'coffre run', paths: ['market/listed', 'market/dev'] })).token;
  assert.deepEqual(Object.keys((await planFor('market/listed', handle)).generate ?? {}), ['SEAL_KEY']);
  assert.equal((await planFor('market/dev', handle)).generate, undefined);
});

test('generate names environments by path and keys by name, or the configuration is refused', () => {
  assert.throws(() => credentialProxy({ credentials: {}, generate: { 'market/local@me': 'all' } }), /generate names environments by path/);
  assert.throws(() => credentialProxy({ credentials: {}, generate: { 'market/local': ['not a key'] } }), /generate\['market\/local'\] is 'all' or a list of keys/);
});

test("a parent's version and recipe are told only to its readers: nothing is generated from what the reader may not know of", async () => {
  const kid = bearer(await sessionFor(KID_ONLY));
  const handle = (await kid.handles.create({ label: 'coffre run market/kid', paths: ['market/kid'] })).token;
  const plan = await planFor('market/kid', handle);
  assert.deepEqual(plan.generate, {});
  // Its own sensitive key a recipe made is generated, as anywhere.
  await root.secrets.set('market/kid', { OWN_KEY: { value: 'kid-own-0123456789', generated: { recipe: 'bytes:16:hex' }, sensitivity: 'sensitive' } });
  assert.deepEqual(Object.keys((await planFor('market/kid', handle)).generate ?? {}), ['OWN_KEY']);
});

test('a plain value reaches the app as it is through a personal config of its environment, once one is made', async () => {
  const dev = bearer(await sessionFor(DEV));
  const handle = (await dev.handles.create({ label: 'coffre run market/local', paths: ['market/local'] })).token;
  assert.equal((await planFor('market/local', handle)).env.TWILIO_SID, 'AC0123456789');
  await dev.secrets.set('market/local@me', { SOMETHING_MINE: 'mine-0123456789' });
  const through = await planFor('market/local', handle);
  assert.equal(through.environment, 'market/local@me');
  assert.equal(through.env.TWILIO_SID, 'AC0123456789');
  assert.equal(through.env.TWILIO_TOKEN, handle);
});
