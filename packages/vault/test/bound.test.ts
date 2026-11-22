// A call over a Cloudflare service binding (docs/design/workload-access.md,
// section 9.2): no token, the service its `props` name on the app's word,
// held to that service's live `cloudflare` bindings and grants. It uses
// values, purpose `use`, and is handed none.
import assert from 'node:assert/strict';
import { after, beforeEach, test } from 'node:test';

import { rowsOf } from '@coffre/db/dialect';
import { sql } from 'drizzle-orm';

import { entryOf, type Entry } from '../src/entry.ts';
import { memoryOf, use, type Ask } from '../src/use.ts';
import { emptyDatabase, openTestVault } from './database.ts';
import { amend, ask, binding, environment, grant, instance, principal, project, role, rows, secret, value, write } from './world.ts';

const vault = await openTestVault();
after(() => vault.close());

const [EDGE, GHOST] = ['token:edge', 'token:ghost'];
const READS = ['secret.read', 'secret.use'];

/**
 * market: prod, staging and dev, each with its DATABASE_URL; billing: prod.
 * edge views market and billing, and has two `cloudflare` bindings, one
 * scoped to market/prod and one to market/staging, and a GitHub binding of
 * all of market, which no binding call stands on. ghost views market and
 * has no `cloudflare` binding.
 */
async function world() {
  const [market, billing] = [project('market'), project('billing')];
  const [prod, staging, dev] = [environment(market, 'prod'), environment(market, 'staging'), environment(market, 'dev')];
  const billed = environment(billing, 'prod');
  const values = await Promise.all([prod, staging, dev, billed].map((place) => value(vault, secret(place, 'DATABASE_URL'), `postgres://${place.slug}`)));
  const flag = value(vault, secret(prod, 'FLAG'), 'on', { plain: true });
  const scoped = (...places: { id: string; projectId: string }[]) => JSON.stringify(places.map((place) => ({ projectId: place.projectId, environmentId: place.id, role: 'viewer' })));
  const cloudflare = (scope: string) => binding(EDGE, { profile: 'cloudflare', issuer: 'urn:coffre:cloudflare', jwksUri: 'urn:coffre:cloudflare', policy: '{}', scope });
  const [onProd, onStaging] = [cloudflare(scoped(prod)), cloudflare(scoped(staging))];
  const github = binding(EDGE, { policy: '{}', scope: JSON.stringify([{ projectId: market.id, environmentId: null, role: 'viewer' }]) });
  await write(
    vault,
    ...rows('projects', market, billing),
    ...rows('environments', prod, staging, dev, billed),
    ...rows('secrets', ...values, flag),
    ...rows('roles', role(true, 'member', []), role(false, 'viewer', READS)),
    ...rows('policy', instance()),
    ...rows('principals', principal(EDGE), principal(GHOST)),
    ...rows('grants', grant(EDGE, 'viewer', { project: market }), grant(EDGE, 'viewer', { project: billing }), grant(GHOST, 'viewer', { project: market })),
    ...rows('bindings', onProd, onStaging, github),
  );
  return { market, prod, staging, dev, onProd, onStaging, github };
}

let w: Awaited<ReturnType<typeof world>>;
beforeEach(async () => {
  await emptyDatabase(vault.owner);
  Object.assign(vault, { memory: memoryOf(0), cap: { count: 1000, windowMs: 15 * 60_000 }, workloads: { noReads: false, useOnly: false } });
  w = await world();
  await vault.owner.execute(sql`DELETE FROM log_pending`);
  vault.woken.length = 0;
});

/** A call over a service binding, as `service`, purpose `use`, for the credential `echo`. */
const bound = (service: string, place: string, keys: readonly string[] | null, more: Partial<Ask> = {}): Ask =>
  ({ ...ask('unused', place, keys, { purpose: 'use', upstream: { credential: 'echo', host: 'api.echo.example' }, ip: null }), token: null, proof: null, bound: service, ...more });

async function got(asked: Ask): Promise<Record<string, string> | string> {
  const result = await use(vault, asked);
  return 'refused' in result ? result.refused : Object.fromEntries(result.values.map((each) => [each.key, 'refused' in each ? `refused: ${each.refused}` : each.value.toString()]));
}
const logged = async (): Promise<Entry[]> => (await rowsOf<{ kept: boolean; body: string; mac: Buffer }>(vault.owner, sql`SELECT kept, body, mac FROM log_pending ORDER BY id`)).map((row) => entryOf(vault.keys, row)!);

test("a binding call uses a key where a cloudflare binding of its service reaches, logged as the service's, naming its bindings and no credential", async () => {
  const result = await use(vault, bound(EDGE, 'market/prod', ['DATABASE_URL', 'FLAG']));
  assert.ok(!('refused' in result), JSON.stringify(result));
  const first = [w.onProd.id, w.onStaging.id].sort()[0];
  assert.deepEqual([result.principal, result.credential, result.workload?.profile, result.workload?.binding], [EDGE, `binding:${first}`, 'cloudflare', first]);
  assert.deepEqual(result.values.map((each) => ('refused' in each ? each.refused : each.value.toString())), ['postgres://prod', 'on']);
  // An hour, which no row ends: what a presigned URL lasts no longer than.
  assert.ok(Math.abs(Date.parse(result.expiresAt) - vault.now() - 3_600_000) < 5000);
  const [entry, ...more] = await logged();
  assert.deepEqual(more, []);
  assert.deepEqual([entry!.action, entry!.actor, entry!.credential, entry!.ip], ['secret.read', EDGE, null, null]);
  for (const object of [`principal:${EDGE}`, `binding:${w.onProd.id}`, `binding:${w.onStaging.id}`]) assert.ok(entry!.objects.includes(object), object);
  assert.ok(!entry!.objects.some((object) => object.startsWith('credential:')));
  assert.equal((entry!.detail as { purpose: string }).purpose, 'use');
  // Its bindings' scopes, all of them: staging too, through the other binding.
  assert.deepEqual(await got(bound(EDGE, 'market/staging', ['DATABASE_URL'])), { DATABASE_URL: 'postgres://staging' });
});

test("nowhere a cloudflare binding does not reach, whatever the service's grants or its other bindings", async () => {
  // dev: its grants reach it, and its GitHub binding's scope; no cloudflare binding's does.
  assert.equal(await got(bound(EDGE, 'market/dev', ['DATABASE_URL'])), 'no_access');
  assert.equal(await got(bound(EDGE, 'billing/prod', ['DATABASE_URL'])), 'no_access');
  // A service with no cloudflare binding, one with no row, and a person's name: nobody.
  assert.equal(await got(bound(GHOST, 'market/prod', ['DATABASE_URL'])), 'unauthenticated');
  assert.equal(await got(bound('token:nobody', 'market/prod', ['DATABASE_URL'])), 'unauthenticated');
  // A deployment that takes no workloads takes no binding call.
  Object.assign(vault, { workloads: null });
  assert.equal(await got(bound(EDGE, 'market/prod', ['DATABASE_URL'])), 'unauthenticated');
  assert.deepEqual(await logged(), []);
});

test('a binding call is handed nothing back, and has no personal config', async () => {
  for (const purpose of ['reveal', 'run', 'expose', 'compare']) assert.equal(await got(bound(EDGE, 'market/prod', ['FLAG'], { purpose })), 'use_only', purpose);
  assert.equal(await got(bound(EDGE, 'market/prod', ['DATABASE_URL'], { mine: true })), 'no_access');
  assert.deepEqual(await logged(), []);
});

test('a binding revoked, frozen or edited behind the vault takes its scope with it; frozen everywhere, the call is told so', async () => {
  await amend(vault, 'bindings', sql`id = ${w.onProd.id}`, { revokedAt: new Date(), revokedBy: 'user:root@acme.example' });
  assert.equal(await got(bound(EDGE, 'market/prod', ['DATABASE_URL'])), 'no_access');
  assert.deepEqual(await got(bound(EDGE, 'market/staging', ['DATABASE_URL'])), { DATABASE_URL: 'postgres://staging' });
  // The other binding's scope rewritten to reach prod, its MAC no longer the vault's: no binding, and so nobody.
  await vault.owner.execute(sql`UPDATE bindings SET scope = ${JSON.stringify([{ projectId: w.market.id, environmentId: w.prod.id, role: 'viewer' }])} WHERE id = ${w.onStaging.id}`);
  assert.equal(await got(bound(EDGE, 'market/prod', ['DATABASE_URL'])), 'unauthenticated');
  assert.equal(await got(bound(EDGE, 'market/staging', ['DATABASE_URL'])), 'unauthenticated');
});

test('a freeze stops a binding call: its binding, all of its service, or every workload', async () => {
  await amend(vault, 'bindings', sql`id = ${w.onProd.id}`, { frozenAt: new Date() });
  assert.equal(await got(bound(EDGE, 'market/prod', ['DATABASE_URL'])), 'no_access');
  await amend(vault, 'bindings', sql`id = ${w.onStaging.id}`, { frozenAt: new Date() });
  assert.equal(await got(bound(EDGE, 'market/staging', ['DATABASE_URL'])), 'frozen');
  await amend(vault, 'bindings', sql`TRUE`, { frozenAt: null });
  await amend(vault, 'principals', sql`id = ${EDGE}`, { frozenAt: new Date() });
  assert.equal(await got(bound(EDGE, 'market/prod', ['DATABASE_URL'])), 'frozen');
  await amend(vault, 'principals', sql`id = ${EDGE}`, { frozenAt: null });
  await amend(vault, 'policy', sql`TRUE`, { workloadsFrozenAt: new Date() });
  assert.equal(await got(bound(EDGE, 'market/prod', ['DATABASE_URL'])), 'frozen');
  await amend(vault, 'policy', sql`TRUE`, { workloadsFrozenAt: null });
  assert.deepEqual(await got(bound(EDGE, 'market/prod', ['DATABASE_URL'])), { DATABASE_URL: 'postgres://prod' });
  // An instance whose policy row is gone cannot say it is not frozen.
  await vault.owner.execute(sql`DELETE FROM policy`);
  assert.equal(await got(bound(EDGE, 'market/prod', ['DATABASE_URL'])), 'frozen');
});

test('where the instance lets no binding list reads, a cloudflare binding that lists them stands on nothing', async () => {
  await amend(vault, 'bindings', sql`id = ${w.onProd.id}`, { policy: JSON.stringify({ reads: { [w.prod.id]: { keys: '*' } } }) });
  Object.assign(vault, { workloads: { noReads: true, useOnly: false } });
  assert.equal(await got(bound(EDGE, 'market/prod', ['DATABASE_URL'])), 'no_access');
  await amend(vault, 'bindings', sql`id = ${w.onStaging.id}`, { policy: JSON.stringify({ reads: { [w.staging.id]: { keys: '*' } } }) });
  assert.equal(await got(bound(EDGE, 'market/staging', ['DATABASE_URL'])), 'no_reads');
});

test("a member removed since its binding was made: the binding's generation is gone", async () => {
  await amend(vault, 'principals', sql`id = ${EDGE}`, { generation: 1 });
  assert.equal(await got(bound(EDGE, 'market/prod', ['DATABASE_URL'])), 'unauthenticated');
});
