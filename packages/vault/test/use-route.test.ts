// A route use (0.16, T186 PR C; docs/design/proxy-ui.md, sections 3, 4 and 6; migration 0058, `use_route`;
// formal/Routing.tla), on both engines: the vault's one call (two on a map miss) finds a UI definition by its name at
// the place, through the fork chain, its seal checked against its object's newest change, and uses every key it sends,
// each decided twice: for the caller, as a use, and for the item's editor, what their save froze intersected with what
// they hold now. Each case is named for the model's protection it holds.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import { decrypt } from '@coffre/core/envelope';
import type { ProxyDefinition, ProxyItemOutcome, RouteUseInput, RouteUseOutcome } from '@coffre/core/vault';
import { createDatabase, type Database } from '@coffre/db';
import { postgresClient } from '@coffre/db/connect';
import { sql } from 'drizzle-orm';

import { ROLES } from '@coffre/core/access';

import { applyOp, itemDigest, objectKey, ROLES_REF, type Input, type Op, type ProxyItem, type Ref } from '../src/inputs.ts';
import { purposeCode, replayStored } from '../src/log-replay.ts';
import { callRoute as postgresRoute, callRouteNamed as postgresNamed } from '../src/use.postgres.ts';
import { callRoute as sqliteRoute, callRouteNamed as sqliteNamed } from '../src/use.sqlite.ts';
import type { Names, RouteCall, UseCall } from '../src/use.ts';
import { openVault, prepareVault } from '../src/vault.ts';
import { ENGINE, HOT_URL, openTestDatabase, rows, run, type TestDatabase } from './database.ts';
import { route, routeWorld } from './route-world.ts';
import { weigh, weighingSession, WORLD_TABLES, type HotCall } from '../../../scripts/matrix-weigh.ts';
import { change, CONFIG, emptyLog, isolate, LOG_015, seal, SIGNING_KEY, useDatabases } from './use-world.ts';

let db: TestDatabase;
let hot: Database;
before(async () => {
  db = await openTestDatabase();
  hot = await useDatabases(db);
});
after(() => db.close());
beforeEach(emptyLog);

const answered = (outcome: RouteUseOutcome) => {
  assert.ok(outcome.served && outcome.route === 'name', JSON.stringify(outcome));
  return outcome as Extract<RouteUseOutcome, { route: 'name' }>;
};

/** Each key's value by name, the use allowed. */
function values(outcome: RouteUseOutcome): Record<string, string | null> {
  const answer = answered(outcome);
  assert.ok(answer.outcome.ok, JSON.stringify(answer.outcome));
  const out: Record<string, string | null> = {};
  for (const [i, key] of answer.keys.entries()) {
    const value = answer.outcome.values[i]!;
    out[key.key] = value === null ? null : 'plain' in value ? value.plain : decrypt(
      { envelopeVersion: value.value.envelope.version, ciphertext: Buffer.from(value.value.envelope.ciphertext, 'base64'), iv: Buffer.from(value.value.envelope.iv, 'base64'), authTag: Buffer.from(value.value.envelope.authTag, 'base64') },
      value.value.context, Buffer.from(value.value.key, 'base64'),
    ).toString();
  }
  return out;
}

/** Why the use was refused: its code, and the key it was refused at (null: the place's, or the route's). */
function refused(outcome: RouteUseOutcome): { code: string; key: string | null } {
  const answer = answered(outcome);
  assert.ok(!answer.outcome.ok && 'code' in answer.outcome, JSON.stringify(answer.outcome));
  return { code: answer.outcome.code, key: answer.outcome.index === null ? null : answer.keys[answer.outcome.index]?.key ?? null };
}

const count = async (table: string) => (await rows(db.owner, sql.raw(`SELECT 1 FROM ${table}`))).length;

/** Every use's decision, replayed from the log alone, held to what each live answer logged (R53). */
async function replayAgrees(live: Map<string, string | null>): Promise<void> {
  const { decided, faults } = await replayStored(db.owner, [SIGNING_KEY]);
  assert.deepEqual(faults, []);
  for (const [number, code] of live) assert.equal(decided.get(number), code, `entry ${number}: live and replay disagree`);
}

/** The entries a use wrote, by number, with the decision it logged (allowed: null). */
function logged(outcome: RouteUseOutcome, into: Map<string, string | null>): void {
  const answer = answered(outcome);
  if (answer.outcome.ok) {
    for (const value of answer.outcome.values) if (value !== null && 'number' in value && !value.covered) into.set(value.number, null);
  } else if ('code' in answer.outcome && answer.outcome.number !== null) into.set(answer.outcome.number, answer.outcome.code);
}

test('a route of one key: decided for its caller and its editor, sent by the item the vault decided on; a copy of that digest leaves the item out', async () => {
  const w = await routeWorld(db);
  const key = await w.key('sk-openai');
  const name = await w.nameOf(key);
  const ada = await w.member([{ environmentId: null, role: 'owner' }]);
  await w.save({ openai: { definition: route('openai', [name]), editor: ada } });
  const { vault, cache } = await isolate();
  const first = await vault.useRoute(w.askRoute('openai'));
  assert.deepEqual(values(first), { [name]: 'sk-openai' });
  const answer = answered(first);
  assert.ok(answer.found?.found);
  assert.equal(answer.found.item.definition?.kind, 'route');
  assert.equal((answer.found.item.definition as Extract<ProxyDefinition, { kind: 'route' }>).upstream, 'https://api.openai.com/v1');
  assert.equal(answer.found.level, 0);
  assert.equal(answer.reading, 'named');
  // The map keeps the route's keys' ids: the next use is one statement, and, its copy's digest named, no item back.
  assert.deepEqual(cache.routeKeys.get(`${w.dev}\nopenai`)?.ids, [{ id: key, through: false }]);
  const again = answered(await vault.useRoute(w.askRoute('openai', { digests: [answer.found.item.digest] })));
  assert.ok(again.found?.found);
  assert.equal(again.found.item.definition, null, 'the copy has that digest');
  assert.equal(again.found.item.digest, answer.found.item.digest);
  const entries = await rows<{ route: string | null }>(db.owner, sql`SELECT route FROM log_uses`);
  assert.ok(entries.length >= 1 && entries.every((entry) => entry.route === 'openai'), 'each entry names its route');
  const live = new Map<string, string | null>();
  logged(first, live);
  await replayAgrees(live);
});

test('a route of two keys, and of plain keys only: every key decided on one version, a plain value handed back with no entry', async () => {
  const w = await routeWorld(db);
  const a = await w.key('access-key');
  const b = await w.key('secret-key');
  const [nameA, nameB] = [await w.nameOf(a), await w.nameOf(b)];
  const { name: plainName } = await w.plain('plain-text');
  const ada = await w.member([{ environmentId: null, role: 'owner' }]);
  await w.save({ s3: { definition: route('s3', [nameA, nameB]), editor: ada }, flags: { definition: route('flags', [plainName]), editor: ada } });
  const { vault } = await isolate();
  assert.deepEqual(values(await vault.useRoute(w.askRoute('s3'))), { [nameA]: 'access-key', [nameB]: 'secret-key' });
  const before = await count('log_uses');
  assert.deepEqual(values(await vault.useRoute(w.askRoute('flags'))), { [plainName]: 'plain-text' });
  assert.equal(await count('log_uses'), before, 'a plain value: no entry');
});

test('EditorStillHolds: an editor demoted or removed after their save routes nothing they no longer read, until a holder saves again', async () => {
  const w = await routeWorld(db);
  const key = await w.key('sk');
  const name = await w.nameOf(key);
  const lin = await w.member([{ environmentId: w.dev, role: 'developer' }]);
  await w.save({ openai: { definition: route('openai', [name]), editor: lin } });
  const { vault } = await isolate();
  const live = new Map<string, string | null>();
  const allowed = await vault.useRoute(w.askRoute('openai'));
  assert.deepEqual(values(allowed), { [name]: 'sk' });
  logged(allowed, live);
  // Demoted to a Viewer of nothing there: her route stops, its entry written, nothing opened.
  await w.restand(lin, []);
  const stopped = await vault.useRoute(w.askRoute('openai'));
  assert.deepEqual(refused(stopped), { code: 'route_not_cleared', key: name });
  const why = answered(stopped).outcome;
  assert.ok(!why.ok && 'why' in why && typeof why.why === 'string', 'the refusal names why');
  logged(stopped, live);
  // Removed from the instance: the same.
  await w.restand(lin, [], true);
  assert.deepEqual(refused(await vault.useRoute(w.askRoute('openai'))), { code: 'route_not_cleared', key: name });
  // An Owner saves it again, unchanged: cleared as hers.
  const ada = await w.member([{ environmentId: null, role: 'owner' }]);
  await w.save({ openai: { definition: route('openai', [name]), editor: ada } });
  const back = await vault.useRoute(w.askRoute('openai'));
  assert.deepEqual(values(back), { [name]: 'sk' });
  logged(back, live);
  await replayAgrees(live);
});

test("ClearanceAtUse: a key made sensitive after a Developer's save is refused at use; an Owner's route of a sensitive key is allowed", async () => {
  const w = await routeWorld(db);
  const key = await w.key('sk');
  const name = await w.nameOf(key);
  const lin = await w.member([{ environmentId: w.dev, role: 'developer' }]);
  await w.save({ openai: { definition: route('openai', [name]), editor: lin } });
  const { vault } = await isolate();
  assert.deepEqual(values(await vault.useRoute(w.askRoute('openai'))), { [name]: 'sk' });
  await w.markSensitive(key);
  const live = new Map<string, string | null>();
  const refusedNow = await vault.useRoute(w.askRoute('openai'));
  assert.deepEqual(refused(refusedNow), { code: 'route_not_cleared', key: name });
  logged(refusedNow, live);
  // Lin made an Owner since: what her save froze still routes no sensitive value (no role widened widens the route).
  await w.restand(lin, [{ environmentId: null, role: 'owner' }]);
  assert.deepEqual(refused(await vault.useRoute(w.askRoute('openai'))), { code: 'route_not_cleared', key: name });
  // An Owner's route of a key sensitive from the start: allowed.
  const ada = await w.member([{ environmentId: null, role: 'owner' }]);
  const hot = await w.key('sensitive-value', true);
  const hotName = await w.nameOf(hot);
  await w.save({ stripe: { definition: route('stripe', [hotName], 'api.stripe.com'), editor: ada } });
  assert.deepEqual(values(await vault.useRoute(w.askRoute('stripe'))), { [hotName]: 'sensitive-value' });
  await replayAgrees(live);
});

test('SealChecked: a row put back from before an edit is `stale`; an item forged in it, or one its index lacks, `tampered`; a deleted row `stale`', async () => {
  const w = await routeWorld(db);
  const key = await w.key('sk');
  const name = await w.nameOf(key);
  const ada = await w.member([{ environmentId: null, role: 'owner' }]);
  await w.save({ openai: { definition: route('openai', [name], 'good.example'), editor: ada } });
  const v7 = (await w.stored(w.dev))!;
  await w.save({ openai: { definition: route('openai', [name], 'evil.example'), editor: ada } });
  const v8 = (await w.stored(w.dev))!;
  const { vault } = await isolate();
  const put = async (row: { items: Record<string, ProxyItem>; digests: Buffer; seal: Buffer }) => {
    const json = JSON.stringify(row.items);
    if (ENGINE === 'postgres') await run(db.owner, sql`UPDATE proxy_definitions SET items = ${json}::jsonb, digests = ${row.digests}, seal = ${row.seal} WHERE environment_id = ${w.dev}`);
    else await run(db.owner, sql`UPDATE proxy_definitions SET items = ${json}, digests = ${row.digests}, seal = ${row.seal} WHERE environment_id = ${w.dev}`);
  };
  // Version 7 put back whole: its seal is the vault's, but not its object's newest change's.
  await put(v7);
  assert.deepEqual(refused(await vault.useRoute(w.askRoute('openai'))), { code: 'stale', key: null });
  // Version 8's index and seal, version 7's body: the item does not hash to its sealed entry.
  await put({ ...v8, items: v7.items });
  assert.deepEqual(refused(await vault.useRoute(w.askRoute('openai'))), { code: 'tampered', key: null });
  // An item planted beside version 8's, its index unchanged: no sealed entry names it.
  await put({ ...v8, items: { ...v8.items, planted: { ...v8.items.openai!, definition: route('planted', [name], 'evil.example') } } });
  assert.deepEqual(refused(await vault.useRoute(w.askRoute('planted'))), { code: 'tampered', key: null });
  // Version 8 back: served again.
  await put(v8);
  assert.deepEqual(values(await vault.useRoute(w.askRoute('openai'))), { [name]: 'sk' });
  // The row deleted: its object had changes, so no row is `stale`.
  await run(db.owner, sql`DELETE FROM proxy_definitions WHERE environment_id = ${w.dev}`);
  assert.deepEqual(refused(await vault.useRoute(w.askRoute('openai'))), { code: 'stale', key: null });
});

test("forks (decision 6): a fork with no item of the name is served by its parent's, its key resolved through the chain; a fork's own item deleted from its row, its index left, is `tampered`, never the parent's", async () => {
  const w = await routeWorld(db);
  const key = await w.key('from-dev');
  const name = await w.nameOf(key);
  const ada = await w.member([{ environmentId: null, role: 'owner' }]);
  await w.save({ openai: { definition: route('openai', [name]), editor: ada } });
  const eu = await w.fork('dev-eu');
  // The caller stands at the fork too.
  await w.grantAt(eu, 'developer');
  const { vault } = await isolate();
  const atFork = (extra: Partial<RouteUseInput> = {}) => w.askRoute('openai', { named: { place: { project: w.slug, environment: 'dev-eu' }, route: 'openai' }, ...extra });
  const served = await vault.useRoute(atFork());
  assert.deepEqual(values(served), { [name]: 'from-dev' });
  const answer = answered(served);
  assert.ok(answer.found?.found);
  assert.equal(answer.found.level, 1, "served by dev's item");
  assert.deepEqual(answer.found.seals[0], '', 'the fork has no object');
  // The fork's own item, then deleted from its row with its index left: tampered, not dev's.
  await w.save({ openai: { definition: route('openai', [name], 'eu.api.openai.com'), editor: ada } }, eu);
  const own = answered(await vault.useRoute(atFork()));
  assert.ok(own.found?.found);
  assert.equal(own.found.level, 0);
  const row = (await w.stored(eu))!;
  const json = JSON.stringify({});
  if (ENGINE === 'postgres') await run(db.owner, sql`UPDATE proxy_definitions SET items = ${json}::jsonb WHERE environment_id = ${eu}`);
  else await run(db.owner, sql`UPDATE proxy_definitions SET items = ${json} WHERE environment_id = ${eu}`);
  assert.ok(row.digests.length > 0);
  assert.deepEqual(refused(await vault.useRoute(atFork())), { code: 'tampered', key: null });
});

test("a personal config serves no UI route (decision 7): `personal`, nothing of the route read", async () => {
  const w = await routeWorld(db);
  const key = await w.key('sk');
  const ada = await w.member([{ environmentId: null, role: 'owner' }]);
  await w.save({ openai: { definition: route('openai', [await w.nameOf(key)]), editor: ada } });
  await w.personal();
  const { vault } = await isolate();
  const answer = answered(await vault.useRoute(w.askRoute('openai', { named: { place: { project: w.slug, environment: 'dev@me' }, route: 'openai' } })));
  assert.equal(answer.personal, true);
  assert.equal(answer.found, null);
});

test('no such route: none found, nothing used; a caller who stands nowhere there learns nothing of the route', async () => {
  const w = await routeWorld(db);
  const { vault } = await isolate();
  const none = answered(await vault.useRoute(w.askRoute('nothing')));
  assert.deepEqual(none.found, { found: false, fault: null, seals: [''] }, 'dev has no object');
  assert.equal(await count('log_uses'), 0);
  // Her grant revoked: refused on the place, before the route is read.
  const key = await w.key('sk');
  const ada = await w.member([{ environmentId: null, role: 'owner' }]);
  await w.save({ openai: { definition: route('openai', [await w.nameOf(key)]), editor: ada } });
  await w.revoke();
  const answer = answered(await vault.useRoute(w.askRoute('openai')));
  assert.equal(answer.stands, false);
  assert.equal(answer.found, null);
});

test('covers are per route: the same key through two routes writes an entry each; a repeat right after an edit, or after the editor changed, writes its own', async () => {
  const w = await routeWorld(db);
  const key = await w.key('sk');
  const name = await w.nameOf(key);
  const ada = await w.member([{ environmentId: null, role: 'owner' }]);
  const lin = await w.member([{ environmentId: w.dev, role: 'developer' }]);
  await w.save({ a: { definition: route('a', [name], 'good.example'), editor: ada }, b: { definition: route('b', [name], 'evil.example'), editor: lin } });
  const { vault } = await isolate();
  const live = new Map<string, string | null>();
  const use = async (name2: string) => {
    const outcome = await vault.useRoute(w.askRoute(name2));
    logged(outcome, live);
    return outcome;
  };
  await use('a');
  const afterA = await count('log_uses');
  const repeat = answered(await use('a'));
  assert.ok(repeat.outcome.ok && repeat.outcome.values[0] !== null && 'covered' in repeat.outcome.values[0] && repeat.outcome.values[0].covered, 'a repeat of route a rides its entry');
  assert.equal(await count('log_uses'), afterA);
  await use('b');
  assert.equal(await count('log_uses'), afterA + 1, "route b's use writes its own, decided under Lin's holdings");
  // An edit of route a: its next use writes its own entry.
  await w.save({ a: { definition: route('a', [name], 'good2.example'), editor: ada } });
  await use('a');
  assert.equal(await count('log_uses'), afterA + 2);
  // Ada's principal changed (another grant): the next use of a writes its own.
  await w.restand(ada, [{ environmentId: null, role: 'owner' }, { environmentId: w.dev, role: 'developer' }]);
  await use('a');
  assert.equal(await count('log_uses'), afterA + 3);
  await replayAgrees(live);
});

test('the stable reading: a handle made for dev reads `/use/openai/…` at dev; the place reading only for an environment it was made for, and a changed made-for list answers `moved` on a hit, then serves', async () => {
  const w = await routeWorld(db);
  const key = await w.key('sk');
  const name = await w.nameOf(key);
  const ada = await w.member([{ environmentId: null, role: 'owner' }]);
  await w.save({ openai: { definition: route('openai', [name]), editor: ada } });
  await run(db.owner, sql`UPDATE credentials SET places = ${JSON.stringify([{ environmentId: w.dev }])} WHERE id = ${w.credentialId}`);
  const { vault, cache } = await isolate();
  // `/use/openai/models`: the stable reading, route openai at the handle's one place.
  const stable = answered(await vault.useRoute(w.askRoute('x', { named: null, stable: 'openai' })));
  assert.equal(stable.reading, 'stable');
  assert.deepEqual(values(stable), { [name]: 'sk' });
  // `/use/<project>/dev/openai/…`: both readings; the handle was made for dev, so the place reading.
  const both = (extra: Partial<RouteUseInput> = {}) => w.askRoute('openai', { stable: w.slug, ...extra });
  const placed = answered(await vault.useRoute(both()));
  assert.equal(placed.reading, 'named');
  assert.deepEqual(values(placed), { [name]: 'sk' });
  assert.ok(cache.madeFor.get(w.tokenHash.toString('base64'))?.has(`${w.slug}/dev`));
  // Made for another place since: the map still picks the place reading, the statement the stable one (`moved`), then serves it.
  const other = await w.environment('other');
  await w.grantAt(other, 'developer');
  await run(db.owner, sql`UPDATE credentials SET places = ${JSON.stringify([{ environmentId: other }])} WHERE id = ${w.credentialId}`);
  const moved = answered(await vault.useRoute(both()));
  assert.equal(moved.reading, 'stable', 'route `<project>` at the handle\'s one place now');
  assert.deepEqual(moved.found, { found: false, fault: null, seals: [''] });
});

test('the place itself (C2b4): `/use/<project>/dev` read both ways, the place for a handle made for dev, answered with nothing of a route read or used; the stable reading otherwise, in the same call', async () => {
  const w = await routeWorld(db);
  const key = await w.key('sk');
  const name = await w.nameOf(key);
  const ada = await w.member([{ environmentId: null, role: 'owner' }]);
  // A route named as the project is: what the stable reading of `/use/<project>/dev` would send.
  await w.save({ [w.slug]: { definition: route(w.slug, [name]), editor: ada } });
  await run(db.owner, sql`UPDATE credentials SET places = ${JSON.stringify([{ environmentId: w.dev }])} WHERE id = ${w.credentialId}`);
  const { vault } = await isolate();
  const itself = () => w.askRoute('x', { named: { place: { project: w.slug, environment: 'dev' }, route: null }, stable: w.slug });
  // Cold, then warm (the map holding the handle's made-for list): the place each time, one statement, nothing written.
  for (const round of ['cold', 'warm']) {
    const place = answered(await vault.useRoute(itself()));
    assert.equal(place.reading, 'named', round);
    assert.deepEqual([place.stands, place.found, place.keys, place.outcome], [true, null, [], { ok: true, values: [] }], round);
    assert.deepEqual(place.place, { project: w.slug, environment: 'dev' }, round);
  }
  assert.equal(await count('log_uses'), 0, 'nothing used');
  // Made for another environment since: the same URL is route `<project>` at that one, its values in the same call.
  const other = await w.environment('other');
  await w.grantAt(other, 'developer');
  await run(db.owner, sql`UPDATE credentials SET places = ${JSON.stringify([{ environmentId: other }])} WHERE id = ${w.credentialId}`);
  await w.save({ [w.slug]: { definition: route(w.slug, [name]), editor: ada } }, other);
  const stable = answered(await vault.useRoute(itself()));
  assert.equal(stable.reading, 'stable');
  assert.ok(stable.found?.found, JSON.stringify(stable.found));
  // A place reading of no route and no stable one decides nothing: the app's bug.
  await assert.rejects(vault.useRoute(w.askRoute('x', { named: { place: { project: w.slug, environment: 'dev' }, route: null }, stable: null })), /names its route/);
});

test("the place itself after a warm stable reading: the map's guess (stable, its keys' ids, the gate light) meets rows that pick the place, and the whole gate answers it, nothing used (C2b4; Fable's review of #486)", async () => {
  const w = await routeWorld(db);
  const ada = await w.member([{ environmentId: null, role: 'owner' }]);
  // Made for `other`, where route `<project>` and its key are saved: `/use/<project>/dev` is that route at `/dev`.
  const other = await w.environment('other');
  await w.grantAt(other, 'developer');
  const key = await w.key('sk', false, other);
  const name = await w.nameOf(key);
  await w.save({ [w.slug]: { definition: route(w.slug, [name]), editor: ada } }, other);
  await run(db.owner, sql`UPDATE credentials SET places = ${JSON.stringify([{ environmentId: other }])} WHERE id = ${w.credentialId}`);
  const { vault } = await isolate();
  const itself = () => w.askRoute('x', { named: { place: { project: w.slug, environment: 'dev' }, route: null }, stable: w.slug });
  // Cold, then warm: the stable reading's values, the second asked with the map's ids, light.
  for (const round of ['cold', 'warm']) {
    const stable = answered(await vault.useRoute(itself()));
    assert.equal(stable.reading, 'stable', round);
    assert.deepEqual(values(stable), { [name]: 'sk' }, round);
  }
  const used = await count('log_uses');
  // Made for dev since: the map still guesses the stable reading, light; the statement picks the place, whose answer
  // is the reading and the whole gate, no key's use made.
  await run(db.owner, sql`UPDATE credentials SET places = ${JSON.stringify([{ environmentId: w.dev }])} WHERE id = ${w.credentialId}`);
  const place = answered(await vault.useRoute(itself()));
  assert.equal(place.reading, 'named');
  assert.deepEqual([place.stands, place.found, place.keys, place.outcome], [true, null, [], { ok: true, values: [] }]);
  assert.deepEqual(place.place, { project: w.slug, environment: 'dev' });
  assert.equal(await count('log_uses'), used, 'nothing used');
});

test("the place itself reads no definition, in either engine's statement: the reading and the gate are its answer, no level of the chain read, nothing used (C2b4; Sol's review r1 of #486)", async () => {
  const w = await routeWorld(db);
  const key = await w.key('sk');
  const ada = await w.member([{ environmentId: null, role: 'owner' }]);
  await w.save({ [w.slug]: { definition: route(w.slug, [await w.nameOf(key)]), editor: ada } });
  await run(db.owner, sql`UPDATE credentials SET places = ${JSON.stringify([{ environmentId: w.dev }])} WHERE id = ${w.credentialId}`);
  const at = Date.now();
  // As the vault asks it on a miss: the handle's names, the place reading's route, the stable one, no ids.
  const ask = (named: string): RouteCall => ({
    tokenHash: w.tokenHash, accepts: { signin: true, issuers: [] }, project: w.slug, environment: 'dev', named, stable: w.slug, reading: null,
    credential: null, way: 0, principal: null, place: null, at, purpose: purposeCode({ purpose: 'use', keepsSensitive: false, way: 'credential' }), deadline: at + 3000,
    mac: Buffer.alloc(16), keys: null, offset: 0, limit: 100, lock: null, use: true, light: false,
  });
  const statement = ENGINE === 'postgres' ? postgresRoute : sqliteRoute;
  const itself = await statement(hot, ask(''));
  assert.deepEqual([itself.reading, itself.stood, itself.place], [1, true, w.dev]);
  assert.deepEqual([itself.levels, itself.editor, itself.keys, itself.made, itself.rows], [[], null, [], false, []], 'no definition read: the route block left at once');
  assert.deepEqual(itself.madeFor, [`${w.slug}/dev`], "the handle's places, for the map's next pick");
  // A route at the same place reads its levels: what the place itself skips.
  const routed = await statement(hot, ask(w.slug));
  assert.equal(routed.reading, 1);
  assert.equal(routed.levels.length, 1);
  assert.equal(await count('log_uses'), 0);
});

test("T205, KeyByItem: an Owner points a route of one key at another key after the map kept the first's id: the use is of the key the item names now, never the map's (formal/Routing.tla, RoutingKeys)", async () => {
  const w = await routeWorld(db);
  const first = await w.key('sk-first');
  const second = await w.key('sk-second');
  const [a, b] = [await w.nameOf(first), await w.nameOf(second)];
  const ada = await w.member([{ environmentId: null, role: 'owner' }]);
  await w.save({ openai: { definition: route('openai', [a]), editor: ada } });
  const { vault, cache } = await isolate();
  for (let i = 0; i < 2; i += 1) assert.deepEqual(values(await vault.useRoute(w.askRoute('openai'))), { [a]: 'sk-first' });
  assert.deepEqual(cache.routeKeys.get(`${w.dev}\nopenai`)?.ids, [{ id: first, through: false }], "the map holds the first key's id");
  const usesOf = async (id: string) => (await rows(db.owner, sql`SELECT 1 FROM log_uses WHERE secret = ${id}`)).length;
  const firstUses = await usesOf(first);
  await w.save({ openai: { definition: route('openai', [b]), editor: ada } });
  assert.deepEqual(values(await vault.useRoute(w.askRoute('openai'))), { [b]: 'sk-second' });
  assert.equal(await usesOf(first), firstUses, 'no use of the key the route no longer names');
  assert.ok(await usesOf(second) >= 1);
  assert.deepEqual(cache.routeKeys.get(`${w.dev}\nopenai`)?.ids, [{ id: second, through: false }], "the map holds the second's now");
});

test("T205: the route's named call at a reading of the URL the map picked wrong reads nothing of the route and writes nothing (`reread`): the place reading only for a handle made for the place, where the URL has a stable reading too; the stable one only where the handle's place is not the one the URL names", async () => {
  const w = await routeWorld(db);
  const key = await w.key('sk');
  const ada = await w.member([{ environmentId: null, role: 'owner' }]);
  await w.save({ openai: { definition: route('openai', [await w.nameOf(key)]), editor: ada } });
  await run(db.owner, sql`UPDATE credentials SET places = ${JSON.stringify([{ environmentId: w.dev }])} WHERE id = ${w.credentialId}`);
  await w.environment('other');
  const at = Date.now();
  // As the vault asks it, but by ids that are not the key's (none), so that a call that reads the route makes no use.
  const call = (names: Partial<Names>): UseCall => ({
    credential: w.credentialId, secretId: null, requestId: '1', at, purpose: purposeCode({ purpose: 'use', keepsSensitive: false, way: 'credential' }), place: null,
    mac: Buffer.alloc(16), deadline: at + 3000, way: 0, principal: null, route: 'openai',
    names: { tokenHash: w.tokenHash, project: null, environment: null, key: null, handle: false, unless: [], accepts: { signin: true, issuers: [] }, forks: true, ...names },
  });
  const named = ENGINE === 'postgres' ? postgresNamed : sqliteNamed;
  const state = async (names: Partial<Names>) => {
    const { row, route: read } = await named(hot, call(names));
    return { state: row.state, read: read === null ? null : { keyed: read.keyed, made: read.made, place: read.place } };
  };
  // `/use/<project>/other/openai/…`, the URL's stable reading `<project>` too: the handle was not made for other.
  assert.deepEqual(await state({ project: w.slug, environment: 'other', unless: [w.slug] }), { state: 'reread', read: null });
  // `/use/<project>/dev/openai/…`: made for dev, the route read, its key resolved; the ids not the key's, nothing made.
  assert.deepEqual(await state({ project: w.slug, environment: 'dev', unless: [w.slug] }), { state: 'moved', read: { keyed: true, made: false, place: w.dev } });
  // No stable reading: the place reading is the URL's only one, made for or not (Bo stands nowhere at other: no route read).
  assert.deepEqual(await state({ project: w.slug, environment: 'other', unless: [] }), { state: 'moved', read: null });
  // The stable reading, `/use/openai/…`, at the handle's one place: read, unless that is the place the URL names.
  assert.deepEqual(await state({ handle: true, unless: [`${w.slug}/dev`] }), { state: 'reread', read: null });
  assert.deepEqual(await state({ handle: true, unless: [`${w.slug}/other`] }), { state: 'moved', read: { keyed: true, made: false, place: w.dev } });
  assert.equal(await count('log_uses'), 0);
});

test('a workload by its way in at its place: the same route use, its caller decided by ids', async () => {
  const w = await routeWorld(db);
  const key = await w.key('sk');
  const name = await w.nameOf(key);
  const ada = await w.member([{ environmentId: null, role: 'owner' }]);
  await w.save({ openai: { definition: route('openai', [name]), editor: ada } });
  const { vault } = await isolate();
  const at = Date.now();
  const input: RouteUseInput = { caller: { kind: 'workload', credential: w.credentialId, place: w.dev }, named: null, stable: 'openai', digests: [], purpose: 'use', at, deadline: at + 3000 };
  assert.deepEqual(values(await vault.useRoute(input)), { [name]: 'sk' });
  assert.deepEqual(values(await vault.useRoute({ ...input, at: Date.now(), deadline: Date.now() + 3000 })), { [name]: 'sk' });
});

test('proxyItem: the item a use would find, or every item the place serves, deciding no use and writing nothing; its keys mapped for the use after', async () => {
  const w = await routeWorld(db);
  const key = await w.key('sk');
  const name = await w.nameOf(key);
  const ada = await w.member([{ environmentId: null, role: 'owner' }]);
  await w.save({ openai: { definition: route('openai', [name]), editor: ada }, maps: { definition: route('maps', [name], 'maps.example'), editor: ada } });
  const eu = await w.fork('dev-eu');
  await w.grantAt(eu, 'developer');
  await w.save({ maps: { definition: route('maps', [name], 'eu.maps.example'), editor: ada } }, eu);
  const { vault, cache } = await isolate();
  const at = Date.now();
  const caller = { kind: 'handle' as const, tokenHash: w.tokenHash.toString('base64'), accepts: { signin: true, issuers: [] } };
  const one = await vault.proxyItem({ caller, place: { project: w.slug, environment: 'dev-eu' }, name: 'openai', at, deadline: at + 3000 });
  assert.ok(one.ok && 'item' in one && one.item !== null, JSON.stringify(one));
  assert.equal(one.item.level, 1);
  assert.equal(one.item.digest, itemDigest((await w.stored(w.dev))!.items.openai!).toString('base64'));
  assert.deepEqual(cache.routeKeys.get(`${eu}\nopenai`)?.ids, [{ id: key, through: true }]);
  const every = await vault.proxyItem({ caller, place: { project: w.slug, environment: 'dev-eu' }, name: null, at, deadline: at + 3000 }) as Extract<ProxyItemOutcome, { ok: true }>;
  assert.ok(every.ok);
  assert.deepEqual(every.items?.map((item) => [item.name, item.level, (item.definition as Extract<ProxyDefinition, { kind: 'route' }>).upstream]), [
    ['maps', 0, 'https://eu.maps.example/v1'], ['openai', 1, 'https://api.openai.com/v1'],
  ]);
  assert.equal(await count('log_uses'), 0);
  // One forged item among them: the whole answer fails (the plan answers 503).
  if (ENGINE === 'postgres') await run(db.owner, sql`UPDATE proxy_definitions SET items = jsonb_set(items, '{maps,savedAt}', '1') WHERE environment_id = ${eu}`);
  else await run(db.owner, sql`UPDATE proxy_definitions SET items = json_set(items, '$.maps.savedAt', 1) WHERE environment_id = ${eu}`);
  const forged = await vault.proxyItem({ caller, place: { project: w.slug, environment: 'dev-eu' }, name: null, at, deadline: at + 3000 });
  assert.ok(forged.ok && 'fault' in forged);
  assert.equal(forged.fault, 'tampered');
  // A caller who stands nowhere there: refused, nothing answered.
  await w.revoke();
  const refusedItem = await vault.proxyItem({ caller, place: { project: w.slug, environment: 'dev' }, name: 'openai', at, deadline: at + 3000 });
  assert.equal(refusedItem.ok, false);
});

test("OneVersion: an edit landing between a use's first round and its second (a key entering the cap's set) answers the whole use again, on the new version", async () => {
  const w = await routeWorld(db);
  const a = await w.key('a');
  const b = await w.key('b');
  const [nameA, nameB] = [await w.nameOf(a), await w.nameOf(b)];
  const ada = await w.member([{ environmentId: null, role: 'owner' }]);
  await w.save({ s3: { definition: route('s3', [nameA, nameB], 'good.example'), editor: ada } });
  // An isolate whose hot pool runs an edit after its first route statement: the cap's set is empty, so every key takes a second round.
  let edits = 0;
  const client = postgresClient(HOT_URL, { max: 2 });
  let statements = 0;
  const pool = ENGINE !== 'postgres' ? null : new Proxy(client, {
    get(target, key) {
      const value: unknown = Reflect.get(target, key, target);
      if (key !== 'unsafe') return value;
      return (...args: unknown[]) => {
        const sent = (value as (...a: unknown[]) => Promise<unknown>).apply(target, args);
        statements += 1;
        if (String(args[0]).includes('use_route') && edits === 0 && statements > 1) {
          edits += 1;
          return Promise.resolve(sent).then(async (result) => {
            await w.save({ s3: { definition: route('s3', [nameA, nameB], 'evil.example'), editor: ada } });
            return result;
          });
        }
        return sent;
      };
    },
  });
  try {
    const prepared = await prepareVault(CONFIG, LOG_015);
    const hot: Database = pool === null ? db.vault : createDatabase(pool);
    const vault = openVault(db.vault, prepared, hot);
    const outcome = answered(await vault.useRoute(w.askRoute('s3')));
    assert.ok(outcome.outcome.ok, JSON.stringify(outcome.outcome));
    assert.ok(outcome.found?.found);
    if (ENGINE === 'postgres') {
      assert.equal(edits, 1, 'the edit landed between rounds');
      assert.equal((outcome.found.item.definition as Extract<ProxyDefinition, { kind: 'route' }>).upstream, 'https://evil.example/v1', 'decided on the version after the edit, every key');
    }
  } finally {
    await client.end();
  }
});

test('a route of more keys than a statement takes: in statements of that many, each read as the first', async () => {
  const w = await routeWorld(db);
  const made = [await w.key('one'), await w.key('two'), await w.key('three')];
  const names = await Promise.all(made.map((id) => w.nameOf(id)));
  const ada = await w.member([{ environmentId: null, role: 'owner' }]);
  await w.save({ many: { definition: route('many', names), editor: ada } });
  const { vault } = await isolate({ uses: { batch: 2 } });
  const expected = Object.fromEntries(names.map((one, i) => [one, ['one', 'two', 'three'][i]!]));
  assert.deepEqual(values(await vault.useRoute(w.askRoute('many'))), expected);
  assert.deepEqual(values(await vault.useRoute(w.askRoute('many'))), expected);
});

test("a route lengthened past a statement's keys while the map holds the shorter list: a miss, then served (Fable's review of #464)", async () => {
  const w = await routeWorld(db);
  const made = [await w.key('one'), await w.key('two'), await w.key('three')];
  const named = await Promise.all(made.map(async (id, i) => ({ name: await w.nameOf(id), value: ['one', 'two', 'three'][i]! })));
  // The key added sorts last, so the first statement's ids are still the names': only the rest are past the map's list.
  named.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  const ada = await w.member([{ environmentId: null, role: 'owner' }]);
  await w.save({ many: { definition: route('many', named.slice(0, 2).map((one) => one.name)), editor: ada } });
  const { vault } = await isolate({ uses: { batch: 2 } });
  assert.deepEqual(values(await vault.useRoute(w.askRoute('many'))), Object.fromEntries(named.slice(0, 2).map((one) => [one.name, one.value])));
  await w.save({ many: { definition: route('many', named.map((one) => one.name)), editor: ada } });
  assert.deepEqual(values(await vault.useRoute(w.askRoute('many'))), Object.fromEntries(named.map((one) => [one.name, one.value])));
});

test("T205: a route of one key given a second while the map holds the one: the route's named call makes no use of the first alone, and the whole route is made, one entry a key", async () => {
  const w = await routeWorld(db);
  const [one, two] = [await w.key('one'), await w.key('two')];
  const [first, second] = [await w.nameOf(one), await w.nameOf(two)];
  const ada = await w.member([{ environmentId: null, role: 'owner' }]);
  await w.save({ pair: { definition: route('pair', [first]), editor: ada } });
  const { vault } = await isolate();
  for (let i = 0; i < 2; i += 1) assert.deepEqual(values(await vault.useRoute(w.askRoute('pair'))), { [first]: 'one' });
  await w.save({ pair: { definition: route('pair', [first, second]), editor: ada } });
  const before = await count('log_uses');
  assert.deepEqual(values(await vault.useRoute(w.askRoute('pair'))), { [first]: 'one', [second]: 'two' });
  assert.equal(await count('log_uses') - before, 2, 'an entry for each key of the route, none of the first alone');
  // The call itself, decided (its lock taken, as a second round's), by the first key's ids, which are right: an item of
  // two keys resolves none, so it uses nothing, and its row is the caller's at the place.
  const at = Date.now();
  const call: UseCall = {
    credential: w.credentialId, secretId: one, requestId: '1', at, purpose: purposeCode({ purpose: 'use', keepsSensitive: false, way: 'credential' }), place: null,
    mac: Buffer.alloc(16), deadline: at + 3000, way: 0, principal: null, route: 'pair', decided: true,
    names: { tokenHash: w.tokenHash, project: w.slug, environment: 'dev', key: null, handle: false, unless: [], accepts: { signin: true, issuers: [] }, forks: true },
  };
  const after = await count('log_uses');
  const { row, route: read } = await (ENGINE === 'postgres' ? postgresNamed : sqliteNamed)(hot, call);
  assert.deepEqual([row.state, row.n_secret, read?.keyed, read?.made, read?.keys], ['moved', null, false, false, [first, second]]);
  assert.equal(await count('log_uses'), after, 'nothing used');
});

test("a later statement's fresh ids reach the map: an edit between a use's statements costs it one attempt, not two (Fable's review of #464)", { skip: ENGINE !== 'postgres' ? 'an edit injected between the hot pool\'s statements' : false }, async () => {
  const w = await routeWorld(db);
  const made = [await w.key('one'), await w.key('two'), await w.key('three'), await w.key('four')];
  const names = await Promise.all(made.map((id) => w.nameOf(id)));
  const ada = await w.member([{ environmentId: null, role: 'owner' }]);
  await w.save({ many: { definition: route('many', names.slice(0, 3)), editor: ada } });
  // An isolate whose hot pool adds a key to the route right after the use's first statement, its map warm on three.
  let armed = false;
  let routed = 0;
  const client = postgresClient(HOT_URL, { max: 2 });
  const pool = new Proxy(client, {
    get(target, key) {
      const value: unknown = Reflect.get(target, key, target);
      if (key !== 'unsafe') return value;
      return (...args: unknown[]) => {
        const sent = (value as (...a: unknown[]) => Promise<unknown>).apply(target, args);
        if (!String(args[0]).includes('use_route')) return sent;
        // A first round's statement: no principal's lock (a key new to the cap's set takes one more, under it). `p_lock`
        // is the third parameter from the end, before `p_use` and `p_light` (0060).
        const params = args[1] as unknown[];
        if (params[params.length - 3] === null) routed += 1;
        if (!armed) return sent;
        armed = false;
        return Promise.resolve(sent).then(async (result) => {
          await w.save({ many: { definition: route('many', names), editor: ada } });
          return result;
        });
      };
    },
  });
  try {
    const prepared = await prepareVault(CONFIG, { ...LOG_015, uses: { batch: 2 } });
    const vault = openVault(db.vault, prepared, createDatabase(pool));
    const expected = (n: number) => Object.fromEntries(names.slice(0, n).map((one, i) => [one, ['one', 'two', 'three', 'four'][i]!]));
    assert.deepEqual(values(await vault.useRoute(w.askRoute('many'))), expected(3));
    armed = true;
    routed = 0;
    assert.deepEqual(values(await vault.useRoute(w.askRoute('many'))), expected(4));
    // Attempt 1: its first statement, then the second answers the four keys' ids; attempt 2, by those: two statements.
    assert.equal(routed, 4, 'the retry is made by the ids the second statement read, not the map\'s three');
  } finally {
    await client.end();
  }
});

test("the editor's principal row is the vault's: a grant planted around the log is `tampered`, a row put back from before a change `stale` (Fable's review of #464)", async () => {
  const w = await routeWorld(db);
  const key = await w.key('sk');
  const name = await w.nameOf(key);
  const lin = await w.member([{ environmentId: w.dev, role: 'developer' }]);
  await w.save({ openai: { definition: route('openai', [name]), editor: lin } });
  const { vault } = await isolate();
  assert.deepEqual(values(await vault.useRoute(w.askRoute('openai'))), { [name]: 'sk' });
  const sealOf = async () => (await rows<{ seal: Buffer }>(db.owner, sql`SELECT seal FROM vault_members WHERE principal = ${lin.principal}`))[0]!.seal;
  const grants = async (role: string) => {
    await run(db.owner, sql`DELETE FROM vault_grants WHERE principal = ${lin.principal}`);
    await run(db.owner, sql`INSERT INTO vault_grants (principal, project_id, environment_id, environment_slug, role, granted_at, granted_by)
      VALUES (${lin.principal}, NULL, ${w.dev}, NULL, ${role}, ${Date.now()}, 'root')`);
  };
  const before = await sealOf();
  // A grant widened in the rows, the log not told: the row is not what its seal covers.
  await grants('owner');
  assert.deepEqual(refused(await vault.useRoute(w.askRoute('openai'))), { code: 'tampered', key: null });
  // Demoted through the log, then her rows put back as they were, seal and all: the vault's seal, not her newest change's.
  await grants('developer');
  await w.restand(lin, []);
  await grants('developer');
  await run(db.owner, sql`UPDATE vault_members SET seal = ${before} WHERE principal = ${lin.principal}`);
  assert.deepEqual(refused(await vault.useRoute(w.askRoute('openai'))), { code: 'stale', key: null });
});


test("the chain is the vault's: a fork's parent re-pointed around the log at another environment never serves that one's route (review r1 of #464)", async () => {
  const w = await routeWorld(db);
  const key = await w.key('sk');
  const name = await w.nameOf(key);
  const ada = await w.member([{ environmentId: null, role: 'owner' }]);
  // dev-eu-x → dev-eu → dev; and `other`, an environment of the project, whose own `openai` sends to evil.example.
  const eu = await w.fork('dev-eu');
  const x = await w.fork('dev-eu-x', eu);
  await w.grantAt(x, 'developer');
  const other = await w.environment('other');
  await w.save({ openai: { definition: route('openai', [name], 'evil.example'), editor: ada } }, other);
  const { vault } = await isolate();
  const atFork = w.askRoute('openai', { named: { place: { project: w.slug, environment: 'dev-eu-x' }, route: 'openai' } });
  assert.deepEqual(answered(await vault.useRoute(atFork)).found, { found: false, fault: null, seals: ['', '', ''] }, 'no level of the chain defines it');
  // dev-eu's parent, the middle of the chain, re-pointed at `other` around the log: its sealed object still names dev.
  await run(db.owner, sql`UPDATE environments SET parent_id = ${other} WHERE id = ${eu}`);
  const grafted = answered(await vault.useRoute({ ...atFork, at: Date.now(), deadline: Date.now() + 3000 }));
  assert.ok(grafted.found !== null && !grafted.found.found, JSON.stringify(grafted.found));
  assert.equal(grafted.found.fault, 'tampered');
  assert.ok(!grafted.outcome.ok);
});

test("the chain is the vault's above the level that serves too: a fork's own route never sends a key a re-pointed ancestor grafts on (review r2 of #464)", async () => {
  const w = await routeWorld(db);
  const key = await w.key('real');
  const name = await w.nameOf(key);
  const ada = await w.member([{ environmentId: null, role: 'owner' }]);
  // dev-eu-x → dev-eu → dev; dev-eu-x defines `openai` itself, sending the key it inherits from dev.
  const eu = await w.fork('dev-eu');
  const x = await w.fork('dev-eu-x', eu);
  await w.grantAt(x, 'developer');
  await w.save({ openai: { definition: route('openai', [name], 'good.example'), editor: ada } }, x);
  // `other`, an environment of the project where the caller is a Developer too, holds a key of the same name: only the
  // chain stands between it and dev-eu-x's upstream.
  const other = await w.environment('other');
  await w.grantAt(other, 'developer');
  const stolen = await w.key('stolen', false, other);
  await run(db.owner, sql`UPDATE secrets SET key = ${name} WHERE id = ${stolen}`);
  const { vault } = await isolate();
  const atFork = () => w.askRoute('openai', { named: { place: { project: w.slug, environment: 'dev-eu-x' }, route: 'openai' } });
  assert.deepEqual(values(await vault.useRoute(atFork())), { [name]: 'real' });
  // dev-eu's parent re-pointed at `other` around the log: dev-eu-x's own item still serves, and the key would resolve
  // through the forged link to `other`'s.
  await run(db.owner, sql`UPDATE environments SET parent_id = ${other} WHERE id = ${eu}`);
  const grafted = answered(await vault.useRoute(atFork()));
  assert.deepEqual(grafted.outcome, { ok: false, index: null, code: 'tampered', number: null });
  assert.deepEqual(grafted.keys, []);
});

test("the reading is picked again under the fence: a rename landing between the pick and the gate serves the reading the rows pick then (review r2 of #464)", { skip: ENGINE !== 'postgres' ? 'a rename held between the statement\'s first reads and its fence' : false }, async () => {
  const w = await routeWorld(db);
  const key = await w.key('sk');
  const name = await w.nameOf(key);
  const ada = await w.member([{ environmentId: null, role: 'owner' }]);
  // `/use/<project>/dev/openai`: the place reading's route `openai` at dev, or the stable reading's route `<project>`.
  await w.save({
    openai: { definition: route('openai', [name], 'named.example'), editor: ada },
    [w.slug]: { definition: route(w.slug, [name], 'stable.example'), editor: ada },
  });
  await run(db.owner, sql`UPDATE credentials SET places = ${JSON.stringify([{ environmentId: w.dev }])} WHERE id = ${w.credentialId}`);
  const { vault } = await isolate();
  const both = () => w.askRoute('openai', { stable: w.slug });
  const placed = answered(await vault.useRoute(both()));
  assert.equal(placed.reading, 'named');
  // dev renamed while the use waits on the fence the rename holds, the place reading picked before it: no `<project>/dev` then.
  let raced!: Promise<RouteUseOutcome>;
  await w.rename(w.dev, 'stage', async (tx) => {
    raced = vault.useRoute(both());
    for (let i = 0; ; i++) {
      const [waiting] = await rows<{ n: number }>(tx, sql`SELECT count(*)::int AS n FROM pg_locks WHERE locktype = 'advisory' AND classid = 1668244070 AND NOT granted`);
      if (waiting!.n > 0) break;
      assert.ok(i < 200, 'the use never waited on the fence');
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
  });
  const answer = answered(await raced);
  assert.equal(answer.reading, 'stable', JSON.stringify(answer.outcome));
  assert.ok(answer.found !== null && answer.found.found, JSON.stringify(answer.found));
  assert.equal(answer.found.item.name, w.slug);
  assert.deepEqual(values(answer), { [name]: 'sk' });
});

test("OneVersion holds the roles too: a role edit landing between a use's rounds decides the editor again on the roles after it (review r1 of #464)", { skip: ENGINE !== 'postgres' ? 'an edit injected between the hot pool\'s statements' : false }, async () => {
  const w = await routeWorld(db);
  const a = await w.key('a');
  const nameA = await w.nameOf(a);
  // Lin, a Developer on dev: what her save froze reads A; Developers read nothing once the role is edited, but use.
  const lin = await w.member([{ environmentId: w.dev, role: 'developer' }]);
  await w.save({ s3: { definition: route('s3', [nameA], 'good.example'), editor: lin } });
  const [config] = await rows<{ value: string }>(db.owner, sql`SELECT value FROM log_config WHERE name = 'roles'`);
  const roles = JSON.parse(config!.value) as Input;
  const developer = ROLES.developer!;
  const op: Op = { op: 'role.define', table: 'roles', role: 'developer', definition: { ...developer, permissions: developer.permissions.filter((permission) => permission !== 'secret.read') } };
  const edited = applyOp(roles, ROLES_REF, op)!;
  let edits = 0;
  const client = postgresClient(HOT_URL, { max: 2 });
  let statements = 0;
  const pool = new Proxy(client, {
    get(target, key) {
      const value: unknown = Reflect.get(target, key, target);
      if (key !== 'unsafe') return value;
      return (...args: unknown[]) => {
        const sent = (value as (...a: unknown[]) => Promise<unknown>).apply(target, args);
        statements += 1;
        // After the use's first round, the route's named call (T205, a key entering the cap's set: `decide`), before its second.
        if ((String(args[0]).includes('use_route') || String(args[0]).includes('use_credential')) && edits === 0 && statements > 1) {
          edits += 1;
          return Promise.resolve(sent).then(async (result) => {
            const ref: Ref = ROLES_REF;
            await change(ref, { ...op, ref } as unknown as Op, edited, async (tx, value2) => {
              await run(tx, sql`UPDATE log_config SET value = ${JSON.stringify(edited)}, seal = ${value2} WHERE name = 'roles'`);
            });
            return result;
          });
        }
        return sent;
      };
    },
  });
  try {
    const prepared = await prepareVault(CONFIG, LOG_015);
    const vault = openVault(db.vault, prepared, createDatabase(pool));
    const outcome = await vault.useRoute(w.askRoute('s3'));
    assert.equal(edits, 1, 'the edit landed between rounds');
    assert.deepEqual(refused(outcome), { code: 'route_not_cleared', key: nameA });
  } finally {
    await client.end();
  }
});

// --- T190: each newest change the route reads, its seal forged --------------------------------------------------------
// The attack T190 closes on every input of a use (use-forged.test.ts), on the three a route use reads beside its caller's:
// a writer with no key puts a row back as the vault once sealed it, then writes that old seal into its object's newest
// change, whose MAC then no longer holds. The rows alone are the vault's; only the MAC says the change is not.

/** The newest change of `ref`'s object made to record `seal`: what the writer writes, its MAC left as it was. */
const forgeNewest = (ref: Ref, seal: Buffer) =>
  run(db.owner, sql`UPDATE log_changes SET seal = ${seal} WHERE number = (SELECT max(number) FROM log_changes WHERE object = ${objectKey(ref)})`);

test("T190: a level's definitions put back from before an edit, the edit's entry made to record their seal: `stale`, never served (ChangeMacChecked)", async () => {
  const w = await routeWorld(db);
  const key = await w.key('sk');
  const name = await w.nameOf(key);
  const ada = await w.member([{ environmentId: null, role: 'owner' }]);
  await w.save({ openai: { definition: route('openai', [name], 'evil.example'), editor: ada } });
  const old = (await w.stored(w.dev))!;
  await w.save({ openai: { definition: route('openai', [name], 'good.example'), editor: ada } });
  const { vault } = await isolate();
  assert.deepEqual(values(await vault.useRoute(w.askRoute('openai'))), { [name]: 'sk' });
  const json = JSON.stringify(old.items);
  if (ENGINE === 'postgres') await run(db.owner, sql`UPDATE proxy_definitions SET items = ${json}::jsonb, digests = ${old.digests}, seal = ${old.seal} WHERE environment_id = ${w.dev}`);
  else await run(db.owner, sql`UPDATE proxy_definitions SET items = ${json}, digests = ${old.digests}, seal = ${old.seal} WHERE environment_id = ${w.dev}`);
  await forgeNewest({ kind: 'proxy', id: w.dev }, old.seal);
  for (const one of [vault, (await isolate()).vault]) {
    assert.deepEqual(refused(await one.useRoute(w.askRoute('openai'))), { code: 'stale', key: null });
    const at = Date.now();
    const caller = { kind: 'handle' as const, tokenHash: w.tokenHash.toString('base64'), accepts: { signin: true, issuers: [] } };
    const item = await one.proxyItem({ caller, place: { project: w.slug, environment: 'dev' }, name: 'openai', at, deadline: at + 3000 });
    assert.ok(item.ok && 'fault' in item && item.fault === 'stale' && item.item === null, JSON.stringify(item));
  }
});

test("T190: an editor demoted, their rows put back and the demotion's entry made to record the old seal: `stale`, never their old clearance (ChangeMacChecked)", async () => {
  const w = await routeWorld(db);
  const key = await w.key('sk');
  const name = await w.nameOf(key);
  const lin = await w.member([{ environmentId: w.dev, role: 'developer' }]);
  await w.save({ openai: { definition: route('openai', [name]), editor: lin } });
  const { vault } = await isolate();
  assert.deepEqual(values(await vault.useRoute(w.askRoute('openai'))), { [name]: 'sk' });
  const [before] = await rows<{ seal: Buffer }>(db.owner, sql`SELECT seal FROM vault_members WHERE principal = ${lin.principal}`);
  await w.restand(lin, []);
  assert.equal(refused(await vault.useRoute(w.askRoute('openai'))).code, 'route_not_cleared');
  // Her grant and her seal put back as they were, and her newest change made to record that seal.
  await run(db.owner, sql`INSERT INTO vault_grants (principal, project_id, environment_id, environment_slug, role, granted_at, granted_by)
    VALUES (${lin.principal}, NULL, ${w.dev}, NULL, 'developer', ${Date.now()}, 'root')`);
  await run(db.owner, sql`UPDATE vault_members SET seal = ${before!.seal} WHERE principal = ${lin.principal}`);
  await forgeNewest({ kind: 'principal', id: lin.principal }, Buffer.from(before!.seal));
  for (const one of [vault, (await isolate()).vault]) assert.deepEqual(refused(await one.useRoute(w.askRoute('openai'))), { code: 'stale', key: null });
});

test("T190: a level's environment archived, its row put back and the archive's entry made to record the old seal: `stale`, never served (ChangeMacChecked; the chain's check alone, since neither the gate nor the key, in dev, reads dev-eu)", async () => {
  const w = await routeWorld(db);
  const key = await w.key('sk');
  const name = await w.nameOf(key);
  const ada = await w.member([{ environmentId: null, role: 'owner' }]);
  const eu = await w.fork('dev-eu');
  const x = await w.fork('dev-eu-x', eu);
  await w.grantAt(x, 'developer');
  await w.save({ openai: { definition: route('openai', [name]), editor: ada } });
  const atFork = () => w.askRoute('openai', { named: { place: { project: w.slug, environment: 'dev-eu-x' }, route: 'openai' } });
  const { vault } = await isolate();
  assert.deepEqual(values(await vault.useRoute(atFork())), { [name]: 'sk' });
  const ref: Ref = { kind: 'environment', id: eu };
  const [row] = await rows<{ seal: Buffer }>(db.owner, sql`SELECT seal FROM environments WHERE id = ${eu}`);
  const archived: Input = { kind: 'environment', id: eu, projectId: w.project, slug: 'dev-eu', owner: null, parentId: w.dev, protected: false, deleted: false, archived: true, projectArchived: false };
  await change(ref, { op: 'environment.archive', archived: true }, archived, async (tx, value) => {
    await run(tx, ENGINE === 'postgres' ? sql`UPDATE environments SET archived_at = now() WHERE id = ${eu}` : sql`UPDATE environments SET archived_at = ${Date.now()} WHERE id = ${eu}`);
    await seal('environments', 'id', eu)(tx, value);
  });
  assert.ok(!answered(await vault.useRoute(atFork())).outcome.ok, 'an archived level serves nothing');
  await run(db.owner, sql`UPDATE environments SET archived_at = NULL, seal = ${row!.seal} WHERE id = ${eu}`);
  await forgeNewest(ref, Buffer.from(row!.seal));
  for (const one of [vault, (await isolate()).vault]) assert.deepEqual(refused(await one.useRoute(atFork())), { code: 'stale', key: null });
});

// --- T200: the light gate --------------------------------------------------------------------------------------------
// A statement made with the map's ids reads its caller's rows once, by its first key's use, under the fence the gate
// took, and the vault decides the caller on that row; the gate only decides, in SQL, that they stand there before the
// route is read (`use_stands`, GateBeforeKeys). Where it makes no use, it asks the whole gate, and answers as without it.

/** An isolate whose hot pool notes each route statement's gate as it answered: `stood`, light (T200), or the whole gate's state. */
async function watched(): Promise<{ vault: ReturnType<typeof openVault>; gates: string[]; end: () => Promise<void> }> {
  const gates: string[] = [];
  const client = postgresClient(HOT_URL, { max: 2 });
  const pool = new Proxy(client, {
    get(target, key) {
      const value: unknown = Reflect.get(target, key, target);
      if (key !== 'unsafe') return value;
      return (...args: unknown[]) => {
        const sent = (value as (...a: unknown[]) => Promise<unknown>).apply(target, args);
        const query = String(args[0]);
        if (!query.includes('use_route') && !query.includes('use_credential')) return sent;
        return Promise.resolve(sent).then((result) => {
          if (query.includes('use_route')) {
            const [row] = result as { route: string }[];
            gates.push((JSON.parse(row!.route) as { gate: { state: string | null } }).gate.state ?? 'null');
          } else {
            // A route's named call (T205, 0071), its key's row's state; any other use by ids or name is no route's.
            const [row] = result as { use: string }[];
            const read = JSON.parse(row!.use) as { row?: { state: string | null } };
            if (read.row !== undefined) gates.push(`one:${read.row.state ?? 'null'}`);
          }
          return result;
        });
      };
    },
  });
  const vault = openVault(db.vault, await prepareVault(CONFIG, LOG_015), createDatabase(pool));
  return { vault, gates, end: () => client.end() };
}

test("T205: a warm route use of one key is the vault's one named call, the use made by the map's ids; one that resolves no key (its item deleted since) answers the caller's use of no key at the place, as the whole gate", { skip: ENGINE !== 'postgres' ? "the hot pool's answers" : false }, async () => {
  const w = await routeWorld(db);
  const key = await w.key('sk');
  const name = await w.nameOf(key);
  const ada = await w.member([{ environmentId: null, role: 'owner' }]);
  await w.save({ openai: { definition: route('openai', [name]), editor: ada } });
  const { vault, gates, end } = await watched();
  try {
    // Cold: the miss reads the ids under the whole gate (`use_route`); then the named call by them, its key entering
    // the cap's set (`decide`), and that round under the lock, `use_route`'s, its gate light.
    assert.deepEqual(values(await vault.useRoute(w.askRoute('openai'))), { [name]: 'sk' });
    assert.deepEqual(gates, ['moved', 'one:decide', 'stood']);
    const cold = gates.length;
    assert.deepEqual(values(await vault.useRoute(w.askRoute('openai'))), { [name]: 'sk' });
    assert.deepEqual(gates.slice(cold), ['one:null'], 'warm: one call, the route\'s named call, its use made');
    // The item deleted since: the call resolves no key, makes no use, and its row is the caller's at the place.
    await w.save({ openai: null });
    const warm = gates.length;
    const gone = answered(await vault.useRoute(w.askRoute('openai')));
    assert.deepEqual(gates.slice(warm), ['one:moved'], 'no use made: one call, the place\'s row');
    assert.equal(gone.stands, true);
    assert.deepEqual(refused(gone), { code: 'missing', key: null });
    // As an isolate whose map is cold answers it, by the whole gate alone.
    const { vault: fresh } = await isolate();
    const cold2 = answered(await fresh.useRoute(w.askRoute('openai')));
    assert.deepEqual([cold2.stands, cold2.standing, cold2.outcome], [gone.stands, gone.standing, gone.outcome]);
  } finally {
    await end();
  }
});

test("T200, T205: under a light gate, or the route's named call, the caller is decided on their key's row: their grant revoked, their rows put back and the revoke's entry made to record the old seal, the credential's route, `stale`, never served, warm or cold (ChangeMacChecked, R64)", async () => {
  const w = await routeWorld(db);
  const key = await w.key('sk');
  const name = await w.nameOf(key);
  const ada = await w.member([{ environmentId: null, role: 'owner' }]);
  await w.save({ openai: { definition: route('openai', [name]), editor: ada } });
  const watch = ENGINE === 'postgres' ? await watched() : null;
  const vault = watch?.vault ?? (await isolate()).vault;
  try {
    for (let i = 0; i < 2; i += 1) assert.deepEqual(values(await vault.useRoute(w.askRoute('openai'))), { [name]: 'sk' });
    const [member] = await rows<{ seal: Buffer }>(db.owner, sql`SELECT seal FROM vault_members WHERE principal = ${w.principal}`);
    const grants = await rows<{ project_id: string | null; environment_id: string | null; environment_slug: string | null; role: string; expires_at: unknown; granted_at: unknown; granted_by: string }>(
      db.owner, sql`SELECT project_id, environment_id, environment_slug, role, expires_at, granted_at, granted_by FROM vault_grants WHERE principal = ${w.principal}`);
    assert.ok(grants.length > 0);
    await w.revoke();
    assert.equal(answered(await vault.useRoute(w.askRoute('openai'))).stands, false, 'revoked: refused on the place');
    // Her grants and her seal put back as they were, and her newest change made to record that seal: the statement's
    // gate finds her standing on the rows, and only the vault, on her key's row, finds the change's MAC not holding.
    for (const g of grants) {
      await run(db.owner, sql`INSERT INTO vault_grants (principal, project_id, environment_id, environment_slug, role, expires_at, granted_at, granted_by)
        VALUES (${w.principal}, ${g.project_id}, ${g.environment_id}, ${g.environment_slug}, ${g.role}, ${g.expires_at}, ${g.granted_at}, ${g.granted_by})`);
    }
    await run(db.owner, sql`UPDATE vault_members SET seal = ${member!.seal} WHERE principal = ${w.principal}`);
    await forgeNewest({ kind: 'principal', id: w.principal }, Buffer.from(member!.seal));
    // Her account's row not as the log says: the credential's own route (`routeOf`), `stale`, as the whole gate answers it.
    const stale = { served: true, route: 'credential', outcome: { ok: false, code: 'stale', number: null } };
    const seen = watch?.gates.length ?? 0;
    assert.deepEqual(await vault.useRoute(w.askRoute('openai')), stale);
    if (watch !== null) assert.equal(watch.gates[seen], 'one:null', 'the warm use went by the route\'s named call (T205), its use made');
    assert.deepEqual(await (await isolate()).vault.useRoute(w.askRoute('openai')), stale);
  } finally {
    await watch?.end();
  }
});

test("T200: a caller who stands nowhere there reads nothing of the route, its gate asked light or not: each refusal weighed beside its twin (a route the world never saved), its key's blocks and its buffers alike whatever the route names (NoKeyBeforeStanding; the named matrix's weighing, slack 6)", { skip: ENGINE !== 'postgres' ? 'the hot path\'s statements, weighed' : false }, async () => {
  const w = await routeWorld(db);
  const held = await w.key('sk');
  const sensitive = await w.key('sens');
  const ada = await w.member([{ environmentId: null, role: 'owner' }]);
  const names = { held: await w.nameOf(held), sensitive: await w.nameOf(sensitive), never: 'NEVER_MADE_BY_THIS_WORLD' };
  await w.save({
    held: { definition: route('held', [names.held]), editor: ada },
    sensitive: { definition: route('sensitive', [names.sensitive]), editor: ada },
    never: { definition: route('never', [names.never]), editor: ada },
  });
  await w.markSensitive(sensitive);
  // Each use_route call as the vault sends it, and each route's named call (T205, `use_credential` naming its route).
  const calls: HotCall[] = [];
  const client = postgresClient(HOT_URL, { max: 2 });
  const pool = new Proxy(client, {
    get(target, key) {
      const value: unknown = Reflect.get(target, key, target);
      if (key !== 'unsafe') return value;
      return (...args: unknown[]) => {
        if (String(args[0]).includes('use_route') || String(args[0]).includes('use_credential')) calls.push({ query: String(args[0]), args: [...(args[1] as unknown[])] });
        return (value as (...a: unknown[]) => unknown).apply(target, args);
      };
    },
  });
  const session = weighingSession(HOT_URL);
  try {
    const warm = openVault(db.vault, await prepareVault(CONFIG, LOG_015), createDatabase(pool));
    // Her map warm on each route while she stood (a refused one too: its ids read), then her grant revoked.
    for (const name of ['held', 'sensitive', 'never'] as const) for (let i = 0; i < 2; i += 1) await warm.useRoute(w.askRoute(name));
    await w.revoke();
    const cold = openVault(db.vault, await prepareVault(CONFIG, LOG_015), createDatabase(pool));
    const asked: { label: string; call: HotCall }[] = [];
    for (const [label, vault] of [['warm', warm], ['cold', cold]] as const) {
      for (const name of ['held', 'sensitive', 'never'] as const) {
        const before = calls.length;
        const answer = answered(await vault.useRoute(w.askRoute(name)));
        assert.equal(answer.stands, false, `${label} ${name}: refused on the place`);
        assert.equal(answer.found, null, `${label} ${name}: nothing of the route read`);
        assert.equal(calls.length - before, 1, `${label} ${name}: one statement`);
        asked.push({ label: `${label} ${name}`, call: calls.at(-1)! });
      }
    }
    // Where the map was warm, the route's named call (T205): `use_credential`, its route its last argument, which read
    // no route for one who stands nowhere; where cold, `use_route`, its gate asked whole.
    assert.ok(asked.slice(0, 3).every(({ call }) => call.query.includes('use_credential') && typeof call.args.at(-1) === 'string'), 'the warm map asked the route\'s named call');
    assert.ok(asked.slice(3).every(({ call }) => call.query.includes('use_route') && call.args.at(-1) === false), 'the cold map asked use_route, its gate whole');
    await run(db.owner, sql.raw(`VACUUM ${WORLD_TABLES.join(', ')}`));
    // The twin: the same call of a route the world never saved (`use_route`'s place reading's route; the named call's route).
    const twinOf = (call: HotCall): HotCall => {
      const args = [...call.args];
      args[call.query.includes('use_route') ? 3 : args.length - 1] = 'nothing-saved';
      return { query: call.query, args };
    };
    const read: { label: string; buffers: number; keyBlocks: number; beyond: number }[] = [];
    for (const { label, call } of asked) {
      const [one, twin] = [await weigh(session, call), await weigh(session, twinOf(call))];
      assert.equal(one.keyBlocks, twin.keyBlocks, `${label}: the key's blocks as its twin's`);
      read.push({ label, buffers: one.buffers, keyBlocks: one.keyBlocks, beyond: one.buffers - twin.buffers });
    }
    const beyond = read.map((one) => one.beyond);
    assert.ok(Math.max(...beyond) - Math.min(...beyond) <= 6, JSON.stringify(read));
    assert.equal(new Set(read.map((one) => one.keyBlocks)).size, 1, JSON.stringify(read));
  } finally {
    await session.end();
    await client.end();
  }
});
