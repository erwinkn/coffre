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

import { applyOp, itemDigest, ROLES_REF, type Input, type Op, type ProxyItem, type Ref } from '../src/inputs.ts';
import { replayStored } from '../src/log-replay.ts';
import { openVault, prepareVault } from '../src/vault.ts';
import { ENGINE, HOT_URL, openTestDatabase, rows, run, type TestDatabase } from './database.ts';
import { route, routeWorld } from './route-world.ts';
import { change, CONFIG, emptyLog, isolate, LOG_015, SIGNING_KEY, useDatabases } from './use-world.ts';

let db: TestDatabase;
before(async () => {
  db = await openTestDatabase();
  await useDatabases(db);
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
        if (String(args[0]).includes('use_route') && edits === 0 && statements > 1) {
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
