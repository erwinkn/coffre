// Proxy definitions written in the UI, as the vault keeps them (0.16, T186; docs/design/proxy-ui.md, sections 2, 6
// and 8): one sealed object per environment, kind `proxy`, its seal over the index of its items' digests; and the
// names code reserved, kind `proxy-reserved`. A save is a change under the fence, CAS on the object's newest change,
// decided on sealed objects alone, by a person holding proxy.edit. A row a writer edits, moves an item in, puts back or
// deletes fails closed (R64); a forged object is replaced whole by an Owner, never carried on. The log replays to the
// rows. And the version gate: a call on another release runs nothing, in this process as over the socket.
// Both engines; the change path is 0.15's log's.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';

import { KekRegistry, LocalKekProvider } from '@coffre/core/kek';
import { RELEASE, versioned, type ProxyDefinition, type ProxyView, type SaveProxyInput } from '@coffre/core/vault';
import { createDatabase, tablesOf } from '@coffre/db';
import { postgresClient } from '@coffre/db/connect';
import { sql } from 'drizzle-orm';

import type { ResolvedVaultConfig } from '../src/config.ts';
import { applyOp, indexBytes, sealKey, sealOf, type ProxyInput, type ProxyItem, type Ref } from '../src/inputs.ts';
import { openLocalVault as openEntry } from '../src/local.ts';
import { replayStored } from '../src/log-replay.ts';
import { proxyLookup, type ProxyLevel } from '../src/proxy.ts';
import { newestChange, readObject } from '../src/store.ts';
import { emptyDatabase, ENGINE, LOG, newEnvironment, newProject, nothingHeld, openLocalVault, openTestDatabase, OWNER_URL, postgresOnly, rows, run, sealed, sealPlaces, VAULT_URL, type LocalVault, type TestDatabase } from './database.ts';

const ROOT = 'user:root@acme.example';
const ADA = 'user:ada@acme.example';
const CI = 'token:ci';
const ON_015 = { skip: LOG === '0.14' ? "proxy definitions are 0.15's log's objects" : false };

let db: TestDatabase;
before(async () => {
  db = await openTestDatabase();
});
after(() => db.close());
beforeEach(() => emptyDatabase(db.owner));

function configure(): ResolvedVaultConfig {
  return { keks: new KekRegistry(LocalKekProvider.generate('test-kek-1')), owners: ['root@acme.example'], signingKeys: [randomBytes(32)], bulkLimit: { count: 1000, windowMs: 15 * 60_000 } };
}

/** A route, `name`, sending `key` to `host`. */
function route(name: string, host = 'api.openai.com', key = 'OPENAI_API_KEY'): ProxyDefinition {
  return {
    kind: 'route', name, upstream: `https://${host}/v1`, inject: [{ kind: 'header', name: 'authorization', template: `Bearer {${key}}` }],
    allow: [{ methods: ['POST'], path: '/chat/completions' }], limit: { perMinute: null, perDay: null }, placeholder: null, egress: null,
  };
}

/** A vault keeping 0.15's log, a project with `dev`, Ada a Developer there. */
async function world() {
  const config = configure();
  const vault = await openLocalVault(db.vault, config, { log: '0.15', sealThrough: sealed, heldOutside: nothingHeld });
  assert.equal((await vault.access(ROOT)).role, 'owner');
  const project = await newProject(db.owner);
  const dev = await newEnvironment(db.owner, project);
  assert.ok((await vault.admit({ actor: ROOT, caller: 'person', principal: ADA })).ok);
  assert.ok((await vault.setAccess({ actor: ROOT, caller: 'person', principal: ADA, changes: [{ projectId: project, environmentId: dev, role: 'developer', expiresAt: null }] })).ok);
  const keys = config.signingKeys.map(sealKey);
  const save = (input: Partial<SaveProxyInput> & Pick<SaveProxyInput, 'items' | 'seal'>, environmentId = dev) =>
    vault.saveProxy({ actor: ROOT, caller: 'person', projectId: project, environmentId, ...input });
  const view = (environmentId = dev) => vault.proxy({ projectId: project, environmentId });
  return { vault, config, keys, project, dev, save, view };
}

type World = Awaited<ReturnType<typeof world>>;

/** A fork of `parent` in `project`, its row sealed as the app makes one. */
async function fork(project: string, parent: string): Promise<string> {
  const { environments } = tablesOf(db.owner);
  const id = randomUUID();
  const slug = `f-${id.slice(0, 8)}`;
  await db.owner.insert(environments).values({ id, projectId: project, slug, name: 'Fork', parentId: parent });
  await sealPlaces(db.owner, [{ id, projectId: project, slug, parentId: parent }]);
  return id;
}

/** The environment's proxy row, as stored. */
async function stored(environmentId: string): Promise<{ items: Record<string, ProxyItem>; digests: Buffer; seal: Buffer } | undefined> {
  const { proxyDefinitions } = tablesOf(db.owner);
  const [row] = await db.owner.select().from(proxyDefinitions).where(sql`${proxyDefinitions.environmentId} = ${environmentId}`);
  return row === undefined ? undefined : { items: (typeof row.items === 'string' ? JSON.parse(row.items) : row.items) as Record<string, ProxyItem>, digests: Buffer.from(row.digests), seal: Buffer.from(row.seal) };
}

/** A writer's own row, around the vault: items and index as given, the seal kept unless given. */
async function write(environmentId: string, items: Record<string, ProxyItem>, digests: Buffer, seal?: Buffer): Promise<void> {
  const json = JSON.stringify(items);
  if (ENGINE === 'postgres') await run(db.owner, sql`UPDATE proxy_definitions SET items = ${json}::jsonb, digests = ${digests}${seal === undefined ? sql`` : sql`, seal = ${seal}`} WHERE environment_id = ${environmentId}`);
  else await run(db.owner, sql`UPDATE proxy_definitions SET items = ${json}, digests = ${digests}${seal === undefined ? sql`` : sql`, seal = ${seal}`} WHERE environment_id = ${environmentId}`);
}

async function count(query: ReturnType<typeof sql>): Promise<number> {
  return Number((await rows<{ n: number | string }>(db.owner, query))[0]!.n);
}

function saved(outcome: Awaited<ReturnType<World['save']>>): ProxyView {
  assert.ok(outcome.ok, JSON.stringify(outcome));
  return outcome.view;
}

function refusedWith(outcome: Awaited<ReturnType<World['save']>>, code: string, message?: RegExp): void {
  assert.equal(outcome.ok, false, 'saved');
  if (!outcome.ok) {
    assert.equal(outcome.refusal.code, code, outcome.refusal.message);
    if (message !== undefined) assert.match(outcome.refusal.message, message);
  }
}

// --- the object and its seal, pure ----------------------------------------------------------------------------------

function item(definition: ProxyDefinition): ProxyItem {
  return { definition, keys: ['OPENAI_API_KEY'], savedBy: ROOT, savedAt: 1, holdings: [] };
}

test('the seal covers the index, names included: a forged body, a body moved under another name and a forged index all fail it', () => {
  const key = sealKey(randomBytes(32));
  const ref: Ref = { kind: 'proxy', id: randomUUID() };
  const object: ProxyInput = { kind: 'proxy', id: ref.id, items: { a: item(route('a')), b: item(route('b', 'eu.api.openai.com')) } };
  const seal = sealOf(key, ref, object);
  assert.ok(sealOf(key, ref, { ...object, items: { b: object.items.b!, a: object.items.a! } }).equals(seal), 'one seal whatever order the items come in');
  const forged = { ...object, items: { ...object.items, a: item(route('a', 'evil.example')) } };
  assert.ok(!sealOf(key, ref, forged).equals(seal));
  // A writer drops `a` and stores A's body under `b`: the sealed entry `b` names B's digest, which A does not hash to.
  assert.ok(!sealOf(key, ref, { ...object, items: { b: object.items.a! } }).equals(seal));
  assert.ok(!sealOf(key, { kind: 'proxy', id: randomUUID() }, object).equals(seal), 'another environment\'s seal');
  // The row's index column: each name's length, the name, its digest.
  assert.equal(indexBytes(object.items).length, 2 * (1 + 1 + 32));
});

test('a save applies to the object as the log has it: each item named added, replaced or removed; replace takes the others out', () => {
  const ref: Ref = { kind: 'proxy', id: randomUUID() };
  const made = applyOp(null, ref, { op: 'proxy.save', items: { a: item(route('a')), b: item(route('b')) }, replace: false, loaded: null }) as ProxyInput;
  assert.deepEqual(Object.keys(made.items), ['a', 'b']);
  const next = applyOp(made, ref, { op: 'proxy.save', items: { a: null, c: item(route('c')) }, replace: false, loaded: 'x' }) as ProxyInput;
  assert.deepEqual(Object.keys(next.items), ['b', 'c']);
  assert.deepEqual(Object.keys((applyOp(next, ref, { op: 'proxy.save', items: { d: item(route('d')) }, replace: true, loaded: 'y' }) as ProxyInput).items), ['d']);
  assert.equal(applyOp(made, ref, { op: 'proxy.save', items: { a: item(route('b')) }, replace: false, loaded: null }), undefined, 'an item filed under another name is no save');
  // Code's reservation deletes items whole; a release frees a name of the set only.
  const reserved: Ref = { kind: 'proxy-reserved', id: 'instance' };
  assert.deepEqual(applyOp(null, reserved, { op: 'proxy.code', names: ['maps'] }), { kind: 'proxy-reserved', names: ['maps'] });
  assert.equal(applyOp({ kind: 'proxy-reserved', names: ['maps'] }, reserved, { op: 'proxy.code', names: ['maps'] }), undefined, 'nothing new reserved is no change');
  assert.deepEqual((applyOp(next, ref, { op: 'proxy.code', names: ['b'], cleared: { b: next.items.b! } }) as ProxyInput).items, { c: next.items.c });
  assert.equal(applyOp(next, ref, { op: 'proxy.code', names: ['z'], cleared: { z: next.items.c! } }), undefined);
  assert.equal(applyOp({ kind: 'proxy-reserved', names: ['maps'] }, reserved, { op: 'proxy.release', name: 'other' }), undefined);
});

// --- a save ----------------------------------------------------------------------------------------------------------

test('an Owner saves a route: the row holds it with its index and seal, the log a change and an entry, and the replay agrees', ON_015, async () => {
  const w = await world();
  const before = await w.view();
  assert.deepEqual(before, { environmentId: w.dev, seal: null, state: 'ok', items: [], reserved: [], reservedState: 'ok' });
  const view = saved(await w.save({ seal: null, items: { openai: route('openai') } }));
  assert.equal(view.state, 'ok');
  assert.deepEqual(view.items.map((each) => [each.definition.name, each.keys, each.savedBy, each.routesSensitive]), [['openai', ['OPENAI_API_KEY'], ROOT, true]]);
  assert.deepEqual(await w.view(), view, 'what it answered is what a read finds');
  const row = (await stored(w.dev))!;
  assert.deepEqual(Object.keys(row.items), ['openai']);
  assert.ok(row.digests.equals(indexBytes(row.items)));
  assert.equal(row.seal.toString('base64'), view.seal);
  // The editor's holdings, frozen with the item, never answered: what they held here, and that they own the project.
  assert.deepEqual(row.items.openai!.holdings.map(({ projectId, environmentId, sensitive }) => ({ projectId, environmentId, sensitive })), [{ projectId: w.project, environmentId: w.dev, sensitive: true }]);
  assert.ok(row.items.openai!.holdings[0]!.permissions.normal.includes('proxy.edit'));
  assert.equal(JSON.stringify(view).includes('holdings'), false);
  assert.equal(await count(sql`SELECT count(*) AS n FROM audit_log WHERE action = 'proxy.save' AND decision = 'allow'`), 1);
  const [entry] = await rows<{ metadata: string }>(db.owner, sql`SELECT metadata FROM audit_log WHERE action = 'proxy.save'`);
  assert.deepEqual(JSON.parse(entry!.metadata).proxy, { replace: false, saved: [{ name: 'openai', kind: 'route', upstream: 'https://api.openai.com/v1', keys: ['OPENAI_API_KEY'], routesSensitive: [] }], removed: [] });
  const { faults } = await replayStored(db.owner, w.config.signingKeys);
  assert.deepEqual(faults, []);
  // Saved again unchanged: nothing to change, nothing logged.
  const changes = await count(sql`SELECT count(*) AS n FROM log_changes`);
  assert.equal(saved(await w.save({ seal: view.seal, items: { openai: route('openai') } })).seal, view.seal);
  assert.equal(await count(sql`SELECT count(*) AS n FROM log_changes`), changes);
});

test('a page behind another save is refused, 409 proxy_changed, and changes nothing; on top of the newest it saves', ON_015, async () => {
  const w = await world();
  const first = saved(await w.save({ seal: null, items: { openai: route('openai') } }));
  refusedWith(await w.save({ seal: null, items: { maps: route('maps', 'maps.example.com', 'MAPS_KEY') } }), 'proxy_changed');
  refusedWith(await w.save({ seal: randomBytes(16).toString('base64'), items: { maps: route('maps', 'maps.example.com', 'MAPS_KEY') } }), 'proxy_changed');
  assert.deepEqual(Object.keys((await stored(w.dev))!.items), ['openai']);
  const second = saved(await w.save({ seal: first.seal, items: { maps: route('maps', 'maps.example.com', 'MAPS_KEY') } }));
  assert.deepEqual(second.items.map((each) => each.definition.name), ['maps', 'openai']);
  // Removing the last items keeps the row: an empty index, sealed, so that a deleted row is still found out.
  const emptied = saved(await w.save({ seal: second.seal, items: { maps: null, openai: null } }));
  assert.deepEqual(emptied.items, []);
  assert.deepEqual((await stored(w.dev))!.items, {});
  assert.deepEqual((await replayStored(db.owner, w.config.signingKeys)).faults, []);
});

test('who saves: a person holding proxy.edit, on a session; a Developer, a token, or a person on a scoped credential, refused', ON_015, async () => {
  const w = await world();
  refusedWith(await w.save({ actor: ADA, seal: null, items: { openai: route('openai') } }), 'no_grant', /proxy\.edit/);
  refusedWith(await w.save({ actor: CI, caller: 'bearer', seal: null, items: { openai: route('openai') } }), 'not_allowed', /person/);
  refusedWith(await w.save({ caller: 'person', credentialScope: [{ projectId: w.project, environmentId: null, role: 'owner' }], seal: null, items: { openai: route('openai') } }), 'not_allowed');
  // A role an Owner gave proxy.edit, beside the reads it takes: its holder saves, and the save freezes what they hold.
  assert.ok((await w.vault.changePolicy({
    actor: ROOT, caller: 'person',
    change: { kind: 'role', role: 'router', definition: { name: 'Router', description: '', permissions: ['secret.read', 'secret.use', 'proxy.edit'], protected: ['secret.use'] } },
  })).ok);
  assert.ok((await w.vault.setAccess({ actor: ROOT, caller: 'person', principal: ADA, changes: [{ projectId: w.project, environmentId: w.dev, role: 'router', expiresAt: null }] })).ok);
  const view = saved(await w.save({ actor: ADA, seal: null, items: { openai: route('openai') } }));
  assert.deepEqual(view.items.map((each) => [each.savedBy, each.routesSensitive]), [[ADA, false]]);
  // Protected, the role's protected column holds no proxy.edit.
  assert.ok((await w.vault.changePolicy({ actor: ROOT, caller: 'person', change: { kind: 'protect', projectId: w.project, environmentIds: [w.dev], protected: true } })).ok);
  refusedWith(await w.save({ actor: ADA, seal: view.seal, items: { maps: route('maps', 'maps.example.com', 'MAPS_KEY') } }), 'no_grant');
  // A role that edits the proxy and reads nothing is no role the rules allow.
  const unreadable = await w.vault.changePolicy({ actor: ROOT, caller: 'person', change: { kind: 'role', role: 'blind', definition: { name: 'Blind', description: '', permissions: ['proxy.edit'], protected: [] } } });
  assert.equal(unreadable.ok, false);
  assert.equal(await count(sql`SELECT count(*) AS n FROM audit_log WHERE action = 'proxy.save' AND decision = 'deny'`), 4);
});

test('what a save refuses before it reads: a definition the rules refuse, an item under another name, 257 items, a personal config', ON_015, async () => {
  const w = await world();
  refusedWith(await w.save({ seal: null, items: { openai: { ...route('openai'), upstream: 'https://169.254.169.254' } } }), 'invalid', /private/);
  refusedWith(await w.save({ seal: null, items: { maps: route('openai') } }), 'invalid', /own name/);
  const many = Object.fromEntries(Array.from({ length: 257 }, (_, i) => [`r${i}`, route(`r${i}`)]));
  refusedWith(await w.save({ seal: null, items: many }), 'invalid', /256/);
  // A personal config takes none of its own (decision 7).
  const { environments } = tablesOf(db.owner);
  const personal = randomUUID();
  await db.owner.insert(environments).values({ id: personal, projectId: w.project, slug: `p-${personal.slice(0, 8)}`, name: 'Mine', parentId: w.dev, owner: ROOT });
  const { prepareChanges } = await import('../src/changes.ts');
  const { appChanges } = await import('@coffre/db/log');
  const calls = prepareChanges({ seals: w.keys, mac: (await import('../src/log-entry.ts')).logMacKey(w.config.signingKeys[0]!) }, Date.now(), ROOT,
    [{ kind: 'environment', id: personal, before: null, after: { id: personal, projectId: w.project, slug: `p-${personal.slice(0, 8)}`, owner: ROOT, parentId: w.dev, protected: null, archived: false, projectArchived: false } }], new Map());
  await db.owner.transaction((tx) => appChanges(tx, calls));
  refusedWith(await w.save({ seal: null, items: { openai: route('openai') } }, personal), 'invalid', /personal config/);
  assert.equal(await stored(w.dev), undefined);
});

// --- forged rows fail closed (R64) -----------------------------------------------------------------------------------

test('a row a writer edits, moves an item in, puts back or deletes shows tampered or stale, with no item; only an Owner replaces it whole', ON_015, async () => {
  const w = await world();
  const first = saved(await w.save({ seal: null, items: { a: route('a'), b: route('b', 'eu.api.openai.com') } }));
  const genuine = (await stored(w.dev))!;
  const second = saved(await w.save({ seal: first.seal, items: { a: route('a', 'api2.openai.com') } }));
  const now = (await stored(w.dev))!;
  const forgeries: [string, () => Promise<void>, 'tampered' | 'stale'][] = [
    ['an upstream edited, the index left', () => write(w.dev, { ...now.items, a: { ...now.items.a!, definition: route('a', 'evil.example') } }, now.digests), 'tampered'],
    ['an upstream edited, the index made again', async () => {
      const items = { ...now.items, a: { ...now.items.a!, definition: route('a', 'evil.example') } };
      await write(w.dev, items, indexBytes(items));
    }, 'tampered'],
    ['B\'s body moved under a\'s name, a dropped', async () => {
      const items = { a: { ...now.items.b!, definition: { ...now.items.b!.definition, name: 'a' } } };
      await write(w.dev, items, indexBytes(items));
    }, 'tampered'],
    ['an item deleted, its index entry left', () => write(w.dev, { b: now.items.b! }, now.digests), 'tampered'],
    ['last save\'s row put back', () => write(w.dev, genuine.items, genuine.digests, genuine.seal), 'stale'],
    ['the row deleted', () => run(db.owner, sql`DELETE FROM proxy_definitions WHERE environment_id = ${w.dev}`), 'stale'],
  ];
  for (const [how, forge, fault] of forgeries) {
    await forge();
    const view = await w.view();
    assert.deepEqual([view.state, view.items, view.seal], [fault, [], second.seal], how);
    // An edit made from it would seal the forgery as its editor's own: refused, whoever asks.
    refusedWith(await w.save({ seal: second.seal, items: { c: route('c') } }), 'tampered', /replaces them whole/);
    // Put right again, for the next one.
    if (ENGINE === 'postgres') await run(db.owner, sql`INSERT INTO proxy_definitions (environment_id, items, digests, seal) VALUES (${w.dev}, ${JSON.stringify(now.items)}::jsonb, ${now.digests}, ${now.seal}) ON CONFLICT (environment_id) DO UPDATE SET items = EXCLUDED.items, digests = EXCLUDED.digests, seal = EXCLUDED.seal`);
    else await run(db.owner, sql`INSERT INTO proxy_definitions (environment_id, items, digests, seal) VALUES (${w.dev}, ${JSON.stringify(now.items)}, ${now.digests}, ${now.seal}) ON CONFLICT (environment_id) DO UPDATE SET items = excluded.items, digests = excluded.digests, seal = excluded.seal`);
    assert.equal((await w.view()).state, 'ok', how);
  }
  // Forged once more, then replaced whole by an Owner of the project, moving on from the newest change's seal.
  await write(w.dev, { a: { ...now.items.a!, definition: route('a', 'evil.example') } }, now.digests);
  refusedWith(await w.save({ actor: ADA, seal: second.seal, items: { c: route('c') }, replace: true }), 'no_grant');
  const replaced = saved(await w.save({ seal: second.seal, items: { c: route('c') }, replace: true }));
  assert.deepEqual([replaced.state, replaced.items.map((each) => each.definition.name)], ['ok', ['c']]);
  assert.deepEqual(await w.view(), replaced);
  assert.deepEqual((await replayStored(db.owner, w.config.signingKeys)).faults, []);
});

test("a row planted where no change was made is stale, and its environment's first save starts from none", ON_015, async () => {
  const w = await world();
  const items = { a: item(route('a', 'evil.example')) };
  if (ENGINE === 'postgres') await run(db.owner, sql`INSERT INTO proxy_definitions (environment_id, items, digests, seal) VALUES (${w.dev}, ${JSON.stringify(items)}::jsonb, ${indexBytes(items)}, ${randomBytes(16)})`);
  else await run(db.owner, sql`INSERT INTO proxy_definitions (environment_id, items, digests, seal) VALUES (${w.dev}, ${JSON.stringify(items)}, ${indexBytes(items)}, ${randomBytes(16)})`);
  assert.equal((await w.view()).state, 'stale');
  refusedWith(await w.save({ seal: null, items: { b: route('b') } }), 'tampered');
  const replaced = saved(await w.save({ seal: null, items: { b: route('b') }, replace: true }));
  assert.deepEqual(replaced.items.map((each) => each.definition.name), ['b']);
});

// --- forks: a lookup by name through the chain (decision 6) ---------------------------------------------------------

test('a lookup walks the fork chain nearest first: a fork of a fork is served by its grandparent; a fork whose own item a writer deleted is tampered, never its parent\'s', ON_015, async () => {
  const w = await world();
  const child = await fork(w.project, w.dev);
  const grandchild = await fork(w.project, child);
  saved(await w.save({ seal: null, items: { openai: route('openai'), maps: route('maps', 'maps.example.com', 'MAPS_KEY') } }));
  const levels = async (chain: readonly string[]): Promise<ProxyLevel[]> => Promise.all(chain.map(async (environmentId) => {
    const ref = { kind: 'proxy' as const, id: environmentId };
    const [{ row, seal }, newest] = await Promise.all([readObject(db.vault, ref), newestChange(db.vault, ref)]);
    return { environmentId, row: row as ProxyInput | null, seal, newest: newest === null ? undefined : newest.seal };
  }));
  const served = proxyLookup(w.keys, await levels([grandchild, child, w.dev]), 'openai');
  assert.ok(served.served);
  assert.equal(served.level, 2);
  assert.deepEqual(served.seals.map((seal) => seal?.toString('base64') ?? null), [null, null, (await w.view()).seal]);
  // The fork's own item overrides the parent's.
  const own = saved(await w.save({ seal: null, items: { openai: route('openai', 'eu.api.openai.com') } }, child));
  const nearer = proxyLookup(w.keys, await levels([grandchild, child, w.dev]), 'openai');
  assert.ok(nearer.served && nearer.level === 1 && (nearer.item.definition as { upstream: string }).upstream === 'https://eu.api.openai.com/v1');
  // `maps`, which the child's index does not name, still the parent's.
  const parents = proxyLookup(w.keys, await levels([child, w.dev]), 'maps');
  assert.ok(parents.served && parents.level === 1);
  // A writer deletes the child's `openai` from its row, its index left: tampered, and the parent's never serves instead.
  const row = (await stored(child))!;
  await write(child, {}, row.digests);
  assert.deepEqual(proxyLookup(w.keys, await levels([grandchild, child, w.dev]), 'openai'), { served: false, fault: 'tampered', seals: [null] });
  // The child's row deleted outright: stale, as its object has a change.
  await run(db.owner, sql`DELETE FROM proxy_definitions WHERE environment_id = ${child}`);
  assert.equal(proxyLookup(w.keys, await levels([child, w.dev]), 'openai').served, false);
  assert.equal((proxyLookup(w.keys, await levels([child, w.dev]), 'openai') as { fault: unknown }).fault, 'stale');
  assert.ok(own.seal !== null);
  assert.equal(proxyLookup(w.keys, await levels([w.dev]), 'nothing').served, false);
});

// --- code's reserved names (section 6) ------------------------------------------------------------------------------

test("code reserves its names: each UI item of one deleted, whole in its entry; a save of one refused; only an instance Owner releases it", ON_015, async () => {
  const w = await world();
  const other = await newEnvironment(db.owner, w.project);
  const dev = saved(await w.save({ seal: null, items: { maps: route('maps', 'maps.example.com', 'MAPS_KEY'), openai: route('openai') } }));
  saved(await w.save({ seal: null, items: { maps: route('maps', 'maps.example.com', 'MAPS_KEY') } }, other));
  const reserved = await w.vault.reserveProxy({ names: ['maps', 'stripe'] });
  assert.ok(reserved.ok);
  assert.deepEqual(reserved.reserved, ['maps', 'stripe']);
  assert.deepEqual(reserved.cleared.map((each) => each.environmentId).sort(), [w.dev, other].sort());
  const view = await w.view();
  assert.deepEqual([view.items.map((each) => each.definition.name), view.reserved], [['openai'], ['maps', 'stripe']]);
  assert.notEqual(view.seal, dev.seal);
  // The item deleted, whole, in its object's change: the log can restore it.
  const [change] = await rows<{ payload: string }>(db.owner, sql`SELECT payload FROM log_changes WHERE payload LIKE '%"op":"proxy.code"%' AND payload LIKE ${`%${w.dev}%`}`);
  assert.equal(JSON.parse(change!.payload).cleared.maps.definition.upstream, 'https://maps.example.com/v1');
  // A second isolate reserving the same names, as a deploy's first ones race: nothing new, nothing written.
  const changes = await count(sql`SELECT count(*) AS n FROM log_changes`);
  assert.deepEqual(await w.vault.reserveProxy({ names: ['stripe', 'maps'] }), { ok: true, reserved: ['maps', 'stripe'], cleared: [] });
  assert.equal(await count(sql`SELECT count(*) AS n FROM log_changes`), changes);
  // A save of a reserved name, from any page: refused by the vault.
  refusedWith(await w.save({ seal: view.seal, items: { maps: route('maps', 'maps.example.com', 'MAPS_KEY') } }), 'reserved', /maps is reserved/);
  // Released by an instance Owner alone; then the name is free again.
  const ada = await w.vault.releaseProxy({ actor: ADA, caller: 'person', name: 'maps' });
  assert.equal(ada.ok ? 'released' : ada.refusal.code, 'not_allowed');
  const token = await w.vault.releaseProxy({ actor: CI, caller: 'bearer', name: 'maps' });
  assert.equal(token.ok ? 'released' : token.refusal.code, 'not_allowed');
  const released = await w.vault.releaseProxy({ actor: ROOT, caller: 'person', name: 'maps' });
  assert.ok(released.ok && released.reserved.join() === 'stripe');
  const again = await w.vault.releaseProxy({ actor: ROOT, caller: 'person', name: 'maps' });
  assert.equal(again.ok ? 'released' : again.refusal.code, 'invalid');
  saved(await w.save({ seal: (await w.view()).seal, items: { maps: route('maps', 'maps.example.com', 'MAPS_KEY') } }));
  assert.deepEqual((await replayStored(db.owner, w.config.signingKeys)).faults, []);
});

test('the reserved set forged around the vault refuses every save: fail closed (R64)', ON_015, async () => {
  const w = await world();
  assert.ok((await w.vault.reserveProxy({ names: ['maps'] })).ok);
  if (ENGINE === 'postgres') await run(db.owner, sql`UPDATE proxy_reserved SET names = '[]'::jsonb`);
  else await run(db.owner, sql`UPDATE proxy_reserved SET names = '[]'`);
  assert.equal((await w.view()).reservedState, 'tampered');
  const outcome = await w.save({ seal: null, items: { maps: route('maps', 'maps.example.com', 'MAPS_KEY') } });
  assert.equal(outcome.ok, false);
});

// --- the version gate (section 3, "One version at a time") ----------------------------------------------------------

test('in this process, a call on another release answers this one and runs nothing: no read, no entry; on this release it runs', ON_015, async () => {
  const w = await world();
  const entry = await openEntry(db.vault, w.config, { log: '0.15', sealThrough: sealed, heldOutside: nothingHeld });
  const entries = await count(sql`SELECT count(*) AS n FROM audit_log`);
  const changes = await count(sql`SELECT count(*) AS n FROM log_changes`);
  for (const [method, args] of [['about', []], ['access', [ROOT]], ['useNamed', [{ tokenHash: 'x' }]], ['saveProxy', [{ actor: ROOT, caller: 'person', projectId: w.project, environmentId: w.dev, seal: null, items: { openai: route('openai') } }]]] as const) {
    assert.deepEqual(await entry.call('0.0.1', method, args), { release: RELEASE }, method);
  }
  assert.equal(await count(sql`SELECT count(*) AS n FROM audit_log`), entries);
  assert.equal(await count(sql`SELECT count(*) AS n FROM log_changes`), changes);
  assert.equal(await stored(w.dev), undefined);
  const answer = await entry.call(RELEASE, 'access', [ROOT]);
  assert.equal(answer.release, RELEASE);
  assert.equal((answer.result as { role: string }).role, 'owner');
  await assert.rejects(entry.call(RELEASE, 'nothing' as never, []), /not a vault call/);
  await assert.rejects(versioned(entry, '0.0.1').about(), (error: Error & { code?: string }) => error.code === 'deploying');
});

test('in this process, a call on another release runs no statement at all, the hot path\'s included', { skip: ON_015.skip || postgresOnly('counts Postgres statements').skip }, async () => {
  const w = await world();
  let statements = 0;
  const clients: { end(): Promise<void> }[] = [];
  const counted = (url: string) => {
    const client = postgresClient(url, { max: 2 });
    clients.push(client);
    return createDatabase(new Proxy(client, {
    get(target, key) {
      const value: unknown = Reflect.get(target, key, target);
      if (key !== 'unsafe') return value;
      return (...args: unknown[]) => {
        statements += 1;
        return (value as (...a: unknown[]) => unknown).apply(target, args);
      };
    },
    }));
  };
  const vault = counted(VAULT_URL);
  const hot = counted(OWNER_URL.replace('coffre_owner:local-dev-only', 'coffre_vault_hot:local-hot-only'));
  try {
    const entry = await openEntry(vault, w.config, { log: '0.15', sealThrough: sealed, heldOutside: nothingHeld }, async () => {}, hot);
    statements = 0;
    await entry.call('0.0.1', 'useNamed', [{ tokenHash: 'x' }]);
    await entry.call('0.0.1', 'about', []);
    await entry.call('0.0.1', 'access', [ROOT]);
    assert.equal(statements, 0);
    await entry.call(RELEASE, 'about', []);
    assert.ok(statements > 0, 'on its own release it reads');
  } finally {
    await Promise.all(clients.map((client) => client.end()));
  }
});
