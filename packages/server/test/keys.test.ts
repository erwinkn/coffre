// An environment's keys over HTTP on the 0.16 contract (docs/design/0.16.md,
// "Pages"): the list, a key's versions, references and missing keys, each one
// call to the vault (`caller`) and one statement, scoped by its answer, never
// a value but a plain one's copy; and the environment's version, one `peek`
// of the vault's and no statement, the one a reveal answers.
import assert from 'node:assert/strict';
import { after, beforeEach, test } from 'node:test';

import { credential, dismissed, emptyDatabase, environment, grant, principal, project, rewrite, role, rows, secret, user, value, write } from '@coffre/vault/testing';
import { sql } from 'drizzle-orm';

import { openApp } from './app-fixture.ts';

const app = await openApp();
const { world } = app;
after(() => app.close());

const [ada, bo, cy, ed, fay, gus] = [user('ada'), user('bo'), user('cy'), user('ed'), user('fay'), user('gus')];
const [ci, cj] = ['token:ci', 'token:cj'];

/**
 * market:
 *   prod     A (secret), B (plain), S (sensitive), C (archived), E (no value), R (a reference to A); Y dismissed
 *   staging  protected: A, Y, Z
 *   dev      a fork of prod: its own A over prod's, D, B dismissed, S reset (its override archived)
 *   prod-ada Ada's personal config of prod: OWN
 *   old      archived: O
 * billing: prod, LINK a reference to market/prod/A; stale, DEAD a reference to market/prod/C, archived.
 *
 * Ada views market, Bo maintains it, Cy owns the instance, Ed views
 * market/dev alone, Fay contributes to market (uses, never reads), Gus
 * holds nothing. ci maintains market on a token an Owner issued, which
 * reads its sensitive values; cj maintains it on one that does not.
 */
let ids: Record<string, string> = {};
beforeEach(async () => {
  await emptyDatabase(world.owner);
  for (const kept of [world.memory.reads, world.memory.callers, world.memory.logged, world.memory.touched, world.refused]) kept.clear();
  const [market, billing] = [project('market'), project('billing')];
  const prod = environment(market, 'prod');
  const staging = environment(market, 'staging', { protected: true });
  const dev = environment(market, 'dev', { parentId: prod.id });
  const old = environment(market, 'old', { archivedAt: new Date(0) });
  const adas = environment(market, 'prod-ada', { parentId: prod.id, owner: ada });
  const [billed, stale] = [environment(billing, 'prod'), environment(billing, 'stale')];
  const a = value(world, secret(prod, 'A'), 'a');
  const b = value(world, secret(prod, 'B'), 'b', { plain: true });
  const c = value(world, secret(prod, 'C', { archivedAt: new Date(0) }), 'c');
  const [own, o] = [value(world, secret(adas, 'OWN'), 'own'), value(world, secret(old, 'O'), 'o')];
  ids = { market: market.id, billing: billing.id, b: b.id, prod: prod.id, staging: staging.id, dev: dev.id, old: old.id, adas: adas.id, billed: billed.id, a: a.id, c: c.id, own: own.id, o: o.id };
  await write(
    world,
    ...rows('projects', market, billing),
    ...rows('environments', prod, staging, dev, old, adas, billed, stale),
    ...rows('secrets',
      a, b, value(world, secret(prod, 'S'), 's', { sensitive: true }), c, secret(prod, 'E'), secret(prod, 'R', { sourceId: a.id, folder: 'links' }),
      value(world, secret(staging, 'A'), 'sa'), value(world, secret(staging, 'Y'), 'y'), value(world, secret(staging, 'Z'), 'z', { plain: true }),
      value(world, secret(dev, 'A'), 'da'), value(world, secret(dev, 'D'), 'd'), value(world, secret(dev, 'S', { archivedAt: new Date(0) }), 'ds'),
      own, o,
      secret(billed, 'LINK', { sourceId: a.id }), secret(stale, 'DEAD', { sourceId: c.id })),
    ...rows('dismissedKeys', dismissed(dev, 'B'), dismissed(prod, 'Y')),
    ...rows('roles',
      role(false, 'viewer', ['secret.read'], []),
      role(false, 'contributor', ['secret.use', 'secret.write'], []),
      role(false, 'maintainer', ['secret.read', 'secret.write', 'environment.manage', 'project.manage']),
      role(true, 'owner', ['secret.read', 'secret.write', 'environment.manage', 'project.manage', 'grant.manage', 'audit.read']),
      role(true, 'member', [])),
    ...rows('principals', principal(ada), principal(bo), principal(cy, { role: 'owner' }), principal(ed), principal(fay), principal(gus), principal(ci), principal(cj)),
    ...rows('grants', grant(ada, 'viewer', { project: market }), grant(bo, 'maintainer', { project: market }), grant(ed, 'viewer', { environment: dev }), grant(fay, 'contributor', { project: market }), grant(ci, 'maintainer', { project: market }), grant(cj, 'maintainer', { project: market })),
    ...rows('credentials',
      ...[ada, bo, cy, ed, fay, gus].map((who) => credential(`${who.slice(5, who.indexOf('@'))}-cli`, who)),
      credential('ci-token', ci, { scope: JSON.stringify([{ projectId: market.id, environmentId: null, role: 'maintainer', sensitive: true }]) }),
      credential('cj-token', cj, { scope: JSON.stringify([{ projectId: market.id, environmentId: null, role: 'maintainer' }]) })),
  );
  await app.request('/livez');
  await app.request('/api/me', { headers: { authorization: 'Bearer nobody' } });
  app.calls.length = 0;
});

type Body = { error?: string; reason?: string; message?: string } & Record<string, unknown>;
const call = async (label: string, method: string, path: string, body?: unknown): Promise<[number, Body]> => {
  const got = await app.request(`/api${path}`, { method, headers: { authorization: `Bearer ${label}` }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  return [got.status, (await got.json()) as Body];
};
async function cost<T>(run: () => Promise<T>): Promise<[T, string[], number]> {
  const [calls, statements] = [app.calls.length, app.statements];
  const result = await run();
  return [result, app.calls.slice(calls), app.statements - statements];
}
const refused = (answer: [number, Body]) => [answer[0], answer[1].error, answer[1].reason];
const NO_ACCESS = [403, 'vault_refused', 'no_access'];

type Key = { key: string; reference: { holder: string; source: string; state: string; version: number | null; canOpenSource: boolean } | null; folder: string | null; archived: boolean; version: number | null; versionId: string | null; updatedAt: string | null; updatedBy: string | null; generated: unknown; value: string | null; sensitivity: string | null; readable: boolean; parent: { from: string; state: string; changed: boolean; reset: boolean; held: boolean } | null };
type List = { permissions: string[]; keys: Key[]; parents: string[]; personal: { of: string; fallback: boolean } | null; protected: boolean; unprotectable: boolean; loosenable: boolean; rotateAfterDays: number | null };
const list = async (label: string, path: string) => {
  const [status, body] = await call(label, 'GET', `/secrets/${path}`);
  assert.equal(status, 200, JSON.stringify(body));
  return body as unknown as List;
};
/** Each key as `[key, version, sensitivity, readable, parent state and where from]`. */
const brief = (keys: Key[]) => keys.map((key) => [key.key, key.version, key.sensitivity, key.readable, key.parent === null ? null : `${key.parent.state} ${key.parent.from}${key.parent.reset ? ' reset' : ''}${key.parent.held ? '' : ' unheld'}`]);

test("an environment's keys: one call to the vault and one statement, no value but a plain one's, each key readable as 0.14 said", async () => {
  const [[status, body], calls, statements] = await cost(() => call('ada-cli', 'GET', '/secrets/market/prod'));
  assert.deepEqual([status, calls, statements], [200, ['caller'], 1], JSON.stringify(body));
  const listed = body as unknown as List;
  // A sensitive value is nobody's to see; an archived key or one with no value, nothing.
  assert.deepEqual(brief(listed.keys), [
    ['A', 1, 'secret', true, null],
    ['B', 1, 'plain', true, null],
    ['C', 1, 'secret', false, null],
    ['E', null, null, false, null],
    ['R', null, 'secret', true, null],
    ['S', 1, 'sensitive', false, null],
  ]);
  assert.deepEqual(listed.keys.map((key) => key.value), [null, 'b', null, null, null, null]);
  const [a, , c, , r] = listed.keys;
  assert.deepEqual([a!.updatedBy !== null, typeof a!.versionId, c!.archived, r!.folder], [true, 'string', true, 'links']);
  // A reference: its source, read live, as old as the version it reads.
  assert.deepEqual({ ...r!.reference, id: undefined }, { id: undefined, holder: 'market/prod/R', source: 'market/prod/A', state: 'live', version: 1, createdBy: null, createdAt: null, endedBy: null, endedAt: null, canOpenSource: true });
  assert.equal(r!.updatedAt, a!.updatedAt);
  assert.deepEqual([listed.permissions, listed.parents, listed.personal, listed.protected, listed.unprotectable, listed.loosenable, listed.rotateAfterDays], [['secret.read'], [], null, false, false, false, 365]);

  // A sensitive value is readable to nobody, as 0.14 listed it: not a service account on an Owner's token, which a reveal hands it, nor an Owner.
  for (const label of ['ci-token', 'cj-token', 'cy-cli']) assert.deepEqual((await list(label, 'market/prod')).keys.filter((key) => key.readable).map((key) => key.key), ['A', 'B', 'R'], label);
  // Fay uses and never reads: she lists the keys, and sees the plain one alone.
  const fays = await list('fay-cli', 'market/prod');
  assert.deepEqual([fays.keys.length, fays.keys.filter((key) => key.readable).map((key) => [key.key, key.value]), fays.permissions], [6, [['B', 'b']], ['secret.use', 'secret.write']]);
  // Bo maintains it; Cy owns the instance, who may loosen a sensitive value and take a protection off.
  assert.deepEqual([(await list('bo-cli', 'market/prod')).permissions, (await list('cy-cli', 'market/prod')).unprotectable, (await list('cy-cli', 'market/prod')).loosenable], [['secret.read', 'secret.write', 'environment.manage', 'project.manage'], true, true]);
  // staging is protected: as its row says.
  assert.equal((await list('bo-cli', 'market/staging')).protected, true);
});

test('a fork lists what it inherits, overrides and removed, and its version and age to a lister of the parent that holds it', async () => {
  const dev = await list('bo-cli', 'market/dev');
  assert.deepEqual(dev.parents, ['prod']);
  // B is dismissed here; S's override was reset to prod's, which a person is not handed.
  assert.deepEqual(brief(dev.keys), [
    ['A', 1, 'secret', true, 'overridden prod'],
    ['B', null, null, false, 'removed prod'],
    ['D', 1, 'secret', true, null],
    ['E', null, null, false, 'inherited prod'],
    ['R', null, 'secret', true, 'inherited prod'],
    ['S', 1, 'sensitive', false, 'inherited prod reset'],
  ]);
  assert.equal(dev.keys[0]!.parent!.changed, false);
  // prod's A written after dev's override of it: flagged.
  await world.owner.execute(sql`UPDATE secret_versions SET created_at = created_at + interval '1 day' WHERE secret_id = ${ids.a}`);
  assert.equal((await list('bo-cli', 'market/dev')).keys[0]!.parent!.changed, true);

  // Ed reads dev alone: prod's keys by name and standing, and nothing of their versions, nor readable through dev.
  const eds = await list('ed-cli', 'market/dev');
  assert.deepEqual(brief(eds.keys), [
    ['A', 1, 'secret', true, 'overridden prod'],
    ['B', null, null, false, 'removed prod'],
    ['D', 1, 'secret', true, null],
    ['E', null, null, false, 'inherited prod'],
    ['R', null, null, false, 'inherited prod'],
    ['S', null, null, false, 'inherited prod reset'],
  ]);
  assert.equal(eds.keys[0]!.parent!.changed, false);

  // A removal of a key no parent passes down any more: listed, to be restored, from the parent that stopped it.
  await world.owner.execute(sql`UPDATE secrets SET archived_at = now() WHERE environment_id = ${ids.prod} AND key = 'B'`);
  assert.deepEqual(brief((await list('bo-cli', 'market/dev')).keys).find(([key]) => key === 'B'), ['B', null, null, false, 'removed prod unheld']);
});

test("dev@me is the caller's personal config of dev, or dev while they have none", async () => {
  const hers = await list('ada-cli', 'market/prod@me');
  assert.deepEqual([hers.personal, hers.parents, hers.unprotectable], [{ of: 'prod', fallback: false }, ['prod'], false]);
  assert.deepEqual(brief(hers.keys), [
    ['A', 1, 'secret', true, 'inherited prod'],
    ['B', 1, 'plain', true, 'inherited prod'],
    ['E', null, null, false, 'inherited prod'],
    ['OWN', 1, 'secret', true, null],
    ['R', null, 'secret', true, 'inherited prod'],
    ['S', 1, 'sensitive', false, 'inherited prod'],
  ]);
  const his = await list('bo-cli', 'market/prod@me');
  assert.deepEqual([his.personal, his.parents, his.keys.map((key) => key.key)], [{ of: 'prod', fallback: true }, [], ['A', 'B', 'C', 'E', 'R', 'S']]);
  // A personal config is protected as its environment is.
  await world.owner.execute(sql`UPDATE environments SET protected = true WHERE id = ${ids.prod}`);
  assert.equal((await list('cy-cli', 'market/prod@me')).protected, true);
});

test('a place that is not there, one the caller holds nothing in and an archived one are the same refusal', async () => {
  const paths = ['/secrets/market/prod', '/secrets/market/prod/A/versions', '/projects/market/prod/missing', '/projects/market/prod/version'];
  for (const path of paths) {
    const [answer, calls, statements] = await cost(() => call('gus-cli', 'GET', path));
    // The version is the vault's alone.
    assert.deepEqual([refused(answer), calls, statements], [NO_ACCESS, ...(path.endsWith('/version') ? [['peek'], 0] : [['caller'], 1])], path);
  }
  for (const path of ['/secrets/market/nope', '/secrets/nope/prod', '/secrets/market/old', '/secrets/market/old/O/versions', '/projects/market/old/missing', '/projects/market/old/version', '/secrets/billing/prod']) {
    assert.deepEqual(refused(await call('ada-cli', 'GET', path)), NO_ACCESS, path);
  }
  // Ed reads dev alone: not prod, not staging.
  assert.deepEqual(refused(await call('ed-cli', 'GET', '/secrets/market/prod')), NO_ACCESS);
  // Ada views market, but not staging, which is protected.
  assert.deepEqual(refused(await call('ada-cli', 'GET', '/secrets/market/staging')), NO_ACCESS);
  // No one is asked about without a credential.
  const [anonymous] = await cost(() => app.request('/api/secrets/market/prod'));
  assert.equal(anonymous.status, 401);
});

test("a key's versions: the newest twenty, then older ones a page at a time, never a value", async () => {
  let h = value(world, secret({ id: ids.prod, projectId: ids.market }, 'H'), 'h1');
  await write(world, ...rows('secrets', h));
  for (let at = 2; at <= 22; at += 1) h = await rewrite(world, h, `h${at}`);
  const [[status, body], calls, statements] = await cost(() => call('ada-cli', 'GET', '/secrets/market/prod/H/versions'));
  assert.deepEqual([status, calls, statements], [200, ['caller'], 1], JSON.stringify(body));
  type Version = { version: number; current: boolean; kek: string; plain: boolean; sensitivity: string; createdBy: string; recipe: string | null };
  const versions = body.versions as Version[];
  assert.deepEqual([body.key, body.archived, body.more, versions.map((version) => version.version)], ['H', false, true, Array.from({ length: 20 }, (_, index) => 22 - index)]);
  assert.deepEqual([versions[0]!.current, versions[1]!.current, versions[0]!.sensitivity, versions[0]!.plain, typeof versions[0]!.kek], [true, false, 'secret', false, 'string']);
  assert.ok(!JSON.stringify(body).includes('h22'));
  const [, older] = await call('ada-cli', 'GET', '/secrets/market/prod/H/versions?before=3');
  assert.deepEqual([(older.versions as Version[]).map((version) => version.version), older.more], [[2, 1], false]);
  // How each is kept; an archived key's history too.
  assert.deepEqual(((await call('ada-cli', 'GET', '/secrets/market/prod/B/versions'))[1].versions as Version[]).map((version) => [version.plain, version.sensitivity]), [[true, 'plain']]);
  assert.deepEqual(((await call('ada-cli', 'GET', '/secrets/market/prod/S/versions'))[1].versions as Version[]).map((version) => version.sensitivity), ['sensitive']);
  assert.equal((await call('ada-cli', 'GET', '/secrets/market/prod/C/versions'))[1].archived, true);
  // A recipe is told for the current version alone: an older one's is not kept.
  const made = value(world, secret({ id: ids.prod, projectId: ids.market }, 'MADE'), 'm1');
  await write(world, ...rows('secrets', made));
  await rewrite(world, made, 'm2');
  // The second was generated (the app reads rows without their MACs).
  await world.owner.execute(sql`UPDATE secrets SET recipe = 'bytes:32:hex' WHERE id = ${made.id}`);
  assert.deepEqual(((await call('ada-cli', 'GET', '/secrets/market/prod/MADE/versions'))[1].versions as Version[]).map((version) => [version.version, version.recipe]), [[2, 'bytes:32:hex'], [1, null]]);
  // Ada's own config's key; one the environment holds no row of, an inherited one included, is not found.
  assert.deepEqual(((await call('ada-cli', 'GET', '/secrets/market/prod@me/OWN/versions'))[1].versions as Version[]).length, 1);
  assert.deepEqual(refused(await call('ada-cli', 'GET', '/secrets/market/dev/E/versions')), [404, 'not_found', 'unknown_key']);
  assert.deepEqual(refused(await call('ada-cli', 'GET', '/secrets/market/prod/NOPE/versions')), [404, 'not_found', 'unknown_key']);
  for (const query of ['?before=0', '?before=x', '?limit=5']) assert.equal((await call('ada-cli', 'GET', `/secrets/market/prod/H/versions${query}`))[0], 400, query);
});

test('references into and out of a place, to whoever lists or manages either end', async () => {
  type Reference = { holder: string; source: string; state: string; version: number | null; readers: string[] | null; canBreak: boolean; holderArchived: boolean };
  const references = async (label: string, path: string) => {
    const [[status, body], calls, statements] = await cost(() => call(label, 'GET', `/references?path=${encodeURIComponent(path)}`));
    // Readers, for an access manager's alone, are one statement more.
    const read = (body.references as Reference[] | undefined)?.some(({ readers }) => readers !== null) === true;
    assert.deepEqual([status, calls, statements], [200, ['caller'], read ? 2 : 1], JSON.stringify(body));
    return (body.references as Reference[]).map(({ holder, source, state, version, readers, canBreak, holderArchived }) => [holder, source, state, version, readers, canBreak, holderArchived]);
  };
  // Billing's, by the end in market Ada lists; market's own.
  assert.deepEqual(await references('ada-cli', 'market'), [
    ['billing/prod/LINK', 'market/prod/A', 'live', 1, null, false, false],
    ['billing/stale/DEAD', 'market/prod/C', 'source_archived', null, null, false, false],
    ['market/prod/R', 'market/prod/A', 'live', 1, null, false, false],
  ]);
  assert.deepEqual((await references('bo-cli', 'market/prod/A')).map(([holder, , , , , canBreak]) => [holder, canBreak]), [['billing/prod/LINK', false], ['market/prod/R', true]]);
  assert.deepEqual(await references('ada-cli', 'market/dev'), []);
  assert.deepEqual(await references('ada-cli', 'market/prod/NOPE'), []);
  // Cy runs the instance: billing's own, and may break any.
  assert.deepEqual((await references('cy-cli', 'billing')).map(([holder, , , , , canBreak]) => [holder, canBreak]), [['billing/prod/LINK', true], ['billing/stale/DEAD', true]]);
  // Billing is a place Ada holds nothing in, but the references she is shown by their end in market name it.
  assert.deepEqual((await references('ada-cli', 'billing')).map(([holder]) => holder), ['billing/prod/LINK', 'billing/stale/DEAD']);
  assert.deepEqual((await references('ada-cli', 'billing/prod')).map(([holder]) => holder), ['billing/prod/LINK']);
  // Ed views market/dev alone: a place he holds nothing in and is shown nothing of answers as one that is not there.
  assert.deepEqual([await references('ed-cli', 'market/dev'), await references('ed-cli', 'market/dev/NOPE')], [[], []]);
  const hidden = [['ed-cli', 'market/prod'], ['ed-cli', 'market/staging'], ['ed-cli', 'market/prod/A'], ['ed-cli', 'billing'], ['ed-cli', 'market/nope'], ['ed-cli', 'nope'], ['ada-cli', 'market/nope'], ['ada-cli', 'nope'], ['gus-cli', 'market']];
  for (const [label, path] of hidden) {
    const [answer, calls, statements] = await cost(() => call(label!, 'GET', `/references?path=${encodeURIComponent(path!)}`));
    assert.deepEqual([refused(answer), calls, statements], [NO_ACCESS, ['caller'], 1], `${label} ${path}`);
  }
  for (const path of ['', 'a/b/c/d', 'Market', 'market/prod/1X']) assert.equal((await call('ada-cli', 'GET', `/references?path=${encodeURIComponent(path)}`))[0], 400, path);
});

test("who reads through a reference: the members who read its holder's environment, to whoever manages either project's access, at one statement more", async () => {
  const [hal, ivy, jo, kim, max, nia, rex] = [user('hal'), user('ivy'), user('jo'), user('kim'), user('max'), user('nia'), user('rex')];
  const [market, billing] = [{ id: ids.market }, { id: ids.billing }];
  const [staging, adas] = [{ id: ids.staging, projectId: ids.market }, { id: ids.adas, projectId: ids.market }];
  // Nia views billing's dev alone, an environment no other reference names; her personal config of it holds one: the vault makes none,
  // but a stored one is read through its parent, and shown alike from either end.
  const billed = environment({ id: ids.billing }, 'dev');
  const nias = environment({ id: ids.billing }, 'dev-nia', { parentId: billed.id, owner: nia });
  await write(
    world,
    ...rows('environments', billed, nias),
    ...rows('secrets', secret(staging, 'SREF', { sourceId: ids.a }), secret(adas, 'MINE', { sourceId: ids.a }), secret(nias, 'NREF', { sourceId: ids.a })),
    ...rows('roles', role(false, 'admin', ['secret.read', 'grant.manage']), role(false, 'manager', ['grant.manage'])),
    // Hal administers billing, Ivy manages market's access and reads nothing, Max owns market alone; Jo's grant has ended,
    // Kim's is from before a removal, Rex is removed. cv is a service account viewing market.
    ...rows('principals', principal(hal), principal(ivy), principal(jo), principal(kim, { generation: 1 }), principal(max, { role: 'owner', scope: JSON.stringify({ projects: { only: [ids.market] }, environments: 'all' }) }), principal(nia), principal(rex, { status: 'removed' }), principal('token:cv')),
    ...rows('grants',
      grant(hal, 'admin', { project: billing }), grant(ivy, 'manager', { project: market }),
      grant(jo, 'viewer', { project: market }, { expiresAt: new Date(Date.UTC(2020, 0, 1)) }), grant(kim, 'viewer', { project: market }), grant(nia, 'viewer', { environment: billed }), grant(rex, 'viewer', { project: market }), grant('token:cv', 'viewer', { project: market })),
    ...rows('credentials', ...[hal, ivy].map((who) => credential(`${who.slice(5, who.indexOf('@'))}-cli`, who))),
  );
  const readers = async (label: string, path: string) => {
    const [[status, body], calls, statements] = await cost(() => call(label, 'GET', `/references?path=${encodeURIComponent(path)}`));
    const shown = body.references as { holder: string; readers: string[] | null }[];
    assert.deepEqual([status, calls, statements], [200, ['caller'], shown.some((reference) => reference.readers !== null) ? 2 : 1], JSON.stringify(body));
    return Object.fromEntries(shown.map(({ holder, readers }) => [holder, readers]));
  };
  // Prod's readers: by grant, a service account's too, and by an instance role whose scope takes market in. Staging is protected:
  // a person who views market holds nothing there, a service account holds its role's other column, a maintainer's role holds its
  // protected column. Ada's config is read by Ada alone.
  const inMarket = { 'market/prod/R': [ci, cj, 'token:cv', ada, bo, cy, max], 'market/staging/SREF': [ci, cj, 'token:cv', bo, cy, max], 'market/prod-ada/MINE': [ada] };
  const inBilling = { 'billing/dev-nia/NREF': [nia], 'billing/prod/LINK': [cy, hal], 'billing/stale/DEAD': [cy, hal] };
  // Ivy manages market's access: every reference with an end there, LINK's readers in billing too, as 0.14.7 showed them.
  assert.deepEqual(await readers('ivy-cli', 'market'), { ...inBilling, ...inMarket });
  // Hal manages billing's: its own references, whose sources are in market.
  assert.deepEqual(await readers('hal-cli', 'billing'), inBilling);
  assert.deepEqual(await readers('cy-cli', 'market/prod/A'), { 'billing/dev-nia/NREF': inBilling['billing/dev-nia/NREF'], 'billing/prod/LINK': inBilling['billing/prod/LINK'], 'market/prod-ada/MINE': inMarket['market/prod-ada/MINE'], 'market/prod/R': inMarket['market/prod/R'], 'market/staging/SREF': inMarket['market/staging/SREF'] });
  // Anyone else is shown none, at one statement; so is a manager shown no reference.
  assert.deepEqual(await readers('bo-cli', 'market/staging'), { 'market/staging/SREF': null });
  assert.deepEqual(await readers('ada-cli', 'market/prod/A'), { 'billing/dev-nia/NREF': null, 'billing/prod/LINK': null, 'market/prod-ada/MINE': null, 'market/prod/R': null, 'market/staging/SREF': null });
  assert.deepEqual(await readers('ivy-cli', 'market/dev'), {});
});

test("what an environment lacks of its siblings' keys, and what its team dismissed", async () => {
  const missing = async (label: string, path: string) => {
    const [[status, body], calls, statements] = await cost(() => call(label, 'GET', `/projects/${path}/missing`));
    assert.deepEqual([status, calls, statements], [200, ['caller'], 1], JSON.stringify(body));
    return body as { missing: { key: string; in: string[]; folder: string | null }[]; dismissed: { key: string; in: string[]; dismissedBy: string; dismissedAt: string }[] };
  };
  // Not dev's D: dev is prod's fork. Not OWN: Ada's config is nobody's sibling. Not O: old is archived.
  const prod = await missing('ada-cli', 'market/prod');
  assert.deepEqual([prod.missing, prod.dismissed.map(({ key, in: where }) => [key, where])], [[{ key: 'Z', in: ['staging'], folder: null }], [['Y', ['staging']]]]);
  // dev inherits prod's keys, so lacks only staging's, and B, which it dismissed.
  const dev = await missing('bo-cli', 'market/dev');
  assert.deepEqual([dev.missing.map(({ key, in: where }) => [key, where]), dev.dismissed.map(({ key, in: where }) => [key, where])], [[['Y', ['staging']], ['Z', ['staging']]], [['B', ['prod']]]]);
  // staging lacks what prod resolves to, and dev's own D.
  assert.deepEqual((await missing('bo-cli', 'market/staging')).missing.map(({ key, in: where }) => [key, where]), [['B', ['prod']], ['D', ['dev']], ['E', ['dev', 'prod']], ['R', ['dev', 'prod']], ['S', ['dev', 'prod']]]);
  // Ada's config inherits prod's keys and holds OWN: it lacks dev's D, which is no fork of it, and staging's, none of which it dismissed.
  assert.deepEqual((await missing('ada-cli', 'market/prod@me')).missing.map(({ key }) => key), ['D', 'Y', 'Z']);
});

/** A version, and a reveal of the whole environment, by the same caller: the same answer, or the same refusal. */
async function sameAsRead(label: string, path: string): Promise<string | null> {
  const [[status, body], calls, statements] = await cost(() => call(label, 'GET', `/projects/${path}/version`));
  const [read] = await cost(() => call(label, 'POST', '/reveals', { path }));
  // One peek of the vault's, which opens and writes nothing, and no statement of the app's.
  assert.deepEqual([calls, statements], [['peek'], 0], `${label} ${path}`);
  if (read[0] === 200) {
    assert.deepEqual([status, body.version], [200, read[1].version], `${label} ${path}: ${JSON.stringify(body)}`);
    return body.version as string;
  }
  assert.deepEqual(refused([status, body]), refused(read), `${label} ${path}`);
  return null;
}

test("an environment's version is the one a read of it answers, peeked without opening anything, and refused as that read would be", async () => {
  const answered = [
    ['ada-cli', 'market/prod'], ['ada-cli', 'market/dev'], ['ada-cli', 'market/prod@me'], ['bo-cli', 'market/prod@me'], ['bo-cli', 'market/dev'],
    ['ci-token', 'market/prod'], ['ci-token', 'market/dev'], ['cy-cli', 'billing/prod'], ['cy-cli', 'market/staging'],
  ];
  const versions = new Map<string, string | null>();
  for (const [label, path] of answered) versions.set(`${label} ${path}`, await sameAsRead(label!, path!));
  assert.ok([...versions.values()].every((version) => version !== null));
  // What each read is handed: Ada's config adds OWN; ci is handed S; Bo, with no config, is handed prod's.
  assert.notEqual(versions.get('ada-cli market/prod@me'), versions.get('ada-cli market/prod'));
  assert.notEqual(versions.get('ci-token market/prod'), versions.get('ada-cli market/prod'));
  assert.equal(versions.get('bo-cli market/prod@me'), versions.get('ada-cli market/prod'));
  // Refused as the read is: a parent Ed does not read, a sensitive value on a token no Owner issued, a reference whose source is archived, Fay, who only uses, and Gus.
  const refusals = [['ed-cli', 'market/dev'], ['cj-token', 'market/prod'], ['cy-cli', 'billing/stale'], ['fay-cli', 'market/prod'], ['gus-cli', 'market/prod'], ['ada-cli', 'market/nope'], ['ada-cli', 'market/old']];
  for (const [label, path] of refusals) assert.equal(await sameAsRead(label!, path!), null, `${label} ${path}`);
  assert.deepEqual(refused(await call('ed-cli', 'GET', '/projects/market/dev/version')), [403, 'forbidden', 'parent_unreadable']);
  assert.deepEqual(refused(await call('cy-cli', 'GET', '/projects/billing/stale/version')), [409, 'conflict', 'unreadable']);

  // A new value of A: a new version for whoever is handed it, through a reference too (dev inherits R, which reads A), and none for staging.
  const before = await sameAsRead('ada-cli', 'market/prod');
  const devBefore = await sameAsRead('ada-cli', 'market/dev');
  const linkBefore = await sameAsRead('cy-cli', 'billing/prod');
  const stagingBefore = await sameAsRead('cy-cli', 'market/staging');
  await rewrite(world, { id: ids.a }, 'a2');
  world.memory.reads.clear();
  assert.notEqual(await sameAsRead('ada-cli', 'market/prod'), before);
  const devAfter = await sameAsRead('ada-cli', 'market/dev');
  assert.notEqual(devAfter, devBefore);
  assert.notEqual(await sameAsRead('cy-cli', 'billing/prod'), linkBefore);
  assert.equal(await sameAsRead('cy-cli', 'market/staging'), stagingBefore);
  // dev's dismissal of B gone: it is handed prod's B, and its version changes.
  await world.owner.execute(sql`DELETE FROM dismissed_keys WHERE environment_id = ${ids.dev} AND key = 'B'`);
  world.memory.reads.clear();
  const devNow = await sameAsRead('ada-cli', 'market/dev');
  assert.notEqual(devNow, devAfter);

  // A row whose MAC is not the vault's is no row, to the version as to the reveal: dev without its D, and prod's R reading an A that is not there.
  await world.owner.execute(sql`UPDATE secrets SET mac = set_byte(mac, 35, (get_byte(mac, 35) + 1) % 256) WHERE environment_id = ${ids.dev} AND key = 'D'`);
  world.memory.reads.clear();
  const forged = await sameAsRead('ada-cli', 'market/dev');
  assert.ok(forged !== null && forged !== devNow);
  await world.owner.execute(sql`UPDATE secrets SET mac = set_byte(mac, 35, (get_byte(mac, 35) + 1) % 256) WHERE id = ${ids.a}`);
  world.memory.reads.clear();
  assert.equal(await sameAsRead('ada-cli', 'market/prod'), null);
  assert.deepEqual(refused(await call('ada-cli', 'GET', '/projects/market/prod/version')), [409, 'conflict', 'unreadable']);
});

test("a plain value's copy is listed, its own or through a live reference, and inherited to a lister of the parent; a secret's never, whatever its version carries", async () => {
  // A's version carries a copy it should not: A is a secret, and no copy of it is listed.
  await world.owner.execute(sql`UPDATE secret_versions SET plaintext = 'planted' WHERE secret_id = ${ids.a}`);
  // billing/prod's PLAIN reads prod's B; dev's dismissal of B is gone, so dev inherits it.
  await write(world, ...rows('secrets', secret({ id: ids.billed, projectId: ids.billing }, 'PLAIN', { sourceId: ids.b })));
  await world.owner.execute(sql`DELETE FROM dismissed_keys WHERE environment_id = ${ids.dev} AND key = 'B'`);
  const shown = async (label: string, path: string) => (await list(label, path)).keys.flatMap((key) => (key.value === null ? [] : [[key.key, key.value]]));
  for (const [label, path, values] of [
    ['ada-cli', 'market/prod', [['B', 'b']]], ['fay-cli', 'market/prod', [['B', 'b']]], ['cy-cli', 'billing/prod', [['PLAIN', 'b']]], ['bo-cli', 'market/dev', [['B', 'b']]], ['ada-cli', 'market/prod@me', [['B', 'b']]],
    // Ed lists dev and not prod: he is told B's name, not its value.
    ['ed-cli', 'market/dev', []],
    ['cy-cli', 'market/staging', [['Z', 'z']]],
  ] as const) assert.deepEqual(await shown(label, path), values, `${label} ${path}`);
  // A key's versions show no value, as 0.14's did.
  assert.ok(((await call('ada-cli', 'GET', '/secrets/market/prod/B/versions'))[1].versions as object[]).every((version) => !('value' in version)));
});

test("readable, as 0.14 said it: a Contributor's personal config reads its own values and none of its parent's; a sensitive value, nobody", async () => {
  const fays = environment({ id: ids.market }, 'dev-fay', { parentId: ids.dev, owner: fay });
  await write(world, ...rows('environments', fays), ...rows('secrets', value(world, secret(fays, 'MINE'), 'mine')));
  assert.deepEqual(brief((await list('fay-cli', 'market/dev@me')).keys).map(([key, , , readable]) => [key, readable]), [['A', false], ['D', false], ['E', false], ['MINE', true], ['R', false], ['S', false]]);
  // Cy owns the instance and reads everywhere: every value but the sensitive one, and none of what is archived or has none.
  assert.deepEqual((await list('cy-cli', 'market/dev')).keys.map((key) => [key.key, key.readable]), [['A', true], ['B', false], ['D', true], ['E', false], ['R', true], ['S', false]]);
});

test('the rules of a use, edge by edge: a chain too long or cut, references that cannot be read, a dismissal restored, a recipe', async () => {
  const [market, billing, prod, staging, old] = [{ id: ids.market }, { id: ids.billing }, { id: ids.prod, projectId: ids.market }, { id: ids.staging, projectId: ids.market }, { id: ids.old, projectId: ids.market }];
  const shelf = project('shelf', { archivedAt: new Date(0) });
  const shelved = environment(shelf, 'prod');
  const sh = value(world, secret(shelved, 'SH'), 'sh');
  // billing/prod's forks, four deep: b4 has one parent too many. Cy keeps a config of b3, the deepest a config may be, and one of b2 that holds a reference.
  const b1 = environment(billing, 'b1', { parentId: ids.billed });
  const b2 = environment(billing, 'b2', { parentId: b1.id });
  const b3 = environment(billing, 'b3', { parentId: b2.id });
  const b4 = environment(billing, 'b4', { parentId: b3.id });
  const [cy3, cy2] = [environment(billing, 'b3-cy', { parentId: b3.id, owner: cy }), environment(billing, 'b2-cy', { parentId: b2.id, owner: cy })];
  // References whose source is in a personal config, an archived environment, an archived project; one held in an archived environment.
  const [toPersonal, toOld, toShelf, gone] = [environment(billing, 'c-personal'), environment(billing, 'c-old'), environment(billing, 'c-shelf'), environment(billing, 'gone', { archivedAt: new Date(0) })];
  // Ed reads b-ed, a fork of billing/prod he alone is granted: its own AREF, to old's archived O, cannot be read, and the keys it inherits are his parent's, which he does not read: that is what he is told.
  const bed = environment(billing, 'b-ed', { parentId: ids.billed });
  // dev2 forks prod and holds a reference to C, archived; orphan forks old, archived; Bo keeps a config of staging, protected, and so does Ada, who reads no protected place; Cy keeps one of old.
  const [dev2, orphan, bos] = [environment(market, 'dev2', { parentId: ids.prod }), environment(market, 'orphan', { parentId: ids.old }), environment(market, 'staging-bo', { parentId: ids.staging, owner: bo })];
  const [adaStaging, cyOld] = [environment(market, 'staging-ada', { parentId: ids.staging, owner: ada }), environment(market, 'old-cy', { parentId: ids.old, owner: cy })];
  await write(
    world,
    ...rows('projects', shelf),
    ...rows('environments', shelved, b1, b2, b3, b4, cy3, cy2, toPersonal, toOld, toShelf, gone, dev2, orphan, bos, bed, adaStaging, cyOld),
    ...rows('secrets',
      sh, { ...value(world, secret({ id: ids.billed, projectId: ids.billing }, 'G'), 'g'), recipe: 'bytes:32:hex' }, value(world, secret(cy3, 'CYS'), 'cys'), secret(cy2, 'REF', { sourceId: ids.a }),
      secret(toPersonal, 'REFP', { sourceId: ids.own }), secret(toOld, 'REFO', { sourceId: ids.o }), secret(toShelf, 'REFS', { sourceId: sh.id }), secret(gone, 'GONE', { sourceId: ids.a }),
      secret(dev2, 'AREF', { sourceId: ids.c }), secret(bed, 'AREF', { sourceId: ids.o }), value(world, secret(bos, 'MINE'), 'mine'), value(world, secret(staging, 'C'), 'sc'),
      value(world, secret(adaStaging, 'AS'), 'as'), value(world, secret(cyOld, 'OC'), 'oc')),
    // b1 dismissed LINK, then restored it: it inherits it.
    ...rows('dismissedKeys', { ...dismissed(b1, 'LINK'), restoredAt: new Date(0), restoredBy: dismissed(b1, 'LINK').dismissedBy }),
    ...rows('grants', grant(ed, 'viewer', { environment: dev2 }), grant(ed, 'viewer', { environment: bed })),
  );
  void prod;
  void old;
  world.memory.reads.clear();
  world.memory.callers.clear();

  for (const [label, path] of [['cy-cli', 'billing/b1'], ['cy-cli', 'billing/b3'], ['cy-cli', 'billing/b3@me'], ['bo-cli', 'market/staging@me'], ['cy-cli', 'billing/prod']]) {
    assert.notEqual(await sameAsRead(label!, path!), null, `${label} ${path}`);
  }
  const refusals = [
    ['cy-cli', 'billing/b4', 409, 'broken_chain'], ['cy-cli', 'market/orphan', 409, 'broken_chain'], ['cy-cli', 'billing/b2@me', 409, 'unreadable'], ['cy-cli', 'billing/c-personal', 409, 'unreadable'],
    // Cy's config of b3 named by its own slug: no `@me`, so no fourth parent.
    ['cy-cli', 'billing/b3-cy', 409, 'broken_chain'],
    ['cy-cli', 'billing/c-old', 409, 'unreadable'], ['cy-cli', 'billing/c-shelf', 409, 'unreadable'], ['ed-cli', 'market/dev2', 403, 'parent_unreadable'], ['ed-cli', 'billing/b-ed', 403, 'parent_unreadable'], ['bo-cli', 'market/dev2', 409, 'unreadable'],
  ] as const;
  for (const [label, path, status, reason] of refusals) {
    assert.equal(await sameAsRead(label, path), null, `${label} ${path}`);
    assert.deepEqual(refused(await call(label, 'GET', `/projects/${path}/version`)).filter((_, index) => index !== 1), [status, reason], `${label} ${path}`);
  }

  // The list: a chain too long is cut, a config of the deepest is no Owner's to unprotect, Bo's config is protected as staging is.
  assert.deepEqual(refused(await call('cy-cli', 'GET', '/secrets/billing/b4')), [409, 'conflict', 'broken_chain']);
  assert.deepEqual(refused(await call('cy-cli', 'GET', '/secrets/billing/b3-cy')), [409, 'conflict', 'broken_chain']);
  // A fork of an archived environment inherits nothing, as a use refuses it.
  assert.deepEqual(refused(await call('cy-cli', 'GET', '/secrets/market/orphan')), [409, 'conflict', 'broken_chain']);
  // A personal config is read through its parent, however it is named: Ada's config of staging, protected, is no more hers than staging is; Cy's of old, archived, is no one's.
  for (const [label, path] of [['ada-cli', 'market/staging-ada'], ['ada-cli', 'market/staging@me'], ['cy-cli', 'market/old-cy']] as const) {
    const key = label === 'ada-cli' ? 'AS' : 'OC';
    assert.deepEqual(refused(await call(label, 'GET', `/secrets/${path}/${key}/versions`)), NO_ACCESS, `${label} ${path} versions`);
    assert.deepEqual(refused(await call(label, 'GET', `/secrets/${path}`)), NO_ACCESS, `${label} ${path}`);
    assert.deepEqual(refused(await call(label, 'GET', `/projects/${path}/version`)), NO_ACCESS, `${label} ${path} version`);
  }
  // Bo, who maintains market, reads his own config of staging's history, named either way.
  for (const path of ['market/staging-bo', 'market/staging@me']) assert.equal((await call('bo-cli', 'GET', `/secrets/${path}/MINE/versions`))[0], 200, path);
  // A reference held in a personal config reads nothing, as a use refuses it.
  assert.deepEqual((await list('cy-cli', 'billing/b2@me')).keys.filter((key) => key.key === 'REF').map((key) => [key.reference!.state, key.reference!.version, key.readable]), [['broken', null, false]]);
  const cys = await list('cy-cli', 'billing/b3@me');
  assert.deepEqual([cys.personal, cys.parents, cys.unprotectable, cys.keys.map((key) => key.key)], [{ of: 'b3', fallback: false }, ['b3', 'b2', 'b1', 'prod'], false, ['CYS', 'G', 'LINK']]);
  assert.deepEqual([(await list('bo-cli', 'market/staging@me')).protected, (await list('bo-cli', 'market/staging@me')).personal], [true, { of: 'staging', fallback: false }]);
  // Ed lists dev2, not prod, where AREF's source is.
  const eds = await list('ed-cli', 'market/dev2');
  assert.deepEqual(eds.keys.filter((key) => key.reference !== null).map((key) => [key.key, key.reference!.state, key.reference!.canOpenSource, key.readable]), [['AREF', 'source_archived', false, false]]);
  // A recipe, read from its secret's row.
  assert.deepEqual((await list('cy-cli', 'billing/prod')).keys.map((key) => [key.key, key.generated]), [['G', { recipe: 'bytes:32:hex' }], ['LINK', null]]);
  assert.deepEqual((await list('cy-cli', 'billing/b1')).keys.map((key) => [key.key, key.parent?.state]), [['G', 'inherited'], ['LINK', 'inherited']]);

  // References: one held in an archived environment says so; Ed is shown only what he lists an end of.
  const [, billed] = await call('cy-cli', 'GET', '/references?path=billing');
  assert.deepEqual((billed.references as { holder: string; state: string; holderArchived: boolean }[]).map(({ holder, state, holderArchived }) => [holder, state, holderArchived]), [
    ['billing/b-ed/AREF', 'source_archived', false],
    ['billing/b2-cy/REF', 'broken', false],
    ['billing/c-old/REFO', 'source_archived', false],
    ['billing/c-personal/REFP', 'broken', false],
    ['billing/c-shelf/REFS', 'source_archived', false],
    ['billing/gone/GONE', 'live', true],
    ['billing/prod/LINK', 'live', false],
    ['billing/stale/DEAD', 'source_archived', false],
  ]);
  assert.deepEqual(((await call('ed-cli', 'GET', '/references?path=market'))[1].references as { holder: string }[]).map(({ holder }) => holder), ['billing/b-ed/AREF', 'market/dev2/AREF']);

  // Missing keys follow a chain as a use does: b4 has one parent too many and inherits nothing, b3 and Cy's config of it, four deep, inherit prod's G.
  const missingAt = async (path: string) => ((await call('cy-cli', 'GET', `/projects/${path}/missing`))[1].missing as { key: string; in: string[] }[]).map(({ key, in: where }) => [key, where.join(' ')]);
  assert.deepEqual((await missingAt('billing/b4')).filter(([key]) => key === 'G' || key === 'LINK'), [['G', 'b-ed b1 b2 b3 prod'], ['LINK', 'b-ed b1 b2 b3 prod']]);
  for (const path of ['billing/b3', 'billing/b3@me']) assert.deepEqual((await missingAt(path)).filter(([key]) => key === 'G' || key === 'LINK'), [], path);

  // C is archived in prod: not missing there, though staging holds it; dev lacks it.
  const [, prodMissing] = await call('bo-cli', 'GET', '/projects/market/prod/missing');
  assert.deepEqual((prodMissing.missing as { key: string }[]).map(({ key }) => key), ['Z']);
  const [, devMissing] = await call('bo-cli', 'GET', '/projects/market/dev/missing');
  assert.deepEqual((devMissing.missing as { key: string; in: string[] }[]).map(({ key, in: where }) => [key, where]), [['AREF', ['dev2']], ['C', ['staging']], ['Y', ['staging']], ['Z', ['staging']]]);
});
