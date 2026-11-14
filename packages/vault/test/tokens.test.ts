// Making a token (src/ops/signin.ts, docs/design/0.16.md, "Signing in"): a
// person's personal token, a handle, a service account's token, each with
// its scope sealed on its row. Through the contract as the app calls it,
// with the signer reading what it wrote.
import assert from 'node:assert/strict';
import { after, beforeEach, test } from 'node:test';

import { PERMISSIONS } from '@coffre/core/access';
import type { Asked, Presented } from '@coffre/core/vault';
import { rowsOf } from '@coffre/db/dialect';
import { environments, grants, principals, roles } from '@coffre/db/schema';
import { sql, type SQL } from 'drizzle-orm';

import { change, commit, drop, part, prepare } from '../src/change.ts';
import { entryOf } from '../src/entry.ts';
import { openLocalVault } from '../src/local.ts';
import { OPERATIONS } from '../src/ops/index.ts';
import { Signer } from '../src/signer.ts';
import { emptyDatabase, memoryStore, openTestVault } from './database.ts';
import { amend, binding, credential, environment, grant, instance, principal, project, role, rows, secret, session, TABLES, tokenOf, user, value, write } from './world.ts';

const world = await openTestVault();
const vault = openLocalVault(world.db, world, { wake: world.wake, now: world.now });
after(() => world.close());

const [root, ada, bo, cy, dee] = [user('root'), user('ada'), user('bo'), user('cy'), user('dee')];
const [ci, both, bare, gone] = ['token:ci', 'token:both', 'token:bare', 'token:gone'];
let signer: Signer;
/** The rows' ids, by name. */
const ids: Record<string, string> = {};

const read = ['secret.read', 'secret.use'];
const DEVELOPER = { normal: ['secret.read', 'secret.use', 'secret.write'], protected: ['secret.use', 'secret.write'] };
const VIEWER = { normal: read, protected: ['secret.use'] };

/**
 * Root owns the instance. market has dev, staging (a fork of dev) and a
 * protected prod; billing has dev. Ada is an Owner of market by a grant,
 * and a Viewer of billing/dev; Bo a Developer of market/dev; Cy a
 * Developer of all market; Dee a Developer of market/staging alone. market's
 * orphan is a fork of an environment since deleted. The service account `ci` holds Developer on
 * market/dev and Viewer on market/prod; `both` Viewer on market/dev and
 * billing/dev, admitted by Ada; `bare` nothing, admitted by Ada; `gone`
 * was removed. Each place holds DATABASE_URL.
 */
beforeEach(async () => {
  await emptyDatabase(world.owner);
  for (const kept of [world.memory.reads, world.memory.callers, world.memory.logged, world.memory.touched, world.refused]) kept.clear();
  world.woken.length = 0;
  signer = await Signer.open({ db: world.db, keys: world.keys, now: world.now, store: memoryStore(), keepUsesDays: 90 });
  const [market, billing] = [project('market'), project('billing')];
  const dev = environment(market, 'dev');
  const staging = environment(market, 'staging', { parentId: dev.id });
  const prod = environment(market, 'prod', { protected: true });
  const billingDev = environment(billing, 'dev');
  const tomb = environment(market, 'old~5f3a');
  const orphan = environment(market, 'orphan', { parentId: tomb.id });
  Object.assign(ids, { market: market.id, billing: billing.id, dev: dev.id, staging: staging.id, prod: prod.id, billingDev: billingDev.id });
  const made = [
    credential('root-cli', root),
    credential('ada-cli', ada),
    credential('bo-cli', bo),
    credential('cy-cli', cy),
    credential('dee-cli', dee),
    credential('cy-pat', cy, { kind: 'personal', scope: JSON.stringify([{ projectId: market.id, environmentId: dev.id, role: 'viewer', permissions: VIEWER }]), expiresAt: new Date(world.now() + 3_600_000) }),
    credential('cy-handle', cy, { kind: 'handle', scope: '[]', places: '[]' }),
    credential('ci-token', ci, { scope: '[]', createdBy: root }),
  ];
  for (const row of made) ids[row.label!] = row.id;
  await write(
    world,
    ...rows('roles', role(true, 'owner', [...PERMISSIONS]), role(true, 'member', []), role(false, 'owner', [...PERMISSIONS]), role(false, 'developer', DEVELOPER.normal, DEVELOPER.protected),
      role(false, 'viewer', VIEWER.normal, VIEWER.protected), role(false, 'reader', ['secret.read']), role(false, 'admin', ['grant.manage', 'project.manage']), role(false, 'keeper', ['environment.manage'])),
    ...rows('principals', principal(root, { role: 'owner' }), principal(ada), principal(bo), principal(cy), principal(dee), principal(ci), principal(both, { statusChangedBy: ada }), principal(bare, { statusChangedBy: ada }), principal(gone, { status: 'removed', generation: 1 })),
    ...rows('projects', market, billing),
    ...rows('environments', dev, staging, prod, billingDev, tomb, orphan),
    ...rows('grants', grant(ada, 'owner', { project: market }), grant(ada, 'viewer', { environment: billingDev }), grant(bo, 'developer', { environment: dev }), grant(cy, 'developer', { project: market }), grant(dee, 'developer', { environment: staging }),
      grant(ci, 'developer', { environment: dev }), grant(ci, 'viewer', { environment: prod }), grant(both, 'viewer', { environment: dev }), grant(both, 'viewer', { environment: billingDev })),
    ...rows('secrets', ...[dev, staging, prod, billingDev].map((place) => value(world, secret(place, 'DATABASE_URL'), `postgres://${place.slug}`))),
    ...rows('policy', instance()),
    ...rows('credentials', ...made),
  );
  // The signer has signed the instance as made: what it finds after is a test's own.
  assert.deepEqual(await checked(), []);
});

const from = { request: 'req-1', ip: '192.0.2.7' };
const shown = (label: string): Presented => ({ token: tokenOf(label).toString('hex'), proof: null, ...from });
const made = (minutes = 60, label: string | null = 'deploy') => ({ token: tokenOf('minted').toString('hex'), minutes, label });
const personal = (label: string, scope: Record<string, string>, minutes = 60) => ({ ...shown(label), op: 'token.create', kind: 'personal', credential: made(minutes), hint: 'coffre_pat_…Ab_9', scope }) as Asked<'token.create'>;
const handle = (label: string, paths: string[], minutes = 60) => ({ ...shown(label), op: 'token.create', kind: 'handle', credential: made(minutes, 'run'), hint: 'coffre_use_…Ab_9', paths }) as Asked<'token.create'>;
const serviceToken = (label: string, member: string, scope: Record<string, string> | null = null, minutes = 60) =>
  ({ ...shown(label), op: 'token.create', kind: 'service', credential: made(minutes, null), hint: 'coffre_svc_…Ab_9', member, scope }) as Asked<'token.create'>;
const deciding = { workloads: world.workloads, owners: world.owners };

/** The token made, as the vault answers a request that shows it, and its row. */
const minted = async () => {
  world.memory.callers.clear();
  const answer = await vault.caller(shown('minted'));
  const [row] = await rowsOf<{ kind: string; principal: string; generation: number; scope: string; places: string | null; label: string | null; token_hint: string; created_by: string; expires_at: Date }>(world.owner,
    sql`SELECT kind, principal, generation, scope, places, label, token_hint, created_by, expires_at FROM credentials WHERE token_hash = ${tokenOf('minted')}`);
  return { who: 'refused' in answer ? answer.refused : `${answer.principal} ${answer.credential.kind}`, row: row!, scope: row === undefined ? [] : (JSON.parse(row.scope) as unknown[]) };
};
/** What a use of `<place>`'s DATABASE_URL by the token made is answered: the value, or why not. */
const uses = async (place: string, label = 'minted') => {
  const [projectSlug, environmentSlug] = place.split('/');
  const answer = await vault.use({ ...shown(label), project: projectSlug!, environment: environmentSlug!, mine: false, keys: ['DATABASE_URL'], purpose: 'reveal', upstream: null });
  return 'refused' in answer ? answer.refused : answer.values.map((item) => ('refused' in item ? item.refused : item.value))[0];
};
/** The entries written, oldest first; `made`, the last `token.create`. */
const entries = async () => (await rowsOf<{ kept: boolean; body: string; mac: Buffer }>(world.owner, sql`SELECT kept, body, mac FROM log_pending ORDER BY id`)).map((row) => ({ kept: row.kept, ...entryOf(world.keys, row)! }));
const lastMade = async () => (await entries()).filter((entry) => entry.action === 'token.create').at(-1)!;
const count = async () => (await rowsOf<{ n: number }>(world.owner, sql`SELECT count(*)::int AS n FROM credentials`))[0]!.n;
/** Everything the vault told the signer of, signed, and the rows held to its mirror: what it found. */
async function checked() {
  for (const hash of world.woken.splice(0)) await signer.wake(hash);
  await signer.run(true);
  return (await signer.take()).map((finding) => finding.found);
}
/** One change that deletes the rows a condition finds, as a revocation of a grant does. */
async function dropped(table: keyof typeof TABLES, where: SQL) {
  const result = await change(world, {
    read: { found: part(TABLES[table], where) },
    decide: ({ found }) => ({ writes: found.map((row) => drop(TABLES[table], row as never)), entry: { kept: true, action: 'test.write', actor: null, credential: null, request: null, ip: null, objects: [], detail: {} }, answer: null }),
  });
  assert.ok(!('refused' in result));
}
/** Rows edited behind the vault: their MAC no longer the vault's. Undone by what it returns, which puts each MAC back. */
async function forged(table: string, where: SQL): Promise<() => Promise<void>> {
  const was = await rowsOf<{ mac: Buffer }>(world.owner, sql`SELECT mac FROM ${sql.identifier(table)} WHERE ${where}`);
  assert.equal(was.length, 1);
  await world.owner.execute(sql`UPDATE ${sql.identifier(table)} SET mac = decode(repeat('00', 36), 'hex') WHERE ${where}`);
  return async () => void (await world.owner.execute(sql`UPDATE ${sql.identifier(table)} SET mac = ${was[0]!.mac} WHERE ${where}`));
}
/** A row taken away behind the vault, as it was. Put back by what it returns, its MAC the vault's own. */
async function hidden(table: string, where: SQL): Promise<() => Promise<void>> {
  await world.owner.execute(sql`DROP TABLE IF EXISTS hidden_rows`);
  await world.owner.execute(sql`CREATE TABLE hidden_rows AS SELECT * FROM ${sql.identifier(table)} WHERE ${where}`);
  await world.owner.execute(sql`DELETE FROM ${sql.identifier(table)} WHERE ${where}`);
  return async () => {
    await world.owner.execute(sql`INSERT INTO ${sql.identifier(table)} SELECT * FROM hidden_rows`);
    await world.owner.execute(sql`DROP TABLE hidden_rows`);
  };
}

test('a personal token: a person on a session, for themselves, within what they hold; its scope sealed by place id, kept no wider than they hold', async () => {
  const done = await vault.change(personal('bo-cli', { 'market/dev': 'viewer' }));
  assert.ok(!('refused' in done), JSON.stringify(done));
  const { credential: id, expiresAt, ...answer } = done.answer;
  assert.deepEqual(answer, { principal: bo, scope: { 'market/dev': 'viewer' } });
  assert.equal(expiresAt, new Date(world.now() + 3_600_000).toISOString());
  const { who, row, scope } = await minted();
  assert.equal(who, `${bo} personal`);
  assert.deepEqual([row.kind, row.principal, row.generation, row.label, row.token_hint, row.created_by, row.places], ['personal', bo, 0, 'deploy', 'coffre_pat_…Ab_9', bo, null]);
  // Viewer as the role holds it, no more than Bo holds at dev in each column.
  assert.deepEqual(scope, [{ projectId: ids.market, environmentId: ids.dev, role: 'viewer', permissions: VIEWER }]);
  assert.deepEqual([await uses('market/dev'), await uses('market/prod')], ['postgres://dev', 'no_access']);
  const entry = await lastMade();
  assert.deepEqual([entry.kept, entry.action, entry.actor, entry.credential, entry.request, entry.ip], [true, 'token.create', bo, ids['bo-cli'], 'req-1', '192.0.2.7']);
  // Ids and kinds: never its label, which the caller typed, nor its token.
  assert.deepEqual(entry.detail, { credential: id, kind: 'personal', principal: bo, expiresAt, scope });
  assert.deepEqual(entry.objects, [`principal:${bo}`, `credential:${ids['bo-cli']}`, `credential:${id}`, `environment:${ids.dev}`]);
  // A Reader reads where nothing is protected, and in a protected one: Bo only uses there, so the token keeps no read in its protected column.
  await dropped('credentials', sql`token_hash = ${tokenOf('minted')}`);
  assert.ok(!('refused' in await vault.change(personal('bo-cli', { 'market/dev': 'reader' }))));
  assert.deepEqual((await minted()).scope, [{ projectId: ids.market, environmentId: ids.dev, role: 'reader', permissions: { normal: ['secret.read'], protected: [] } }]);
  assert.deepEqual(await checked(), []);
});

test("a personal token on a project keeps each column of what its person holds there, and reaches its protected environments only where they hold the role's protected column", async () => {
  // Cy, a Developer of all market: Viewer of market uses prod, as Cy does.
  const done = await vault.change(personal('cy-cli', { market: 'viewer', 'billing': 'viewer' }));
  assert.deepEqual(done, { refused: 'no_access' });
  const ok = await vault.change(personal('cy-cli', { market: 'viewer' }));
  assert.ok(!('refused' in ok));
  assert.deepEqual((await minted()).scope, [{ projectId: ids.market, environmentId: null, role: 'viewer', permissions: VIEWER }]);
  assert.deepEqual([await uses('market/dev'), await uses('market/prod')], ['postgres://dev', 'no_access']);
  // A Reader reads prod too, which Cy does not: the token would reach past them.
  await dropped('credentials', sql`token_hash = ${tokenOf('minted')}`);
  assert.deepEqual(await vault.change(personal('cy-cli', { market: 'reader' })), { refused: 'no_access' });
  assert.deepEqual(await vault.change(personal('cy-cli', { 'market/prod': 'reader' })), { refused: 'no_access' });
});

test('a personal token names what it reaches: a role there is, that its place takes and that manages no access; a place there is and that they hold all of', async () => {
  const before = await count();
  for (const [scope, refused] of [
    [{ 'market/dev': 'ghost' }, 'invalid'],
    [{ 'market/dev': 'admin' }, 'invalid'],
    [{ market: 'owner' }, 'invalid'],
    [{ 'market/dev': 'keeper' }, 'invalid'],
    [{ 'market/dev': 'viewer', 'market/prod': 'admin' }, 'invalid'],
    [{ 'market/nope': 'viewer' }, 'no_access'],
    [{ nope: 'viewer' }, 'no_access'],
    [{ 'market/prod': 'viewer' }, 'no_access'],
    [{ market: 'viewer' }, 'no_access'],
    [{ 'market/dev': 'viewer', 'billing/dev': 'viewer' }, 'no_access'],
  ] as const) {
    assert.deepEqual(await vault.change(personal('bo-cli', scope)), { refused }, JSON.stringify(scope));
  }
  assert.equal(await count(), before);
  // Refused to a caller who stands: logged once a minute for whoever asked and what, with the places found.
  const logged = (await entries()).filter((entry) => entry.action === 'token.create');
  assert.deepEqual(logged.map((entry) => [entry.kept, entry.actor, entry.detail.refused]), [[false, bo, 'invalid']]);
  assert.deepEqual(logged[0]!.objects, [`principal:${bo}`, `credential:${ids['bo-cli']}`, `environment:${ids.dev}`]);
  assert.deepEqual(await checked(), []);
});

test('only a person on a session makes a personal token: a token never makes another, a service has its own, a workload makes none', async () => {
  const bound = binding(ci, { profile: 'kubernetes', policy: '{}' });
  await write(world, ...rows('bindings', bound), ...rows('credentials', session('ci-pod', bound)));
  const scope = { 'market/dev': 'viewer' };
  assert.deepEqual(await vault.change(personal('cy-pat', scope)), { refused: 'no_access' });
  assert.deepEqual(await vault.change(personal('ci-token', scope)), { refused: 'not_a_person' });
  assert.deepEqual(await vault.change({ ...personal('ci-pod', scope), proof: 'ci-pod' }), { refused: 'workload_cannot_issue' });
  assert.deepEqual(await vault.change({ ...handle('ci-pod', ['market/dev']), proof: 'ci-pod' }), { refused: 'workload_cannot_issue' });
  assert.deepEqual(await vault.change({ ...serviceToken('ci-pod', ci), proof: 'ci-pod' }), { refused: 'workload_cannot_issue' });
  // A handle is the proxy's: it makes nothing, and is nobody here.
  assert.deepEqual(await vault.change(personal('cy-handle', scope)), { refused: 'unauthenticated' });
  assert.deepEqual(await vault.change(handle('cy-handle', ['market/dev'])), { refused: 'unauthenticated' });
  // Nobody else's.
  assert.deepEqual(await vault.change(personal('nobody', scope)), { refused: 'unauthenticated' });
  assert.equal((await minted()).row, undefined);
});

test("a handle reaches each environment named and each parent it inherits from that its person reads or uses: viewer where they read, contributor where they only use; it ages out", async () => {
  const done = await vault.change(handle('cy-cli', ['market/staging', 'market/prod@me', 'market/staging']));
  assert.ok(!('refused' in done), JSON.stringify(done));
  assert.deepEqual(done.answer.scope, { 'market/dev': 'viewer', 'market/prod': 'contributor', 'market/staging': 'viewer' });
  const { who, row, scope } = await minted();
  assert.equal(who, 'unauthenticated');
  assert.deepEqual([row.kind, row.principal, row.label, row.token_hint], ['handle', cy, 'run', 'coffre_use_…Ab_9']);
  // Each place keeps what Cy holds there of reading and using, in each column: a Developer of a protected prod only uses it.
  const capped = { normal: read, protected: ['secret.use'] };
  const expected = [
    { projectId: ids.market, environmentId: ids.dev, role: 'viewer', permissions: capped },
    { projectId: ids.market, environmentId: ids.prod, role: 'contributor', permissions: capped },
    { projectId: ids.market, environmentId: ids.staging, role: 'viewer', permissions: capped },
  ].sort((a, b) => (`${a.projectId}/${a.environmentId}` < `${b.projectId}/${b.environmentId}` ? -1 : 1));
  assert.deepEqual(scope, expected);
  assert.deepEqual(JSON.parse(row.places!), [{ environmentId: ids.staging, personal: false }, { environmentId: ids.prod, personal: true }]);
  const entry = await lastMade();
  assert.deepEqual([entry.kept, entry.action, entry.actor], [false, 'token.create', cy]);
  assert.deepEqual(entry.detail.places, JSON.parse(row.places!));
  // A place its person holds nothing in, a parent included, is not one it reaches: Bo holds dev alone.
  await dropped('credentials', sql`token_hash = ${tokenOf('minted')}`);
  assert.deepEqual(await vault.change(handle('bo-cli', ['market/staging'])), { refused: 'no_access' });
  assert.deepEqual(await vault.change(handle('bo-cli', ['market/nope'])), { refused: 'no_access' });
  const own = await vault.change(handle('bo-cli', ['market/dev']));
  assert.ok(!('refused' in own));
  assert.deepEqual(own.answer.scope, { 'market/dev': 'viewer' });
  // A parent its person holds nothing in is left out, as a read leaves it; a deleted one is no parent.
  await dropped('credentials', sql`token_hash = ${tokenOf('minted')}`);
  const staged = await vault.change(handle('dee-cli', ['market/staging']));
  assert.ok(!('refused' in staged));
  assert.deepEqual(staged.answer.scope, { 'market/staging': 'viewer' });
  await dropped('credentials', sql`token_hash = ${tokenOf('minted')}`);
  const orphaned = await vault.change(handle('cy-cli', ['market/orphan']));
  assert.ok(!('refused' in orphaned));
  assert.deepEqual(orphaned.answer.scope, { 'market/orphan': 'viewer' });
  assert.deepEqual(await checked(), []);
});

test('a handle on a personal token reaches nothing past it, and ends when it does', async () => {
  assert.deepEqual(await vault.change(handle('cy-pat', ['market/staging'])), { refused: 'no_access' });
  const done = await vault.change(handle('cy-pat', ['market/dev'], 7 * 24 * 60));
  assert.ok(!('refused' in done));
  // An hour left on the token: the handle ends with it.
  assert.equal(done.answer.expiresAt, new Date(world.now() + 3_600_000).toISOString());
  assert.deepEqual((await minted()).scope, [{ projectId: ids.market, environmentId: ids.dev, role: 'viewer', permissions: { normal: read, protected: ['secret.use'] } }]);
  // Nor does a service's token make one for anyone.
  assert.deepEqual(await vault.change(handle('ci-token', ['market/dev'])), { refused: 'not_a_person' });
  assert.deepEqual(await checked(), []);
});

test("a service's token, asked nothing: every grant it holds, sealed explicitly, each place reading sensitive values only if its maker is an Owner of its project", async () => {
  const done = await vault.change(serviceToken('root-cli', ci, null, 366 * 24 * 60));
  assert.ok(!('refused' in done), JSON.stringify(done));
  const { credential: id, expiresAt, ...answer } = done.answer;
  assert.deepEqual(answer, { principal: ci, scope: { 'market/dev': 'developer', 'market/prod': 'viewer' } });
  assert.equal(expiresAt, new Date(world.now() + 366 * 86_400_000).toISOString());
  const { who, row, scope } = await minted();
  assert.equal(who, `${ci} service`);
  assert.deepEqual([row.kind, row.principal, row.label, row.created_by, row.token_hint], ['service', ci, null, root, 'coffre_svc_…Ab_9']);
  const expected = [
    { projectId: ids.market, environmentId: ids.dev, role: 'developer', permissions: DEVELOPER, sensitive: true },
    { projectId: ids.market, environmentId: ids.prod, role: 'viewer', permissions: VIEWER, sensitive: true },
  ].sort((a, b) => (a.environmentId! < b.environmentId! ? -1 : 1));
  assert.deepEqual(scope, expected);
  assert.deepEqual([await uses('market/dev'), await uses('market/prod'), await uses('market/staging')], ['postgres://dev', 'postgres://prod', 'no_access']);
  const entry = await lastMade();
  assert.deepEqual([entry.kept, entry.action, entry.actor], [true, 'token.create', root]);
  assert.deepEqual(entry.detail, { credential: id, kind: 'service', principal: ci, expiresAt, scope });
  assert.ok(entry.objects.includes(`principal:${ci}`));
  assert.deepEqual(await checked(), []);
});

test("R32 as 0.14.7 had it: an Owner of one project by a grant issues a token that reads that project's sensitive values, and not another's", async () => {
  const done = await vault.change(serviceToken('ada-cli', both));
  assert.ok(!('refused' in done), JSON.stringify(done));
  const sensitive = Object.fromEntries((await minted()).scope.map((grant) => [(grant as { projectId: string }).projectId, (grant as { sensitive: boolean }).sensitive]));
  assert.deepEqual(sensitive, { [ids.market!]: true, [ids.billing!]: false });
});

test("a service's token, asked a scope: each place one the service holds, every permission of its role, and one its maker could give it", async () => {
  const ok = await vault.change(serviceToken('root-cli', ci, { 'market/dev': 'viewer' }));
  assert.ok(!('refused' in ok));
  assert.deepEqual((await minted()).scope, [{ projectId: ids.market, environmentId: ids.dev, role: 'viewer', permissions: VIEWER, sensitive: true }]);
  await dropped('credentials', sql`token_hash = ${tokenOf('minted')}`);
  // A role the service holds no grant of, by its own row.
  assert.ok(!('refused' in await vault.change(serviceToken('root-cli', ci, { 'market/dev': 'reader' }))));
  assert.deepEqual((await minted()).scope, [{ projectId: ids.market, environmentId: ids.dev, role: 'reader', permissions: { normal: ['secret.read'], protected: ['secret.read'] }, sensitive: true }]);
  await dropped('credentials', sql`token_hash = ${tokenOf('minted')}`);
  for (const [scope, refused] of [
    [{ 'market/staging': 'viewer' }, 'no_access'],
    [{ market: 'viewer' }, 'no_access'],
    [{ 'market/prod': 'developer' }, 'no_access'],
    [{ 'market/nope': 'viewer' }, 'no_access'],
    [{ 'market/dev': 'ghost' }, 'invalid'],
    [{ 'market/dev': 'admin' }, 'invalid'],
    [{ 'market/dev': 'keeper' }, 'invalid'],
  ] as const) {
    assert.deepEqual(await vault.change(serviceToken('root-cli', ci, scope)), { refused }, JSON.stringify(scope));
  }
  assert.deepEqual(await checked(), []);
});

test("who manages a service makes its tokens: who runs the instance, or a person who holds all it holds; nobody makes one of a service that holds nothing, or is gone", async () => {
  // Bo holds dev, not prod; Cy holds prod's protected column, which gives a service nothing to read there.
  for (const label of ['bo-cli', 'cy-cli', 'ci-token']) assert.deepEqual(await vault.change(serviceToken(label, ci)), { refused: 'no_access' }, label);
  // Ada admitted bare, which holds nothing: nothing to reach, for her as for root.
  assert.deepEqual(await vault.change(serviceToken('ada-cli', bare)), { refused: 'no_grants' });
  assert.deepEqual(await vault.change(serviceToken('root-cli', bare)), { refused: 'no_grants' });
  assert.deepEqual(await vault.change(serviceToken('bo-cli', bare)), { refused: 'no_access' });
  // Removed, or never there: told so only who runs the instance; anyone else, as for one they do not manage.
  for (const member of [gone, 'token:nobody']) {
    assert.deepEqual(await vault.change(serviceToken('root-cli', member)), { refused: 'unknown_principal' }, member);
    assert.deepEqual(await vault.change(serviceToken('ada-cli', member)), { refused: 'no_access' }, member);
  }
  // A strict instance makes no service a bearer token.
  const strict = openLocalVault(world.db, { ...world, workloads: { noReads: false, useOnly: true } }, { wake: world.wake, now: world.now });
  assert.deepEqual(await strict.change(serviceToken('root-cli', ci)), { refused: 'use_only' });
  assert.equal((await minted()).row, undefined);
});

test("a service's token manages no service, even one whose scope holds grant.manage: it makes no token, of another or of itself, and ends none but its own service's", async () => {
  // ops is an Admin of market, and so is its token's scope: on a session, that would manage ci.
  const ops = 'token:ops';
  const admin = ['grant.manage', 'project.manage'];
  const token = credential('ops-token', ops, { scope: JSON.stringify([{ projectId: ids.market, environmentId: null, role: 'admin', permissions: { normal: admin, protected: admin } }]), createdBy: root });
  await write(world, ...rows('principals', principal(ops)), ...rows('grants', grant(ops, 'admin', { project: { id: ids.market } })), ...rows('credentials', token));
  for (const member of [ci, ops]) assert.deepEqual(await vault.change(serviceToken('ops-token', member, null, 366 * 24 * 60)), { refused: 'no_access' }, member);
  assert.equal((await minted()).row, undefined);
  assert.deepEqual(await vault.change({ ...shown('ops-token'), op: 'credential.end', credential: ids['ci-token']!, of: { member: ci } } as Asked<'credential.end'>), { refused: 'unknown_credential' });
  assert.equal((await rowsOf<{ revoked_at: Date | null }>(world.owner, sql`SELECT revoked_at FROM credentials WHERE id = ${ids['ci-token']}::uuid`))[0]!.revoked_at, null);
  assert.deepEqual(await checked(), []);
});

test("a service's grant taken away while a token is made widens nothing: the token holds its sealed scope, each grant one its maker holds", async () => {
  // The prod grant hidden, Bo, a Developer of dev, manages ci: the read says it holds dev alone.
  const putBack = await hidden('grants', sql`principal = ${ci} AND environment_id = ${ids.prod}::uuid`);
  const done = await vault.change(serviceToken('bo-cli', ci));
  assert.ok(!('refused' in done), JSON.stringify(done));
  assert.deepEqual(done.answer.scope, { 'market/dev': 'developer' });
  await putBack();
  assert.deepEqual((await minted()).scope, [{ projectId: ids.market, environmentId: ids.dev, role: 'developer', permissions: DEVELOPER, sensitive: false }]);
  // Back, the grant reaches no token made without it.
  assert.deepEqual([await uses('market/dev'), await uses('market/prod')], ['postgres://dev', 'no_access']);
  // The entry says who made it, kept.
  const entry = await lastMade();
  assert.deepEqual([entry.kept, entry.actor, entry.detail.principal], [true, bo, ci]);
});

test('a row the decision reads that is not the vault\'s refuses it, tampered: a grant, an environment, a role, the policy', async () => {
  const cases: [string, SQL, Asked<'token.create'>][] = [
    ['grants', sql`principal = ${ci} AND environment_id = ${ids.prod}::uuid`, serviceToken('bo-cli', ci)],
    ['grants', sql`principal = ${ci} AND environment_id = ${ids.prod}::uuid`, serviceToken('root-cli', ci)],
    ['environments', sql`id = ${ids.prod}::uuid`, serviceToken('cy-cli', ci, { 'market/dev': 'viewer' })],
    ['environments', sql`id = ${ids.prod}::uuid`, personal('cy-cli', { market: 'viewer' })],
    ['environments', sql`id = ${ids.dev}::uuid`, handle('cy-cli', ['market/staging'])],
    ['grants', sql`principal = ${cy}`, personal('cy-cli', { 'market/dev': 'viewer' })],
    ['roles', sql`id = 'viewer' AND NOT instance`, personal('cy-cli', { 'market/dev': 'viewer' })],
    ['policy', sql`only_row`, serviceToken('bo-cli', both)],
  ];
  for (const [table, where, asked] of cases) {
    const undo = await forged(table, where);
    assert.deepEqual(await vault.change(asked), { refused: 'tampered' }, `${table} ${asked.kind}`);
    await undo();
  }
  assert.equal((await minted()).row, undefined);
});

test('a grant of the caller revoked, a role edited, an environment protected or a service removed and back, between the read and the write, starts the change over', async () => {
  const make = (asked: Asked<'token.create'>) => prepare(world, OPERATIONS['token.create'](asked, deciding));
  // Bo's grant revoked: refused when it starts over.
  let prepared = await make(personal('bo-cli', { 'market/dev': 'viewer' }));
  assert.ok(!('refused' in prepared));
  await dropped('grants', sql`${grants.principal} = ${bo}`);
  assert.equal(await commit(world, prepared), false);
  assert.deepEqual(await vault.change(personal('bo-cli', { 'market/dev': 'viewer' })), { refused: 'no_access' });
  // The role asked edited.
  prepared = await make(personal('cy-cli', { 'market/dev': 'viewer' }));
  assert.ok(!('refused' in prepared));
  await amend(world, 'roles', sql`${roles.id} = 'viewer' AND NOT ${roles.instance}`, { permissions: ['secret.read', 'secret.use', 'secret.write'] });
  assert.equal(await commit(world, prepared), false);
  // An environment of the project protected: Cy holds less in it.
  prepared = await make(personal('cy-cli', { market: 'developer' }));
  assert.ok(!('refused' in prepared));
  await amend(world, 'environments', sql`${environments.id} = ${ids.staging}::uuid`, { protected: true });
  assert.equal(await commit(world, prepared), false);
  // A handle's parent protected: the parent it reads.
  prepared = await make(handle('cy-cli', ['market/staging']));
  assert.ok(!('refused' in prepared));
  await amend(world, 'environments', sql`${environments.id} = ${ids.dev}::uuid`, { protected: true });
  assert.equal(await commit(world, prepared), false);
  // The service removed and let back in: a new generation, which the token must be of.
  prepared = await make(serviceToken('root-cli', ci));
  assert.ok(!('refused' in prepared));
  await amend(world, 'principals', sql`${principals.id} = ${ci}`, { status: 'removed', generation: 1 });
  await amend(world, 'principals', sql`${principals.id} = ${ci}`, { status: 'active' });
  assert.equal(await commit(world, prepared), false);
  // Its grants were of the generation before: it holds nothing now.
  assert.deepEqual(await vault.change(serviceToken('root-cli', ci)), { refused: 'no_grants' });
  // A grant given to the service meanwhile: what Bo must hold to manage it.
  await write(world, ...rows('grants', grant(bo, 'viewer', { environment: { id: ids.billingDev! } })));
  prepared = await make(serviceToken('ada-cli', both));
  assert.ok(!('refused' in prepared));
  await write(world, ...rows('grants', grant(both, 'viewer', { environment: { id: ids.staging! } })));
  assert.equal(await commit(world, prepared), false);
  assert.equal((await minted()).row, undefined);
  assert.deepEqual(await checked(), []);
});

test("a token's hash is one credential's: of two made at once with the same, one is made", async () => {
  const [a, b] = await Promise.all([vault.change(personal('cy-cli', { 'market/dev': 'viewer' })), vault.change(personal('bo-cli', { 'market/dev': 'viewer' }))].map((call) => call.then((answer) => answer, (error: Error) => error)));
  assert.equal([a, b].filter((answer) => !(answer instanceof Error) && !('refused' in answer)).length, 1, JSON.stringify([a, b]));
});

test('what the contract takes is checked before anything is read: a fault, never a refusal', async () => {
  const scope = { 'market/dev': 'viewer' };
  const faults: unknown[] = [
    { ...personal('bo-cli', scope), kind: 'session' },
    { ...personal('bo-cli', scope), credential: { ...made(), token: 'abc' } },
    personal('bo-cli', scope, 0),
    personal('bo-cli', scope, 7 * 24 * 60 + 1),
    serviceToken('root-cli', ci, null, 366 * 24 * 60 + 1),
    { ...personal('bo-cli', scope), credential: { ...made(), label: null } },
    { ...personal('bo-cli', scope), credential: { ...made(), label: ' deploy' } },
    { ...personal('bo-cli', scope), credential: { ...made(), label: 'a\u0007b' } },
    { ...personal('bo-cli', scope), credential: { ...made(), label: 'x'.repeat(121) } },
    { ...personal('bo-cli', scope), hint: 'coffre_svc_…Ab_9' },
    { ...personal('bo-cli', scope), hint: 'coffre_pat_…Ab' },
    personal('bo-cli', {}),
    personal('bo-cli', Object.fromEntries(Array.from({ length: 1001 }, (_, i) => [`p${i}`, 'viewer']))),
    personal('bo-cli', { 'market/dev/x': 'viewer' }),
    personal('bo-cli', { 'Market/dev': 'viewer' }),
    personal('bo-cli', { 'market/dev~1': 'viewer' }),
    personal('bo-cli', { 'market/dev': 'Viewer' }),
    personal('bo-cli', { 'market/dev': 3 } as never),
    { ...personal('bo-cli', scope), scope: [['market/dev', 'viewer']] },
    handle('cy-cli', []),
    handle('cy-cli', ['market']),
    handle('cy-cli', ['market/dev@you']),
    handle('cy-cli', Array.from({ length: 1001 }, () => 'market/dev')),
    { ...handle('cy-cli', ['market/dev']), paths: 'market/dev' },
    serviceToken('root-cli', bo),
    serviceToken('root-cli', 'token:'),
    serviceToken('root-cli', ci, {}),
    { ...serviceToken('root-cli', ci), scope: undefined },
    { ...personal('bo-cli', scope), credential: 'nope' },
  ];
  for (const asked of faults) await assert.rejects(vault.change(asked as Asked<'token.create'>), TypeError, JSON.stringify(asked).slice(0, 200));
  assert.equal((await entries()).length, 0);
});
