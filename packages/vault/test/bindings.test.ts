// Trusting a workload as a service, and no longer (src/ops/bindings.ts, docs/design/0.16.md, "A workload signing in"):
// a binding made, replacing others, its keys replaced, one removed. Through the contract as the app calls it, with the
// signer reading what it wrote.
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { after, beforeEach, test } from 'node:test';

import { PERMISSIONS } from '@coffre/core/access';
import { CARRIED, canonicalClaims, MAX_BINDINGS } from '@coffre/core/identity';
import type { Asked, NewBinding, Presented } from '@coffre/core/vault';
import { rowsOf } from '@coffre/db/dialect';
import { sql, type SQL } from 'drizzle-orm';

import { change, drop, part, prepare, written } from '../src/change.ts';
import { entryOf } from '../src/entry.ts';
import { openLocalVault } from '../src/local.ts';
import { OPERATIONS } from '../src/ops/index.ts';
import { Signer } from '../src/signer.ts';
import { emptyDatabase, memoryStore, openTestVault } from './database.ts';
import { binding, credential, environment, grant, instance, principal, project, role, rows, secret, TABLES, tokenOf, user, value, write } from './world.ts';

const world = await openTestVault();
const vault = openLocalVault(world.db, world, { wake: world.wake, now: world.now });
after(() => world.close());

const [root, ada, bo, cy] = [user('root'), user('ada'), user('bo'), user('cy')];
const [ci, devs, bare, gone] = ['token:ci', 'token:devs', 'token:bare', 'token:gone'];
const KUBE = 'https://kubernetes.acme.example';
const KEYS = `${KUBE}/openid/v1/jwks`;
const POD = { sub: 'system:serviceaccount:ci:runner' };
let signer: Signer;
/** The rows' ids, by name. */
const ids: Record<string, string> = {};

const DEVELOPER = { normal: ['secret.read', 'secret.use', 'secret.write'], protected: ['secret.use', 'secret.write'] };
const VIEWER = { normal: ['secret.read', 'secret.use'], protected: ['secret.use'] };

/**
 * Root owns the instance. market has dev and a protected prod; billing has
 * dev. Ada is an Owner of market by a grant; Bo a Developer of market/dev;
 * Cy a Developer of all market. The service `ci` holds Developer on
 * market/dev and Viewer on market/prod; `devs` Developer on market/dev;
 * `bare` nothing; `gone` was removed. dev holds DATABASE_URL, the
 * sensitive TOKEN and the archived OLD; prod DATABASE_URL and the
 * sensitive STRIPE.
 */
beforeEach(async () => {
  await emptyDatabase(world.owner);
  for (const kept of [world.memory.reads, world.memory.callers, world.memory.logged, world.memory.touched, world.refused]) kept.clear();
  world.woken.length = 0;
  signer = await Signer.open({ db: world.db, keys: world.keys, now: world.now, store: memoryStore(), keepUsesDays: 90 });
  const [market, billing] = [project('market'), project('billing')];
  const dev = environment(market, 'dev');
  const prod = environment(market, 'prod', { protected: true });
  const billingDev = environment(billing, 'dev');
  Object.assign(ids, { market: market.id, billing: billing.id, dev: dev.id, prod: prod.id, billingDev: billingDev.id });
  const made = [credential('root-cli', root), credential('ada-cli', ada), credential('bo-cli', bo), credential('cy-cli', cy)];
  for (const row of made) ids[row.label!] = row.id;
  const keys = {
    devUrl: value(world, secret(dev, 'DATABASE_URL'), 'postgres://dev'),
    token: value(world, secret(dev, 'TOKEN'), 'tok', { sensitive: true }),
    old: { ...value(world, secret(dev, 'OLD'), 'old'), archivedAt: new Date(Date.UTC(2026, 0, 1)) },
    prodUrl: value(world, secret(prod, 'DATABASE_URL'), 'postgres://prod'),
    stripe: value(world, secret(prod, 'STRIPE'), 'sk', { sensitive: true }),
  };
  for (const [name, row] of Object.entries(keys)) ids[name] = row.id;
  await write(
    world,
    ...rows('roles', role(true, 'owner', [...PERMISSIONS]), role(true, 'member', []), role(false, 'owner', [...PERMISSIONS]), role(false, 'developer', DEVELOPER.normal, DEVELOPER.protected), role(false, 'viewer', VIEWER.normal, VIEWER.protected)),
    ...rows('principals', principal(root, { role: 'owner' }), principal(ada), principal(bo), principal(cy), principal(ci), principal(devs), principal(bare, { statusChangedBy: ada }), principal(gone, { status: 'removed', generation: 1 })),
    ...rows('projects', market, billing),
    ...rows('environments', dev, prod, billingDev),
    ...rows('grants', grant(ada, 'owner', { project: market }), grant(bo, 'developer', { environment: dev }), grant(cy, 'developer', { project: market }),
      grant(ci, 'developer', { environment: dev }), grant(ci, 'viewer', { environment: prod }), grant(devs, 'developer', { environment: dev })),
    ...rows('secrets', ...Object.values(keys)),
    ...rows('policy', instance()),
    ...rows('credentials', ...made),
  );
  assert.deepEqual(await checked(), []);
});

const from = { request: 'req-1', ip: '192.0.2.7' };
const shown = (label: string): Presented => ({ token: tokenOf(label).toString('hex'), proof: null, ...from });
const asked = (more: Partial<NewBinding> = {}): NewBinding => ({ profile: 'custom', issuer: KUBE, claims: POD, keys: { uri: KEYS }, policy: null, scope: null, label: 'pods', replaces: [], ...more });
const bind = (label: string, member: string, more: Partial<NewBinding> = {}) => ({ ...shown(label), op: 'token.bind', member, binding: asked(more) }) as Asked<'token.bind'>;
const rekey = (label: string, member: string, issuer: string, jwks: unknown) => ({ ...shown(label), op: 'token.bind', member, keys: { issuer, jwks } }) as Asked<'token.bind'>;
const unbind = (label: string, member: string, id: string) => ({ ...shown(label), op: 'token.unbind', member, binding: id }) as Asked<'token.unbind'>;
const deciding = { workloads: world.workloads, owners: world.owners };
/** A key set of one P-256 key, as an issuer publishes it. */
const jwksOf = (kid: string) => ({ keys: [{ ...generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ format: 'jwk' }), kid, use: 'sig', alg: 'ES256' }] });

type BindingRow = { id: string; generation: number; profile: string; issuer: string; jwks_uri: string; jwks: string | null; claims: string; scope: string; policy: string | null; label: string | null; created_at: Date; created_by: string; revoked_at: Date | null; revoked_by: string | null };
/** A service's bindings, oldest first, revoked ones too. */
const bindingsOf = async (member: string) => (await rowsOf<BindingRow>(world.owner, sql`SELECT id, generation, profile, issuer, jwks_uri, jwks, claims, scope, policy, label, created_at, created_by, revoked_at, revoked_by FROM bindings WHERE principal = ${member} ORDER BY created_at, id`))
  .map((row) => ({ ...row, created_at: new Date(row.created_at), revoked_at: row.revoked_at === null ? null : new Date(row.revoked_at) }));
const scopeOf = (row: BindingRow | undefined) => JSON.parse(row!.scope) as unknown[];
/** The entries written, oldest first. */
const entries = async () => (await rowsOf<{ kept: boolean; body: string; mac: Buffer }>(world.owner, sql`SELECT kept, body, mac FROM log_pending ORDER BY id`)).map((row) => ({ kept: row.kept, ...entryOf(world.keys, row)! }));
const last = async (action: string) => (await entries()).filter((entry) => entry.action === action).at(-1)!;
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
/** Rows edited behind the vault: their MAC no longer the vault's. Undone by what it returns. */
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
/** A binding's answer, or why not. */
const made = async (ask: Asked<'token.bind'> | Asked<'token.unbind'>) => {
  const done = await vault.change(ask as Asked<'token.bind'>);
  return 'refused' in done ? done.refused : done.answer;
};

test('a binding made: its scope all the service holds, sealed by place id; its claims, keys and policy as checked; a kept entry', async () => {
  const done = await vault.change(bind('root-cli', ci));
  assert.ok(!('refused' in done), JSON.stringify(done));
  const [row] = await bindingsOf(ci);
  assert.deepEqual(done.answer, { bindings: [{ id: row!.id, scope: { 'market/dev': 'developer', 'market/prod': 'viewer' } }], replaced: [] });
  assert.deepEqual([row!.generation, row!.profile, row!.issuer, row!.jwks_uri, row!.jwks, row!.claims, row!.policy, row!.label, row!.created_by, row!.revoked_at],
    [0, 'custom', KUBE, KEYS, null, canonicalClaims(POD), null, 'pods', root, null]);
  assert.equal(row!.created_at.getTime(), world.now());
  // Root runs the instance and so owns market: the binding reads its sensitive values.
  const both = [{ projectId: ids.market, environmentId: ids.dev, role: 'developer', permissions: DEVELOPER, sensitive: true }, { projectId: ids.market, environmentId: ids.prod, role: 'viewer', permissions: VIEWER, sensitive: true }]
    .sort((a, b) => (`${a.projectId}/${a.environmentId}` < `${b.projectId}/${b.environmentId}` ? -1 : 1));
  assert.deepEqual(scopeOf(row), both);
  const entry = await last('token.bind');
  assert.deepEqual([entry.kept, entry.actor, entry.credential, entry.request, entry.ip], [true, root, ids['root-cli'], 'req-1', '192.0.2.7']);
  assert.deepEqual(entry.detail, { binding: row!.id, principal: ci, profile: 'custom', issuer: KUBE, jwksUri: KEYS, claims: POD, scope: both, replaces: [] });
  assert.deepEqual(entry.objects, [`principal:${root}`, `credential:${ids['root-cli']}`, `principal:${ci}`, `binding:${row!.id}`, ...both.map((grant) => `environment:${grant.environmentId}`)]);
  assert.deepEqual(await checked(), []);
});

test("who binds, and what: whoever manages the service, each grant one they could give it and it holds; a non-Owner's reads no sensitive value", async () => {
  // Bo, a Developer of dev, manages devs, which holds dev alone, and not ci, which holds prod too.
  const done = await vault.change(bind('bo-cli', devs, { scope: { 'market/dev': 'viewer' } }));
  assert.ok(!('refused' in done), JSON.stringify(done));
  assert.deepEqual(scopeOf((await bindingsOf(devs))[0]), [{ projectId: ids.market, environmentId: ids.dev, role: 'viewer', permissions: VIEWER, sensitive: false }]);
  assert.equal(await made(bind('bo-cli', ci)), 'no_access');
  // A place the service does not hold, one the caller could not give, one that is not there; a role that is none.
  assert.equal(await made(bind('bo-cli', devs, { scope: { 'market/prod': 'viewer' } })), 'no_access');
  assert.equal(await made(bind('root-cli', ci, { scope: { 'billing/dev': 'viewer' } })), 'no_access');
  assert.equal(await made(bind('root-cli', ci, { scope: { 'market/qa': 'viewer' } })), 'no_access');
  assert.equal(await made(bind('root-cli', ci, { scope: { 'market/dev': 'nobody' } })), 'invalid');
  // A service removed, and one that holds nothing yet.
  assert.equal(await made(bind('root-cli', gone)), 'unknown_principal');
  assert.equal(await made(bind('root-cli', bare)), 'no_grants');
  assert.equal(await made(bind('nobody', ci)), 'unauthenticated');
  assert.equal((await bindingsOf(ci)).length, 0);
  assert.deepEqual(await checked(), []);
});

test("a service's token binds for no service, even one whose scope holds grant.manage: on a session, it would manage ci", async () => {
  const ops = 'token:ops';
  const admin = ['grant.manage', 'project.manage'];
  const token = credential('ops-token', ops, { scope: JSON.stringify([{ projectId: ids.market, environmentId: null, role: 'admin', permissions: { normal: admin, protected: admin } }]), createdBy: root });
  await write(world, ...rows('roles', role(false, 'admin', admin, admin)), ...rows('principals', principal(ops)), ...rows('grants', grant(ops, 'admin', { project: { id: ids.market! } })), ...rows('credentials', token));
  for (const member of [ci, ops]) assert.equal(await made(bind('ops-token', member)), 'no_access', member);
  assert.equal((await bindingsOf(ci)).length + (await bindingsOf(ops)).length, 0);
  assert.deepEqual(await checked(), []);
});

test("a grant of the service's hidden while a Developer of dev binds: the binding reaches dev, its sealed scope, and never prod once the grant is back", async () => {
  // Cy develops all of market, and uses prod, which is protected: Cy gives no viewer there, and does not manage ci.
  assert.equal(await made(bind('cy-cli', ci)), 'no_access');
  const back = await hidden('grants', sql`principal = ${ci} AND environment_id = ${ids.prod}`);
  const done = await vault.change(bind('cy-cli', ci));
  assert.ok(!('refused' in done), JSON.stringify(done));
  assert.equal(await made(bind('cy-cli', ci, { scope: { 'market/prod': 'viewer' }, claims: { sub: 'x' } })), 'no_access');
  await back();
  const [row] = await bindingsOf(ci);
  assert.deepEqual(scopeOf(row), [{ projectId: ids.market, environmentId: ids.dev, role: 'developer', permissions: DEVELOPER, sensitive: false }]);
  assert.deepEqual(done.answer.bindings[0]!.scope, { 'market/dev': 'developer' });
});

test('a row the decision reads that is not the vault\'s refuses, tampered: a grant, a live binding, the policy row, a key its reads list, the caller\'s own', async () => {
  const listed = { policy: { reads: { 'market/dev': ['DATABASE_URL'] } } };
  const old = binding(ci, { scope: '[]' });
  await write(world, ...rows('bindings', old));
  const cases: [string, SQL][] = [
    ['grants', sql`principal = ${ci} AND environment_id = ${ids.prod}`],
    ['bindings', sql`id = ${old.id}`],
    ['policy', sql`only_row`],
    ['secrets', sql`id = ${ids.devUrl}`],
    ['principals', sql`id = ${ci}`],
    ['credentials', sql`id = ${ids['root-cli']}`],
  ];
  for (const [table, where] of cases) {
    const undo = await forged(table, where);
    const answer = await made(bind('root-cli', ci, listed));
    await undo();
    // The caller's own credential not the vault's is no caller.
    assert.equal(answer, table === 'credentials' ? 'unauthenticated' : 'tampered', table);
  }
  assert.equal((await bindingsOf(ci)).length, 1);
  assert.ok(!('refused' in await vault.change(bind('root-cli', ci, listed))));
});

test('a binding that replaces others: those revoked, its scope what they reached and the service still holds, no more than each held', async () => {
  const first = await vault.change(bind('root-cli', ci, { scope: { 'market/dev': 'viewer' } }));
  assert.ok(!('refused' in first));
  const was = first.answer.bindings[0]!.id;
  const second = await vault.change(bind('ada-cli', ci, { claims: { sub: 'system:serviceaccount:ci:next' }, replaces: [was] }));
  assert.ok(!('refused' in second), JSON.stringify(second));
  const made_ = await bindingsOf(ci);
  const [old, now] = [was, second.answer.bindings[0]!.id].map((id) => made_.find((row) => row.id === id));
  assert.deepEqual([old!.id, old!.revoked_at?.getTime(), old!.revoked_by], [was, world.now(), ada]);
  assert.deepEqual(second.answer, { bindings: [{ id: now!.id, scope: { 'market/dev': 'viewer' } }], replaced: [was] });
  // Ada owns market: the sensitive values Root's binding read, hers reads too.
  assert.deepEqual(scopeOf(now), [{ projectId: ids.market, environmentId: ids.dev, role: 'viewer', permissions: VIEWER, sensitive: true }]);
  assert.deepEqual((await last('token.bind')).detail.replaces, [{ binding: was, why: 'asked' }]);
  // Not live any more, or none at all.
  assert.equal(await made(bind('root-cli', ci, { replaces: [was] })), 'unknown_binding');
  assert.equal(await made(bind('root-cli', ci, { replaces: ['00000000-0000-4000-8000-000000000000'] })), 'unknown_binding');

  // One that kept less than its role: what replaces it keeps no more, and no sensitive value it did not read.
  const narrow = binding(ci, { scope: JSON.stringify([{ projectId: ids.market, environmentId: ids.dev, role: 'viewer', permissions: { normal: ['secret.use'], protected: [] }, sensitive: false }]) });
  await write(world, ...rows('bindings', narrow));
  const third = await vault.change(bind('root-cli', ci, { replaces: [narrow.id], claims: { sub: 'n' } }));
  assert.ok(!('refused' in third));
  assert.deepEqual(scopeOf((await bindingsOf(ci)).find((row) => row.id === third.answer.bindings[0]!.id)), [{ projectId: ids.market, environmentId: ids.dev, role: 'viewer', permissions: { normal: ['secret.use'], protected: [] }, sensitive: false }]);

  // What they reached that the service holds no longer drops out; nothing left is refused, as two roles at one place are.
  const onProd = binding(ci, { scope: JSON.stringify([{ projectId: ids.market, environmentId: ids.prod, role: 'viewer', permissions: VIEWER }]) });
  const twoRoles = binding(ci, { scope: JSON.stringify([{ projectId: ids.market, environmentId: ids.dev, role: 'developer', permissions: DEVELOPER }]) });
  await write(world, ...rows('bindings', onProd, twoRoles));
  assert.equal(await made(bind('root-cli', ci, { replaces: [twoRoles.id, third.answer.bindings[0]!.id] })), 'invalid');
  await dropped('grants', sql`principal = ${ci} AND environment_id = ${ids.prod}`);
  assert.equal(await made(bind('root-cli', ci, { replaces: [onProd.id] })), 'invalid');

  // A place still there where the service now holds less than the role kept, the role still read by its grant on billing/dev: that grant drops out whole, the rest stays.
  const both = binding(ci, { scope: JSON.stringify([
    { projectId: ids.market, environmentId: ids.dev, role: 'developer', permissions: DEVELOPER, sensitive: false },
    { projectId: ids.billing, environmentId: ids.billingDev, role: 'viewer', permissions: VIEWER, sensitive: false },
  ]) });
  await write(world, ...rows('bindings', both), ...rows('grants', grant(ci, 'developer', { environment: { id: ids.billingDev! } })));
  await dropped('grants', sql`principal = ${ci} AND environment_id = ${ids.dev}`);
  await write(world, ...rows('grants', grant(ci, 'viewer', { environment: { id: ids.dev! } })));
  const fourth = await vault.change(bind('root-cli', ci, { replaces: [both.id], claims: { sub: 'less' } }));
  assert.ok(!('refused' in fourth), JSON.stringify(fourth));
  assert.deepEqual(fourth.answer.bindings[0]!.scope, { 'billing/dev': 'viewer' });

  // A role only the binding replaced names, no grant of the service's or the caller's: Root, who holds none, still finds it.
  const viewerOnly = binding(devs, { scope: JSON.stringify([{ projectId: ids.market, environmentId: ids.dev, role: 'viewer', permissions: VIEWER, sensitive: false }]) });
  await write(world, ...rows('bindings', viewerOnly));
  const fifth = await vault.change(bind('root-cli', devs, { replaces: [viewerOnly.id], claims: { sub: 'v' } }));
  assert.ok(!('refused' in fifth), JSON.stringify(fifth));
  assert.deepEqual(fifth.answer.bindings[0]!.scope, { 'market/dev': 'viewer' });
  assert.deepEqual(await checked(), []);
});

test("its issuer's other bindings whose keys are elsewhere go with it; one with keys uploaded, on either side, refuses; a service holds 16 at most", async () => {
  const onDev = JSON.stringify([{ projectId: ids.market, environmentId: ids.dev, role: 'viewer', permissions: VIEWER, sensitive: true }]);
  const before = binding(ci, { profile: 'custom', issuer: KUBE, jwksUri: `${KUBE}/old/jwks`, claims: canonicalClaims({ sub: 'a' }), scope: onDev });
  const elsewhere = binding(ci, { profile: 'custom', issuer: 'https://other.acme.example', jwksUri: 'https://other.acme.example/jwks', claims: canonicalClaims({ sub: 'b' }), scope: '[]' });
  await write(world, ...rows('bindings', before, elsewhere));
  const done = await vault.change(bind('root-cli', ci));
  assert.ok(!('refused' in done), JSON.stringify(done));
  // Asked no scope, it reaches what the one its issuer's move replaces did, as 0.14.7's did.
  assert.deepEqual(done.answer, { bindings: [{ id: done.answer.bindings[0]!.id, scope: { 'market/dev': 'viewer' } }], replaced: [before.id] });
  assert.deepEqual((await last('token.bind')).detail.replaces, [{ binding: before.id, why: 'keys_moved' }]);
  assert.deepEqual((await bindingsOf(ci)).filter((row) => row.revoked_at === null).map((row) => row.id).sort(), [elsewhere.id, done.answer.bindings[0]!.id].sort());

  const jwks = jwksOf('k1');
  assert.equal(await made(bind('root-cli', ci, { keys: { jwks }, claims: { sub: 'c' } })), 'keys_differ');

  await dropped('bindings', sql`principal = ${ci}`);
  const full = Array.from({ length: MAX_BINDINGS }, (_, n) => binding(ci, { profile: 'custom', issuer: KUBE, jwksUri: KEYS, claims: canonicalClaims({ sub: `s${n}` }), scope: '[]', createdAt: new Date(Date.UTC(2026, 5, 1, n)) }));
  await write(world, ...rows('bindings', ...full));
  assert.equal(await made(bind('root-cli', ci)), 'too_many_bindings');
  assert.ok(!('refused' in await vault.change(bind('root-cli', ci, { replaces: [full[0]!.id], scope: { 'market/dev': 'viewer' } }))));
});

test("a binding's reads: each environment and key found and sealed by id, within its scope; a sensitive key only an Owner's to list", async () => {
  const done = await vault.change(bind('root-cli', ci, { policy: { reads: { 'market/prod': ['STRIPE', 'DATABASE_URL'], 'market/dev': '*' } } }));
  assert.ok(!('refused' in done), JSON.stringify(done));
  const [row] = await bindingsOf(ci);
  const policy = JSON.parse(row!.policy!) as { reads: Record<string, { keys: string[] | '*' }> };
  assert.deepEqual(policy.reads, { [ids.dev!]: { keys: '*' }, [ids.prod!]: { keys: [ids.prodUrl!, ids.stripe!].sort() } });
  // Not a key on the scope: a session reads what its binding lists now.
  assert.ok(scopeOf(row).every((grant) => !Object.hasOwn(grant as object, 'reads')));

  // Bo binds devs, as a Developer of dev who owns nothing: its sensitive TOKEN is no key Bo's binding lists.
  assert.equal(await made(bind('bo-cli', devs, { policy: { reads: { 'market/dev': ['TOKEN'] } } })), 'not_owner_issued');
  assert.ok(!('refused' in await vault.change(bind('bo-cli', devs, { policy: { reads: { 'market/dev': ['DATABASE_URL'] } } }))));
  // Outside its scope, a key it does not hold, one archived, an environment that is not there.
  assert.equal(await made(bind('root-cli', devs, { policy: { reads: { 'market/prod': ['DATABASE_URL'] } } })), 'invalid');
  assert.equal(await made(bind('root-cli', devs, { policy: { reads: { 'market/dev': ['NOPE'] } } })), 'invalid');
  assert.equal(await made(bind('root-cli', devs, { policy: { reads: { 'market/dev': ['OLD'] } } })), 'invalid');
  assert.equal(await made(bind('root-cli', devs, { policy: { reads: { 'market/qa': '*' } } })), 'no_access');
  // A deployment that lets no binding list reads.
  const noReads = await prepare(world, OPERATIONS['token.bind'](bind('root-cli', devs, { policy: { reads: { 'market/dev': '*' } } }), { ...deciding, workloads: { noReads: true, useOnly: false } }));
  assert.deepEqual('refused' in noReads && noReads.refused, 'no_reads');
  assert.deepEqual(await checked(), []);
});

test('under useOnly every binding is a workload\'s, with a policy; a binding with its keys uploaded keeps them, checked, its address their digest', async () => {
  const ready = await prepare(world, OPERATIONS['token.bind'](bind('root-cli', ci), { ...deciding, workloads: { noReads: false, useOnly: true } }));
  assert.ok(!('refused' in ready));
  assert.equal(await written(world, ready), 'made');
  assert.notEqual((await bindingsOf(ci))[0]!.policy, null);

  await dropped('bindings', sql`principal = ${ci}`);
  const jwks = jwksOf('k1');
  const done = await vault.change(bind('root-cli', ci, { keys: { jwks } }));
  assert.ok(!('refused' in done), JSON.stringify(done));
  const [row] = await bindingsOf(ci);
  assert.ok(row!.jwks_uri.startsWith(CARRIED));
  assert.deepEqual(JSON.parse(row!.jwks!).keys.map((key: { kid: string }) => key.kid), ['k1']);
  assert.deepEqual(((await last('token.bind')).detail.keys as { kid: string }[]).map((key) => key.kid), ['k1']);
  // No key set, a private key, none that signs.
  assert.equal(await made(bind('root-cli', ci, { keys: { jwks: { keys: [] } }, claims: { sub: 'b' } })), 'invalid');
  const { d: _, ...pub } = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ format: 'jwk' }) as Record<string, string>;
  assert.equal(await made(bind('root-cli', ci, { keys: { jwks: { keys: [{ ...pub, d: 'x' }] } }, claims: { sub: 'b' } })), 'invalid');
});

test("new keys for a service's bindings on an issuer: each replaced by one the same but for its keys, in their order, reaching what it did", async () => {
  const VIEWER_DEV = JSON.stringify([{ projectId: ids.market, environmentId: ids.dev, role: 'viewer', permissions: VIEWER, sensitive: false }]);
  const a = binding(ci, { profile: 'custom', issuer: KUBE, jwksUri: KEYS, claims: canonicalClaims({ sub: 'a' }), scope: VIEWER_DEV, policy: '{}', label: 'a', createdAt: new Date(Date.UTC(2026, 0, 1)) });
  const b = binding(ci, { profile: 'custom', issuer: KUBE, jwksUri: KEYS, claims: canonicalClaims({ sub: 'b' }), scope: VIEWER_DEV, label: 'b', createdAt: new Date(Date.UTC(2026, 1, 1)) });
  const other = binding(ci, { profile: 'custom', issuer: 'https://other.acme.example', jwksUri: 'https://other.acme.example/jwks', claims: canonicalClaims({ sub: 'c' }), scope: VIEWER_DEV });
  await write(world, ...rows('bindings', a, b, other));
  const jwks = jwksOf('k2');
  const done = await vault.change(rekey('root-cli', ci, KUBE, jwks));
  assert.ok(!('refused' in done), JSON.stringify(done));
  assert.deepEqual(done.answer.replaced, [a.id, b.id]);
  const after = await bindingsOf(ci);
  const fresh = done.answer.bindings.map(({ id }) => after.find((row) => row.id === id)!);
  assert.deepEqual(fresh.map((row) => [row.label, row.claims, row.policy, row.created_at.getTime()]), [['a', a.claims, '{}', world.now()], ['b', b.claims, null, world.now() + 1]]);
  assert.ok(fresh.every((row) => row.jwks_uri.startsWith(CARRIED) && row.scope === VIEWER_DEV));
  assert.deepEqual(after.filter((row) => row.revoked_at !== null).map((row) => row.id).sort(), [a.id, b.id].sort());
  assert.equal((await last('token.bind')).detail.reason, 'keys_replaced');
  // The same keys again, an issuer it has none on, keys that are none, a URN profile that carries none.
  assert.equal(await made(rekey('root-cli', ci, KUBE, jwks)), 'same_keys');
  assert.equal(await made(rekey('root-cli', ci, 'https://nobody.acme.example', jwks)), 'unknown_binding');
  assert.equal(await made(rekey('root-cli', ci, KUBE, { keys: 'no' })), 'invalid');
  const aws = binding(devs, { profile: 'aws', issuer: 'urn:coffre:aws', jwksUri: 'urn:coffre:aws', claims: canonicalClaims({ account: '123456789012' }), scope: VIEWER_DEV, policy: '{}' });
  await write(world, ...rows('bindings', aws));
  assert.equal(await made(rekey('root-cli', devs, 'urn:coffre:aws', jwks)), 'invalid');
  assert.equal(await made(rekey('bo-cli', ci, KUBE, jwksOf('k3'))), 'no_access');

  // A role only its bindings name, no grant of the service's or the caller's: Root, who holds none, still finds it.
  const viewing = binding(devs, { profile: 'custom', issuer: KUBE, jwksUri: KEYS, claims: canonicalClaims({ sub: 'v' }), scope: VIEWER_DEV });
  await write(world, ...rows('bindings', viewing));
  const moved = await vault.change(rekey('root-cli', devs, KUBE, jwks));
  assert.ok(!('refused' in moved), JSON.stringify(moved));
  assert.deepEqual(moved.answer.bindings.map((made_) => made_.scope), [{ 'market/dev': 'viewer' }]);
  assert.deepEqual(await checked(), []);
});

test("an issuer and its keys' address as long as the contract carries: 2,048 characters, not a name's 256", async () => {
  const issuer = `https://id.acme.example/${'a'.repeat(250)}`;
  const done = await vault.change(bind('root-cli', ci, { issuer, keys: { uri: `${issuer}/${'k'.repeat(1000)}` } }));
  assert.ok(!('refused' in done), JSON.stringify(done));
  assert.equal((await bindingsOf(ci))[0]!.issuer, issuer);
  assert.throws(() => OPERATIONS['token.bind'](bind('root-cli', ci, { issuer: `https://id.acme.example/${'a'.repeat(2048)}` }), deciding), TypeError);
});

test('a binding removed: its row revoked, which ends what it issued; refused for one not live, another service\'s, or by one who does not manage it', async () => {
  const done = await vault.change(bind('root-cli', ci));
  assert.ok(!('refused' in done));
  const id = done.answer.bindings[0]!.id;
  const [row] = await bindingsOf(ci);
  await write(world, ...rows('credentials', credential('run', ci, { createdBy: `binding:${id}`, scope: row!.scope, expiresAt: new Date(world.now() + 300_000) })));
  const runs = async () => {
    world.memory.callers.clear();
    const answer = await vault.caller(shown('run'));
    return 'refused' in answer ? answer.refused : answer.principal;
  };
  assert.equal(await runs(), ci);
  assert.equal(await made(unbind('bo-cli', ci, id) ), 'no_access');
  const theirs = binding(devs, { scope: '[]' });
  await write(world, ...rows('bindings', theirs));
  assert.equal(await made(unbind('root-cli', ci, theirs.id) ), 'unknown_binding');
  const undo = await forged('bindings', sql`id = ${id}`);
  assert.equal(await made(unbind('root-cli', ci, id) ), 'tampered');
  await undo();
  const removed = await vault.change(unbind('root-cli', ci, id));
  assert.ok(!('refused' in removed));
  assert.deepEqual(removed.answer, { binding: id });
  assert.deepEqual((await bindingsOf(ci)).map((other) => [other.revoked_at?.getTime(), other.revoked_by]), [[world.now(), root]]);
  const entry = await last('token.unbind');
  assert.deepEqual([entry.kept, entry.actor, entry.objects, entry.detail], [true, root, [`principal:${root}`, `credential:${ids['root-cli']}`, `principal:${ci}`, `binding:${id}`], { binding: id, principal: ci, reason: 'removed' }]);
  assert.equal(await runs(), 'unauthenticated');
  assert.equal(await made(unbind('root-cli', ci, id) ), 'unknown_binding');
  assert.deepEqual(await checked(), []);
});

test('two at once: two that replace one binding, and two that would pass the most a service holds, make one each', async () => {
  const one = binding(ci, { scope: '[]' });
  await write(world, ...rows('bindings', one));
  const [x, y] = await Promise.all([made(bind('root-cli', ci, { replaces: [one.id], scope: { 'market/dev': 'viewer' }, claims: { sub: 'x' } })), made(bind('ada-cli', ci, { replaces: [one.id], scope: { 'market/dev': 'viewer' }, claims: { sub: 'y' } }))]);
  assert.deepEqual([x, y].filter((answer) => typeof answer === 'string'), ['unknown_binding']);

  await dropped('bindings', sql`principal = ${ci}`);
  const full = Array.from({ length: MAX_BINDINGS - 1 }, (_, n) => binding(ci, { profile: 'custom', issuer: KUBE, jwksUri: KEYS, claims: canonicalClaims({ sub: `s${n}` }), scope: '[]', createdAt: new Date(Date.UTC(2026, 5, 1, n)) }));
  await write(world, ...rows('bindings', ...full));
  // Each decided on the same 15, before either writes: the second's read finds a row more under the lock, and decides again.
  const first = await prepare(world, OPERATIONS['token.bind'](bind('root-cli', ci, { claims: { sub: 'p' } }), deciding));
  const second = await prepare(world, OPERATIONS['token.bind'](bind('ada-cli', ci, { claims: { sub: 'q' } }), deciding));
  assert.ok(!('refused' in first) && !('refused' in second));
  assert.deepEqual([await written(world, first), await written(world, second)], ['made', 'moved']);
  assert.equal(await made(bind('ada-cli', ci, { claims: { sub: 'q' } })), 'too_many_bindings');
  assert.equal((await bindingsOf(ci)).filter((row) => row.revoked_at === null).length, MAX_BINDINGS);
});

test('malformed asks throw before anything is read', () => {
  const ok = bind('root-cli', ci);
  const wrong: Record<string, unknown>[] = [
    { member: 'user:ada@acme.example' }, { member: 'token:' }, { keys: { issuer: KUBE, jwks: {} } },
    { binding: asked({ profile: 'nope' }) }, { binding: asked({ claims: { aud: 'x' } }) }, { binding: asked({ keys: { uri: 7 } as never }) },
    { binding: asked({ issuer: 'http://kubernetes.acme.example' }) }, { binding: asked({ scope: { 'market/dev/x': 'viewer' } }) }, { binding: asked({ scope: {} }) },
    { binding: asked({ label: ' padded ' }) }, { binding: asked({ replaces: ['nope'] }) }, { binding: asked({ replaces: Array.from({ length: MAX_BINDINGS + 1 }, () => '00000000-0000-4000-8000-000000000000') }) },
    { binding: asked({ policy: { reads: { 'market/dev': ['A'], market: ['B'] } } }) }, { binding: asked({ policy: { nope: true } }) }, { binding: asked({ policy: [] as never }) },
    { binding: asked({ profile: 'aws', issuer: null, claims: { account: '123456789012' }, keys: { uri: 'https://x.example/jwks' } }) },
  ];
  for (const more of wrong) assert.throws(() => OPERATIONS['token.bind']({ ...ok, ...more } as never, deciding), TypeError, JSON.stringify(more).slice(0, 80));
  assert.throws(() => OPERATIONS['token.bind']({ ...shown('root-cli'), op: 'token.bind', member: ci, keys: { issuer: 7, jwks: {} } } as never, deciding), TypeError);
  assert.throws(() => OPERATIONS['token.unbind'](unbind('root-cli', ci, 'nope'), deciding), TypeError);
  assert.throws(() => OPERATIONS['token.unbind'](unbind('root-cli', 'user:x', '00000000-0000-4000-8000-000000000000'), deciding), TypeError);
});
