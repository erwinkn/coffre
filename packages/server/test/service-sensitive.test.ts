// A service account reads a sensitive value only on a token or trust binding
// an Owner of its project issued (R32, `readsSensitive` in @coffre/core):
// nobody who cannot read one gets it through an account they set up, nor
// through a value made sensitive after they issued its credential. Everyone
// else's tokens and bindings read every other value, as before, and are told
// when they are made what they will not read. docs/design/roles.md, section 3.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomUUID, sign as signWith, type KeyObject } from 'node:crypto';

import { createClient, type CoffreClient } from '@coffre/client';
import { generateToken, github, hashToken, signin, tokenHint, type BindingClaims } from '@coffre/core/identity';
import { and, asc, eq } from 'drizzle-orm';

import { coffreRoute } from '../src/app.ts';
import { unsealedCredentials } from '@coffre/db/grants';

import { authMac } from '../src/auth-rows.ts';
import { sealScopes } from '../src/api/services.ts';
import { resolveConfig } from '../src/config.ts';
import { createRuntime, type CoffreRuntime } from '../src/runtime.ts';
import { forgetKeys } from '../src/workloads/keys.ts';
import { processLimits } from '../src/workloads/limits.ts';
import type { WorkloadTransport } from '../src/workloads/transport.ts';
import { auditLog, credentials, environments, secrets, secretVersions, serviceBindings, vaultMembers } from './db/tables.ts';
import { clientFor, openTestDatabase, resetDatabase, testDeps, type FixtureDeps } from './api-fixture.ts';

const ORIGIN = 'https://secrets.acme.example';
const ROOT = 'admin@acme.example';
/** A Developer of backend, who reads backend/dev but not its sensitive STRIPE_SECRET_KEY. */
const ADA = 'ada@acme.example';
/** An Owner of backend, by a grant on it. */
const OWEN = 'owen@acme.example';
/** An Owner of billing, by a grant on it, and a Developer of backend. */
const BO = 'bo@acme.example';
const CI = 'token:ci';
const STRIPE = 'sk_live_0123456789abcdef';
const ISSUER = 'https://token.actions.githubusercontent.com';
const KEYS = `${ISSUER}/.well-known/jwks`;
const DEPLOY: BindingClaims = {
  repository_owner_id: '9919',
  repository_id: '41532',
  workflow_ref: 'acme/api/.github/workflows/deploy.yml@refs/heads/main',
  ref: 'refs/heads/main',
  event_name: 'push',
};

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;
let runtime: CoffreRuntime;
let root: CoffreClient;
let ada: CoffreClient;
let owen: CoffreClient;
let bo: CoffreClient;
let signer: { privateKey: KeyObject; jwk: Record<string, unknown> };

const transport: WorkloadTransport = {
  json: async (url) => (url.href === KEYS ? { keys: [signer.jwk] } : { issuer: ISSUER, jwks_uri: KEYS }),
};

before(async () => {
  db = await openTestDatabase();
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  signer = { privateKey, jwk: { ...publicKey.export({ format: 'jwk' }), kid: 'es-1', alg: 'ES256', use: 'sig' } };
});

after(async () => {
  await db.close();
});

beforeEach(async () => {
  await resetDatabase(db.owner);
  forgetKeys();
  deps = testDeps(db.runtime, [ROOT]);
  const config = resolveConfig({
    publicUrl: ORIGIN,
    vault: deps.vault,
    auth: signin({ providers: [github({ clientId: 'a', clientSecret: 'b' })], workloads: { limits: processLimits({ perSource: 1000, total: 1000 }) } }),
    auditChainKey: deps.chainKey.toString('base64'),
  });
  runtime = createRuntime(config, deps.db, deps.vault, transport);
  deps.signin = runtime.signin!;
  deps.workloads = runtime.workloads!;
  root = clientFor(deps, ROOT);
  [ada, owen, bo] = [ADA, OWEN, BO].map((email) => clientFor(deps, email));
  await root.projects.create('backend');
  await root.projects.create('billing');
  for (const path of ['backend/dev', 'backend/staging', 'billing/dev']) await root.environments.create(path);
  await root.secrets.set('backend/dev', { STRIPE_SECRET_KEY: { value: STRIPE, sensitivity: 'sensitive' }, API_URL: 'https://api.dev.acme.example' });
  await root.secrets.set('backend/staging', { API_URL: 'https://api.staging.acme.example' });
  await root.secrets.set('billing/dev', { BILLING_KEY: { value: 'bk_0123456789', sensitivity: 'sensitive' } });
  for (const email of [ADA, OWEN, BO]) await root.members.add(`user:${email}`);
  await root.access.set(`user:${ADA}`, { backend: 'developer' });
  await root.access.set(`user:${OWEN}`, { backend: 'owner' });
  await root.access.set(`user:${BO}`, { backend: 'developer', billing: 'owner' });
  // Ada sets up CI for backend/dev, as anyone may give a service account what they hold there.
  await ada.members.add(CI);
  await ada.access.set(CI, { 'backend/dev': 'viewer', 'backend/staging': 'viewer' });
});

/** The API as a request with this bearer token sees it, through the app's front door. */
function bearer(token: string): CoffreClient {
  return createClient({ url: ORIGIN, headers: () => ({ authorization: `Bearer ${token}` }), transport: (request) => coffreRoute(request, runtime, '203.0.113.7').then((response) => response!) });
}

/** A key's value read with `token`, or why it was refused: its status and reason. */
async function read(token: string, path: string): Promise<string> {
  try {
    const { values } = await bearer(token).secrets.reveal(path);
    return Object.values(values).join();
  } catch (error) {
    const { status, reason } = error as { status: number; reason?: string };
    return `${status} ${reason ?? ''}`.trim();
  }
}

/** A run's ID token as GitHub would sign it for `deploy.yml` on main, for this instance. */
function idToken(): string {
  const part = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
  const now = Math.floor(Date.now() / 1000);
  const input = `${part({ alg: 'ES256', kid: 'es-1', typ: 'JWT' })}.${part({ iss: ISSUER, aud: ORIGIN, sub: 'repo:acme/api:ref:refs/heads/main', iat: now - 5, exp: now + 295, jti: randomUUID(), run_id: '7001', ...DEPLOY })}`;
  return `${input}.${signWith('sha256', Buffer.from(input), { key: signer.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url')}`;
}

/** A CI run's five-minute credential, bought with its ID token through the bindings of `CI`. */
async function exchanged(): Promise<string> {
  const response = await coffreRoute(
    new Request(`${ORIGIN}/api/auth/oidc`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ service: CI, token: idToken() }) }),
    runtime,
    '203.0.113.7',
  );
  const body = (await response!.json()) as { token: string };
  assert.equal(response!.status, 200, JSON.stringify(body));
  return body.token;
}

/** The scope a token's row stores, each place's role and whether it reads sensitive values there, by place id. */
async function stored(table: typeof credentials | typeof serviceBindings, id: string): Promise<{ role: string; sensitive: boolean }[]> {
  const [row] = await db.owner.select({ scope: table.scope }).from(table).where(eq(table.id, id));
  return (JSON.parse(row!.scope!) as { role: string; sensitive: boolean }[]).map(({ role, sensitive }) => ({ role, sensitive }));
}

test("a Developer's service account reads every value of backend/dev but its sensitive one, refused whole and named, and is told so when its token is issued", async () => {
  assert.deepEqual(await ada.tokens.preview(CI, { expiresInDays: 30, scope: { 'backend/dev': 'viewer' } }), { scope: { 'backend/dev': 'viewer' }, withheld: ['backend/dev'] });
  const issued = await ada.tokens.issue(CI, { expiresInDays: 30, scope: { 'backend/dev': 'viewer' } });
  assert.deepEqual(issued.withheld, ['backend/dev']);
  assert.deepEqual(await stored(credentials, issued.id), [{ role: 'viewer', sensitive: false }]);
  assert.equal(await read(issued.token, 'backend/dev/API_URL'), 'https://api.dev.acme.example');
  assert.equal(await read(issued.token, 'backend/dev/STRIPE_SECRET_KEY'), '403 not_owner_issued');
  await assert.rejects(bearer(issued.token).secrets.reveal('backend/dev'), {
    status: 403,
    message: 'backend/dev holds STRIPE_SECRET_KEY, sensitive: a service account reads it only on a token or trust binding an Owner of backend issued',
  });
  // The app refused it, before the vault was asked: logged once, by the app, naming the key.
  const refused = await db.owner.select({ author: auditLog.author, actor: auditLog.actor, metadata: auditLog.metadata })
    .from(auditLog).where(and(eq(auditLog.action, 'secret.read'), eq(auditLog.decision, 'deny'))).orderBy(asc(auditLog.seq));
  assert.deepEqual(refused.map((entry) => {
    const { reason, keys } = JSON.parse(entry.metadata) as { reason: string; keys: string[] };
    return [entry.author, entry.actor, reason, keys];
  }), [
    ['app', CI, 'not_owner_issued', ['STRIPE_SECRET_KEY']],
    ['app', CI, 'not_owner_issued', ['STRIPE_SECRET_KEY']],
  ]);
  // A dry run tells it nothing of the value it does not read: a write of it is a change.
  assert.deepEqual({ ...(await bearer(issued.token).secrets.dryRun('backend/dev', { STRIPE_SECRET_KEY: STRIPE })).keys }, { STRIPE_SECRET_KEY: 'changed' });
});

test('a value made sensitive after a Developer issued the token is refused to it from then on', async () => {
  const issued = await ada.tokens.issue(CI, { expiresInDays: 30 });
  assert.deepEqual(issued.withheld, ['backend/dev'], 'backend/staging holds no sensitive value yet');
  assert.equal(await read(issued.token, 'backend/staging/API_URL'), 'https://api.staging.acme.example');
  await root.secrets.set('backend/staging', { API_URL: { sensitivity: 'sensitive' } });
  assert.equal(await read(issued.token, 'backend/staging/API_URL'), '403 not_owner_issued');
  assert.equal(await read(issued.token, 'backend/staging'), '403 not_owner_issued');
});

test("an Owner's token reads the sensitive values, of the instance or of the project by a grant; an Owner of another project's, only that project's", async () => {
  for (const owner of [root, owen]) {
    const issued = await owner.tokens.issue(CI, { expiresInDays: 30 });
    assert.deepEqual(issued.withheld, []);
    assert.deepEqual(await stored(credentials, issued.id), [{ role: 'viewer', sensitive: true }, { role: 'viewer', sensitive: true }]);
    assert.equal(await read(issued.token, 'backend/dev/STRIPE_SECRET_KEY'), STRIPE);
    assert.equal(await read(issued.token, 'backend/dev'), `https://api.dev.acme.example,${STRIPE}`);
    // A dry run compares a value it reads.
    assert.deepEqual({ ...(await bearer(issued.token).secrets.dryRun('backend/dev', { STRIPE_SECRET_KEY: STRIPE })).keys }, { STRIPE_SECRET_KEY: 'unchanged' });
  }
  // Bo owns billing, and is a Developer of backend: his account's token reads billing's sensitive values, and not backend's.
  await bo.members.add('token:bo-ci');
  await bo.access.set('token:bo-ci', { 'backend/dev': 'viewer', 'billing/dev': 'viewer' });
  const issued = await bo.tokens.issue('token:bo-ci', { expiresInDays: 30 });
  assert.deepEqual(issued.withheld, ['backend/dev']);
  assert.equal(await read(issued.token, 'billing/dev/BILLING_KEY'), 'bk_0123456789');
  assert.equal(await read(issued.token, 'backend/dev/STRIPE_SECRET_KEY'), '403 not_owner_issued');
  // A token's log entry says, place by place, whether it reads them.
  const made = await db.owner.select({ actor: auditLog.actor, metadata: auditLog.metadata }).from(auditLog)
    .where(and(eq(auditLog.action, 'token.create'), eq(auditLog.decision, 'allow'))).orderBy(asc(auditLog.seq));
  const reading = (entry: { metadata: string }) => (JSON.parse(entry.metadata) as { scope: { sensitive: boolean }[] }).scope.map((grant) => grant.sensitive).sort();
  assert.deepEqual(made.map((entry) => [entry.actor, reading(entry)]), [
    [`user:${ROOT}`, [true, true]],
    [`user:${OWEN}`, [true, true]],
    [`user:${BO}`, [false, true]],
  ]);
});

/** Run `meanwhile` once, as the vault is next asked about `principal`, before it answers. */
function beforeNextAccess(principal: string, meanwhile: () => Promise<unknown>): void {
  const access = deps.vault.access;
  deps.vault.access = async (asked, ...rest) => {
    if (asked === principal) {
      deps.vault.access = access;
      await meanwhile();
    }
    return access(asked, ...rest);
  };
}

test('an Owner demoted while issuing a token gives it no sensitive value: weighed as the vault answered, committed only while still so (formal/Issuing.tla)', async () => {
  // Owen is an Owner of backend as his request is checked, and as the vault answers for his token; demoted before it commits.
  beforeNextAccess(CI, () => root.access.set(`user:${OWEN}`, { backend: 'developer' }));
  await assert.rejects(owen.tokens.issue(CI, { expiresInDays: 30 }), { status: 409, reason: 'access_changed' });
  assert.deepEqual(await db.owner.select().from(credentials).where(eq(credentials.principal, CI)), []);
  // Asked again, he is weighed as he is now: a Developer's token, which reads none.
  const issued = await owen.tokens.issue(CI, { expiresInDays: 30 });
  assert.deepEqual(await stored(credentials, issued.id), [{ role: 'viewer', sensitive: false }, { role: 'viewer', sensitive: false }]);
  assert.equal(await read(issued.token, 'backend/dev/STRIPE_SECRET_KEY'), '403 not_owner_issued');
});

test('a trust binding is weighed the same: an Owner demoted while binding a workload binds nothing', async () => {
  beforeNextAccess(CI, () => root.access.set(`user:${OWEN}`, { backend: 'developer' }));
  await assert.rejects(owen.bindings.create(CI, { profile: 'github', claims: DEPLOY, scope: { 'backend/dev': 'viewer' } }), { status: 409, reason: 'access_changed' });
  assert.deepEqual(await db.owner.select().from(serviceBindings), []);
  const theirs = await owen.bindings.create(CI, { profile: 'github', claims: DEPLOY, scope: { 'backend/dev': 'viewer' } });
  assert.deepEqual(await stored(serviceBindings, theirs.binding.id), [{ role: 'viewer', sensitive: false }]);
});

test("an Owner's personal token issues no service token: what it made would outlive it, and its scope makes it no Owner", async () => {
  const personal = await root.tokens.issue(`user:${ROOT}`, { label: 'agent', expiresInMinutes: 60, scope: { backend: 'maintainer' } });
  await assert.rejects(bearer(personal.token).tokens.issue(CI, { expiresInDays: 30 }), { status: 403 });
});

test("a reference takes its source's nature: a Developer's token reads no reference to a sensitive value where it is held, an Owner's does", async () => {
  await root.secrets.set('backend/staging', { STRIPE_SECRET_KEY: { ref: 'backend/dev/STRIPE_SECRET_KEY' } });
  const theirs = await ada.tokens.issue(CI, { expiresInDays: 30, scope: { 'backend/staging': 'viewer' } });
  assert.deepEqual(theirs.withheld, ['backend/staging'], 'a reference to a sensitive value counts where it is held');
  assert.equal(await read(theirs.token, 'backend/staging/STRIPE_SECRET_KEY'), '403 not_owner_issued');
  const owners = await owen.tokens.issue(CI, { expiresInDays: 30, scope: { 'backend/staging': 'viewer' } });
  assert.equal(await read(owners.token, 'backend/staging/STRIPE_SECRET_KEY'), STRIPE, "backend's Owner issued it: backend/dev itself need not be in its scope");
});

test("a reference into another project lends its sensitive value only on a credential an Owner of that project issued: an Owner of the holder's project is not enough", async () => {
  // Bo, an Owner of billing and a Developer of backend, refers billing/dev to backend's sensitive key, as a reader of it may (R24).
  await bo.secrets.set('billing/dev', { LEAK: { ref: 'backend/dev/STRIPE_SECRET_KEY' } });
  await bo.members.add('token:bo-ci');
  await bo.access.set('token:bo-ci', { 'billing/dev': 'viewer' });
  const his = await bo.tokens.issue('token:bo-ci', { expiresInDays: 30 });
  assert.deepEqual(his.withheld, ['billing/dev'], "billing/dev lends a value of backend's, which no Owner of backend issued it");
  assert.equal(await read(his.token, 'billing/dev/BILLING_KEY'), 'bk_0123456789', "billing's own, which its Owner issued it");
  assert.equal(await read(his.token, 'billing/dev/LEAK'), '403 not_owner_issued');
  await assert.rejects(bearer(his.token).secrets.reveal('billing/dev'), {
    status: 403,
    message: 'billing/dev holds LEAK, sensitive: a service account reads it only on a token or trust binding an Owner of the project each value is from issued',
  });
  // An Owner of the whole instance issues it one that reaches backend too: it reads it, decided where it is held.
  await root.access.set('token:bo-ci', { 'backend/staging': 'viewer' });
  const owners = await root.tokens.issue('token:bo-ci', { expiresInDays: 30 });
  assert.deepEqual(owners.withheld, []);
  assert.equal(await read(owners.token, 'billing/dev/LEAK'), STRIPE);
  // Scoped to billing alone, even an Owner of the whole instance's says nothing for backend.
  const narrow = await root.tokens.issue('token:bo-ci', { expiresInDays: 30, scope: { 'billing/dev': 'viewer' } });
  assert.deepEqual(narrow.withheld, ['billing/dev']);
  assert.equal(await read(narrow.token, 'billing/dev/LEAK'), '403 not_owner_issued');
});

test("a fork's inherited sensitive value is decided where it is held, its parent: an Owner's token there reads it, a Developer's does not", async () => {
  await root.environments.create('backend/dev-eu', { from: 'dev', inherit: true });
  await root.access.set(CI, { 'backend/dev-eu': 'viewer' });
  const theirs = await ada.tokens.issue(CI, { expiresInDays: 30, scope: { 'backend/dev': 'viewer', 'backend/dev-eu': 'viewer' } });
  assert.deepEqual(theirs.withheld, ['backend/dev', 'backend/dev-eu'], 'backend/dev-eu holds none of its own, but inherits one');
  assert.equal(await read(theirs.token, 'backend/dev-eu/STRIPE_SECRET_KEY'), '403 not_owner_issued');
  assert.equal(await read(theirs.token, 'backend/dev-eu/API_URL'), 'https://api.dev.acme.example');
  const owners = await root.tokens.issue(CI, { expiresInDays: 30, scope: { 'backend/dev': 'viewer', 'backend/dev-eu': 'viewer' } });
  assert.deepEqual(owners.withheld, []);
  assert.equal(await read(owners.token, 'backend/dev-eu/STRIPE_SECRET_KEY'), STRIPE);
});

test("a binding's runs read the sensitive values only where an Owner bound it; one replacing an Owner's keeps that only for an Owner", async () => {
  const planned = await ada.bindings.preview(CI, { profile: 'github', claims: DEPLOY, scope: { 'backend/dev': 'viewer' } });
  assert.deepEqual(planned.withheld, ['backend/dev']);
  const theirs = await ada.bindings.create(CI, { profile: 'github', claims: DEPLOY, scope: { 'backend/dev': 'viewer' } });
  assert.deepEqual(await stored(serviceBindings, theirs.binding.id), [{ role: 'viewer', sensitive: false }]);
  assert.equal(await read(await exchanged(), 'backend/dev/STRIPE_SECRET_KEY'), '403 not_owner_issued');

  const owners = await root.bindings.create(CI, { profile: 'github', claims: DEPLOY, scope: { 'backend/dev': 'viewer' }, replaces: [theirs.binding.id] });
  assert.equal(await read(await exchanged(), 'backend/dev/STRIPE_SECRET_KEY'), STRIPE);
  // Ada trusts the workload again in its place, inheriting its scope: the narrower of the two, which reads no sensitive value.
  const again = await ada.bindings.create(CI, { profile: 'github', claims: DEPLOY, replaces: [owners.binding.id] });
  assert.deepEqual(await stored(serviceBindings, again.binding.id), [{ role: 'viewer', sensitive: false }]);
  assert.equal(await read(await exchanged(), 'backend/dev/STRIPE_SECRET_KEY'), '403 not_owner_issued');
});

test("a binding an older release made, replaced before anything sealed it, is sealed first: its Owner's say is kept, never dropped", async () => {
  const [member] = await db.owner.select().from(vaultMembers).where(eq(vaultMembers.principal, CI));
  const [dev] = await db.owner.select({ projectId: environments.projectId, id: environments.id }).from(environments).where(eq(environments.slug, 'dev'));
  const scope = JSON.stringify([{ projectId: dev!.projectId, environmentId: dev!.id, role: 'viewer', permissions: { normal: ['secret.read', 'secret.use'], protected: ['secret.use'] } }]);
  const binding = { id: randomUUID(), principal: CI, generation: member!.generation, profile: 'github', issuer: ISSUER, jwksUri: KEYS, claims: JSON.stringify(DEPLOY), revokedAt: null, scope };
  await db.owner.insert(serviceBindings).values({ ...binding, label: null, createdBy: OWEN, authMac: authMac(deps.chainKey, 'service_bindings', binding) });
  // A preview seals nothing: it writes and logs nothing, and inherits the scope as read, which says nothing of sensitive values.
  const planned = await owen.bindings.preview(CI, { profile: 'github', claims: DEPLOY, replaces: [binding.id] });
  assert.deepEqual(planned.withheld, ['backend/dev']);
  assert.deepEqual(await db.owner.select({ scope: serviceBindings.scope }).from(serviceBindings).where(eq(serviceBindings.id, binding.id)), [{ scope }]);
  assert.deepEqual(await db.owner.select({ seq: auditLog.seq }).from(auditLog).where(eq(auditLog.action, 'token.seal')), []);
  // Owen trusts the workload again in its place, inheriting its scope.
  const again = await owen.bindings.create(CI, { profile: 'github', claims: DEPLOY, replaces: [binding.id] });
  assert.deepEqual(await stored(serviceBindings, again.binding.id), [{ role: 'viewer', sensitive: true }]);
  assert.equal(await read(await exchanged(), 'backend/dev/STRIPE_SECRET_KEY'), STRIPE);
});

test('the vault decides it too, whatever the app asks: a service reads a sensitive value only on a scope that says an Owner issued it there', async () => {
  const [version] = await db.owner
    .select({ id: secretVersions.id })
    .from(secretVersions)
    .innerJoin(secrets, eq(secrets.id, secretVersions.secretId))
    .innerJoin(environments, eq(environments.id, secrets.environmentId))
    .where(and(eq(secrets.key, 'STRIPE_SECRET_KEY'), eq(environments.slug, 'dev')));
  const [project] = await db.owner.select({ id: environments.projectId, environmentId: environments.id }).from(environments).where(eq(environments.slug, 'dev'));
  const grant = { projectId: project!.id, environmentId: project!.environmentId, role: 'viewer', permissions: { normal: ['secret.read', 'secret.use'], protected: ['secret.use'] } };
  const ask = (credentialScope: unknown, purpose: 'reveal' | 'use' = 'reveal') =>
    deps.vault.unwrap({ principal: CI, purpose, items: [{ secretVersionId: version!.id }], credentialScope: credentialScope as never });
  const refused = { ok: false, refusal: { code: 'not_owner_issued', message: 'a service account reads a sensitive value only on a token or trust binding an Owner of its project issued' } };
  assert.deepEqual(await ask([{ ...grant, sensitive: false }]), refused);
  assert.deepEqual(await ask([grant]), refused, 'a scope that does not say reads none');
  assert.deepEqual(await ask(null), refused, 'nor does a service with no credential, which none signs in without');
  assert.equal((await ask([{ ...grant, sensitive: true }])).ok, true);
  assert.equal((await ask([{ ...grant, sensitive: false }], 'use')).ok, true, 'used, never handed back, it is opened as for anyone who uses it');
  const denied = await db.owner.select({ actor: auditLog.actor, code: auditLog.code }).from(auditLog)
    .where(and(eq(auditLog.author, 'vault'), eq(auditLog.action, 'secret.read'), eq(auditLog.decision, 'deny')));
  assert.deepEqual(denied, Array(3).fill({ actor: CI, code: 'not_owner_issued' }));
});

test('tokens and bindings issued before 0.11 are sealed once by who issued them: an Owner of the project keeps reading its sensitive values, anyone else does not', async () => {
  const [member] = await db.owner.select().from(vaultMembers).where(eq(vaultMembers.principal, CI));
  const [dev] = await db.owner.select({ projectId: environments.projectId, id: environments.id }).from(environments).where(eq(environments.slug, 'dev'));
  // As 0.10 stored a scope: each place's role and what it held, nothing said of sensitive values.
  const scope = JSON.stringify([{ projectId: dev!.projectId, environmentId: dev!.id, role: 'viewer', permissions: { normal: ['secret.read', 'secret.use'], protected: ['secret.use'] } }]);
  const legacy = async (createdBy: string, stored = scope) => {
    const token = generateToken('service');
    const row = {
      id: randomUUID(), kind: 'service', tokenHash: hashToken(token), generation: member!.generation, tokenHint: tokenHint(token),
      principal: CI, identityId: null, label: '0.10', createdBy, expiresAt: new Date(Date.now() + 86_400_000), revokedAt: null, scope: stored,
    };
    await db.owner.insert(credentials).values({ ...row, authMac: authMac(deps.chainKey, 'credentials', row) });
    return { id: row.id, token };
  };
  const [owners, theirs] = [await legacy(ROOT), await legacy(ADA)];
  const binding = { id: randomUUID(), principal: CI, generation: member!.generation, profile: 'github', issuer: ISSUER, jwksUri: KEYS, claims: JSON.stringify(DEPLOY), revokedAt: null, scope };
  await db.owner.insert(serviceBindings).values({ ...binding, label: null, createdBy: OWEN, authMac: authMac(deps.chainKey, 'service_bindings', binding) });

  // The first credential this configuration checks seals them all, before it reads anything.
  assert.equal(await read(owners.token, 'backend/dev/STRIPE_SECRET_KEY'), STRIPE);
  assert.equal(await read(theirs.token, 'backend/dev/STRIPE_SECRET_KEY'), '403 not_owner_issued');
  assert.equal(await read(theirs.token, 'backend/dev/API_URL'), 'https://api.dev.acme.example');
  assert.equal(await read(await exchanged(), 'backend/dev/STRIPE_SECRET_KEY'), STRIPE, 'bound by an Owner of backend');
  assert.deepEqual(await stored(credentials, owners.id), [{ role: 'viewer', sensitive: true }]);
  assert.deepEqual(await stored(credentials, theirs.id), [{ role: 'viewer', sensitive: false }]);
  assert.deepEqual(await stored(serviceBindings, binding.id), [{ role: 'viewer', sensitive: true }]);
  // One sealed while its account held nothing names no place: it is sealed, and never sealed again, nor listed.
  await legacy(ROOT, '[]');
  assert.deepEqual(await unsealedCredentials(db.owner, new Date()), []);
  assert.equal(await sealScopes(deps.db, deps.chainKey, deps.vault), 0);
  // Logged by the app, one entry per scope it wrote, naming the rows it sealed with it.
  const seals = await db.owner.select({ actor: auditLog.actor, metadata: auditLog.metadata }).from(auditLog).where(eq(auditLog.action, 'token.seal')).orderBy(asc(auditLog.seq));
  assert.deepEqual(seals.map((entry) => {
    const { tokens, bindings, scope: sealed } = JSON.parse(entry.metadata) as { tokens: string[]; bindings: string[]; scope: { sensitive: boolean }[] };
    return [entry.actor, [...tokens, ...bindings].sort(), sealed.map((grant) => grant.sensitive)];
  }), [
    ['system:app', [binding.id, owners.id].sort(), [true]],
    ['system:app', [theirs.id], [false]],
  ]);
});
