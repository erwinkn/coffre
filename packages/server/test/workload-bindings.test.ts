import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import { defineSignin, github, MAX_BINDINGS, signin as signinAuth, type BindingClaims } from '@coffre/core/identity';
import type { Database } from '@coffre/db';
import { asc, eq, sql, type SQL } from 'drizzle-orm';

import { auditLog, serviceBindings } from './db/tables.ts';
import { SigninService } from '../src/api/signin.ts';
import { WorkloadService } from '../src/api/workloads.ts';
import { processLimits } from '../src/workloads/limits.ts';
import { liveBindings, tombstoned } from '../src/db/queries.ts';
import { FetchRefused, type WorkloadTransport } from '../src/workloads/transport.ts';
import { clientFor, openTestDatabase, resetDatabase, testDeps, type FixtureDeps } from './api-fixture.ts';
import { TEST_ENGINE } from './db/engine.ts';

const ROOT = 'admin@acme.example';
const LEAD = 'lead@acme.example';
const DEV = 'dev@acme.example';
const SERVICE = 'api-deploy';
const MEMBER = `token:${SERVICE}`;
const GITHUB = 'https://token.actions.githubusercontent.com';
const KEYS = `${GITHUB}/.well-known/jwks`;

/** `deploy.yml`, pushed to `main` of `acme/api`. */
const DEPLOY: BindingClaims = {
  repository_owner_id: '9919',
  repository_id: '41532',
  workflow_ref: 'acme/api/.github/workflows/deploy.yml@refs/heads/main',
  ref: 'refs/heads/main',
  event_name: 'push',
};

const LIMITS = processLimits();
const SIGNIN = defineSignin({ publicUrl: 'https://secrets.acme.example', providers: [github({ clientId: 'a', clientSecret: 'b' })], workloads: { limits: LIMITS } });

let db: { owner: Database; runtime: Database; close: () => Promise<void> };
let deps: FixtureDeps;
/** What each issuer's discovery answers, by URL. */
let documents: Map<string, unknown>;

const transport: WorkloadTransport = {
  json: async (url) => {
    if (!documents.has(url.href)) throw new FetchRefused(url, 'answered 404');
    return documents.get(url.href);
  },
};

before(async () => {
  db = await openTestDatabase();
});

after(async () => {
  await db.close();
});

beforeEach(async () => {
  await resetDatabase(db.owner);
  documents = new Map([[`${GITHUB}/.well-known/openid-configuration`, { issuer: GITHUB, jwks_uri: KEYS }]]);
  deps = testDeps(db.runtime, [ROOT]);
  const signin = new SigninService({ db: deps.db, chainKey: deps.chainKey, vault: deps.vault, signin: SIGNIN });
  deps.workloads = new WorkloadService({
    db: deps.db, chainKey: deps.chainKey, vault: deps.vault, config: SIGNIN.workloads!, transport, signin, publicUrl: SIGNIN.publicUrl,
  });
  for (const [principal, owner] of [[`user:${LEAD}`, true], [`user:${DEV}`, false], [MEMBER, false]] as const) {
    assert.equal((await deps.vault.admit({ actor: `user:${ROOT}`, principal, owner })).ok, true);
  }
});

const as = (id: string) => clientFor(deps, id);
const bind = (claims: BindingClaims = DEPLOY, extra: { label?: string; replaces?: string[] } = {}, by = LEAD) =>
  as(by).bindings.create(MEMBER, { profile: 'github', claims, ...extra });
/** `deploy.yml` on another branch: a binding of its own. */
const branch = (name: string): BindingClaims => ({ ...DEPLOY, ref: `refs/heads/${name}`, workflow_ref: `acme/api/.github/workflows/deploy.yml@refs/heads/${name}` });

async function entries(action?: string) {
  const rows = await db.owner
    .select({ actor: auditLog.actor, action: auditLog.action, decision: auditLog.decision, metadata: auditLog.metadata })
    .from(auditLog)
    .where(eq(auditLog.author, 'app'))
    .orderBy(asc(auditLog.seq));
  return rows
    .filter((row) => action === undefined || row.action === action)
    .map((row) => ({ ...row, metadata: JSON.parse(row.metadata) as Record<string, unknown> }));
}

const live = async () => (await as(LEAD).bindings.list(MEMBER)).bindings;

test('an owner previews a binding, with the keys its issuer names, then saves it, logged as token.bind', async () => {
  const plan = await as(LEAD).bindings.preview(MEMBER, { profile: 'github', claims: { ...DEPLOY } });
  assert.deepEqual(plan, { profile: 'github', issuer: GITHUB, jwksUri: KEYS, claims: Object.fromEntries(Object.entries(DEPLOY).sort()), replaces: [] });
  assert.deepEqual(await live(), [], 'a preview writes nothing');
  assert.deepEqual(await entries(), [], 'and logs nothing');

  const { binding, replaced } = await bind(DEPLOY, { label: 'deploys to prod' });
  assert.deepEqual(replaced, []);
  assert.deepEqual(
    { ...binding, id: undefined, createdAt: undefined },
    { id: undefined, createdAt: undefined, profile: 'github', issuer: GITHUB, jwksUri: KEYS, claims: plan.claims, label: 'deploys to prod', createdBy: LEAD, lastUsedAt: null },
  );
  assert.deepEqual(await live(), [binding]);
  // The service itself may see its bindings; another member may not.
  assert.deepEqual((await clientFor(deps, SERVICE, 'service').bindings.list(MEMBER)).bindings, [binding]);
  await assert.rejects(as(DEV).bindings.list(MEMBER), /only owners may see trust bindings/);

  const [entry] = await entries('token.bind');
  assert.deepEqual(entry, {
    actor: `user:${LEAD}`,
    action: 'token.bind',
    decision: 'allow',
    metadata: { bindingId: binding.id, principalType: 'service', principalId: SERVICE, profile: 'github', issuer: GITHUB, jwksUri: KEYS, claims: plan.claims, replaces: [] },
  });
});

test('the server holds every binding to its profile, from the API as from anywhere', async () => {
  const create = (input: Parameters<ReturnType<typeof as>['bindings']['create']>[1]) => as(LEAD).bindings.create(MEMBER, input);
  const { event_name: _, ...noEvent } = DEPLOY;
  await assert.rejects(create({ profile: 'github', claims: noEvent }), /the github profile requires event_name/);
  await assert.rejects(create({ profile: 'github', claims: { ...DEPLOY, event_name: 'pull_request_target' } }), /event_name must be one of/);
  await assert.rejects(create({ profile: 'github-reusable', claims: { ...DEPLOY } }), /requires job_workflow_ref, job_workflow_sha/);
  await assert.rejects(create({ profile: 'gitlab', claims: { project_id: '345', ref_type: 'branch', ref: 'main', pipeline_source: 'push' } }), /requires namespace_id/);
  await assert.rejects(create({ profile: 'gitlab', issuer: GITHUB, claims: {} }), /signs only for the github profiles/);
  await assert.rejects(create({ profile: 'custom', issuer: 'https://idp.acme.example', claims: { email: 'x' } }), /requires sub/);
  await assert.rejects(create({ profile: 'custom', issuer: 'http://idp.acme.example', claims: { sub: 'x' } }), /must use https/);
  assert.deepEqual(await live(), []);
  assert.deepEqual(await entries(), [], 'an invalid binding is a bad request, not a decision');
});

test('only owners trust workloads; a refusal is logged, and an unknown service is no service', async () => {
  await assert.rejects(bind(DEPLOY, {}, DEV), /only owners may trust workloads/);
  await assert.rejects(as(DEV).bindings.preview(MEMBER, { profile: 'github', claims: { ...DEPLOY } }), /only owners may trust workloads/);
  await assert.rejects(as(LEAD).bindings.create('token:nobody', { profile: 'github', claims: { ...DEPLOY } }), /unknown service/);
  await assert.rejects(as(LEAD).bindings.create(`user:${DEV}`, { profile: 'github', claims: { ...DEPLOY } }), /only tokens hold service tokens/);
  assert.deepEqual(
    (await entries('token.bind')).map((entry) => [entry.actor, entry.decision, entry.metadata.reason, entry.metadata.principalId]),
    [
      [`user:${DEV}`, 'deny', 'requires_instance_owner', SERVICE],
      [`user:${DEV}`, 'deny', 'requires_instance_owner', SERVICE],
      [`user:${LEAD}`, 'deny', 'unknown_principal', 'nobody'],
    ],
  );
});

test('an issuer whose discovery does not hold up is refused, saying why', async () => {
  documents.set(`${GITHUB}/.well-known/openid-configuration`, { issuer: 'https://evil.example', jwks_uri: KEYS });
  await assert.rejects(bind(), /coffre could not use https:\/\/token.actions.githubusercontent.com: the issuer's discovery document names "https:\/\/evil.example"/);
  documents.set(`${GITHUB}/.well-known/openid-configuration`, { issuer: GITHUB, jwks_uri: 'https://10.0.0.7/keys' });
  await assert.rejects(bind(), /jwks_uri names a host, not an IP address/);
  documents.clear();
  await assert.rejects(bind(), /discovery document: .*answered 404/);
  assert.deepEqual(await live(), []);
});

test(`a service holds at most ${MAX_BINDINGS} bindings, even when two are made at once`, async () => {
  for (let i = 0; i < MAX_BINDINGS - 1; i++) await bind(branch(`b${i}`));
  // The log's head serializes them: one finds the last place, the other finds none.
  const outcomes = await Promise.allSettled([bind(branch('x')), bind(branch('y'))]);
  assert.deepEqual(outcomes.map((outcome) => outcome.status).sort(), ['fulfilled', 'rejected']);
  assert.match(String((outcomes.find((outcome) => outcome.status === 'rejected') as PromiseRejectedResult).reason), /at most 16 bindings/);
  assert.equal((await live()).length, MAX_BINDINGS);
  await assert.rejects(bind(branch('z')), /at most 16 bindings/);
});

test('a binding is never edited: a change replaces it, and an issuer that moved its keys replaces the others', async () => {
  const { binding: first } = await bind(DEPLOY);
  const { binding: second } = await bind(branch('release'));
  // A change: the binding replaced, in one step, its removal logged.
  const { binding: changed, replaced } = await bind({ ...DEPLOY, event_name: 'workflow_dispatch' }, { replaces: [first.id] });
  assert.deepEqual(replaced, [first.id]);
  assert.deepEqual((await live()).map((row) => row.id), [second.id, changed.id]);
  await assert.rejects(bind(DEPLOY, { replaces: [first.id] }), /no live binding of service:api-deploy's is/);

  // GitHub moves its keys: a binding made now names the new URL, and the others, which would fail anyway, go.
  documents.set(`${GITHUB}/.well-known/openid-configuration`, { issuer: GITHUB, jwks_uri: `${GITHUB}/keys/v2` });
  const plan = await as(LEAD).bindings.preview(MEMBER, { profile: 'github', claims: { ...DEPLOY } });
  assert.deepEqual(plan.replaces, [{ id: second.id, why: 'keys_moved' }, { id: changed.id, why: 'keys_moved' }]);
  const { binding: moved } = await bind(DEPLOY);
  assert.deepEqual((await live()).map((row) => [row.id, row.jwksUri]), [[moved.id, `${GITHUB}/keys/v2`]]);
  assert.deepEqual(
    (await entries('token.unbind')).map((entry) => [entry.metadata.bindingId, entry.metadata.reason, entry.metadata.by]),
    [[first.id, 'replaced', changed.id], [second.id, 'keys_moved', moved.id], [changed.id, 'keys_moved', moved.id]],
  );
  // The policy itself cannot be changed in place: the app may update the label, last use and revocation only.
  if (TEST_ENGINE !== 'sqlite') {
    await assert.rejects(
      db.runtime.update(serviceBindings).set({ claims: '{}' }).where(eq(serviceBindings.id, moved.id)),
      (error: Error) => /permission denied/.test(String((error.cause as Error | undefined)?.message)),
    );
  }
});

test('removing a binding writes its tombstone; a denied attempt is no tombstone, and a removed row put back stays removed', async () => {
  const { binding } = await bind(DEPLOY);
  const [row] = await db.owner.select().from(serviceBindings).where(eq(serviceBindings.id, binding.id));

  // Someone who is not an owner tries: refused and logged, under the same action, and the binding stands.
  await assert.rejects(as(DEV).bindings.remove(MEMBER, binding.id), /only owners may remove trust bindings/);
  assert.deepEqual(await tombstoned(db.runtime, [binding.id]), new Set());
  assert.deepEqual((await live()).map((candidate) => candidate.id), [binding.id]);

  assert.deepEqual(await as(LEAD).bindings.remove(MEMBER, binding.id), { unbound: true });
  assert.deepEqual(await live(), []);
  assert.deepEqual(await tombstoned(db.runtime, [binding.id]), new Set([binding.id]));
  assert.deepEqual(
    (await entries('token.unbind')).map((entry) => [entry.actor, entry.decision, entry.metadata.bindingId, entry.metadata.reason]),
    [[`user:${DEV}`, 'deny', binding.id, 'requires_instance_owner'], [`user:${LEAD}`, 'allow', binding.id, 'removed']],
  );
  await assert.rejects(as(LEAD).bindings.remove(MEMBER, binding.id), /unknown trust binding/);

  // Whoever owns the database puts the genuine row back, MAC and all: its tombstone still holds.
  await db.owner.update(serviceBindings).set({ revokedAt: null, revokedBy: null, authMac: row!.authMac }).where(eq(serviceBindings.id, binding.id));
  assert.deepEqual(await live(), []);
  assert.deepEqual(await liveBindings(db.runtime, deps.chainKey, MEMBER, 0), []);
});

test('a binding row changed around the app, or made without its key, is passed over', async () => {
  const { binding } = await bind(DEPLOY);
  await db.owner.update(serviceBindings).set({ claims: JSON.stringify({ ...DEPLOY, repository_id: '1' }) }).where(eq(serviceBindings.id, binding.id));
  assert.deepEqual(await live(), []);
  await assert.rejects(as(LEAD).bindings.remove(MEMBER, binding.id), /unknown trust binding/);
});

test('removing the service ends its bindings, and admitting it again does not bring them back', async () => {
  await bind(DEPLOY);
  assert.equal((await deps.vault.remove({ actor: `user:${ROOT}`, principal: MEMBER })).ok, true);
  assert.equal((await deps.vault.admit({ actor: `user:${ROOT}`, principal: MEMBER })).ok, true);
  assert.deepEqual(await live(), []);
  // A new binding in the new generation counts.
  const { binding } = await bind(DEPLOY);
  assert.deepEqual((await live()).map((row) => row.id), [binding.id]);
});

test('with workloads off, the routes say how to turn them on', async () => {
  delete deps.workloads;
  await assert.rejects(bind(), /this instance trusts no workloads: the deployment's signin\(\{ workloads \}\) turns them on/);
  // The configuration that turns them on.
  assert.deepEqual(SIGNIN.workloads, { allowLoopback: false, limits: LIMITS });
  // Never without both limits.
  assert.throws(
    () => defineSignin({ publicUrl: 'https://secrets.acme.example', providers: [github({ clientId: 'a', clientSecret: 'b' })], workloads: {} as never }),
    /workloads need their limits, per source and in total/,
  );
  assert.equal(defineSignin({ publicUrl: 'https://secrets.acme.example', providers: [github({ clientId: 'a', clientSecret: 'b' })] }).workloads, null);
});

test('loopback issuers are for development: an instance off loopback refuses to start with them', () => {
  const at = (publicUrl: string) =>
    defineSignin({ publicUrl, providers: [github({ clientId: 'a', clientSecret: 'b' })], workloads: { limits: LIMITS, allowLoopbackIssuersForDevelopment: true } }).workloads;
  assert.throws(() => at('https://secrets.acme.example'), /allowLoopbackIssuersForDevelopment is for an instance on loopback, and https:\/\/secrets\.acme\.example is not one: turn it off/);
  assert.throws(() => at('https://127.0.0.1.nip.io'), /is not one/);
  for (const publicUrl of ['http://127.0.0.1:3000', 'http://localhost:3000', 'http://[::1]:3000']) {
    assert.deepEqual(at(publicUrl), { allowLoopback: true, limits: LIMITS });
  }
  // As a deployment writes it: signin() takes it, and the instance's own URL decides.
  const auth = signinAuth({ providers: [github({ clientId: 'a', clientSecret: 'b' })], workloads: { limits: LIMITS, allowLoopbackIssuersForDevelopment: true } });
  assert.throws(() => auth.resolve('https://secrets.acme.example'), /is not one: turn it off/);
  const local = auth.resolve('http://127.0.0.1:3082');
  assert.equal(local.mode === 'signin' && local.signin.workloads?.allowLoopback, true);
});

test("an owner looks up a public repository's or project's IDs; a private one is not found, and its IDs are typed in", async () => {
  documents.set('https://api.github.com/repos/acme/api', { id: 41532, owner: { id: 9919 } });
  documents.set('https://gitlab.com/api/v4/projects/acme%2Fapi', { id: 345, namespace: { id: 12 } });
  documents.set('https://gitlab.acme.example/api/v4/projects/infra%2Fdeploy', { id: 7, namespace: { id: 3 } });
  const lead = as(LEAD);
  assert.deepEqual(await lead.bindings.lookup({ github: 'acme/api' }), { github: 'acme/api', repositoryId: '41532', ownerId: '9919' });
  assert.deepEqual(await lead.bindings.lookup({ gitlab: 'acme/api' }), { gitlab: 'acme/api', projectId: '345', namespaceId: '12' });
  assert.deepEqual(
    await lead.bindings.lookup({ gitlab: 'infra/deploy', gitlabUrl: 'https://gitlab.acme.example' }),
    { gitlab: 'infra/deploy', projectId: '7', namespaceId: '3' },
  );
  await assert.rejects(lead.bindings.lookup({ github: 'acme/private' }), /api.github.com did not find it: for a private one, type its IDs/);
  await assert.rejects(lead.bindings.lookup({ github: '../../users' }), /a GitHub repository is <owner>\/<name>/);
  await assert.rejects(lead.bindings.lookup({ gitlab: 'acme/api', gitlabUrl: 'http://10.0.0.1' }), /must use https/);
  await assert.rejects(lead.bindings.lookup({}), /look up a GitHub repository or a GitLab project/);
  await assert.rejects(as(DEV).bindings.lookup({ github: 'acme/api' }), /only owners may trust workloads/);
});
