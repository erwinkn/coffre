// Each service token and trust binding carries its own scope, at most what
// its account holds and its issuer could give when it is made, and a request
// made with it reaches what both its scope and the account hold then:
// docs/design/instance-roles.md, "Credentials' scopes" (D105).
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';

import { createClient, type CoffreClient } from '@coffre/client';
import { defineSignin, generateToken, github, hashToken, signin, tokenHint } from '@coffre/core/identity';
import { unsealedCredentials } from '@coffre/db/grants';
import { and, asc, eq, inArray } from 'drizzle-orm';

import { authMac } from '../src/auth-rows.ts';
import { CredentialUncheckable, SigninService } from '../src/api/signin.ts';
import { WorkloadService } from '../src/api/workloads.ts';
import { processLimits } from '../src/workloads/limits.ts';
import { sealScopes } from '../src/api/services.ts';
import { fetchApi } from '../src/fetch-api.ts';
import { resolveConfig } from '../src/config.ts';
import { createRuntime, type CoffreRuntime } from '../src/runtime.ts';
import { auditLog, credentials, environments, secrets, secretVersions, serviceBindings, vaultMembers } from './db/tables.ts';
import { clientFor, openTestDatabase, resetDatabase, testDeps, waitUntil, type FixtureDeps } from './api-fixture.ts';

const ORIGIN = 'https://secrets.acme.example';
const ROOT = 'admin@acme.example';
const ADA = 'user:ada@acme.example';
const CI = 'token:ci-web';

const GITHUB = 'https://token.actions.githubusercontent.com';
/** Where the issuer says its keys are: a test moves them. */
let jwks = `${GITHUB}/.well-known/jwks`;
const SIGNIN = defineSignin({ publicUrl: ORIGIN, providers: [github({ clientId: 'a', clientSecret: 'b' })], workloads: { limits: processLimits() } });

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;
let runtime: CoffreRuntime;
let root: CoffreClient;
/** A Developer of every project's dev, who sets up CI for it. */
let ada: CoffreClient;

before(async () => {
  db = await openTestDatabase();
});

after(async () => {
  await db.close();
});

beforeEach(async () => {
  await resetDatabase(db.owner);
  jwks = `${GITHUB}/.well-known/jwks`;
  deps = testDeps(db.runtime, [ROOT]);
  const signin = new SigninService({ db: deps.db, chainKey: deps.chainKey, vault: deps.vault, signin: SIGNIN });
  deps.signin = signin;
  deps.workloads = new WorkloadService({
    db: deps.db,
    chainKey: deps.chainKey,
    vault: deps.vault,
    config: SIGNIN.workloads!,
    transport: { json: async () => ({ issuer: GITHUB, jwks_uri: jwks }) },
    signin,
    publicUrl: ORIGIN,
  });
  runtime = {
    db: deps.db,
    vault: deps.vault,
    chainKey: deps.chainKey,
    signin,
    workloads: null,
    mcp: null,
    auth: { mode: 'signin', signin: SIGNIN },
    publicUrl: ORIGIN,
    verifier: signin,
    waitUntil,
    schema: { migrated: true },
  } as CoffreRuntime;
  root = clientFor(deps, ROOT);
  ada = clientFor(deps, 'ada@acme.example');
  await root.projects.create('market', { name: 'Market' });
  for (const environment of ['dev', 'prod']) {
    await root.environments.create(`market/${environment}`, { name: environment });
    await root.secrets.set(`market/${environment}`, { API_KEY: `${environment}-key` });
  }
  await root.members.add(ADA, { role: 'developer', scope: { environments: { only: ['dev'] } } });
  await ada.members.add(CI);
  await ada.access.set(CI, { 'market/dev': 'developer' });
});

/** The API as a request with this bearer token sees it, through the app's front door. */
function bearer(token: string): CoffreClient {
  return createClient({
    url: ORIGIN,
    headers: () => ({ authorization: `Bearer ${token}` }),
    transport: (request) => fetchApi(request, runtime, { sourceIp: null }),
  });
}

/** Whether a request with `token` reads `market/<environment>`'s value: its value, or the refusal's status. */
async function reads(token: string, environment: string): Promise<string | number> {
  try {
    return (await bearer(token).secrets.reveal(`market/${environment}`)).values.API_KEY!;
  } catch (error) {
    return (error as { status: number }).status;
  }
}

test("an Admin who widens an account widens none of the tokens made before: a request holds what both its scope and the account hold", async () => {
  const issued = await ada.tokens.issue(CI, { label: 'deploy', expiresInDays: 30 });
  assert.deepEqual(issued.scope, { 'market/dev': 'developer' }, 'all the account held, left out');
  assert.equal(await reads(issued.token, 'dev'), 'dev-key');

  await root.access.set(CI, { 'market/prod': 'viewer' });
  assert.equal(await reads(issued.token, 'prod'), 403, "the account's new grant does not reach the token");
  await assert.rejects(bearer(issued.token).secrets.list('market/prod'), { status: 403 });
  // The vault decides on the scope too, should the app ever ask it for more, and logs its refusal.
  const [version] = await db.owner
    .select({ id: secretVersions.id })
    .from(secretVersions)
    .innerJoin(secrets, eq(secrets.id, secretVersions.secretId))
    .innerJoin(environments, eq(environments.id, secrets.environmentId))
    .where(eq(environments.slug, 'prod'));
  const [{ scope }] = await db.owner.select({ scope: credentials.scope }).from(credentials);
  const ask = (credentialScope: unknown) =>
    deps.vault.unwrap({ principal: CI, purpose: 'reveal', items: [{ secretVersionId: version!.id }], credentialScope: credentialScope as never });
  assert.deepEqual(await ask(JSON.parse(scope!)), { ok: false, refusal: { code: 'no_grant', message: 'no grant covers this' } });
  const [refused] = await db.owner
    .select({ actor: auditLog.actor, code: auditLog.code })
    .from(auditLog)
    .where(and(eq(auditLog.author, 'vault'), eq(auditLog.action, 'secret.read'), eq(auditLog.decision, 'deny')));
  assert.deepEqual(refused, { actor: CI, code: 'no_grant' });
  assert.equal((await ask(null)).ok, true, 'the account itself reads prod now');

  // A token made now, by someone who could give it prod, reaches prod.
  const later = await root.tokens.issue(CI, { label: 'release', expiresInDays: 30 });
  assert.deepEqual(later.scope, { 'market/dev': 'developer', 'market/prod': 'viewer' });
  assert.equal(await reads(later.token, 'prod'), 'prod-key');
});

test('narrowing the account narrows every token at once, and a token narrower than its account stays so', async () => {
  const viewer = await ada.tokens.issue(CI, { label: 'reads', expiresInDays: 30, scope: { 'market/dev': 'viewer' } });
  const writer = await ada.tokens.issue(CI, { label: 'writes', expiresInDays: 30 });
  assert.equal(await reads(viewer.token, 'dev'), 'dev-key');
  await assert.rejects(bearer(viewer.token).secrets.set('market/dev', { API_KEY: 'x' }), { status: 403 }, 'its scope reads, and writes nothing');
  await bearer(writer.token).secrets.set('market/dev', { API_KEY: 'written' });

  await ada.access.set(CI, { 'market/dev': 'viewer' });
  await assert.rejects(bearer(writer.token).secrets.set('market/dev', { API_KEY: 'y' }), { status: 403 }, 'the account no longer writes, so no token does');
  assert.equal(await reads(writer.token, 'dev'), 'written');
  await ada.access.set(CI, { 'market/dev': null });
  assert.equal(await reads(writer.token, 'dev'), 403);
  assert.equal(await reads(viewer.token, 'dev'), 403);
  // Given back, it reaches again, as far as each scope says.
  await ada.access.set(CI, { 'market/dev': 'developer' });
  await assert.rejects(bearer(viewer.token).secrets.set('market/dev', { API_KEY: 'z' }), { status: 403 });
  await bearer(writer.token).secrets.set('market/dev', { API_KEY: 'again' });
});

test('a scope names places by id: a place deleted takes its grants with it, and one made again under its name is another place', async () => {
  const issued = await ada.tokens.issue(CI, { expiresInDays: 30 });
  await root.environments.update('market/dev', { archived: true });
  await root.environments.delete('market/dev');
  assert.deepEqual((await root.tokens.list(CI)).tokens[0]!.scope, {}, 'what it reached is gone');
  // market/dev again: a new environment, which the account is given, and the token is not.
  await root.environments.create('market/dev', { name: 'dev' });
  await root.secrets.set('market/dev', { API_KEY: 'new-dev-key' });
  await root.access.set(CI, { 'market/dev': 'developer' });
  assert.equal(await reads(issued.token, 'dev'), 403);
  const again = await ada.tokens.issue(CI, { expiresInDays: 30 });
  assert.equal(await reads(again.token, 'dev'), 'new-dev-key', 'a token made now reaches the new one');
});

test('nobody makes a token or a binding past the account or past what they could give it, through the API, and the refusal is logged', async () => {
  await root.access.set(CI, { 'market/prod': 'viewer' });
  // The account now holds prod, which Ada does not reach: she manages it no more, whatever scope she asks.
  for (const scope of [undefined, { 'market/dev': 'viewer' as const }]) {
    await assert.rejects(ada.tokens.issue(CI, { expiresInDays: 30, ...(scope === undefined ? {} : { scope }) }), { status: 403 });
  }
  await root.access.set(CI, { 'market/prod': null });

  // Past the account: a role it does not hold, a place it does not hold.
  await assert.rejects(ada.tokens.issue(CI, { expiresInDays: 30, scope: { 'market/dev': 'owner' } }), { status: 400 }, 'owner is not for an environment');
  await assert.rejects(ada.tokens.issue(CI, { expiresInDays: 30, scope: { 'market/prod': 'viewer' } }), { status: 403 });
  await assert.rejects(ada.tokens.issue(CI, { expiresInDays: 30, scope: { market: 'viewer' } }), { status: 403 });
  await assert.rejects(root.tokens.issue(CI, { expiresInDays: 30, scope: { 'market/prod': 'viewer' } }), { status: 403 }, 'not even for who runs the instance');
  const DEPLOY = { repository_owner_id: '9919', repository_id: '41532', workflow_ref: 'acme/api/.github/workflows/deploy.yml@refs/heads/main', ref: 'refs/heads/main', event_name: 'push' };
  await assert.rejects(ada.bindings.preview(CI, { profile: 'github', claims: DEPLOY, scope: { 'market/prod': 'viewer' } }), { status: 403 });
  assert.deepEqual((await ada.bindings.preview(CI, { profile: 'github', claims: DEPLOY, scope: { 'market/dev': 'viewer' } })).scope, { 'market/dev': 'viewer' });
  await assert.rejects(ada.tokens.issue(CI, { expiresInDays: 30, scope: {} }), { status: 400 }, 'a scope that reaches nothing');
  await assert.rejects(ada.tokens.issue(CI, { expiresInDays: 30, scope: { 'market/nope': 'viewer' } }), { status: 404 });

  // An account with nothing yet: a token would reach nothing, ever.
  await ada.members.add('token:ci-empty');
  await assert.rejects(ada.tokens.issue('token:ci-empty', { expiresInDays: 30 }), { status: 400 });

  const refusals = await db.owner
    .select({ actor: auditLog.actor, metadata: auditLog.metadata })
    .from(auditLog)
    .where(and(eq(auditLog.action, 'token.create'), eq(auditLog.decision, 'deny')))
    .orderBy(asc(auditLog.seq));
  assert.deepEqual(
    refusals.map((row) => [row.actor, JSON.parse(row.metadata).reason, JSON.parse(row.metadata).path ?? null]),
    [
      [ADA, 'not_service_manager', null],
      [ADA, 'not_service_manager', null],
      [ADA, 'beyond_account', 'market/prod'],
      [ADA, 'beyond_account', 'market'],
      [`user:${ROOT}`, 'beyond_account', 'market/prod'],
    ],
  );
  const binds = await db.owner.select({ metadata: auditLog.metadata }).from(auditLog).where(and(eq(auditLog.action, 'token.bind'), eq(auditLog.decision, 'deny')));
  assert.deepEqual(binds.map((row) => [JSON.parse(row.metadata).reason, JSON.parse(row.metadata).path]), [['beyond_account', 'market/prod']]);
  assert.deepEqual((await db.owner.select().from(credentials)).length, 0, 'no token was made');
});

test('a binding that replaces others reaches what they reached of what the account still holds, unless told: trusting a workload again never widens it', async () => {
  const DEPLOY = { repository_owner_id: '9919', repository_id: '41532', workflow_ref: 'acme/api/.github/workflows/deploy.yml@refs/heads/main', ref: 'refs/heads/main', event_name: 'push' };
  const narrow = await ada.bindings.create(CI, { profile: 'github', claims: DEPLOY, scope: { 'market/dev': 'viewer' } });
  await root.access.set(CI, { 'market/prod': 'viewer' });
  // Asked to replace it, by someone who could give it all the account holds now: what it reached, not prod.
  const again = await root.bindings.create(CI, { profile: 'github', claims: DEPLOY, replaces: [narrow.binding.id] });
  assert.deepEqual(again.binding.scope, { 'market/dev': 'viewer' });
  // Its issuer moved its keys: the binding made on the new ones takes the old one's place, and its scope, as the preview says.
  jwks = `${GITHUB}/.well-known/jwks-2`;
  const plan = await root.bindings.preview(CI, { profile: 'github', claims: DEPLOY });
  assert.deepEqual([plan.scope, plan.replaces], [{ 'market/dev': 'viewer' }, [{ id: again.binding.id, why: 'keys_moved' }]]);
  const moved = await root.bindings.create(CI, { profile: 'github', claims: DEPLOY });
  assert.deepEqual(moved.binding.scope, { 'market/dev': 'viewer' });
  // Named, the scope is what it says, within the account.
  const told = await root.bindings.create(CI, { profile: 'github', claims: DEPLOY, scope: { 'market/dev': 'developer', 'market/prod': 'viewer' }, replaces: [moved.binding.id] });
  assert.deepEqual(told.binding.scope, { 'market/dev': 'developer', 'market/prod': 'viewer' });
  // What the account lost drops out: prod taken back, the next one reaches dev alone; nothing left of it, it is refused.
  await root.access.set(CI, { 'market/prod': null });
  const after = await root.bindings.create(CI, { profile: 'github', claims: DEPLOY, replaces: [told.binding.id] });
  assert.deepEqual(after.binding.scope, { 'market/dev': 'developer' });
  await root.access.set(CI, { 'market/dev': null, 'market/prod': 'viewer' });
  await assert.rejects(root.bindings.create(CI, { profile: 'github', claims: DEPLOY, replaces: [after.binding.id] }), { status: 400 });
  assert.deepEqual((await root.bindings.list(CI)).bindings.map((each) => each.id), [after.binding.id], 'refused, it replaced nothing');
});

test('the scope is listed wherever tokens are, and logged by id when made', async () => {
  const issued = await ada.tokens.issue(CI, { label: 'deploy', expiresInDays: 30, scope: { 'market/dev': 'viewer' } });
  const [listed] = (await ada.tokens.list(CI)).tokens;
  assert.deepEqual(listed!.scope, { 'market/dev': 'viewer' });
  // Offboarding Ada lists what she issued, with what each reaches.
  const report = await root.members.get(ADA);
  assert.deepEqual(report.issuedTokens.map((token) => [token.id, token.scope]), [[issued.id, { 'market/dev': 'viewer' }]]);
  const [entry] = await db.owner
    .select({ metadata: auditLog.metadata })
    .from(auditLog)
    .where(and(eq(auditLog.action, 'token.create'), eq(auditLog.decision, 'allow')));
  const [dev] = await db.owner.select({ id: environments.id, projectId: environments.projectId }).from(environments).where(eq(environments.slug, 'dev'));
  assert.deepEqual(JSON.parse(entry!.metadata).scope, [{ projectId: dev!.projectId, environmentId: dev!.id, role: 'viewer' }]);
});

test("a scope changed or cleared around the app fails the row's MAC, and the token is refused", async () => {
  const issued = await ada.tokens.issue(CI, { expiresInDays: 30, scope: { 'market/dev': 'viewer' } });
  await root.access.set(CI, { 'market/prod': 'viewer' });
  const [row] = await db.owner.select({ id: credentials.id, scope: credentials.scope }).from(credentials);
  const [dev] = JSON.parse(row!.scope!) as { projectId: string; environmentId: string; role: string }[];
  // Developer on dev, and prod, which the account holds now.
  const prod = (await db.owner.select({ id: environments.id }).from(environments).where(eq(environments.slug, 'prod')))[0]!.id;
  const wider = JSON.stringify([{ ...dev!, role: 'developer' }, { ...dev!, environmentId: prod, role: 'viewer' }]);
  for (const forged of [wider, null]) {
    await db.owner.update(credentials).set({ scope: forged }).where(eq(credentials.id, row!.id));
    assert.equal(await reads(issued.token, 'dev'), 401, `scope ${forged}`);
  }
  await db.owner.update(credentials).set({ scope: row!.scope }).where(eq(credentials.id, row!.id));
  assert.equal(await reads(issued.token, 'dev'), 'dev-key', 'its own scope put back checks again');
});

/** A token of 0.4, issued for `principal`: no scope, its MAC over 0.4's tuple. Its value. */
async function legacyToken(principal: string): Promise<{ token: string; id: string }> {
  const token = generateToken('service');
  const [member] = await db.owner.select().from(vaultMembers).where(eq(vaultMembers.principal, principal));
  const row = {
    id: randomUUID(),
    kind: 'service',
    tokenHash: hashToken(token),
    generation: member!.generation,
    tokenHint: tokenHint(token),
    principal,
    identityId: null,
    label: '0.4',
    createdBy: 'ada@acme.example',
    expiresAt: new Date(Date.now() + 86_400_000),
    revokedAt: null,
  };
  await db.owner.insert(credentials).values({ ...row, authMac: authMac(deps.chainKey, 'credentials', row) });
  return { token, id: row.id };
}

test("two processes sealing 0.4's tokens at once seal each once, and each token reaches what its account held", async () => {
  const tokens = await Promise.all(Array.from({ length: 6 }, () => legacyToken(CI)));
  // Each its own process, as two isolates or two Node servers starting together.
  const counts = await Promise.all([sealScopes(deps.db, deps.chainKey, deps.vault), sealScopes(deps.db, deps.chainKey, deps.vault)]);
  assert.equal(counts[0] + counts[1], tokens.length, `sealed once each, not ${counts.join(' and ')}`);
  assert.deepEqual(await unsealedCredentials(db.owner, new Date()), []);
  for (const { token } of tokens) assert.equal(await reads(token, 'dev'), 'dev-key', 'its MAC checks, its scope the account\'s');
  await root.access.set(CI, { 'market/prod': 'viewer' });
  for (const { token } of tokens) assert.equal(await reads(token, 'prod'), 403);
});

test('a vault that cannot answer seals nothing: the credential is uncheckable, never sealed empty or in part, and the next check seals it', async () => {
  const { token, id } = await legacyToken(CI);
  const access = deps.vault.access.bind(deps.vault);
  let down = true;
  deps.vault.access = async (principal) => {
    if (down) throw new Error('the vault is down');
    return access(principal);
  };
  await assert.rejects(runtime.signin!.verify(token), CredentialUncheckable);
  const unsealed = async () => (await db.owner.select({ scope: credentials.scope }).from(credentials).where(eq(credentials.id, id)))[0]!.scope;
  assert.equal(await unsealed(), null);
  assert.equal(await reads(token, 'dev'), 503, 'unavailable, not let through');
  down = false;
  assert.equal(await reads(token, 'dev'), 'dev-key');
  assert.notEqual(await unsealed(), null);
});

test('on Workers, where each request builds its runtime, the isolate seals once: a later request reads no unsealed rows, and asks the vault of no other account', async () => {
  const issued = await ada.tokens.issue(CI, { expiresInDays: 30 });
  await ada.members.add('token:ci-old');
  await ada.access.set('token:ci-old', { 'market/dev': 'viewer' });
  const first = await legacyToken('token:ci-old');
  // What `createCoffre` keeps for the isolate, and `runtimeFor` builds each runtime from, request by request.
  const config = resolveConfig({ publicUrl: ORIGIN, vault: deps.vault, auth: signin({ providers: [github({ clientId: 'a', clientSecret: 'b' })] }), auditChainKey: deps.chainKey.toString('base64') });
  const transport = { json: async () => ({}) };
  const asked: string[] = [];
  const access = deps.vault.access.bind(deps.vault);
  deps.vault.access = async (principal) => {
    asked.push(principal);
    return access(principal);
  };
  const scope = async (id: string) => (await db.owner.select({ scope: credentials.scope }).from(credentials).where(eq(credentials.id, id)))[0]!.scope;
  /** A request of the isolate, with its own runtime: what it read of `credentials`' unsealed rows, and whom it asked the vault about. */
  const request = async (isolate: typeof config) => {
    asked.length = 0;
    const answered = await fetchApi(
      new Request(`${ORIGIN}/api/me`, { headers: { authorization: `Bearer ${issued.token}` } }),
      createRuntime(isolate, deps.db, deps.vault, transport),
      { sourceIp: null },
    );
    assert.equal(answered.status, 200);
    return [...asked];
  };
  assert.deepEqual(await request(config), ['token:ci-old', CI], 'the first request seals, then checks its own token');
  assert.notEqual(await scope(first.id), null);
  // A token 0.4 makes while both run: no request of this isolate reads it, nor asks the vault about its account.
  const second = await legacyToken('token:ci-old');
  for (let i = 0; i < 3; i++) assert.deepEqual(await request(config), [CI]);
  assert.equal(await scope(second.id), null);
  // Another isolate, or process, seals it on its first request.
  const another = resolveConfig({ publicUrl: ORIGIN, vault: deps.vault, auth: signin({ providers: [github({ clientId: 'a', clientSecret: 'b' })] }), auditChainKey: deps.chainKey.toString('base64') });
  assert.deepEqual(await request(another), ['token:ci-old', CI]);
  assert.notEqual(await scope(second.id), null);
});

test('a token 0.4 makes after this process sealed is sealed on its first use, with the answer its check already asked of the vault, and widened by nothing after', async () => {
  const issued = await ada.tokens.issue(CI, { expiresInDays: 30 });
  assert.equal(await reads(issued.token, 'dev'), 'dev-key', 'the first check seals what there is');
  const straggler = await legacyToken(CI);
  const asked: string[] = [];
  const access = deps.vault.access.bind(deps.vault);
  deps.vault.access = async (principal) => {
    asked.push(principal);
    return access(principal);
  };
  assert.equal(await reads(straggler.token, 'dev'), 'dev-key');
  assert.deepEqual(asked.slice(0, 1), [CI], 'its own check, once, before the request reads anything');
  const scope = async (id: string) => (await db.owner.select({ scope: credentials.scope }).from(credentials).where(eq(credentials.id, id)))[0]!.scope;
  assert.equal(await scope(straggler.id), await scope(issued.id), "the account's grants, as a token issued now reaches them");
  const seals = await db.owner.select({ actor: auditLog.actor, metadata: auditLog.metadata }).from(auditLog).where(eq(auditLog.action, 'token.seal'));
  assert.deepEqual(seals.map((entry) => [entry.actor, JSON.parse(entry.metadata) as unknown]), [[
    'system:app',
    { principalType: 'service', principalId: 'ci-web', tokens: [straggler.id], bindings: [], scope: JSON.parse((await scope(issued.id))!) as unknown },
  ]]);
  // Widened after, it reaches no more than it did; as one sealed with the rest would.
  await root.access.set(CI, { 'market/prod': 'viewer' });
  assert.equal(await reads(straggler.token, 'prod'), 403);
  assert.equal(await reads(straggler.token, 'dev'), 'dev-key');
});

test("a token's dry run says what it would reach, checked as issuing it is, and issues and logs nothing", async () => {
  assert.deepEqual(await ada.tokens.preview(CI, { expiresInDays: 30 }), { scope: { 'market/dev': 'developer' } });
  assert.deepEqual(await ada.tokens.preview(CI, { expiresInDays: 30, scope: { 'market/dev': 'viewer' } }), { scope: { 'market/dev': 'viewer' } });
  await assert.rejects(ada.tokens.preview(CI, { expiresInDays: 30, scope: { 'market/prod': 'viewer' } }), { status: 403 });
  assert.deepEqual(await db.owner.select().from(credentials).where(eq(credentials.principal, CI)), []);
  assert.deepEqual(await db.owner.select().from(auditLog).where(eq(auditLog.action, 'token.create')).then((rows) => rows.filter((row) => row.decision === 'allow')), []);
});

test("0.4's tokens and bindings keep exactly what they reached: sealed with the account's grants once, as coffre migrate lists them, and widened by nothing after", async () => {
  // A token 0.4 issued: no scope, its MAC over 0.4's tuple.
  const token = generateToken('service');
  const [member] = await db.owner.select().from(vaultMembers).where(eq(vaultMembers.principal, CI));
  const row = {
    id: randomUUID(),
    kind: 'service',
    tokenHash: hashToken(token),
    generation: member!.generation,
    tokenHint: tokenHint(token),
    principal: CI,
    identityId: null,
    label: '0.4',
    createdBy: 'ada@acme.example',
    expiresAt: new Date(Date.now() + 86_400_000),
    revokedAt: null,
  };
  await db.owner.insert(credentials).values({ ...row, authMac: authMac(deps.chainKey, 'credentials', row) });
  // A binding 0.4 made, and one it removed, which stays as it is.
  const binding = (id: string, revokedAt: Date | null) => ({
    id,
    principal: CI,
    generation: member!.generation,
    profile: 'custom',
    issuer: 'https://ci.acme.example',
    jwksUri: 'https://ci.acme.example/keys',
    claims: JSON.stringify({ sub: id }),
    revokedAt,
  });
  const [bound, removed] = [binding(randomUUID(), null), binding(randomUUID(), new Date())];
  for (const each of [bound, removed]) {
    await db.owner.insert(serviceBindings).values({ ...each, label: null, createdBy: 'ada@acme.example', authMac: authMac(deps.chainKey, 'service_bindings', each) });
  }
  const listed = await unsealedCredentials(db.owner, new Date());
  assert.deepEqual(listed, [{ kind: 'binding', id: bound.id, principal: CI }, { kind: 'token', id: row.id, principal: CI }]);

  // The first credential this process checks seals it, before anything else.
  await root.access.set(CI, { 'market/prod': 'viewer' });
  assert.equal(await reads(token, 'prod'), 'prod-key', "the account's grants when it is sealed, as 0.4 read them");
  const sealed = [
    ...await db.owner.select({ id: credentials.id, scope: credentials.scope }).from(credentials).where(inArray(credentials.id, listed.map((each) => each.id))),
    ...await db.owner.select({ id: serviceBindings.id, scope: serviceBindings.scope }).from(serviceBindings).where(inArray(serviceBindings.id, listed.map((each) => each.id))),
  ];
  assert.equal(sealed.length, listed.length, 'what migrate listed is what was sealed');
  assert.equal(new Set(sealed.map((each) => each.scope)).size, 1, "both with the account's grants");
  assert.ok(sealed.every((each) => each.scope !== null));
  assert.deepEqual((await root.bindings.list(CI)).bindings.map((each) => [each.id, each.scope]), [[bound.id, { 'market/dev': 'developer', 'market/prod': 'viewer' }]]);
  assert.equal((await db.owner.select({ scope: serviceBindings.scope }).from(serviceBindings).where(eq(serviceBindings.id, removed.id)))[0]!.scope, null, 'a removed binding is left as it is');
  assert.deepEqual(await unsealedCredentials(db.owner, new Date()), []);
  assert.equal(await sealScopes(deps.db, deps.chainKey, deps.vault), 0, 'once');
  // Logged, by the app, naming each row it sealed and what they reach.
  const seals = await db.owner.select({ actor: auditLog.actor, metadata: auditLog.metadata }).from(auditLog).where(eq(auditLog.action, 'token.seal'));
  assert.deepEqual(seals.map((entry) => [entry.actor, JSON.parse(entry.metadata) as unknown]), [[
    'system:app',
    { principalType: 'service', principalId: 'ci-web', tokens: [row.id], bindings: [bound.id], scope: JSON.parse(sealed[0]!.scope!) as unknown },
  ]]);

  // Widened after, it reaches no more than it did.
  await root.projects.create('billing', { name: 'Billing' });
  await root.environments.create('billing/dev', { name: 'dev' });
  await root.access.set(CI, { 'billing/dev': 'viewer' });
  const me = bearer(token);
  await assert.rejects(me.secrets.list('billing/dev'), { status: 403 });
  assert.deepEqual((await root.tokens.list(CI)).tokens.find((each) => each.id === row.id)?.scope, {
    'market/dev': 'developer',
    'market/prod': 'viewer',
  });
});
