// A person's personal token acts as them, within the scope it was made with:
// at most what they held then, and at each request what both its scope and
// they hold now. It reaches their secrets and places, never their access or
// sign-in, and every entry made with it names it (docs/design/personal-tokens.md).
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import { createClient, type CoffreClient } from '@coffre/client';
import { issuedGrant } from '@coffre/core/access';
import { defineSignin, github } from '@coffre/core/identity';
import { and, asc, eq } from 'drizzle-orm';

import { SigninService } from '../src/api/signin.ts';
import { fetchApi } from '../src/fetch-api.ts';
import type { CoffreRuntime } from '../src/runtime.ts';
import { auditLog, credentials } from './db/tables.ts';
import { clientFor, contextFor, openTestDatabase, resetDatabase, testDeps, waitUntil, type FixtureDeps } from './api-fixture.ts';

const ORIGIN = 'https://secrets.acme.example';
const ROOT = 'admin@acme.example';
const ADA = 'user:ada@acme.example';
const SIGNIN = defineSignin({ publicUrl: ORIGIN, providers: [github({ clientId: 'a', clientSecret: 'b' })] });

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;
let runtime: CoffreRuntime;
let signin: SigninService;
let root: CoffreClient;
/** A Developer of every project's dev. */
let ada: CoffreClient;

before(async () => {
  db = await openTestDatabase();
});

after(async () => {
  await db.close();
});

beforeEach(async () => {
  await resetDatabase(db.owner);
  deps = testDeps(db.runtime, [ROOT]);
  signin = new SigninService({ db: deps.db, chainKey: deps.chainKey, vault: deps.vault, signin: SIGNIN });
  deps.signin = signin;
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
    rotateAfterDays: 365,
    plugins: [],
  } as CoffreRuntime;
  root = clientFor(deps, ROOT);
  ada = clientFor(deps, 'ada@acme.example');
  await root.projects.create('market', { name: 'Market' });
  for (const environment of ['dev', 'prod']) {
    await root.environments.create(`market/${environment}`, { name: environment });
    await root.secrets.set(`market/${environment}`, { API_KEY: `${environment}-key` });
  }
  await root.members.add(ADA, { role: 'developer', scope: { environments: { only: ['dev'] } } });
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

/** The status a call answers with, or 200. */
async function status(call: Promise<unknown>): Promise<number> {
  try {
    await call;
    return 200;
  } catch (error) {
    return (error as { status: number }).status;
  }
}

/** The app's refusals of `action`, as reasons, oldest first. */
async function refusals(action: string): Promise<string[]> {
  const rows = await db.owner
    .select({ metadata: auditLog.metadata })
    .from(auditLog)
    .where(and(eq(auditLog.author, 'app'), eq(auditLog.action, action), eq(auditLog.decision, 'deny')))
    .orderBy(asc(auditLog.seq));
  return rows.map((row) => JSON.parse(row.metadata).reason);
}

test('a personal token acts as its person within its scope: it reads what it names, writes nothing a viewer would, and reaches no other place', async () => {
  const issued = await ada.tokens.issue(ADA, { label: 'cursor-agent', expiresInMinutes: 240, scope: { 'market/dev': 'viewer' } });
  assert.match(issued.token, /^coffre_pat_/);
  assert.deepEqual(issued.scope, { 'market/dev': 'viewer' });
  assert.ok(Math.abs(Date.parse(issued.expiresAt) - Date.now() - 240 * 60_000) < 60_000, 'four hours');

  assert.equal(await reads(issued.token, 'dev'), 'dev-key');
  assert.equal(await status(bearer(issued.token).secrets.set('market/dev', { API_KEY: 'x' })), 403, 'its scope reads, though Ada writes');
  assert.equal(await reads(issued.token, 'prod'), 403);

  const me = await bearer(issued.token).me();
  assert.deepEqual(me.principal, { type: 'user', id: 'ada@acme.example' });
  assert.deepEqual(me.personalToken && { label: me.personalToken.label, scope: me.personalToken.scope }, { label: 'cursor-agent', scope: { 'market/dev': 'viewer' } });
  assert.deepEqual(me.environments, [{ project: 'market', environment: 'dev', permissions: ['secret.read', 'secret.use'] }]);
  assert.equal((await ada.me()).personalToken, null, 'a session is no token');
});

test('a scope is at most what its person holds when it is made, never a role that manages access, and every part of it said', async () => {
  const make = (input: Parameters<CoffreClient['tokens']['issue']>[1]) => status(ada.tokens.issue(ADA, input));
  const base = { label: 'agent', expiresInMinutes: 60 };
  // Ada is a Developer of every dev: prod, and market as a whole, are not hers.
  assert.equal(await make({ ...base, scope: { 'market/prod': 'viewer' } }), 403);
  assert.equal(await make({ ...base, scope: { market: 'viewer' } }), 403);
  assert.equal(await make({ ...base, scope: { 'market/dev': 'auditor' } }), 403, 'more than she holds there');
  // Roles that manage access, whoever holds them.
  assert.equal(await status(root.tokens.issue(`user:${ROOT}`, { ...base, scope: { market: 'owner' } })), 400);
  assert.equal(await status(root.tokens.issue(`user:${ROOT}`, { ...base, scope: { market: 'access-manager' } })), 400);
  // Every part said, and a lifetime of a minute to a week.
  assert.equal(await make({ label: null, expiresInMinutes: 60, scope: { 'market/dev': 'viewer' } }), 400);
  assert.equal(await make({ ...base }), 400, 'no scope');
  assert.equal(await make({ ...base, scope: {} }), 400, 'a scope that reaches nothing');
  assert.equal(await make({ label: 'agent', expiresInDays: 1, scope: { 'market/dev': 'viewer' } }), 400, 'days are a service token\'s');
  assert.equal(await make({ ...base, expiresInMinutes: 7 * 24 * 60 + 1, scope: { 'market/dev': 'viewer' } }), 400);
  assert.equal(await make({ ...base, scope: { 'market/nope': 'viewer' } }), 404);
  // For themselves alone.
  assert.equal(await status(root.tokens.issue(ADA, { ...base, scope: { 'market/dev': 'viewer' } })), 403);
  assert.equal(await status(clientFor(deps, 'ci', 'service').tokens.issue(ADA, { ...base, scope: { 'market/dev': 'viewer' } })), 403);

  assert.deepEqual(await refusals('token.create'), ['beyond_holder', 'beyond_holder', 'beyond_holder']);
  assert.equal((await db.owner.select().from(credentials)).length, 0, 'no token was made');
  // An Owner of the whole instance makes one for all of market, as a maintainer.
  assert.deepEqual((await root.tokens.issue(`user:${ROOT}`, { ...base, scope: { market: 'maintainer' } })).scope, { market: 'maintainer' });
});

test('a token weighs its person as they are at each request: narrowed, it narrows; widened, it does not widen; removed, it is gone for good', async () => {
  const issued = await ada.tokens.issue(ADA, { label: 'script', expiresInMinutes: 60, scope: { 'market/dev': 'developer' } });
  await bearer(issued.token).secrets.set('market/dev', { API_KEY: 'written' });

  await root.access.set(ADA, { 'market/prod': 'viewer' });
  assert.equal(await reads(issued.token, 'prod'), 403, 'what Ada is given later does not reach it');

  await root.members.add(ADA, { role: 'member' });
  assert.equal(await reads(issued.token, 'dev'), 403, 'Ada no longer reads dev, so neither does her token');
  await root.access.set(ADA, { 'market/dev': 'viewer' });
  assert.equal(await reads(issued.token, 'dev'), 'written', 'a grant reaches it as the role did');
  assert.equal(await status(bearer(issued.token).secrets.set('market/dev', { API_KEY: 'again' })), 403, 'as far as Ada holds');

  await root.members.remove(ADA);
  assert.equal(await status(bearer(issued.token).me()), 401);
  await root.members.add(ADA, { role: 'developer' });
  assert.equal(await status(bearer(issued.token).me()), 401, 'adding her again starts from nothing');
});

/**
 * Run `meanwhile` once, as the vault is next asked for values: after the
 * request's credential was checked, before the vault releases anything.
 */
function beforeNextRelease(meanwhile: () => Promise<unknown>): void {
  const unwrap = deps.vault.unwrap;
  deps.vault.unwrap = async (...args) => {
    deps.vault.unwrap = unwrap;
    await meanwhile();
    return unwrap(...args);
  };
}

test('a token revoked while its read is under way gets nothing: the read checks it again once the vault has released (formal/Credentials.tla)', async () => {
  const issued = await ada.tokens.issue(ADA, { label: 'script', expiresInMinutes: 60, scope: { 'market/dev': 'viewer' } });
  beforeNextRelease(() => root.tokens.revoke(ADA, issued.id));
  assert.equal(await reads(issued.token, 'dev'), 401);
  // The vault's release is in the log, and after it, the app's refusal: withheld, not handed to a revoked token.
  assert.deepEqual(await refusals('secret.read'), ['credential_ended']);
  // Removed and added again meanwhile: the vault finds her active, but at a generation the token was not issued at.
  const again = await ada.tokens.issue(ADA, { label: 'again', expiresInMinutes: 60, scope: { 'market/dev': 'viewer' } });
  beforeNextRelease(async () => {
    await root.members.remove(ADA);
    await root.members.add(ADA, { role: 'developer', scope: { environments: { only: ['dev'] } } });
  });
  assert.equal(await reads(again.token, 'dev'), 401);
  // A session, read the same way, still reads.
  assert.equal((await ada.secrets.reveal('market/dev')).values.API_KEY, 'dev-key');
});

test('a personal token makes nothing that outlives it: no token, session, app, grant, member, service account or binding; nor runs the instance', async () => {
  const issued = await root.tokens.issue(`user:${ROOT}`, { label: 'agent', expiresInMinutes: 60, scope: { market: 'maintainer' } });
  const token = bearer(issued.token);
  const refused: [string, () => Promise<unknown>][] = [
    ['personal token', () => token.tokens.issue(`user:${ROOT}`, { label: 'again', expiresInMinutes: 60, scope: { 'market/dev': 'viewer' } })],
    ['service token', () => token.tokens.issue('token:ci', { label: null, expiresInDays: 1 })],
    ['its own tokens', () => token.tokens.list(`user:${ROOT}`)],
    ['a member', () => token.members.add(ADA, { role: 'owner' })],
    ['a service account', () => token.members.add('token:ci')],
    ['access', () => token.access.set(ADA, { market: 'owner' })],
    ['the members', () => token.members.list()],
    ['a binding', () => token.bindings.list('token:ci')],
    ['settings', () => token.settings.set({ serviceAccounts: { projects: 'all', environments: 'all' } })],
    ['sessions', () => token.sessions.list()],
    ['a CLI sign-in', () => token.deviceLogins.decide('BCDF-GHJK', true)],
    ['deleting', () => token.environments.delete('market/dev')],
    ['verifying the log', () => token.audit.verify()],
  ];
  for (const [what, call] of refused) assert.equal(await status(call()), 403, what);
  // Each attempt is logged, as the token tried it, naming the route.
  const used = await db.owner.select({ metadata: auditLog.metadata }).from(auditLog).where(and(eq(auditLog.action, 'token.use'), eq(auditLog.decision, 'deny'))).orderBy(asc(auditLog.seq));
  assert.equal(used.length, refused.length);
  assert.ok(used.every((row) => JSON.parse(row.metadata).reason === 'personal_token' && JSON.parse(row.metadata).credentialId === issued.id));
  assert.deepEqual(JSON.parse(used[0]!.metadata).route, 'POST /members/:member/tokens');

  // What its routes reach, its scope holds to: a project needs an Admin's instance role, which a scope never carries.
  assert.equal(await status(token.projects.create('billing', {})), 403);
  await token.environments.create('market/staging', {});
  await token.secrets.set('market/staging', { API_KEY: 'staging-key' });
  assert.equal(await reads(issued.token, 'staging'), 'staging-key', 'a grant on a project reaches the environments made in it later');
  // The log of the places it reaches, not the instance's: an Owner's token for market's log reads market's alone.
  assert.equal(await status(token.audit.list({})), 403, 'a maintainer reads no log');
  const auditor = await root.tokens.issue(`user:${ROOT}`, { label: 'log', expiresInMinutes: 60, scope: { market: 'auditor' } });
  const { entries } = await bearer(auditor.token).audit.list({ detail: '1' });
  assert.ok(entries.length > 0 && entries.every((entry) => entry.project === 'market'), 'no sign-in, member or settings entry');
});

test('every entry made with a personal token names its person and the token, the vault\'s too, and the log shows its label', async () => {
  const issued = await ada.tokens.issue(ADA, { label: 'cursor-agent', expiresInMinutes: 60, scope: { 'market/dev': 'developer' } });
  await bearer(issued.token).secrets.set('market/dev', { API_KEY: 'from-agent' });
  assert.equal(await reads(issued.token, 'dev'), 'from-agent');

  const written = await db.owner
    .select({ author: auditLog.author, actor: auditLog.actor, action: auditLog.action, metadata: auditLog.metadata })
    .from(auditLog)
    .where(and(eq(auditLog.actor, ADA)))
    .orderBy(asc(auditLog.seq));
  const made = written.filter((row) => JSON.parse(row.metadata).credentialId === issued.id).map((row) => `${row.author} ${row.action}`);
  for (const action of ['app secret.write', 'vault key.wrap', 'vault secret.read']) assert.ok(made.includes(action), action);

  const { entries } = await root.audit.list({ actor: ADA, detail: '1' });
  const create = entries.find((entry) => entry.action === 'token.create')!;
  assert.deepEqual([create.metadata.kind, create.metadata.label, create.metadata.targetCredentialId, create.token], ['personal', 'cursor-agent', issued.id, null]);
  const read = entries.find((entry) => entry.action === 'secret.read')!;
  assert.deepEqual([read.actorId, read.token], ['ada@acme.example', { id: issued.id, label: 'cursor-agent' }]);
  const write = entries.find((entry) => entry.action === 'secret.write')!;
  assert.deepEqual(write.token, { id: issued.id, label: 'cursor-agent' });
});

test('a person lists and revokes their own tokens, and whoever runs the instance theirs; nobody else; and a token signs itself out', async () => {
  const first = await ada.tokens.issue(ADA, { label: 'first', expiresInMinutes: 60, scope: { 'market/dev': 'viewer' } });
  const second = await ada.tokens.issue(ADA, { label: 'second', expiresInMinutes: 30, scope: { 'market/dev': 'developer' } });
  const third = await ada.tokens.issue(ADA, { label: 'third', expiresInMinutes: 30, scope: { 'market/dev': 'viewer' } });
  const listed = (await ada.tokens.list(ADA)).tokens;
  assert.deepEqual(listed.map((token) => [token.label, token.scope]), [['third', { 'market/dev': 'viewer' }], ['second', { 'market/dev': 'developer' }], ['first', { 'market/dev': 'viewer' }]]);
  assert.match(listed[0]!.hint, /^coffre_pat_…/);
  assert.equal((await root.tokens.list(ADA)).tokens.length, 3);
  assert.deepEqual((await ada.sessions.list()).sessions, [], 'tokens are not sessions');

  await root.members.add('user:bo@acme.example', { role: 'admin', scope: { projects: 'all', environments: { only: ['dev'] } } });
  const bo = clientFor(deps, 'bo@acme.example');
  assert.equal(await status(bo.tokens.list(ADA)), 403, 'a scoped Admin runs no instance');
  assert.equal(await status(bo.tokens.revoke(ADA, first.id)), 403);
  assert.equal(await status(root.tokens.revoke('user:bo@acme.example', first.id)), 404, "not one of Bo's");

  await ada.tokens.revoke(ADA, first.id);
  assert.equal(await reads(first.token, 'dev'), 401);
  await root.tokens.revoke(ADA, second.id);
  assert.equal(await reads(second.token, 'dev'), 401);
  // `coffre logout` with the token: it revokes itself.
  await signin.signOut(third.token, { requestId: 'logout', sourceIp: null });
  assert.equal(await reads(third.token, 'dev'), 401);
  assert.deepEqual((await ada.tokens.list(ADA)).tokens, []);

  // Removing Ada revokes what she still holds, and the report counts it first.
  await ada.tokens.issue(ADA, { label: 'left', expiresInMinutes: 60, scope: { 'market/dev': 'viewer' } });
  const report = await root.members.get(ADA);
  assert.deepEqual([report.live.tokens, report.live.sessions, report.personalTokens.map((token) => token.label)], [1, 0, ['left']]);
  const { revoked } = await root.members.remove(ADA);
  assert.equal(revoked.tokens, 1);
});

test('a personal token is a bearer token alone: planted in the session cookie it is no session, and it links no sign-in account', async () => {
  const issued = await ada.tokens.issue(ADA, { label: 'agent', expiresInMinutes: 60, scope: { 'market/dev': 'viewer' } });
  const cookie = createClient({
    url: ORIGIN,
    headers: () => ({ cookie: `__Host-coffre_session=${issued.token}` }),
    transport: (request) => fetchApi(request, runtime, { sourceIp: null }),
  });
  assert.equal(await status(cookie.me()), 401);
  // Linking an account checks its caller itself too, as approving a sign-in and connecting an app do.
  const asked = await contextFor(deps, 'ada@acme.example');
  const scoped = { ...asked, caller: { ...asked.caller, credentialScope: [issuedGrant({ projectId: 'p', environmentId: null, role: 'viewer' })] } };
  await assert.rejects(signin.linkIdentity(scoped, { provider: 'github', subject: 'mallory', emails: ['mallory@evil.example'], name: null } as never), { status: 403 });
  await assert.rejects(signin.decideDevice(scoped, 'BCDF-GHJK', true), { status: 403 });
});

test("a personal token's label is shown wherever it goes, so it holds no control character; and its own sign-out names it", async () => {
  for (const label of ['agent\u001b[2K', 'two\nlines', 'tab\there']) {
    assert.equal(await status(ada.tokens.issue(ADA, { label, expiresInMinutes: 60, scope: { 'market/dev': 'viewer' } })), 400, JSON.stringify(label));
  }
  const issued = await ada.tokens.issue(ADA, { label: 'agent', expiresInMinutes: 60, scope: { 'market/dev': 'viewer' } });
  await signin.signOut(issued.token, { requestId: 'logout', sourceIp: null });
  const { entries } = await root.audit.list({ actor: ADA, detail: '1' });
  const out = entries.find((entry) => entry.action === 'sign_out')!;
  assert.deepEqual(out.token, { id: issued.id, label: 'agent' });
});

test("a token of a personal config's owner keeps to its scope's role there too: a viewer's reads their dev@me, and writes nothing", async () => {
  await ada.secrets.set('market/dev@me', { API_KEY: 'ada-own' });
  const issued = await ada.tokens.issue(ADA, { label: 'agent', expiresInMinutes: 60, scope: { 'market/dev': 'viewer' } });
  assert.equal((await bearer(issued.token).secrets.reveal('market/dev@me')).values.API_KEY, 'ada-own');
  assert.equal(await status(bearer(issued.token).secrets.set('market/dev@me', { API_KEY: 'x' })), 403);
  assert.equal(await status(bearer(issued.token).secrets.update('market/dev@me/API_KEY', { archived: true })), 403);
  assert.equal((await ada.secrets.reveal('market/dev@me')).values.API_KEY, 'ada-own');
  // The vault holds it to the same, whatever the app asks.
  const writer = await ada.tokens.issue(ADA, { label: 'writer', expiresInMinutes: 60, scope: { 'market/dev': 'developer' } });
  await bearer(writer.token).secrets.set('market/dev@me', { API_KEY: 'from-a-writer' });
  assert.equal((await ada.secrets.reveal('market/dev@me')).values.API_KEY, 'from-a-writer');
});
