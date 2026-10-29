// A person's personal token acts as them, within the scope it was made with:
// at most what they held then, and at each request what both its scope and
// they hold now. It reaches their secrets and places, never their access or
// sign-in, and every entry made with it names it (docs/design/personal-tokens.md).
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import { createClient, type CoffreClient } from '@coffre/client';
import { issuedGrant } from '@coffre/core/access';
import { defineSignin, github } from '@coffre/core/identity';
import { logObject } from '@coffre/db/log';
import { and, asc, eq, sql } from 'drizzle-orm';

import { SigninService } from '../src/api/signin.ts';
import { HIDDEN_COUNTED } from '../src/db/queries.ts';
import { fetchApi } from '../src/fetch-api.ts';
import type { CoffreRuntime } from '../src/runtime.ts';
import { auditLog, credentials, logChanges } from './db/tables.ts';
import { clientFor, contextFor, issuesLogged, LOG, openTestDatabase, resetDatabase, revokesLogged, testDeps, usesLogged, waitUntil, type FixtureDeps } from './api-fixture.ts';

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
    previousChainKeys: [],
    signin,
    workloads: null,
    mcp: null,
    auth: { mode: 'signin', signin: SIGNIN },
    publicUrl: ORIGIN,
    verifier: signin,
    waitUntil,
    schema: { migrated: true }, appKey: { settled: true },
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
 * request's credential was checked, before the vault decides. 0.14's unwrap
 * decides on the member, not the credential: only the app's check after the
 * release stands between the value and a credential that ended meanwhile
 * (Revoking). 0.15's use decides on the credential itself, as its own
 * statement reads it, its generation included, and no check follows it
 * (Revoking015Folded).
 */
function beforeNextRelease(meanwhile: () => Promise<unknown>): void {
  if (LOG === '0.15') {
    const use = deps.vault.use!;
    deps.vault.use = async (...args) => {
      deps.vault.use = use;
      await meanwhile();
      return use(...args);
    };
    return;
  }
  const unwrap = deps.vault.unwrap;
  deps.vault.unwrap = async (...args) => {
    deps.vault.unwrap = unwrap;
    await meanwhile();
    return unwrap(...args);
  };
}

test('a token revoked while its read is under way gets nothing: 0.14\'s read checks it again once the vault has released, 0.15\'s use decides on it (formal/Credentials.tla)', async () => {
  const issued = await ada.tokens.issue(ADA, { label: 'script', expiresInMinutes: 60, scope: { 'market/dev': 'viewer' } });
  beforeNextRelease(() => root.tokens.revoke(ADA, issued.id));
  assert.equal(await reads(issued.token, 'dev'), 401);
  // 0.14: the vault's release is in the log, and after it, the app's refusal: withheld, not handed to a revoked token.
  // 0.15: the use, refused, is its own record (`usesLogged`).
  assert.deepEqual(await refusals('secret.read'), LOG === '0.15' ? [] : ['credential_ended']);
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

test("0.15: a token revoked once its use has decided ends after that read, which stands: the log orders the use before the revoke (Revoking015Folded)", { skip: LOG === '0.15' ? false : "0.14's read checks the token again after the vault's release" }, async () => {
  const issued = await ada.tokens.issue(ADA, { label: 'script', expiresInMinutes: 60, scope: { 'market/dev': 'viewer' } });
  const use = deps.vault.use!;
  deps.vault.use = async (...args) => {
    deps.vault.use = use;
    const used = await use(...args);
    await root.tokens.revoke(ADA, issued.id);
    return used;
  };
  assert.equal(await reads(issued.token, 'dev'), 'dev-key');
  assert.equal(await reads(issued.token, 'dev'), 401);
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
  // The read, under 0.15's log, is a use, its credential the token's: no entry here.
  for (const action of ['app secret.write', 'vault key.wrap', ...(LOG === '0.14' ? ['vault secret.read'] : [])]) assert.ok(made.includes(action), action);
  if (LOG === '0.15') assert.deepEqual((await usesLogged(db.owner)).map((use) => use.credential), [issued.id]);

  // With 0.15's log, the vault issues it (T149), and its change records it (D147): the page lists it in 0.14's entry's
  // place, and the token's label beside what it made, read from either (T164).
  if (LOG === '0.15') {
    assert.deepEqual((await issuesLogged(db.owner)).map(({ kind, label, targetCredentialId }) => [kind, label, targetCredentialId]), [['personal', 'cursor-agent', issued.id]]);
  }
  const { entries } = await root.audit.list({ actor: ADA, detail: '1', sealed: '1' });
  const create = entries.find((entry) => entry.action === 'token.create')!;
  assert.deepEqual([create.log, create.metadata.kind, create.metadata.label, create.metadata.targetCredentialId, create.token], [LOG, 'personal', 'cursor-agent', issued.id, null]);
  // The audit page reads 0.15's uses from plan PR 8: until then, the read it shows is 0.14's entry.
  if (LOG === '0.14') {
    const read = entries.find((entry) => entry.action === 'secret.read')!;
    assert.deepEqual([read.actorId, read.token], ['ada@acme.example', { id: issued.id, label: 'cursor-agent' }]);
  }
  const write = entries.find((entry) => entry.action === 'secret.write')!;
  assert.deepEqual(write.token, { id: issued.id, label: 'cursor-agent' });
});

test("a token of a person's own, asked on a request made before they were removed and admitted again, or on a session that ends meanwhile, is refused: 403, the session ended (T149, review r1)", async (t) => {
  const input = { label: 'agent', expiresInMinutes: 60, scope: { 'market/dev': 'viewer' } };
  // Loaded before Ada left and came back: her old membership's request.
  const before = await contextFor(deps, 'ada@acme.example');
  await root.members.remove(ADA);
  await root.members.add(ADA, { role: 'developer', scope: { environments: { only: ['dev'] } } });
  await assert.rejects(signin.issuePersonalToken(before, input), { code: 'forbidden', message: 'that session has ended' });
  await assert.rejects(signin.issueHandle({ ...before, personalToken: null }, { label: 'run', expiresInMinutes: 60, paths: ['market/dev'] }), { code: 'forbidden', message: 'that session has ended' });
  assert.deepEqual(await refusals('token.create'), ['session_ended', 'session_ended']);
  if (LOG !== '0.15') return;
  // With 0.15's log, a session of hers that ends once the request was checked, before the vault writes the token.
  const started = await signin.startDevice({ clientLabel: 'laptop', sourceIp: null });
  await signin.decideDevice(await contextFor(deps, 'ada@acme.example'), started.userCode, true);
  const polled = await signin.pollDevice(started.deviceCode, { requestId: 'device', sourceIp: null });
  assert.ok(polled.status === 'approved');
  const vault = deps.vault as unknown as Record<string, (...args: unknown[]) => Promise<unknown>>;
  const call = vault.issueToken!.bind(vault);
  t.mock.method(vault, 'issueToken', async (...args: unknown[]) => {
    await signin.signOut(polled.credential.token, { requestId: 'signed-out', sourceIp: null });
    return call(...args);
  }, { times: 1 });
  assert.equal(await status(bearer(polled.credential.token).tokens.issue(ADA, input)), 403);
  assert.deepEqual(await refusals('token.create'), ['session_ended', 'session_ended', 'session_ended']);
  assert.equal((await db.owner.select().from(credentials).where(eq(credentials.kind, 'personal'))).length, 0, 'no token was made');
});

test('a personal token made on a session 0.14 made, which the log never held, is issued as before: the vault authenticates nothing of it (T149, review r3)', async () => {
  const started = await signin.startDevice({ clientLabel: 'laptop', sourceIp: null });
  await signin.decideDevice(await contextFor(deps, 'ada@acme.example'), started.userCode, true);
  const polled = await signin.pollDevice(started.deviceCode, { requestId: 'device', sourceIp: null });
  assert.ok(polled.status === 'approved');
  // As 0.14 left it: no seal, no change.
  await db.owner.update(credentials).set({ seal: null }).where(eq(credentials.id, polled.credential.id));
  await db.owner.delete(logChanges).where(sql`${logChanges.payload} LIKE ${`%${polled.credential.id}%`}`);
  const made = await bearer(polled.credential.token).tokens.issue(ADA, { label: 'agent', expiresInMinutes: 60, scope: { 'market/dev': 'viewer' } });
  assert.equal(await reads(made.token, 'dev'), 'dev-key');
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

test("a run ends its own handle, on a personal token too: a handle of the caller's only, never another credential nor another person's", async () => {
  const pat = await ada.tokens.issue(ADA, { label: 'agent', expiresInMinutes: 60, scope: { 'market/dev': 'viewer' } });
  const agent = bearer(pat.token);
  const revokedAt = async (id: string) => (await db.owner.select({ revokedAt: credentials.revokedAt }).from(credentials).where(eq(credentials.id, id)))[0]!.revokedAt;
  // Made with the token, as `coffre run` makes one, and ended with it once the run's command ends.
  const ran = await agent.handles.create({ label: 'coffre run', paths: ['market/dev'] });
  await agent.handles.revoke(ran.id);
  assert.notEqual(await revokedAt(ran.id), null);
  // Only a handle: not the token itself, a session or any other credential, which stays with the person.
  assert.equal(await status(agent.handles.revoke(pat.id)), 404);
  assert.equal(await status(agent.tokens.revoke(ADA, pat.id)), 403);
  // Only the caller's own: whoever runs the instance ends another's handle as a token, not here.
  const other = await ada.handles.create({ label: 'coffre run', paths: ['market/dev'] });
  assert.equal(await status(root.handles.revoke(other.id)), 404);
  assert.equal(await revokedAt(other.id), null);
  assert.equal(await revokedAt(pat.id), null);
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
  // With 0.15's log, the vault ends it (T149), and its change, which the page lists in 0.14's entry's place (T164), names
  // the token it ends.
  if (LOG === '0.15') assert.deepEqual(await revokesLogged(db.owner), [{ actor: ADA, reason: 'sign_out', targetCredentialId: issued.id }]);
  const { entries } = await root.audit.list({ actor: ADA, detail: '1', sealed: '1' });
  const out = entries.find((entry) => entry.action === 'sign_out')!;
  assert.deepEqual([out.log, out.metadata.targetCredentialId, out.metadata.kind, out.token], [LOG, issued.id, 'personal', { id: issued.id, label: 'agent' }]);
});

/**
 * A person's tokens on the audit pages, a page at a time, under either log (T164): their issues, revokes and
 * sign-outs, which 0.15's log records in place of 0.14's detail entries, are left out and counted, each on the page
 * of its own time, between the entries the pages show, as 0.14's entries are, never all on the first, though 0.15's
 * log holds no sign-in of a person's to page by. Asked for, they are listed among the rest. Pages tile both logs:
 * every entry on one, every hidden one counted on one.
 */
test("a person's token issues, revokes and sign-outs are counted on the page of their time, and every one listed once when asked", async () => {
  const pause = () => new Promise((resolve) => setTimeout(resolve, 25));
  const wrote = async (value: string) => {
    await ada.secrets.set('market/dev', { API_KEY: value });
    await pause();
  };
  await wrote('one');
  const first = await ada.tokens.issue(ADA, { label: 'first', expiresInMinutes: 60, scope: { 'market/dev': 'viewer' } });
  await pause();
  await wrote('two');
  const second = await ada.tokens.issue(ADA, { label: 'second', expiresInMinutes: 60, scope: { 'market/dev': 'viewer' } });
  await pause();
  await ada.tokens.revoke(ADA, second.id);
  await pause();
  await signin.signOut(first.token, { requestId: 'logout', sourceIp: null });
  await pause();
  await wrote('three');

  const TOKENS = new Set(['token.create', 'token.revoke', 'sign_out']);
  type Page = Awaited<ReturnType<CoffreClient['audit']['list']>>;
  // Counted (`hidden`) where a test asks, as no page of coffre's own does.
  const walk = async (query: { actor?: string; detail?: '1'; hidden?: '1' }, limit: number) => {
    const pages: Page[] = [];
    for (let before: string | undefined; ;) {
      const page = await root.audit.list({ ...query, sealed: '1', limit, ...(before === undefined ? {} : { before }) });
      assert.ok(page.entries.length <= limit);
      assert.equal(page.more, page.next !== null);
      pages.push(page);
      if (page.next === null) return pages;
      before = page.next;
    }
  };
  const tokens = (page: Page) => Object.fromEntries((page.hidden ?? []).filter(({ action }) => TOKENS.has(action)).map(({ action, count }) => [action, count]));
  // Ada's pages, a write a page, counted: none after the newest; then the second token's issue and revoke, and the
  // first's sign-out, between the second write and the third; then the first's issue. A full page of 0.14's says there
  // may be more, so the last is empty.
  const activity = await walk({ actor: ADA, hidden: '1' }, 1);
  assert.deepEqual(activity.map((page) => page.entries.map((entry) => `${entry.action} ${entry.log}`)), [['secret.write 0.14'], ['secret.write 0.14'], ['secret.write 0.14'], []]);
  assert.deepEqual(activity.map(tokens), [{}, { 'token.create': 1, 'token.revoke': 1, sign_out: 1 }, { 'token.create': 1 }, {}]);

  // Asked for, each is listed, as 0.14's entry put it.
  const listed = (await root.audit.list({ actor: ADA, detail: '1', sealed: '1', limit: 500 })).entries.filter((entry) => TOKENS.has(entry.action));
  assert.deepEqual(listed.map((entry) => [entry.log, entry.action, entry.actorId, entry.metadata.targetCredentialId, entry.detail]), [
    [LOG, 'sign_out', 'ada@acme.example', first.id, true],
    [LOG, 'token.revoke', 'ada@acme.example', second.id, true],
    [LOG, 'token.create', 'ada@acme.example', second.id, true],
    [LOG, 'token.create', 'ada@acme.example', first.id, true],
  ]);

  const named = (entries: Page['entries']) => entries.map((entry) => `${entry.log}:${entry.seq}`);
  for (const query of [{}, { hidden: '1' as const }, { detail: '1' as const }, { actor: ADA }, { actor: ADA, hidden: '1' as const }, { actor: ADA, detail: '1' as const }]) {
    const [whole] = await walk(query, 500);
    assert.equal(whole!.next, null);
    for (const limit of [1, 2, 5]) {
      const pages = await walk(query, limit);
      assert.deepEqual(named(pages.flatMap((page) => page.entries)), named(whole!.entries), `${JSON.stringify(query)}, ${limit} a page`);
      const hidden = new Map<string, number>();
      for (const { action, count } of pages.flatMap((page) => page.hidden ?? [])) hidden.set(action, (hidden.get(action) ?? 0) + count);
      assert.deepEqual(hidden, new Map((whole!.hidden ?? []).map(({ action, count }) => [action, count])), `${JSON.stringify(query)}, ${limit} a page: hidden`);
    }
  }
});

/**
 * Token records past what the pages show, more of them than a page counts (`HIDDEN_COUNTED`). A page that counts
 * them (`hidden`, asked for) counts no more than that, and shows nothing older than the last it counts, though an
 * entry it would show lies just below; the pages after count the rest, and show it, every one once. A page that does
 * not ask, as every page of coffre's own, counts nothing and shows the entry at once. Planted as the vault writes them,
 * as only the pages are under test (reviews r2, r3, r4 of W261): a person with nothing but their handles, and a
 * service whose runs' sign-outs came after an old sign-in.
 */
test("token records are counted a page's worth at a time, and an entry below them waits for the page that reaches it", async () => {
  const at = Date.now() - 3_600_000;
  const row = (i: number, actor: string, record: Record<string, unknown>) => {
    const id = crypto.randomUUID();
    return { number: 10_000_000n + BigInt(i), at: at + i, requestId: crypto.randomUUID(), object: logObject('credential', id), actor, payload: JSON.stringify({ ...record, ref: { id, kind: 'credential' } }), mac: Buffer.alloc(16) };
  };
  const CI = 'token:ci';
  const rows = [
    // Keys in the vault's order: an issue's, a sign-in's, a revoke's.
    ...Array.from({ length: 2 * HIDDEN_COUNTED + 500 }, (_, i) => row(i, ADA, {
      caller: 'person', expiresAt: at + 60_000, generation: 0, issue: { by: ADA, kind: 'handle', label: `run ${i}`, via: null }, op: 'credential.issue', principal: ADA,
    })),
    row(5_000, CI, { caller: 'bearer', expiresAt: at + 60_000, generation: 0, op: 'credential.issue', principal: CI, signIn: { binding: 'b', issuer: 'https://issuer.example', proof: 'oidc', run: { run_id: '7' } } }),
    ...Array.from({ length: 2 * HIDDEN_COUNTED + 500 }, (_, i) => row(5_001 + i, CI, { op: 'credential.revoke', revoke: { kind: 'service', principal: CI, reason: 'sign_out', via: null } })),
  ].map((planted) => ({ ...planted, payload: canonicalJson(JSON.parse(planted.payload)) }));
  for (let i = 0; i < rows.length; i += 500) await db.owner.insert(logChanges).values(rows.slice(i, i + 500));
  const walk = async (actor: string, action: string) => {
    const pages: { shown: string[]; counted: number }[] = [];
    for (let before: string | undefined; ;) {
      const page = await root.audit.list({ actor, sealed: '1', hidden: '1', limit: 50, ...(before === undefined ? {} : { before }) });
      pages.push({ shown: page.entries.map((entry) => entry.action), counted: page.hidden?.find((hidden) => hidden.action === action)?.count ?? 0 });
      if (page.next === null) return pages;
      before = page.next;
    }
  };
  assert.deepEqual(await walk(ADA, 'token.create'), [{ shown: [], counted: HIDDEN_COUNTED }, { shown: [], counted: HIDDEN_COUNTED }, { shown: [], counted: 500 }]);
  assert.deepEqual(await walk(CI, 'sign_out'), [{ shown: [], counted: HIDDEN_COUNTED }, { shown: [], counted: HIDDEN_COUNTED }, { shown: ['token.exchange'], counted: 500 }]);
  // Not asked: nothing counted, and the sign-in on the first page; Ada's first page is her last, and empty.
  const service = await root.audit.list({ actor: CI, sealed: '1', limit: 50 });
  assert.deepEqual([service.entries.map((entry) => entry.action), service.next, service.hidden], [['token.exchange'], null, undefined]);
  const person = await root.audit.list({ actor: ADA, sealed: '1', limit: 50 });
  assert.deepEqual([person.entries, person.next, person.hidden], [[], null, undefined]);
});

/** JSON with its objects' keys in order, as the vault writes a change's payload. */
function canonicalJson(value: unknown): string {
  return JSON.stringify(value, (_, v: unknown) => (v !== null && typeof v === 'object' && !Array.isArray(v) ? Object.fromEntries(Object.entries(v).sort(([a], [b]) => (a < b ? -1 : 1))) : v));
}

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
