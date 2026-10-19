// Protected environments, and roles an Owner edits (docs/design/roles.md),
// through the API: whoever manages a project's environments protects one,
// and a person there holds their role's protected column, a service account
// its other one; only an Owner of the whole instance unprotects one, and
// edits or makes roles, each change weighed first. A credential keeps what
// its roles held when it was issued: a role widened later widens none, and
// one narrowed narrows each at once, through its holder.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import { createClient, type CoffreClient, type RoleView } from '@coffre/client';
import { ROLES, UNWRITTEN_FORK_MS } from '@coffre/core/access';
import { defineSignin, github } from '@coffre/core/identity';
import { asc, eq } from 'drizzle-orm';

import { SigninService } from '../src/api/signin.ts';
import { fetchApi } from '../src/fetch-api.ts';
import type { CoffreRuntime } from '../src/runtime.ts';
import { lockLogHead } from '@coffre/db/log';
import { postgresOnly } from './db/engine.ts';
import { auditLog } from './db/tables.ts';
import { clientFor, openTestDatabase, resetDatabase, testDeps, waitUntil, type FixtureDeps } from './api-fixture.ts';

const ORIGIN = 'https://secrets.acme.example';
const ROOT = 'admin@acme.example';
const ADA = 'user:ada@acme.example';
const BOB = 'user:bob@acme.example';
const MAYA = 'user:maya@acme.example';
const VIC = 'user:vic@acme.example';
const CI = 'token:ci';
const SIGNIN = defineSignin({ publicUrl: ORIGIN, providers: [github({ clientId: 'a', clientSecret: 'b' })] });

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;
let runtime: CoffreRuntime;
let root: CoffreClient;
/** A Developer of market. */
let ada: CoffreClient;
/** A Maintainer of market, who manages its environments. */
let maya: CoffreClient;
/** A Viewer of market. */
let vic: CoffreClient;
/** A service account, a Viewer of market/prod. */
let ci: CoffreClient;

before(async () => {
  db = await openTestDatabase();
});

after(async () => {
  await db.close();
});

beforeEach(async () => {
  await resetDatabase(db.owner);
  deps = testDeps(db.runtime, [ROOT]);
  const signin = new SigninService({ db: deps.db, chainKey: deps.chainKey, vault: deps.vault, signin: SIGNIN });
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
  maya = clientFor(deps, 'maya@acme.example');
  vic = clientFor(deps, 'vic@acme.example');
  ci = clientFor(deps, 'ci', 'service');
  await root.projects.create('market');
  for (const environment of ['dev', 'prod']) {
    await root.environments.create(`market/${environment}`);
    await root.secrets.set(`market/${environment}`, { API_KEY: `${environment}-key` });
  }
  for (const [member, access] of [[ADA, { market: 'developer' }], [MAYA, { market: 'maintainer' }], [VIC, { market: 'viewer' }], [CI, { 'market/prod': 'viewer' }]] as const) {
    await root.members.add(member);
    await root.access.set(member, access);
  }
});

/** The API as a request with this bearer token sees it, through the app's front door. */
function bearer(token: string): CoffreClient {
  return createClient({ url: ORIGIN, headers: () => ({ authorization: `Bearer ${token}` }), transport: (request) => fetchApi(request, runtime, { sourceIp: null }) });
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

/** The status and reason a call is refused with, or 200. */
async function refusal(call: Promise<unknown>): Promise<{ status: number; reason?: string }> {
  try {
    await call;
    return { status: 200 };
  } catch (error) {
    const { status, reason } = error as { status: number; reason?: string };
    return { status, reason };
  }
}

async function actions(): Promise<string[]> {
  const rows = await db.owner.select({ action: auditLog.action, decision: auditLog.decision }).from(auditLog).orderBy(asc(auditLog.seq));
  return rows.map((row) => `${row.action} ${row.decision}`);
}

const protectedOf = async (client: CoffreClient, path: string) => {
  const [project, environment] = path.split('/');
  const listed = (await client.projects.list()).projects.find((each) => each.slug === project)!;
  return listed.environments.find((each) => each.slug === environment)!.protected;
};

test('protecting prod narrows a Developer there to use and write, while a service account Viewer still reads it', async () => {
  assert.equal(await status(ada.secrets.reveal('market/prod')), 200, 'before it is protected');
  // A Maintainer manages market's environments, and protects one.
  assert.equal((await maya.environments.protect('market/prod')).environment.protected, true);
  assert.equal(await protectedOf(ada, 'market/prod'), true);
  assert.equal(await protectedOf(ada, 'market/dev'), false);
  const listed = await ada.secrets.list('market/prod');
  assert.equal(listed.protected, true);
  assert.deepEqual(listed.permissions, ['secret.use', 'secret.write']);
  assert.equal(await status(ada.secrets.reveal('market/prod')), 403);
  assert.equal(await status(ada.secrets.reveal('market/dev')), 200, 'dev reads as before');
  assert.equal(await status(ada.secrets.set('market/prod', { API_KEY: 'rotated' })), 200, 'she sets values she does not read');
  // CI, a Viewer of prod, reads it as it always did: the protected column is a person's.
  assert.deepEqual((await ci.secrets.reveal('market/prod')).values, { API_KEY: 'rotated' });
  const entry = (await db.owner.select().from(auditLog).where(eq(auditLog.action, 'policy.change')))[0]!;
  assert.equal(entry.author, 'vault');
  assert.equal(entry.actor, MAYA);
  // The log lists it, beside what people did, not as a technical detail.
  const page = await root.audit.list({ limit: 20 });
  assert.ok(page.entries.some((listed) => listed.action === 'policy.change' && !listed.detail && listed.environment === 'prod'));
});

test('only an Owner of the whole instance unprotects an environment, or edits a role', async () => {
  await maya.environments.protect('market/prod');
  // A Developer manages no environment; a Maintainer protects but never unprotects.
  assert.equal(await status(ada.environments.protect('market/dev')), 403);
  assert.equal(await status(maya.environments.protect('market/prod', false)), 403);
  assert.equal(await protectedOf(root, 'market/prod'), true);
  assert.equal((await root.environments.protect('market/prod', false)).environment.protected, false);
  assert.equal(await status(ada.secrets.reveal('market/prod')), 200);

  const definition = { ...ROLES.developer, permissions: [...ROLES.developer.permissions], protected: ['secret.read', 'secret.use', 'secret.write'] as ('secret.read' | 'secret.use' | 'secret.write')[] };
  assert.equal(await status(maya.roles.set('developer', definition)), 403);
  assert.equal(await status(maya.roles.preview('developer', definition)), 403, 'nor weighs a change: it names everyone it reaches');
  assert.equal(await status(root.roles.set('owner', { ...ROLES.owner, permissions: [], protected: [] })), 400, 'Owner holds everything, always');
  assert.equal(await status(root.roles.set('member', { ...ROLES.viewer, permissions: [...ROLES.viewer.permissions], protected: [] }, { instance: true })), 400);
  assert.equal(await status(root.roles.set('developer', { ...definition, protected: ['secret.read'] })), 400, 'reading takes using');
  assert.equal((await root.roles.set('developer', definition)).role?.edited, true);
});

test('a fork of a protected environment is protected from its first moment, a copy or one that inherits', async () => {
  await root.environments.protect('market/prod');
  const copy = await root.environments.create('market/prod-copy', { from: 'prod' });
  const inherits = await root.environments.create('market/prod-next', { from: 'prod', inherit: true });
  assert.equal(copy.environment.protected, true);
  assert.equal(inherits.environment.protected, true);
  for (const fork of ['market/prod-copy', 'market/prod-next']) {
    assert.equal(await protectedOf(ada, fork), true, fork);
    // A Developer of the fork uses its values, and reads none.
    assert.equal(await status(ada.secrets.reveal(fork)), 403, fork);
  }
  // The vault protected each id before its row was written.
  const log = (await actions()).filter((action) => action.startsWith('policy.change') || action.startsWith('environment.create'));
  assert.deepEqual(log.slice(-4), ['policy.change allow', 'environment.create allow', 'policy.change allow', 'environment.create allow']);
  // A fork of dev, which nothing protects, is not.
  assert.equal((await root.environments.create('market/dev-copy', { from: 'dev' })).environment.protected, false);
});

test('a custom role is made, granted and used, and not deleted while a grant names it', async () => {
  const made = await root.roles.set('release-manager', {
    name: 'Release manager',
    description: 'Ships releases: sets values, and runs on them.',
    permissions: ['secret.use', 'secret.write'],
    protected: ['secret.use'],
  });
  assert.deepEqual(made.role && { builtin: made.role.builtin, edited: made.role.edited, assignable: made.role.assignableToEnvironment }, { builtin: false, edited: false, assignable: true });
  await root.members.add(BOB);
  await root.access.set(BOB, { 'market/dev': 'release-manager' });
  const bob = clientFor(deps, 'bob@acme.example');
  assert.equal(await status(bob.secrets.set('market/dev', { RELEASE: '1.2.3' })), 200);
  assert.equal(await status(bob.secrets.reveal('market/dev')), 403);
  const [listed] = (await root.members.list('market/dev')).members.filter((member) => member.member === BOB);
  assert.deepEqual(listed!.grants.map((grant) => [grant.role, grant.roleName, grant.permissions]), [['release-manager', 'Release manager', ['secret.use', 'secret.write']]]);
  // A role the instance does not define is refused, by name.
  const unknown = await root.access.set(BOB, { 'market/prod': 'release-captain' }).catch((error: unknown) => error as { status: number; message: string });
  assert.equal((unknown as { status: number }).status, 400);
  assert.match((unknown as { message: string }).message, /no role "release-captain"/);

  assert.equal(await status(root.roles.reset('release-manager')), 409);
  assert.ok((await root.roles.list()).roles.some((role) => role.id === 'release-manager' && role.grants === 1));
  await root.access.set(BOB, { 'market/dev': null });
  assert.deepEqual(await root.roles.reset('release-manager'), { role: null });
  assert.ok(!(await root.roles.list()).roles.some((role) => role.id === 'release-manager'));
});

test('a preview of a change says whom it widens and narrows, where, and changes nothing', async () => {
  await root.environments.protect('market/prod');
  await root.members.add(BOB);
  await root.access.set(BOB, { 'market/dev': 'developer' });
  // Developer reads prod too, and writes nowhere.
  const definition = { name: 'Developer', description: 'Read and use secrets.', permissions: ['secret.read', 'secret.use'], protected: ['secret.read', 'secret.use'] } as const;
  const before = await actions();
  const { impact, sentence } = await root.roles.preview('developer', { ...definition, permissions: [...definition.permissions], protected: [...definition.protected] });
  assert.deepEqual(impact.map(({ change, permission, protected: guarded, people, environments }) => [change, permission, guarded, people, environments]), [
    ['widens', 'secret.read', true, 1, 1],
    ['narrows', 'secret.write', false, 2, 1],
    ['narrows', 'secret.write', true, 1, 1],
  ]);
  assert.deepEqual(impact[0]!.examples, ['ada@acme.example on market/prod']);
  assert.equal(sentence, 'Widens secret.read for 1 person on market/prod, protected; narrows secret.write for 2 people on market/dev; narrows secret.write for 1 person on market/prod, protected');
  assert.deepEqual(await actions(), before, 'a preview writes nothing');
  assert.equal(await status(ada.secrets.set('market/dev', { API_KEY: 'still-hers' })), 200);
  // Reset weighs the same way: a role as it ships changes nobody.
  assert.equal((await root.roles.previewReset('developer')).sentence, 'Changes what nobody holds');
});

test('a token issued before its role was widened does not grow, and one narrowed is cut at once', async () => {
  // Vic's personal token, and CI's service token, each holding viewer as it shipped.
  const personal = await vic.tokens.issue(VIC, { label: 'agent', expiresInMinutes: 60, scope: { 'market/dev': 'viewer' } });
  const service = await root.tokens.issue(CI, { label: 'deploy', expiresInDays: 30 });
  const viewer = (permissions: string[], guarded: string[]) => ({ name: 'Viewer', description: 'Read and use secret values.', permissions, protected: guarded }) as Parameters<CoffreClient['roles']['set']>[1];
  await root.roles.set('viewer', viewer(['secret.read', 'secret.use', 'secret.write'], ['secret.use']));
  // Vic writes now, on a session; neither token does.
  assert.equal(await status(vic.secrets.set('market/dev', { API_KEY: 'vic-wrote' })), 200);
  assert.equal(await status(bearer(personal.token).secrets.set('market/dev', { API_KEY: 'token-wrote' })), 403);
  assert.equal(await status(bearer(service.token).secrets.set('market/prod', { API_KEY: 'ci-wrote' })), 403);
  assert.equal(await status(bearer(personal.token).secrets.reveal('market/dev')), 200);
  assert.equal(await status(bearer(service.token).secrets.reveal('market/prod')), 200);
  // Viewer narrowed to using: each token is cut through its holder, at once.
  await root.roles.set('viewer', viewer(['secret.use'], ['secret.use']));
  assert.equal(await status(bearer(personal.token).secrets.reveal('market/dev')), 403);
  assert.equal(await status(bearer(service.token).secrets.reveal('market/prod')), 403);
  // A token issued now holds the role as it is now.
  const later = await vic.tokens.issue(VIC, { label: 'later', expiresInMinutes: 60, scope: { 'market/dev': 'viewer' } });
  assert.equal(await status(bearer(later.token).secrets.list('market/dev')), 200);
  assert.equal(await status(bearer(later.token).secrets.reveal('market/dev')), 403);
});

test('GET /roles lists every role in both columns, as it ships or as an Owner edited it, and who may edit them', async () => {
  const listed = await ada.roles.list();
  assert.equal(listed.editable, false);
  assert.equal((await root.roles.list()).editable, true);
  const developer = listed.roles.find((role) => role.id === 'developer')!;
  const shipped = { name: 'Developer', description: ROLES.developer.description, permissions: [...ROLES.developer.permissions], protected: [...ROLES.developer.protected] };
  assert.deepEqual(developer, {
    id: 'developer',
    ...shipped,
    builtin: true,
    edited: false,
    fixed: false,
    default: shipped,
    assignableToEnvironment: true,
    grants: 1,
  } satisfies RoleView);
  assert.deepEqual(listed.roles.map((role) => role.id), Object.keys(ROLES));
  assert.deepEqual(listed.roles.filter((role) => role.fixed).map((role) => role.id), ['owner']);
  assert.deepEqual(listed.instanceRoles.filter((role) => role.fixed).map((role) => role.id), ['member', 'owner']);
  assert.equal(listed.roles.find((role) => role.id === 'maintainer')!.assignableToEnvironment, false);
  assert.equal(listed.instanceRoles.find((role) => role.id === 'owner')!.grants, 1, 'the instance has one Owner');

  await root.roles.set('auditor', { name: 'Log reader', description: 'Reads the log.', permissions: ['audit.read'], protected: ['audit.read'] }, { instance: true });
  const edited = (await ada.roles.list()).instanceRoles.find((role) => role.id === 'auditor')!;
  assert.deepEqual([edited.name, edited.edited, edited.default?.name], ['Log reader', true, 'Auditor']);
  await root.roles.reset('auditor', { instance: true });
  assert.equal((await ada.roles.list()).instanceRoles.find((role) => role.id === 'auditor')!.edited, false);
});

test("a person gives a service account a role on a whole project only if they hold it in the project's protected environments too", async () => {
  // Before anything is protected, a Developer of market sets up a Viewer of all of it.
  await ada.members.add('token:ci-before', { access: { market: 'viewer' } });
  await maya.environments.protect('market/prod');
  // Now the service would read prod, which Ada only uses: refused, by the app and by the vault.
  assert.equal(await status(ada.members.add('token:ci-after', { access: { market: 'viewer' } })), 403);
  assert.equal(await status(ada.members.add('token:ci-dev', { access: { 'market/dev': 'viewer' } })), 200, "dev's alone, which she reads");
});

test("whoever reads the whole log reads it as the instance's Auditor role is now, and a project's log leaves out a protected environment its role leaves out", async () => {
  await root.members.add('user:audrey@acme.example', { role: 'auditor' });
  const audrey = clientFor(deps, 'audrey@acme.example');
  assert.equal(await status(audrey.audit.list({ limit: 5 })), 200);
  await root.roles.set('auditor', { name: 'Auditor', description: 'None.', permissions: [], protected: [] }, { instance: true });
  assert.equal(await status(audrey.audit.list({ limit: 5 })), 403, 'the Auditor role reads nothing now');
  // A project Auditor that reads no protected environment's log.
  await root.roles.set('auditor', { name: 'Auditor', description: 'The log, but a protected environment\'s.', permissions: ['audit.read'], protected: [] });
  await root.members.add('user:paul@acme.example');
  await root.access.set('user:paul@acme.example', { market: 'auditor' });
  await maya.environments.protect('market/prod');
  await root.secrets.set('market/prod', { PROD_ONLY: 'p' });
  await root.secrets.set('market/dev', { DEV_ONLY: 'd' });
  // A reference held in dev to prod: its entry names prod besides, and is prod's too.
  await root.secrets.set('market/dev', { FROM_PROD: { ref: 'market/prod/PROD_ONLY' } });
  const paul = clientFor(deps, 'paul@acme.example');
  const seen = (await paul.audit.list({ limit: 200 })).entries;
  assert.ok(seen.some((entry) => entry.environment === 'dev'));
  assert.ok(!seen.some((entry) => entry.environment === 'prod'), 'none of prod');
  assert.ok(!seen.some((entry) => entry.action === 'secret.reference'), 'nor one that names prod besides');
  assert.ok((await root.audit.list({ limit: 200 })).entries.some((entry) => entry.action === 'secret.reference'));
});

test("a built-in role is put back as it ships only where that is coherent: not a project-wide permission over grants on environments", async () => {
  await root.roles.set('maintainer', { name: 'Maintainer', description: 'Uses.', permissions: ['secret.use'], protected: ['secret.use'] });
  await root.access.set(VIC, { 'market/prod': 'maintainer' });
  assert.equal(await status(root.roles.reset('maintainer')), 409);
});

test("a credential keeps what its role held when it was issued, both columns: a role as it ships, or as an Owner edited it", async () => {
  const shipped = await vic.tokens.issue(VIC, { label: 'shipped', expiresInMinutes: 60, scope: { 'market/dev': 'viewer' } });
  await root.roles.set('viewer', { name: 'Viewer', description: 'Uses.', permissions: ['secret.use'], protected: ['secret.use'] });
  await root.access.set(VIC, { market: 'viewer' });
  const edited = await vic.tokens.issue(VIC, { label: 'edited', expiresInMinutes: 60, scope: { 'market/dev': 'viewer' } });
  assert.deepEqual((await storedScopeOf(shipped.id))[0]!.permissions, { normal: ['secret.read', 'secret.use'], protected: ['secret.use'] });
  assert.deepEqual((await storedScopeOf(edited.id))[0]!.permissions, { normal: ['secret.use'], protected: ['secret.use'] });
});

/**
 * Run `meanwhile` once, as the vault answers the first `method` asked of
 * it whose input `when` picks: after the request that asked loaded its
 * caller, and before it commits.
 */
function meanwhileOn(method: 'access' | 'unwrap' | 'changePolicy', when: (input: unknown) => boolean, meanwhile: () => Promise<unknown>): void {
  const vault = deps.vault;
  let done = false;
  deps.vault = new Proxy(vault, {
    get(target, key) {
      const value = Reflect.get(target, key, target) as unknown;
      if (typeof value !== 'function') return value;
      if (key !== method) return value.bind(target);
      return async (input: unknown) => {
        const answer = await (value as (input: unknown) => Promise<unknown>).call(target, input);
        if (!done && when(input)) {
          done = true;
          deps.vault = vault;
          await meanwhile();
        }
        return answer;
      };
    },
  });
}

test('a fork of a protected environment refused for its row protects nothing first: no id kept, no change for requests in flight', async () => {
  await maya.environments.protect('market/prod');
  const changes = async () => (await actions()).filter((action) => action === 'policy.change allow').length;
  const before = await changes();
  // Its slug taken, or its parent archived (not found as a source): refused before the vault protects anything.
  assert.equal(await status(root.environments.create('market/dev', { from: 'prod', inherit: true })), 409);
  await root.environments.update('market/prod', { archived: true });
  assert.equal(await status(root.environments.create('market/prod-next', { from: 'prod', inherit: true })), 404);
  assert.equal(await changes(), before);
});

test('a fork decided while its source was not protected, which commits once it is, is refused: protected, or not made', async () => {
  // Prod protected once Maya's request has loaded her, before her fork that inherits is written: nothing is made.
  meanwhileOn('access', (asked) => asked === MAYA, () => root.environments.protect('market/prod'));
  assert.equal(await status(maya.environments.create('market/prod-next', { from: 'prod', inherit: true })), 409);
  assert.equal((await root.projects.list()).projects[0]!.environments.some((each) => each.slug === 'prod-next'), false);
  // A copy: prod protected once its values are opened, before they are written to the fork, which holds none then.
  await root.environments.protect('market/prod', false);
  meanwhileOn('unwrap', () => true, () => root.environments.protect('market/prod'));
  assert.equal(await status(maya.environments.create('market/prod-copy', { from: 'prod' })), 409);
  assert.deepEqual((await root.secrets.list('market/prod-copy')).keys, []);
  // Maya uses prod now, and reads none of it to copy; an Owner's fork into the empty one protects it first.
  assert.equal(await status(maya.environments.create('market/prod-copy', { from: 'prod' })), 403);
  assert.equal((await root.environments.create('market/prod-copy', { from: 'prod' })).environment.protected, true);
  assert.equal(await status(maya.secrets.reveal('market/prod-copy')), 403);
});

test("a service token weighed before prod was protected, issued once it is, is refused: it would read prod for a Developer who only uses it", async () => {
  await ada.members.add('token:ci-all', { access: { market: 'viewer' } });
  meanwhileOn('access', (asked) => asked === ADA, () => maya.environments.protect('market/prod'));
  assert.equal(await status(ada.tokens.issue('token:ci-all', { label: 'deploy', expiresInDays: 30 })), 409);
  assert.deepEqual((await root.tokens.list('token:ci-all')).tokens, []);
  // Asked again, it is decided as the policy is now: Ada no longer manages a Viewer of all of market.
  assert.equal(await status(ada.tokens.issue('token:ci-all', { label: 'deploy', expiresInDays: 30 })), 403);
});

test("an instance Auditor whose role reads no protected environment's log reads the rest, not the whole log", async () => {
  await root.members.add('user:audrey@acme.example', { role: 'auditor' });
  const audrey = clientFor(deps, 'audrey@acme.example');
  await root.roles.set('auditor', { name: 'Auditor', description: 'The log, but a protected environment\'s.', permissions: ['audit.read'], protected: [] }, { instance: true });
  await maya.environments.protect('market/prod');
  await root.secrets.set('market/prod', { PROD_ONLY: 'p' });
  await root.secrets.set('market/dev', { DEV_ONLY: 'd' });
  const seen = (await audrey.audit.list({ limit: 200 })).entries;
  assert.ok(seen.some((entry) => entry.environment === 'dev'));
  assert.ok(!seen.some((entry) => entry.environment === 'prod'), 'none of prod');
  // Verifying the log is reading all of it.
  assert.equal(await status(audrey.audit.verify()), 403);
  await root.roles.reset('auditor', { instance: true });
  assert.ok((await audrey.audit.list({ limit: 200 })).entries.some((entry) => entry.environment === 'prod'));
  assert.equal((await audrey.audit.verify()).ok, true);
});

test('a protected environment deleted protects nothing: a Developer gives a service account a role on all of its project again', async () => {
  await maya.environments.protect('market/prod');
  assert.equal(await status(ada.members.add('token:ci-before', { access: { market: 'viewer' } })), 403);
  await root.environments.update('market/prod', { archived: true });
  await root.environments.delete('market/prod');
  assert.equal(await status(ada.members.add('token:ci-after', { access: { market: 'viewer' } })), 200);
  // One made again under its name is another environment, which nothing protects.
  await root.environments.create('market/prod');
  assert.equal(await protectedOf(ada, 'market/prod'), false);
});

// The rules that hold the policy (docs/design/roles.md, "Rules that hold the policy"), each with a case its protection decides.

/** What a credential's row keeps of its scope, as stored. */
async function storedScopeOf(id: string): Promise<{ role: string; permissions?: { normal: string[]; protected: string[] } }[]> {
  const { credentials } = await import('./db/tables.ts');
  return JSON.parse((await db.owner.select({ scope: credentials.scope }).from(credentials).where(eq(credentials.id, id)))[0]!.scope!) as never;
}

const READS_PROTECTED = { name: 'Viewer', description: 'Read and use secret values, protected ones too.', permissions: ['secret.read', 'secret.use'], protected: ['secret.read', 'secret.use'] } as Parameters<CoffreClient['roles']['set']>[1];

test('rule 2: a reveal of plain values, which the app opens itself, weighed before prod was protected and answered after, is refused', async () => {
  await root.secrets.set('market/prod', { REGION: { value: 'eu-west-3', plain: true } });
  // No vault call opens a plain value: the app's fence, under the head, is all that sees prod protected meanwhile.
  meanwhileOn('access', (asked) => asked === ADA, () => maya.environments.protect('market/prod'));
  assert.deepEqual(await refusal(ada.secrets.reveal('market/prod/REGION')), { status: 409, reason: 'policy_changed' });
  // Asked again, it is decided as the policy is now: Ada only uses prod.
  assert.equal(await status(ada.secrets.reveal('market/prod/REGION')), 403);
});

test('rule 3: a personal token holds no more than its person held when it was issued, in both columns: Developer widened later, her viewer token still only uses prod', async () => {
  // Viewer reads in a protected environment too; nothing is protected yet, so Ada, a Developer, holds all a Viewer
  // does where her token reaches today, and would only use a protected environment.
  await root.roles.set('viewer', READS_PROTECTED);
  const token = await ada.tokens.issue(ADA, { label: 'agent', expiresInMinutes: 60, scope: { market: 'viewer' } });
  await maya.environments.protect('market/prod');
  await root.roles.set('developer', { ...ROLES.developer, permissions: [...ROLES.developer.permissions], protected: ['secret.read', 'secret.use', 'secret.write'] });
  assert.equal(await status(ada.secrets.reveal('market/prod')), 200, 'Ada reads prod now');
  assert.equal(await status(bearer(token.token).secrets.reveal('market/prod')), 403, 'her token does not');
  assert.equal(await status(bearer(token.token).secrets.reveal('market/dev')), 200);
  assert.deepEqual((await storedScopeOf(token.id))[0]!.permissions, { normal: ['secret.read', 'secret.use'], protected: ['secret.use'] });
});

test("rule 3: a personal token on dev reads dev's reference into a protected prod as dev's readers do, and nothing else of prod", async () => {
  await root.secrets.set('market/dev', { FROM_PROD: { ref: 'market/prod/API_KEY' } });
  await maya.environments.protect('market/prod');
  // The Owner's token, made for dev, reads all of dev, the reference included; prod itself is no place it reaches.
  const token = await root.tokens.issue(`user:${ROOT}`, { label: 'agent', expiresInMinutes: 60, scope: { 'market/dev': 'viewer' } });
  assert.equal((await bearer(token.token).secrets.reveal('market/dev')).values.FROM_PROD, 'prod-key');
  assert.equal(await status(bearer(token.token).secrets.reveal('market/prod')), 403);
  // A Developer's, who only uses prod, too: the reference's permissions are dev's.
  const hers = await ada.tokens.issue(ADA, { label: 'agent', expiresInMinutes: 60, scope: { 'market/dev': 'viewer' } });
  assert.equal((await bearer(hers.token).secrets.reveal('market/dev')).values.FROM_PROD, 'prod-key');
  assert.equal(await status(bearer(hers.token).secrets.reveal('market/prod')), 403);
});

test('rule 3: a service token issued under a narrowed role keeps it when the role is put back as it ships', async () => {
  await root.roles.set('viewer', { ...READS_PROTECTED, permissions: ['secret.use'], protected: ['secret.use'] });
  const token = await root.tokens.issue(CI, { label: 'deploy', expiresInDays: 30, scope: { 'market/prod': 'viewer' } });
  assert.deepEqual((await storedScopeOf(token.id))[0]!.permissions, { normal: ['secret.use'], protected: ['secret.use'] });
  // Viewer reads again, CI with it; its token holds Viewer as it was when it was issued.
  await root.roles.reset('viewer');
  assert.equal(await status(ci.secrets.reveal('market/prod')), 200);
  assert.equal(await status(bearer(token.token).secrets.reveal('market/prod')), 403);
});

test("rule 4: a personal token on a whole project takes holding its role in the project's protected environments too", async () => {
  await root.roles.set('viewer', READS_PROTECTED);
  await maya.environments.protect('market/prod');
  // Ada holds viewer's normal column on market, and only uses prod: a viewer token on all of market would read prod.
  assert.equal(await status(ada.tokens.issue(ADA, { label: 'agent', expiresInMinutes: 60, scope: { market: 'viewer' } })), 403);
  assert.equal(await status(ada.tokens.issue(ADA, { label: 'agent', expiresInMinutes: 60, scope: { 'market/dev': 'viewer' } })), 200, "dev's alone, which she reads");
  // As Viewer ships, it only uses a protected environment, as Ada does.
  await root.roles.reset('viewer');
  assert.equal(await status(ada.tokens.issue(ADA, { label: 'agent', expiresInMinutes: 60, scope: { market: 'viewer' } })), 200);
});

test("rule 4: who reads through a reference held in a protected environment is weighed as the policy has it", async () => {
  await root.secrets.set('market/prod', { DEV_KEY: { ref: 'market/dev/API_KEY' } });
  await maya.environments.protect('market/prod');
  const [held] = (await root.references.list('market/prod')).references;
  // Ada, Maya and Vic only use prod now; CI, a service account, reads it, and the Owner.
  assert.deepEqual([...held!.readers!].sort(), [CI, `user:${ROOT}`].sort());
});

test("a reference takes its value and nature from its source and its permissions from where it lives: protecting prod after it was made leaves it working", async () => {
  await root.secrets.set('market/dev', { DATABASE_URL: { ref: 'market/prod/API_KEY' } });
  await root.members.add('token:ci-dev', { access: { 'market/dev': 'viewer' } });
  const ciDev = clientFor(deps, 'ci-dev', 'service');
  await maya.environments.protect('market/prod');
  // Ada, a Developer, reads dev, and only uses prod: dev's reference to a prod secret reads through dev's grants alone.
  assert.equal((await ada.secrets.reveal('market/dev')).values.DATABASE_URL, 'prod-key');
  assert.equal((await ada.secrets.reveal('market/dev/DATABASE_URL')).values.DATABASE_URL, 'prod-key');
  assert.deepEqual((await ada.secrets.list('market/dev')).keys.map((key) => [key.key, key.readable]), [['API_KEY', true], ['DATABASE_URL', true]]);
  assert.equal(await status(ada.secrets.reveal('market/prod')), 403, 'prod itself she only uses');
  // Its readers are dev's.
  const [held] = (await root.references.list('market/dev')).references;
  assert.deepEqual([...held!.readers!].sort(), [ADA, MAYA, VIC, 'token:ci-dev', `user:${ROOT}`].sort());
  assert.equal((await ciDev.secrets.reveal('market/dev')).values.DATABASE_URL, 'prod-key');
});

test("a reference to a sensitive source is use-only where it lives, a plain one plain, and making one takes what the source's nature asks there", async () => {
  await maya.environments.protect('market/prod');
  await root.secrets.set('market/prod', { STRIPE_KEY: { value: 'sk_live_0123456789', sensitivity: 'sensitive' }, REGION: { value: 'eu-west-3', plain: true } });
  // Ada, a Developer of market, uses prod, and reads none of it: she refers to what she uses, never to a secret she does not read.
  assert.equal(await status(ada.secrets.set('market/dev', { PROD_API: { ref: 'market/prod/API_KEY' } })), 403);
  await ada.secrets.set('market/dev', { STRIPE_KEY: { ref: 'market/prod/STRIPE_KEY' }, REGION: { ref: 'market/prod/REGION' } });
  const listed = new Map((await vic.secrets.list('market/dev')).keys.map((key) => [key.key, key]));
  assert.deepEqual([listed.get('STRIPE_KEY')!.sensitivity, listed.get('STRIPE_KEY')!.readable], ['sensitive', false]);
  assert.deepEqual([listed.get('REGION')!.sensitivity, listed.get('REGION')!.value], ['plain', 'eu-west-3']);
  // Vic, a Viewer of dev, reads dev: the plain one as it is, the sensitive one no person reads.
  const read = await vic.secrets.reveal('market/dev');
  assert.equal(read.values.REGION, 'eu-west-3');
  assert.equal(read.values.STRIPE_KEY, undefined);
  assert.ok(read.sensitive.includes('STRIPE_KEY'));
  assert.equal(await status(vic.secrets.reveal('market/dev/STRIPE_KEY')), 403);
});

test("an old value brought back into a key a reference reads takes what its nature asks there: no write-only path lends a secret its writer never read", async () => {
  await maya.environments.protect('market/prod');
  // Ada, a Developer of market, uses and writes prod, and reads dev. A reference to prod's secret takes reading it.
  assert.equal(await status(ada.secrets.set('market/dev', { LEAK: { ref: 'market/prod/API_KEY' } })), 403);
  // A value she types, plain, she may lend; the secret it replaced, brought back by a restore, she may not.
  await ada.secrets.set('market/prod', { API_KEY: { value: 'placeholder', plain: true } });
  await ada.secrets.set('market/dev', { LEAK: { ref: 'market/prod/API_KEY' } });
  assert.deepEqual(await refusal(ada.secrets.restore('market/prod/API_KEY', 1)), { status: 403, reason: 'missing_secret_read' });
  assert.equal((await vic.secrets.reveal('market/dev')).values.LEAK, 'placeholder');
  // The plain value she typed, brought back, she may: listing it is what lending it takes.
  await ada.secrets.set('market/prod', { API_KEY: { value: 'placeholder-2', plain: true } });
  await ada.secrets.restore('market/prod/API_KEY', 2);
  assert.equal((await vic.secrets.reveal('market/dev')).values.LEAK, 'placeholder');
  // An Owner, who reads prod, brings the secret back: it flows through, and dev's secret readers read it, as R20 says.
  await root.secrets.restore('market/prod/API_KEY', 1);
  assert.equal((await vic.secrets.reveal('market/dev')).values.LEAK, 'prod-key');
  assert.equal((await vic.secrets.list('market/dev')).keys.find((key) => key.key === 'LEAK')!.sensitivity, 'secret');
});

test("a reference binds to its source key, not its name: renamed, the key is still read through it; another made under the old name is not", async () => {
  await root.secrets.set('market/dev', { FROM_PROD: { ref: 'market/prod/API_KEY' } });
  await root.secrets.rename('market/prod/API_KEY', 'PROD_KEY');
  assert.equal((await vic.secrets.reveal('market/dev')).values.FROM_PROD, 'prod-key');
  await root.secrets.set('market/prod', { API_KEY: 'another-value' });
  assert.equal((await vic.secrets.reveal('market/dev')).values.FROM_PROD, 'prod-key');
});

test('a role edit weighed from a policy another change overtook is refused, policy_changed, to be asked again, rather than applied', async () => {
  // The Owner previewed Viewer reading in protected environments with nothing protected; prod is protected before it is saved.
  meanwhileOn('access', (asked) => asked === `user:${ROOT}`, () => maya.environments.protect('market/prod'));
  assert.deepEqual(await refusal(root.roles.set('viewer', READS_PROTECTED)), { status: 409, reason: 'policy_changed' });
  assert.equal((await root.roles.list()).roles.find((role) => role.id === 'viewer')!.edited, false);
  // Asked again, as the policy is now, it is made.
  await root.roles.set('viewer', READS_PROTECTED);
  assert.equal((await root.roles.list()).roles.find((role) => role.id === 'viewer')!.edited, true);
});

test('rule 2: a plain value is fenced by a read of the newest policy change, which waits on no write', postgresOnly('one writer at a time is SQLite\'s'), async () => {
  await root.secrets.set('market/prod', { REGION: { value: 'eu-west-3', plain: true } });
  // Another transaction holds the log's head, as any write does while it commits: the read is not queued behind it.
  let release!: () => void;
  let holding!: () => void;
  const held = new Promise<void>((resolve) => (holding = resolve));
  const writing = db.owner.transaction(async (tx) => {
    await lockLogHead(tx);
    holding();
    await new Promise<void>((resolve) => (release = resolve));
  });
  await held;
  try {
    const read = ada.secrets.reveal('market/prod/REGION');
    const answered = await Promise.race([read.then(() => true), new Promise((resolve) => setTimeout(resolve, 3000, false))]);
    assert.equal(answered, true, 'answered while the head was held');
    assert.equal((await read).values.REGION, 'eu-west-3');
  } finally {
    release();
    await writing;
  }
});

// What changes the policy (docs/design/roles.md, "What changes the policy"): every change that can change what a decision
// made from it decides, each made while a request decided from the policy before it is in flight. Ada, a Developer of
// market and an Owner of every prod, gives a Viewer of all of market a token, which she may only as she holds Viewer in
// protected prod too (rule 4). One the policy is changed by refuses her request, 409 `policy_changed`, by its newest
// `policy.change` (seq) or by its protected environments' rows (rows), read again by id; one it cannot be changed by
// commits it.
const CHANGES: { change: string; by: 'seq' | 'rows' | 'nothing'; make: () => Promise<unknown> }[] = [
  { change: 'an environment protected', by: 'seq', make: () => maya.environments.protect('market/dev') },
  { change: 'an environment unprotected', by: 'seq', make: () => root.environments.protect('market/prod', false) },
  { change: 'a fork of a protected environment, protected before its row', by: 'seq', make: () => root.environments.create('market/prod-next', { from: 'prod', inherit: true }) },
  { change: 'a role edited', by: 'seq', make: () => root.roles.set('viewer', READS_PROTECTED) },
  { change: 'a role made', by: 'seq', make: () => root.roles.set('release-manager', { ...READS_PROTECTED, name: 'Release manager' }) },
  { change: 'an instance role edited', by: 'seq', make: () => root.roles.set('auditor', { name: 'Auditor', description: '', permissions: ['audit.read'], protected: [] }, { instance: true }) },
  { change: 'a protected environment renamed', by: 'rows', make: () => root.environments.update('market/prod', { slug: 'staging' }) },
  {
    change: 'a protected environment deleted',
    by: 'rows',
    make: async () => {
      await root.environments.update('market/prod', { archived: true });
      await root.environments.delete('market/prod');
    },
  },
  {
    // Another project's: deleting market itself would leave the account nothing to hold, refused before any fence.
    change: "a protected environment's project deleted",
    by: 'rows',
    make: async () => {
      await root.projects.update('billing', { archived: true });
      await root.projects.delete('billing');
    },
  },
  // The policy reads no name but a protected environment's slug, and no archive.
  { change: 'an environment not protected renamed', by: 'nothing', make: () => root.environments.update('market/dev', { slug: 'development' }) },
  { change: 'a protected environment named again', by: 'nothing', make: () => root.environments.update('market/prod', { name: 'Production' }) },
  { change: 'a protected environment archived', by: 'nothing', make: () => root.environments.update('market/prod', { archived: true }) },
  { change: 'a project renamed: scopes name projects by id', by: 'nothing', make: () => root.projects.update('market', { slug: 'shop' }) },
  { change: 'an environment made', by: 'nothing', make: () => root.environments.create('market/qa') },
  // Who holds what is no policy: the vault decides each grant under its head, and a credential holds at most what its
  // holder holds at each use.
  { change: "another member's grant changed", by: 'nothing', make: () => root.access.set(VIC, { market: 'developer' }) },
];

for (const { change, by, make } of CHANGES) {
  test(`what changes the policy: ${change}, while a token is given, ${by === 'nothing' ? 'leaves it given' : `refuses it (${by})`}`, async () => {
    await maya.environments.protect('market/prod');
    await root.projects.create('billing');
    await root.environments.create('billing/prod');
    await root.environments.protect('billing/prod');
    await root.members.add(ADA, { role: 'owner', scope: { projects: 'all', environments: { only: ['prod'] } } });
    await ada.members.add('token:ci-all', { access: { market: 'viewer' } });
    meanwhileOn('access', (asked) => asked === ADA, make);
    const issued = await refusal(ada.tokens.issue('token:ci-all', { label: 'deploy', expiresInDays: 30 }));
    assert.deepEqual(issued, by === 'nothing' ? { status: 200 } : { status: 409, reason: 'policy_changed' });
  });
}

test('rule 2: a protected environment renamed while a token is given, out of the reach of the role it was given by, is refused, and asked again, not given', async () => {
  await maya.environments.protect('market/prod');
  await root.members.add(ADA, { role: 'owner', scope: { projects: 'all', environments: { only: ['prod'] } } });
  await ada.members.add('token:ci-all', { access: { market: 'viewer' } });
  meanwhileOn('access', (asked) => asked === ADA, () => root.environments.update('market/prod', { slug: 'staging' }));
  assert.deepEqual(await refusal(ada.tokens.issue('token:ci-all', { label: 'deploy', expiresInDays: 30 })), { status: 409, reason: 'policy_changed' });
  assert.deepEqual((await root.tokens.list('token:ci-all')).tokens, []);
  // Asked again: staging, protected, is not prod, and Ada, a Developer there, only uses it.
  assert.equal(await status(ada.tokens.issue('token:ci-all', { label: 'deploy', expiresInDays: 30 })), 403);
});

test('a role edit confirmed with its preview is made as previewed, or refused, policy_changed, once another change came between', async () => {
  const preview = await root.roles.preview('viewer', READS_PROTECTED);
  assert.equal(preview.sentence, 'Changes what nobody holds');
  await maya.environments.protect('market/prod');
  // What the preview said is no longer what it does: Vic would read prod.
  assert.deepEqual(await refusal(root.roles.set('viewer', READS_PROTECTED, { revision: preview.revision })), { status: 409, reason: 'policy_changed' });
  assert.equal((await root.roles.list()).roles.find((role) => role.id === 'viewer')!.edited, false);
  const again = await root.roles.preview('viewer', READS_PROTECTED);
  assert.match(again.sentence, /^Widens secret.read for 1 person on market\/prod, protected/);
  await root.roles.set('viewer', READS_PROTECTED, { revision: again.revision });
  assert.equal((await root.roles.list()).roles.find((role) => role.id === 'viewer')!.edited, true);
  // A reset, the same way.
  const reset = await root.roles.previewReset('viewer');
  await maya.environments.protect('market/dev');
  assert.deepEqual(await refusal(root.roles.reset('viewer', { revision: reset.revision })), { status: 409, reason: 'policy_changed' });
});

test('a role edit confirmed with its preview is refused, policy_changed, once a protected environment it was weighed in is renamed', async () => {
  // Ada, a Developer of market and an Owner of every prod: Developer reading in protected environments widens nothing
  // for her while prod is protected as prod, where her Owner role reads already.
  await maya.environments.protect('market/prod');
  await root.members.add(ADA, { role: 'owner', scope: { projects: 'all', environments: { only: ['prod'] } } });
  const reads = { name: 'Developer', description: '', permissions: ['secret.read', 'secret.use', 'secret.write'], protected: ['secret.read', 'secret.use', 'secret.write'] } as Parameters<CoffreClient['roles']['set']>[1];
  const preview = await root.roles.preview('developer', reads);
  assert.doesNotMatch(preview.sentence, /secret\.read/);
  // Renamed staging, it is out of her Owner role's reach: the change widens her read there, which the preview did not say.
  await root.environments.update('market/prod', { slug: 'staging' });
  assert.deepEqual(await refusal(root.roles.set('developer', reads, { revision: preview.revision })), { status: 409, reason: 'policy_changed' });
  assert.match((await root.roles.preview('developer', reads)).sentence, /^Widens secret\.read for 1 person on market\/staging, protected/);
});

test("a role's impact counts the service accounts it reaches, which hold its first column in a protected environment too", async () => {
  await maya.environments.protect('market/prod');
  const narrowed = { name: 'Viewer', description: '', permissions: ['secret.use'], protected: ['secret.use'] } as Parameters<CoffreClient['roles']['set']>[1];
  const { impact, sentence } = await root.roles.preview('viewer', narrowed);
  const read = impact.find((line) => line.change === 'narrows' && line.permission === 'secret.read')!;
  // Vic reads dev; ci, a Viewer of prod, reads prod, as a service account does where it is protected.
  assert.deepEqual([read.people, read.services], [1, 0]);
  const there = impact.find((line) => line.change === 'narrows' && line.permission === 'secret.read' && line.protected)!;
  assert.deepEqual([there.people, there.services, there.examples], [0, 1, [`${CI} on market/prod`]]);
  assert.match(sentence, /narrows secret.read for 1 service account on market\/prod, protected/);
});

test('a fork of a protected environment whose row would come after the policy may have let its id go is refused, and nothing is made', async () => {
  await maya.environments.protect('market/prod');
  const now = Date.now;
  meanwhileOn('changePolicy', () => true, async () => {
    Date.now = () => now() + UNWRITTEN_FORK_MS / 2 + 60_000;
  });
  try {
    assert.equal(await status(root.environments.create('market/prod-next', { from: 'prod', inherit: true })), 409);
  } finally {
    Date.now = now;
  }
  assert.equal((await root.projects.list()).projects[0]!.environments.some((each) => each.slug === 'prod-next'), false);
});
