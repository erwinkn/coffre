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
import { ROLES } from '@coffre/core/access';
import { defineSignin, github } from '@coffre/core/identity';
import { asc, eq } from 'drizzle-orm';

import { SigninService } from '../src/api/signin.ts';
import { fetchApi } from '../src/fetch-api.ts';
import type { CoffreRuntime } from '../src/runtime.ts';
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
  const paul = clientFor(deps, 'paul@acme.example');
  const seen = (await paul.audit.list({ limit: 200 })).entries;
  assert.ok(seen.some((entry) => entry.environment === 'dev'));
  assert.ok(!seen.some((entry) => entry.environment === 'prod'), 'none of prod');
});

test("a built-in role is put back as it ships only where that is coherent: not a project-wide permission over grants on environments", async () => {
  await root.roles.set('maintainer', { name: 'Maintainer', description: 'Uses.', permissions: ['secret.use'], protected: ['secret.use'] });
  await root.access.set(VIC, { 'market/prod': 'maintainer' });
  assert.equal(await status(root.roles.reset('maintainer')), 409);
});

test("a credential of a role as it ships keeps its name alone, as a release before 0.10 reads a scope; an edited role's, what it holds", async () => {
  const { credentials } = await import('./db/tables.ts');
  const shipped = await vic.tokens.issue(VIC, { label: 'shipped', expiresInMinutes: 60, scope: { 'market/dev': 'viewer' } });
  await root.roles.set('viewer', { name: 'Viewer', description: 'Uses.', permissions: ['secret.use'], protected: ['secret.use'] });
  await root.access.set(VIC, { market: 'viewer' });
  const edited = await vic.tokens.issue(VIC, { label: 'edited', expiresInMinutes: 60, scope: { 'market/dev': 'viewer' } });
  const scopeOf = async (id: string) => JSON.parse((await db.owner.select({ scope: credentials.scope }).from(credentials).where(eq(credentials.id, id)))[0]!.scope!) as unknown[];
  const [kept] = (await scopeOf(shipped.id)) as Record<string, unknown>[];
  assert.deepEqual(Object.keys(kept!).sort(), ['environmentId', 'projectId', 'role']);
  assert.deepEqual(((await scopeOf(edited.id)) as { permissions?: unknown }[])[0]!.permissions, { normal: ['secret.use'], protected: ['secret.use'] });
});

/**
 * Run `meanwhile` once, as the vault answers the first `method` asked of
 * it whose input `when` picks: after the request that asked loaded its
 * caller, and before it commits.
 */
function meanwhileOn(method: 'access' | 'unwrap', when: (input: unknown) => boolean, meanwhile: () => Promise<unknown>): void {
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
