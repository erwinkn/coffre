// `GET /api/me` only shows its caller, and asks the vault nothing: the app
// reads the vault's rows itself (`answerShown`), by the vault's own rule
// (`answerFrom` in @coffre/core/vault), so it shows what the vault would
// answer while the rows are the vault's. It cannot check them: a row
// changed around the vault is shown as it says, and decides nothing, since
// no other route takes such a caller and the vault decides everything the
// caller asks for next.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';

import { CoffreError, createClient } from '@coffre/client';
import { github, signin } from '@coffre/core/identity';
import type { Vault } from '@coffre/core/vault';
import { tablesOf } from '@coffre/db';
import { eq } from 'drizzle-orm';

import { SigninService } from '../src/api/signin.ts';
import { authenticateRequest } from '../src/auth.ts';
import { answerShown } from '../src/db/answers.ts';
import { fetchApi, pageClient } from '../src/fetch-api.ts';
import type { CoffreRuntime } from '../src/runtime.ts';
import { clientFor, contextFor, EDITS_ROLES, openTestDatabase, resetDatabase, START_OVER_014, testDeps, waitUntil, type FixtureDeps } from './api-fixture.ts';

const ORIGIN = 'https://secrets.acme.example';
const ROOT = 'admin@acme.example';
const DEV = 'dev@acme.example';
const LEAD = 'lead@acme.example';
const GONE = 'gone@acme.example';
const SERVICE = 'token:ci-web';
const auth = signin({ providers: [github({ clientId: 'gh-id', clientSecret: 'gh-secret' })] }).resolve(ORIGIN);

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;
/** Each call the app made of the vault, by its method's name. */
let calls: string[];
let runtime: CoffreRuntime;

before(async () => {
  db = await openTestDatabase();
  deps = testDeps(db.runtime, [ROOT]);
  const counted = new Proxy(deps.vault, {
    get(target, key) {
      const value: unknown = Reflect.get(target, key, target);
      if (typeof value !== 'function') return value;
      return (...args: unknown[]) => {
        calls.push(String(key));
        return (value as (...args: unknown[]) => unknown).apply(target, args);
      };
    },
  }) as Vault;
  if (auth.mode !== 'signin') throw new Error('unreachable');
  const service = new SigninService({ ...deps, vault: counted, signin: auth.signin });
  runtime = {
    db: deps.db, vault: counted, chainKey: deps.chainKey, previousChainKeys: [], signin: service, workloads: null, mcp: null, auth,
    publicUrl: ORIGIN, verifier: service, waitUntil, schema: { migrated: true }, appKey: { settled: true }, rotateAfterDays: 365, plugins: [],
  };
});

after(async () => {
  await resetDatabase(db.owner);
  await db.close();
});

beforeEach(async () => {
  await resetDatabase(db.owner);
  const root = clientFor(deps, ROOT);
  await root.projects.create('market', { name: 'Market' });
  await root.projects.create('billing', { name: 'Billing' });
  for (const path of ['market/dev', 'market/prod', 'market/staging', 'billing/dev']) await root.environments.create(path, { name: path });
  await root.members.add(`user:${DEV}`);
  await root.access.set(`user:${DEV}`, { 'market/dev': 'developer', billing: { role: 'viewer', until: new Date(Date.now() + 86_400_000).toISOString() } });
  await root.members.add(`user:${LEAD}`, { role: 'admin', scope: { projects: { only: ['market'] }, environments: 'all' } });
  await root.members.add(SERVICE);
  await root.access.set(SERVICE, { 'market/dev': 'viewer' });
  await root.members.add(`user:${GONE}`);
  await root.members.remove(`user:${GONE}`);
  // A policy and settings of the instance's own: a protected environment, one protected then deleted, and a role edited.
  await root.environments.protect('market/prod');
  await root.environments.protect('market/staging');
  await root.environments.update('market/staging', { archived: true });
  await root.environments.delete('market/staging');
  if (EDITS_ROLES) await root.roles.set('viewer', { name: 'Viewer', description: '', permissions: ['secret.read', 'secret.use', 'secret.archive'], protected: ['secret.use'] });
  await root.settings.set({ serviceAccounts: { projects: 'all', environments: { except: ['prod'] } } });
  calls = [];
});

/** A CLI session for `email`, from an approved device login. */
async function cliToken(email: string): Promise<string> {
  const service = runtime.signin!;
  const started = await service.startDevice({ clientLabel: 'laptop', sourceIp: null });
  await service.decideDevice(await contextFor(deps, email), started.userCode, true);
  const polled = await service.pollDevice(started.deviceCode, { requestId: randomUUID(), sourceIp: null });
  if (polled.status !== 'approved') throw new Error('the device login was not approved');
  return polled.credential.token;
}

const me = (token: string) => fetchApi(new Request(`${ORIGIN}/api/me`, { headers: { authorization: `Bearer ${token}` } }), runtime, { sourceIp: null });

/** A page's render, its session cookie the token: a CLI token works the same as a cookie value here. */
const render = (token: string) => pageClient(new Request(`${ORIGIN}/projects`, { headers: { cookie: `__Host-coffre_session=${token}` } }), runtime, null);

/** A client that calls the API as the CLI does, its token checked on each request. */
const bearer = (token: string) => createClient({ url: ORIGIN, headers: () => ({ authorization: `Bearer ${token}` }), transport: (request) => fetchApi(request, runtime, { sourceIp: null }) });

test("the app's answer from the vault's rows is the vault's, for every kind of member, and the settings too", async () => {
  for (const principal of [`user:${ROOT}`, `user:${DEV}`, `user:${LEAD}`, SERVICE, `user:${GONE}`, 'user:stranger@acme.example', 'not a principal']) {
    const shown = await answerShown(db.runtime, principal);
    assert.deepEqual(shown.access, await deps.vault.access(principal), principal);
  }
  assert.deepEqual((await answerShown(db.runtime, `user:${DEV}`)).settings, await deps.vault.settings());
});

test('`GET /api/me` asks the vault nothing, and shows what a render, which asks it, does', async () => {
  for (const [email, token] of [[ROOT, await cliToken(ROOT)], [DEV, await cliToken(DEV)], [LEAD, await cliToken(LEAD)], [SERVICE, (await clientFor({ ...deps, signin: runtime.signin! }, ROOT).tokens.issue(SERVICE, { label: 'ci', expiresInDays: 1 })).token]] as const) {
    calls = [];
    const response = await me(token);
    assert.equal(response.status, 200, email);
    assert.deepEqual(calls, [], email);
    const rendered = await render(token).me();
    assert.deepEqual(calls, ['access'], 'a render asks the vault about its caller, once');
    assert.deepEqual(await response.json(), JSON.parse(JSON.stringify(rendered)), email);
  }
});

test('a caller the app read from the rows reaches no route but `GET /api/me`', async () => {
  const token = await cliToken(DEV);
  const headers = { authorization: `Bearer ${token}` };
  const identity = await authenticateRequest(new Request(`${ORIGIN}/api/me`, { headers }), runtime, randomUUID(), token, null, { shows: 'caller' });
  if (identity instanceof Response) throw new Error(`refused: ${identity.status}`);
  assert.equal(identity.caller.unchecked, true);
  for (const path of ['/api/projects', '/api/secrets/market/dev', '/api/members']) {
    const response = await fetchApi(new Request(`${ORIGIN}${path}`, { headers }), runtime, { sourceIp: null, authenticate: async () => identity });
    assert.equal(response.status, 500, path);
  }
  calls = [];
  assert.equal((await fetchApi(new Request(`${ORIGIN}/api/me`, { headers }), runtime, { sourceIp: null, authenticate: async () => identity })).status, 200);
  assert.deepEqual(calls, []);
});

test('a removed member, or one removed and admitted again, is shown as the vault would show them', async () => {
  const token = await cliToken(DEV);
  await clientFor(deps, ROOT).members.remove(`user:${DEV}`);
  assert.equal((await me(token)).status, 401, 'removed, their session ended');
  await clientFor(deps, ROOT).members.add(`user:${DEV}`);
  assert.equal((await me(token)).status, 401, 'admitted again, a session of before is no one now');
  const body = await (await me(await cliToken(DEV))).json() as { registered: boolean; environments: unknown[] };
  assert.deepEqual([body.registered, body.environments], [true, []]);
});

test('a row changed around the vault is shown as it says, and decides nothing: what the caller asks next, the vault refuses', { skip: START_OVER_014 }, async () => {
  const token = await cliToken(DEV);
  const { vaultMembers } = tablesOf(db.owner);
  // Someone who owns the database makes DEV an Owner, around the vault.
  await db.owner.update(vaultMembers).set({ owner: true, role: 'owner' }).where(eq(vaultMembers.principal, `user:${DEV}`));
  const shown = await (await me(token)).json() as { instanceRole: string; runsInstance: boolean; tampered: boolean };
  assert.deepEqual([shown.instanceRole, shown.runsInstance, shown.tampered], ['owner', true, false], 'shown as the row says: the app cannot check it');
  // Anything else asks the vault, which refuses the row, and their session with it: as before, at every request but this one.
  const client = bearer(token);
  for (const asked of [() => render(token).me(), () => client.projects.list(), () => client.members.list(), () => client.secrets.reveal('market/dev')]) {
    await assert.rejects(asked(), (error: unknown) => error instanceof CoffreError && error.status === 401);
  }
});
