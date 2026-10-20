// One call to the vault for each request: checking a coffre credential asks
// the vault who its member is, and that answer is the caller, rather than
// a second call; a reveal asks nothing but the call that opens its values,
// whose answer says who is asking; and a page's render, which makes several
// API calls in process, checks its credential once for all of them. Every vault call
// costs a round trip to the vault Worker, and on Cloudflare the page that
// made seven of them was the slowest, and the likeliest to meet a hang.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';

import { github, signin } from '@coffre/core/identity';
import type { Vault } from '@coffre/core/vault';
import { tablesOf } from '@coffre/db';
import { and, asc, eq } from 'drizzle-orm';

import { SigninService } from '../src/api/signin.ts';
import { authenticateRequest } from '../src/auth.ts';
import { fetchApi, pageClient } from '../src/fetch-api.ts';
import type { CoffreRuntime } from '../src/runtime.ts';
import { clientFor, contextFor, openTestDatabase, resetDatabase, testDeps, waitUntil, type FixtureDeps } from './api-fixture.ts';

const ORIGIN = 'https://secrets.acme.example';
const ROOT = 'admin@acme.example';
const DEV = 'dev@acme.example';
const QA = 'qa@acme.example';
const auth = signin({ providers: [github({ clientId: 'gh-id', clientSecret: 'gh-secret' })] }).resolve(ORIGIN);

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;
/** Each principal the vault was asked about, in order. */
let asked: string[];
/** Each call that opened values, by its principal, in order. */
let unwrapped: string[];
let runtime: CoffreRuntime;

before(async () => {
  db = await openTestDatabase();
  deps = testDeps(db.runtime, [ROOT]);
  const vault: Vault = {
    ...deps.vault,
    access: (principal: string) => {
      asked.push(principal);
      return deps.vault.access(principal);
    },
    unwrap: (input) => {
      unwrapped.push(input.principal);
      return deps.vault.unwrap(input);
    },
  };
  if (auth.mode !== 'signin') throw new Error('unreachable');
  const service = new SigninService({ ...deps, vault, signin: auth.signin });
  runtime = {
    db: deps.db,
    vault,
    chainKey: deps.chainKey,

    signin: service,
    workloads: null,
    mcp: null,
    auth,
    publicUrl: ORIGIN,
    verifier: service,
    waitUntil,
    schema: { migrated: true },
    rotateAfterDays: 365,
    plugins: [],
  };
});

after(async () => {
  await resetDatabase(db.owner);
  await db.close();
});

beforeEach(async () => {
  await resetDatabase(db.owner);
  const root = clientFor(deps, ROOT);
  await root.members.add(`user:${DEV}`);
  await root.projects.create('market', { name: 'Market' });
  await root.environments.create('market/dev', { name: 'Development' });
  await root.access.set(`user:${DEV}`, { market: 'developer' });
  asked = [];
  unwrapped = [];
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

test('an API request with a coffre credential asks the vault once', async () => {
  const token = await cliToken(DEV);
  asked = [];
  for (const path of ['/api/me', '/api/projects', '/api/secrets/market/dev']) {
    const response = await fetchApi(new Request(`${ORIGIN}${path}`, { headers: { authorization: `Bearer ${token}` } }), runtime, { sourceIp: null });
    assert.equal(response.status, 200, path);
  }
  assert.deepEqual(asked, [`user:${DEV}`, `user:${DEV}`, `user:${DEV}`], 'one vault call for each request');
});

test("a page's render, its loaders calling the API at once, asks the vault once for all of them", async () => {
  const token = await cliToken(DEV);
  asked = [];
  // The browser's session cookie, as the page was asked for with it; a CLI token works the same as a cookie value here.
  const page = new Request(`${ORIGIN}/projects`, { headers: { cookie: `__Host-coffre_session=${token}` } });
  const client = pageClient(page, runtime, null);
  // As the shell and the projects page load: who is looking, how one signs in, the projects, and each environment's keys.
  const [me, , { projects }, { keys }] = await Promise.all([
    client.me(),
    client.auth(),
    client.projects.list(),
    client.secrets.list('market/dev'),
  ]);
  assert.equal(me.principal.id, DEV);
  assert.deepEqual([projects.map(({ slug }) => slug), keys], [['market'], []]);
  await client.me();
  assert.deepEqual(asked, [`user:${DEV}`], 'one vault call for the whole render');

  // A refusal is answered to every call of the render, each its own response.
  const signedOut = pageClient(new Request(`${ORIGIN}/projects`, { headers: { cookie: '__Host-coffre_session=coffre_cli_unknown' } }), runtime, null);
  const refused = await Promise.allSettled([signedOut.me(), signedOut.projects.list()]);
  assert.deepEqual(
    refused.map((outcome) => outcome.status === 'rejected' && (outcome.reason as { status: number }).status),
    [401, 401],
  );
});

/** A reveal of `path` with `token`, as the CLI asks: the status and the body. */
async function reveal(token: string, path: string): Promise<{ status: number; body: { values?: Record<string, string>; message?: string; reason?: string } }> {
  const response = await fetchApi(
    new Request(`${ORIGIN}/api/reveals`, { method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body: JSON.stringify({ path }) }),
    runtime,
    { sourceIp: null },
  );
  return { status: response.status, body: (await response.json()) as never };
}

/** The log's reads by `principal`, each its author, decision and code. */
async function readsBy(principal: string): Promise<[string, string, string | null][]> {
  const { auditLog } = tablesOf(db.owner);
  const rows = await db.owner.select().from(auditLog).where(and(eq(auditLog.actor, principal), eq(auditLog.action, 'secret.read'))).orderBy(asc(auditLog.seq));
  return rows.map((row) => [row.author, row.decision, row.code]);
}

test('a reveal asks the vault nothing but the call that opens its values, which says who is asking', async () => {
  await clientFor(deps, ROOT).secrets.set('market/dev', { API_KEY: 'dev-key' });
  const token = await cliToken(DEV);
  asked = [];
  const read = await reveal(token, 'market/dev/API_KEY');
  assert.deepEqual([read.status, read.body.values], [200, { API_KEY: 'dev-key' }]);
  assert.deepEqual([asked, unwrapped], [[], [`user:${DEV}`]]);
});

test("a reveal the vault refuses is worded as the app words it, and logged once, by the vault", async () => {
  const root = clientFor(deps, ROOT);
  await root.secrets.set('market/dev', { API_KEY: 'dev-key' });
  await root.environments.create('market/prod', { name: 'Prod' });
  await root.secrets.set('market/prod', { API_KEY: 'prod-key' });
  await root.members.add(`user:${QA}`);
  await root.access.set(`user:${QA}`, { 'market/dev': 'viewer' });
  const token = await cliToken(QA);
  asked = [];
  const refused = await reveal(token, 'market/prod');
  assert.deepEqual([refused.status, refused.body.reason], [403, 'missing_secret_read'], 'as the app words it, the reason a client branches on included');
  assert.deepEqual(await readsBy(`user:${QA}`), [['vault', 'deny', 'no_grant']], 'the vault refused it, and nothing else logged it again');
  assert.deepEqual(asked, [], 'its answer said who asked');
});

test("a fork's inherited values take read on the fork too, decided by the vault with them", async () => {
  const root = clientFor(deps, ROOT);
  await root.secrets.set('market/dev', { API_KEY: 'dev-key' });
  await root.environments.create('market/dev-eu', { from: 'dev', inherit: true });
  await root.members.add(`user:${QA}`);
  await root.access.set(`user:${QA}`, { 'market/dev': 'viewer' });
  const token = await cliToken(QA);
  // Every value of dev-eu is dev's, which QA reads; dev-eu itself, QA does not.
  assert.equal((await reveal(token, 'market/dev')).status, 200);
  const fork = await reveal(token, 'market/dev-eu');
  assert.deepEqual([fork.status, fork.body.reason], [403, 'missing_secret_read']);
  await root.access.set(`user:${QA}`, { 'market/dev-eu': 'viewer' });
  assert.deepEqual((await reveal(token, 'market/dev-eu')).body.values, { API_KEY: 'dev-key' });
});

test('a session of an earlier membership reveals nothing: removed and admitted again, its member signs in again', async () => {
  const root = clientFor(deps, ROOT);
  await root.secrets.set('market/dev', { API_KEY: 'dev-key' });
  const token = await cliToken(DEV);
  await root.members.remove(`user:${DEV}`);
  await root.members.add(`user:${DEV}`);
  await root.access.set(`user:${DEV}`, { market: 'developer' });
  unwrapped = [];
  // Its credential went with the removal; were it read before the revocation committed, the vault would refuse its generation.
  const stale = await reveal(token, 'market/dev');
  assert.deepEqual([stale.status, unwrapped], [401, []]);
  assert.equal((await reveal(await cliToken(DEV), 'market/dev')).status, 200);
});

test("behind Access, a reveal's caller is asked of the vault first, and whoever it turns away learns nothing of what is there", async () => {
  const STRANGER = 'stranger@acme.example';
  await clientFor(deps, ROOT).secrets.set('market/dev', { API_KEY: 'dev-key' });
  // Access in front: every token is the email of whoever holds it, and only the vault says who is a member.
  const access: CoffreRuntime = { ...runtime, signin: null, verifier: { verify: async (token: string) => ({ type: 'user', id: token, email: token, subject: token }) } };
  const ask = async (path: string) => {
    const response = await fetchApi(new Request(`${ORIGIN}/api/reveals`, {
      method: 'POST', headers: { authorization: `Bearer ${STRANGER}`, 'content-type': 'application/json' }, body: JSON.stringify({ path }),
    }), access, { sourceIp: null });
    return [response.status, ((await response.json()) as { error: string }).error];
  };
  assert.deepEqual(await ask('market/dev'), [403, 'registration_required']);
  assert.deepEqual(await ask('nope/dev'), [403, 'registration_required'], 'the same, whether or not the place exists');
  assert.deepEqual(await ask('not a path'), [403, 'registration_required'], 'and for a request it could not even parse');
  // Behind Access, anyone reaches the app: the vault is asked who they are first, and decides no read of theirs.
  assert.deepEqual([await readsBy(`user:${STRANGER}`), unwrapped], [[], []]);
});

test('a session of an earlier membership that reaches the vault, before its revocation commits, is refused there', async () => {
  await clientFor(deps, ROOT).secrets.set('market/dev', { API_KEY: 'dev-key' });
  const token = await cliToken(DEV);
  // Removed and admitted again by the vault alone: the app's revocation of the session has not happened yet.
  assert.ok((await deps.vault.remove({ actor: `user:${ROOT}`, principal: `user:${DEV}` })).ok);
  assert.ok((await deps.vault.admit({ actor: `user:${ROOT}`, principal: `user:${DEV}` })).ok);
  const { projects } = tablesOf(db.owner);
  const [project] = await db.owner.select({ id: projects.id }).from(projects).where(eq(projects.slug, 'market'));
  assert.ok((await deps.vault.setAccess({ actor: `user:${ROOT}`, principal: `user:${DEV}`, changes: [{ projectId: project!.id, environmentId: null, role: 'developer', expiresAt: null }] })).ok);
  asked = [];
  const stale = await reveal(token, 'market/dev');
  assert.deepEqual([stale.status, unwrapped.at(-1), asked], [401, `user:${DEV}`, []], 'answered by the read, and asked nothing again');
  assert.deepEqual((await readsBy(`user:${DEV}`)).at(-1), ['vault', 'deny', 'removed']);
});

test("a session the vault no longer vouches for learns nothing of what is there: every answer waits for the vault's", async () => {
  await clientFor(deps, ROOT).secrets.set('market/dev', { API_KEY: 'dev-key' });
  const token = await cliToken(DEV);
  // Removed by the vault alone: the app's revocation of the session has not happened yet.
  assert.ok((await deps.vault.remove({ actor: `user:${ROOT}`, principal: `user:${DEV}` })).ok);
  for (const path of ['nope/dev', 'not a path', 'market/dev/MISSING', 'market/dev']) {
    asked = [];
    unwrapped = [];
    const answer = await reveal(token, path);
    assert.equal(answer.status, 401, path);
    // Nothing the vault decides on to open, it is asked who they are; something to open, the read itself says.
    assert.deepEqual([asked.length + unwrapped.length], [1], path);
  }
});

test('a vault older than the app, whose read says nothing of who asked, hands back nothing: deploy the vault first', async () => {
  await clientFor(deps, ROOT).secrets.set('market/dev', { API_KEY: 'dev-key' });
  const token = await cliToken(DEV);
  // A vault of 0.10 decides the values alone, not the environment asked of nor the credential's generation.
  const older: Vault = { ...runtime.vault, unwrap: async (input) => {
    const { access: _, ...answer } = await runtime.vault.unwrap(input);
    return answer;
  } };
  const response = await fetchApi(
    new Request(`${ORIGIN}/api/reveals`, { method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body: JSON.stringify({ path: 'market/dev' }) }),
    { ...runtime, vault: older },
    { sourceIp: null },
  );
  const body = await response.text();
  assert.equal(response.status, 503);
  assert.doesNotMatch(body, /dev-key/);
});

test('a reveal answers alike whether its caller is asked of the vault first or by the read itself, and logs no allow behind a refusal', async () => {
  const root = clientFor(deps, ROOT);
  await root.secrets.set('market/dev', { API_KEY: 'dev-key', TOKEN: { value: 'dev-token', sensitivity: 'sensitive' } });
  await root.environments.create('market/prod', { name: 'Prod' });
  await root.secrets.set('market/prod', { API_KEY: 'prod-key', REGION: { value: 'eu-west-3', plain: true } });
  await root.environments.create('market/dev-eu', { from: 'dev', inherit: true });
  await root.environments.protect('market/prod');
  await root.members.add(`user:${QA}`);
  await root.access.set(`user:${QA}`, { 'market/dev': 'viewer' });
  await clientFor(deps, DEV).secrets.set('market/dev@me', { API_KEY: 'dev-own' });
  const paths = ['market/dev', 'market/dev/API_KEY', 'market/dev/TOKEN', 'market/dev/MISSING', 'market/prod', 'market/prod/REGION', 'market/dev-eu', 'market/dev@me', 'nope/dev'];
  const { auditLog } = tablesOf(db.owner);
  const allows = async () => (await db.owner.select({ seq: auditLog.seq }).from(auditLog)
    .where(and(eq(auditLog.author, 'vault'), eq(auditLog.action, 'secret.read'), eq(auditLog.decision, 'allow')))).length;
  for (const email of [DEV, QA]) {
    const token = await cliToken(email);
    for (const path of paths) {
      const ask = (eager: boolean) => fetchApi(
        new Request(`${ORIGIN}/api/reveals`, { method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body: JSON.stringify({ path }) }),
        runtime,
        // The eager way: the vault is asked who they are when the credential is checked, as for any other request.
        { sourceIp: null, ...(eager ? { authenticate: (credential: string) => authenticateRequest(new Request(ORIGIN), runtime, randomUUID(), credential, null) } : {}) },
      );
      const allowed = await allows();
      const deferred = await ask(false);
      const answer = { status: deferred.status, body: (await deferred.json()) as Record<string, unknown> };
      if (!deferred.ok) assert.equal(await allows(), allowed, `${email} ${path}: no allow behind a refusal`);
      const eager = await ask(true);
      const expected = { status: eager.status, body: (await eager.json()) as Record<string, unknown> };
      // An operation's id is each read's own.
      delete answer.body.operationId;
      delete expected.body.operationId;
      assert.deepEqual(answer, expected, `${email} ${path}`);
    }
  }
});

