// A request of one key is the vault's one call by name (T145, PR B; src/named-use.ts, `useByName`): a reveal of
// `market/dev/API_KEY`, of `market/dev` with `keys: ['API_KEY']`, a handle's /use. The vault resolves the names and
// decides on the caller as its sealed rows have them; the app checks the credential's row, its MAC over the token's
// hash and a handle's places among it, on the rows the use answered, before any value leaves. Several keys go as before until PR B2. With
// 0.15's log whichever log the suite runs, as a deployment of 0.15 keeps it.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

import { github, hashToken, signin } from '@coffre/core/identity';
import type { Vault } from '@coffre/core/vault';
import { and, eq, gt } from 'drizzle-orm';

import { resolveConfig } from '../src/config.ts';
import { fetchApi } from '../src/fetch-api.ts';
import { checkPlugins, pluginRoute } from '../src/plugins.ts';
import { credentialProxy, header } from '../src/plugins/credential-proxy.ts';
import { createRuntime, type CoffreRuntime } from '../src/runtime.ts';
import { processLimits } from '../src/workloads/limits.ts';
import { clientFor, contextFor, openTestDatabase, resetDatabase, sealedNow, testDeps, testVault, usesLogged, type FixtureDeps } from './api-fixture.ts';
import { auditLog, credentials as credentialRows, environments, logBulk, logFence, logUses, vaultGrants } from './db/tables.ts';

const ORIGIN = 'https://secrets.acme.example';
const ROOT = 'admin@acme.example';
const DEV = 'dev@acme.example';
const GONE = 'gone@acme.example';
const FORGED = 'forged@acme.example';
const LEFT = 'left@acme.example';
const DEV_KEY = 'sk_dev_0123456789';
const PROD_KEY = 'sk_prod_0123456789';

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;
const kek = randomBytes(32);
/** The runtime, and the same with a vault that serves nothing by name: a request as before PR B. */
let runtime: CoffreRuntime;
let unnamed: CoffreRuntime;
/** The vault's calls by name, as the runtime makes them. */
let named = 0;
/** What the proxy's upstream was sent: the key it injected, if any. */
const sent: (string | null)[] = [];

const egress = { fetch: async (_target: unknown, init?: RequestInit) => {
  sent.push(new Headers(init?.headers).get('x-api-key'));
  return new Response(null, { status: 204 });
} };
/** `api`, through an egress; `ro`, the same key, GET only. */
const credentials = {
  api: { upstream: 'https://api.example', inject: header('x-api-key', '{API_KEY}'), egress },
  ro: { upstream: 'https://api.example', inject: header('x-api-key', '{API_KEY}'), egress, methods: ['GET'] },
};

function runtimeOver(vault: Vault): CoffreRuntime {
  const config = resolveConfig({
    publicUrl: ORIGIN, vault, auth: signin({ providers: [github({ clientId: 'a', clientSecret: 'b' })] }), auditChainKey: deps.chainKey.toString('base64'),
    plugins: [credentialProxy({ credentials, cacheSeconds: 0 })],
  });
  const made = createRuntime(config, deps.db, vault, { json: async (url) => { throw new Error(`no fetch of ${url.href} here`); } });
  made.plugins = checkPlugins(config.plugins);
  return made;
}

/** The vault, its calls by name counted, or none served (`useNamed` gone). */
function counted(vault: Vault, serves: boolean): Vault {
  return new Proxy(vault, {
    get(target, key) {
      if (key === 'useNamed' && !serves) return undefined;
      const value: unknown = Reflect.get(target, key, target);
      if (key !== 'useNamed' || typeof value !== 'function') return value;
      return (...args: unknown[]) => {
        named += 1;
        return (value as (...callArgs: unknown[]) => unknown).apply(target, args);
      };
    },
  });
}

before(async () => {
  db = await openTestDatabase();
  await resetDatabase(db.owner);
  await db.owner.update(logFence).set({ atFloor: Date.now() - 60_000 });
  deps = testDeps(db.runtime, [ROOT], { vault: testVault([ROOT], {}, { kek }, {}, { log: '0.15', sealThrough: sealedNow }) });
  runtime = runtimeOver(counted(deps.vault, true));
  unnamed = runtimeOver(counted(deps.vault, false));
  deps.signin = runtime.signin!;
  const root = clientFor(deps, ROOT);
  await root.projects.create('market', { name: 'Market' });
  for (const path of ['market/dev', 'market/prod']) await root.environments.create(path);
  await root.secrets.set('market/dev', { API_KEY: DEV_KEY, OTHER: 'other', TOKEN: { value: 'tok_0123456789', sensitivity: 'sensitive' } });
  await root.secrets.set('market/prod', { API_KEY: PROD_KEY });
  for (const person of [DEV, GONE, FORGED, LEFT]) {
    await root.members.add(`user:${person}`);
    await root.access.set(`user:${person}`, { 'market/dev': 'developer' });
  }
});

after(async () => {
  await resetDatabase(db.owner);
  await db.close();
});

const personalToken = async (person: string, scope: Record<string, 'viewer' | 'developer'> = { 'market/dev': 'developer' }) =>
  (await runtime.signin!.issuePersonalToken(await contextFor(deps, person), { label: 'script', expiresInMinutes: 60, scope })).token;

/** `POST /api/reveals` with a bearer token: its status and body. */
async function reveal(token: string, body: { path: string; keys?: readonly string[] }, at: CoffreRuntime = runtime): Promise<{ status: number; body: Record<string, unknown> }> {
  const response = await fetchApi(new Request(`${ORIGIN}/api/reveals`, {
    method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body: JSON.stringify(body),
  }), at, { sourceIp: null });
  return { status: response.status, body: (await response.json()) as Record<string, unknown> };
}

/** The app's entries since `seq`, as action, decision and code. */
async function entriesSince(seq: bigint): Promise<string[]> {
  const rows = await db.owner.select({ action: auditLog.action, decision: auditLog.decision, code: auditLog.code, metadata: auditLog.metadata }).from(auditLog).where(gt(auditLog.seq, seq)).orderBy(auditLog.seq);
  // A proxy's use as it names it (`logged`): its credential, host, and egress.
  const named = (metadata: unknown) => {
    const { credential, host, egress: through } = (typeof metadata === 'string' ? JSON.parse(metadata) : metadata ?? {}) as Record<string, unknown>;
    return credential === undefined ? '' : ` ${JSON.stringify({ credential, host, egress: through })}`;
  };
  return rows.map((row) => `${row.action} ${row.decision} ${row.code ?? ''}`.trim() + named(row.metadata));
}
const newest = async () => (await db.owner.select({ seq: auditLog.seq }).from(auditLog)).reduce((max, row) => (row.seq > max ? row.seq : max), -1n);

test('one key, by its path or as a list of one, a person\'s or a service\'s, is the vault\'s one call by name; several are not', async () => {
  const token = await personalToken(DEV);
  const root = clientFor(deps, ROOT);
  await root.members.add('token:ci');
  await root.access.set('token:ci', { 'market/dev': 'viewer' });
  const service = (await runtime.signin!.issueServiceToken(await contextFor(deps, ROOT), 'ci', { label: 'ci', expiresInDays: 1 })).token;
  for (const [name, caller, body] of [
    ['its path', token, { path: 'market/dev/API_KEY' }],
    ['a list of one', token, { path: 'market/dev', keys: ['API_KEY'] }],
    ["a service's", service, { path: 'market/dev/API_KEY' }],
  ] as const) {
    named = 0;
    const read = await reveal(caller, body);
    assert.equal(read.status, 200, JSON.stringify(read.body));
    assert.deepEqual(read.body.values, { API_KEY: DEV_KEY }, name);
    assert.equal(named, 1, `${name}: by name`);
  }
  named = 0;
  const several = await reveal(token, { path: 'market/dev', keys: ['API_KEY', 'OTHER'] });
  assert.deepEqual(several.body.values, { API_KEY: DEV_KEY, OTHER: 'other' });
  assert.equal(named, 0, 'several keys: as before, until PR B2');
});

test('a key the place does not hold, and a sensitive one a list of one leaves out, are answered and logged as before', async () => {
  const token = await personalToken(DEV);
  for (const body of [{ path: 'market/dev/NEVER_MADE' }, { path: 'market/dev', keys: ['NEVER_MADE'] }, { path: 'market/dev', keys: ['TOKEN'] }]) {
    const answers: unknown[] = [];
    for (const at of [unnamed, runtime]) {
      const since = await newest();
      const read = await reveal(token, body, at);
      answers.push({ status: read.status, values: read.body.values, sensitive: read.body.sensitive, error: read.body.error, entries: await entriesSince(since) });
    }
    assert.deepEqual(answers[1], answers[0], JSON.stringify(body));
  }
});

test("a writer who moves a token's hash onto another credential reads nothing through it: its MAC is checked before any value leaves", async () => {
  const mine = await personalToken(DEV);
  const theirs = await personalToken(ROOT, { 'market/dev': 'viewer', 'market/prod': 'viewer' });
  assert.equal((await reveal(theirs, { path: 'market/prod/API_KEY' })).status, 200);
  // The Owner's credential row given DEV's token's hash, DEV's own another: DEV's token now names the Owner's row.
  const [own] = await db.owner.select({ id: credentialRows.id }).from(credentialRows).where(eq(credentialRows.tokenHash, hashToken(mine)));
  const [owner] = await db.owner.select({ id: credentialRows.id }).from(credentialRows).where(eq(credentialRows.tokenHash, hashToken(theirs)));
  await db.owner.update(credentialRows).set({ tokenHash: randomBytes(32) }).where(eq(credentialRows.id, own!.id));
  await db.owner.update(credentialRows).set({ tokenHash: hashToken(mine) }).where(eq(credentialRows.id, owner!.id));
  for (const body of [{ path: 'market/prod/API_KEY' }, { path: 'market/prod', keys: ['API_KEY'] }]) {
    const read = await reveal(mine, body);
    // The vault used the Owner's credential, as the rows have it; the app's check of the row's MAC refuses it (without it, the value goes).
    assert.equal(read.status, 401, JSON.stringify(read.body));
    assert.ok(!JSON.stringify(read.body).includes(PROD_KEY), 'no value');
  }
});

test("a writer who moves a handle's environment off the ones it was made for uses nothing there: its places are under its row's MAC", async () => {
  const handle = (await runtime.signin!.issueHandle({ ...(await contextFor(deps, DEV)), personalToken: null }, { label: 'run', expiresInMinutes: 60, paths: ['market/dev'] })).token;
  const use = () => pluginRoute(new Request(`${ORIGIN}/use/api/thing`, { headers: { 'x-api-key': handle } }), runtime, '203.0.113.7')!;
  sent.length = 0;
  assert.equal((await use()).status, 204);
  assert.deepEqual(sent, [DEV_KEY]);
  const [prod] = await db.owner.select({ id: environments.id }).from(environments).where(and(eq(environments.slug, 'prod')));
  const [row] = await db.owner.select({ id: credentialRows.id, places: credentialRows.places }).from(credentialRows).where(eq(credentialRows.tokenHash, hashToken(handle)));
  const [dev] = await db.owner.select({ id: environments.id }).from(environments).where(eq(environments.slug, 'dev'));
  await db.owner.update(credentialRows).set({ places: row!.places!.replace(dev!.id, prod!.id) }).where(eq(credentialRows.id, row!.id));
  sent.length = 0;
  const moved = await use();
  // The vault would use the key where the row now points, if the handle's sealed scope reaches it (here it does not):
  // the app's check of the row's MAC, which covers its places, refuses it either way, before any value leaves.
  assert.equal(moved.status, 401, await moved.text());
  assert.deepEqual(sent, [], 'nothing sent upstream');
});

test('revoked, someone learns nothing of a key made since, by its path or a list of one, however busy the vault (Probing.tla)', async () => {
  // The proxy's, a handle's one key, is held to the same in proxy-handle-check.test.ts (review r2 of #406).
  const token = await personalToken(GONE);
  assert.equal((await reveal(token, { path: 'market/dev/API_KEY' })).status, 200);
  const root = clientFor(deps, ROOT);
  await root.access.set(`user:${GONE}`, { 'market/dev': null });
  await root.secrets.set('market/dev', { MADE_SINCE: 'made-since' });
  // The vault as it is, and one of the same instance with every call in flight taken: busy before it reads anything.
  const busy = runtimeOver(testVault([ROOT], {}, { kek }, {}, { log: '0.15', sealThrough: sealedNow, uses: { inFlight: 0 } }));
  for (const at of [runtime, busy]) {
    const logged = (await usesLogged(db.owner)).length;
    for (const ask of [(key: string) => ({ path: `market/dev/${key}` }), (key: string) => ({ path: 'market/dev', keys: [key] })]) {
      const made = await reveal(token, ask('MADE_SINCE'), at);
      const never = await reveal(token, ask('NEVER_MADE'), at);
      assert.equal(made.status, at === busy ? 503 : 403, JSON.stringify(made.body));
      assert.deepEqual(made, never, 'alike');
    }
    // Refused, each request of a key held is logged (R53), and none of one never made; busy, none at all.
    assert.equal((await usesLogged(db.owner)).length - logged, at === busy ? 0 : 2);
  }
});

/** A request through the proxy with a handle: its status and body. */
async function proxied(url: string, handle: string, at: CoffreRuntime = runtime): Promise<{ status: number; body: string }> {
  const response = await pluginRoute(new Request(`${ORIGIN}${url}`, { headers: { 'x-api-key': handle } }), at, '203.0.113.7')!;
  return { status: response.status, body: await response.text() };
}

/** `ask` against today's path (a vault that serves nothing by name), then the named one: each's answer and the app's entries. */
async function both<T>(ask: (at: CoffreRuntime) => Promise<T>): Promise<{ answer: T; entries: string[] }[]> {
  const answers: { answer: T; entries: string[] }[] = [];
  for (const at of [unnamed, runtime]) {
    const since = await newest();
    answers.push({ answer: await ask(at), entries: await entriesSince(since) });
  }
  return answers;
}

test('a grant a writer put back after its revoke stands for nothing: the request asks the vault, and is answered as before (review r1 of #412)', async () => {
  const token = await personalToken(FORGED);
  assert.equal((await reveal(token, { path: 'market/dev/API_KEY' })).status, 200);
  const grants = await db.owner.select().from(vaultGrants).where(eq(vaultGrants.principal, `user:${FORGED}`));
  await clientFor(deps, ROOT).access.set(`user:${FORGED}`, { 'market/dev': null });
  await db.owner.insert(vaultGrants).values(grants);
  // The vault reports a tampered row once a process (`vault.tampered`): whichever asks first.
  const since = await newest();
  const reported = ({ answer, entries }: { answer: unknown; entries: string[] }) => ({ answer, entries: entries.filter((entry) => !entry.startsWith('vault.tampered')) });
  for (const body of [{ path: 'market/dev/API_KEY' }, { path: 'market/dev/NEVER_MADE' }, { path: 'market/dev', keys: ['TOKEN'] }]) {
    const [before, now] = await both((at) => reveal(token, body, at));
    assert.deepEqual(reported(now!), reported(before!), JSON.stringify(body));
    assert.ok(now!.answer.status >= 400, `${now!.answer.status} ${JSON.stringify(now!.answer.body)}`);
  }
  assert.ok((await entriesSince(since)).includes('vault.tampered deny mac'), 'the forged grant reported');
});

test("the proxy's use of a plain value, or of a key its environment does not hold, is logged as before (review r1 of #412)", async () => {
  const root = clientFor(deps, ROOT);
  for (const path of ['market/plain', 'market/empty']) await root.environments.create(path);
  await root.secrets.set('market/plain', { API_KEY: { value: 'pk_public_0123', sensitivity: 'plain' } });
  await root.secrets.set('market/empty', { OTHER: 'other' });
  await root.access.set(`user:${DEV}`, { 'market/dev': 'developer', 'market/plain': 'developer', 'market/empty': 'developer' });
  for (const env of ['plain', 'empty']) {
    const handle = (await runtime.signin!.issueHandle({ ...(await contextFor(deps, DEV)), personalToken: null }, { label: 'run', expiresInMinutes: 60, paths: [`market/${env}`] })).token;
    for (const url of [`/use/market/${env}/api/v1/thing`, '/use/api/v1/thing']) {
      const [before, now] = await both((at) => proxied(url, handle, at));
      assert.deepEqual(now, before, `${env}: ${url}`);
      // Its entry names the credential, its host, and the egress it left through (review r2 of #412).
      if (now!.answer.status === 204) assert.ok(now!.entries.some((entry) => entry.startsWith('credential.use') && entry.includes('"egress":true')), `${env}: ${url}: ${JSON.stringify(now)}`);
    }
  }
});

test("a handle whose person lost their grant is refused by the use, logged, as before: the handle's check decides nothing of what they may do (review r1 of #412)", async () => {
  const handle = (await runtime.signin!.issueHandle({ ...(await contextFor(deps, LEFT)), personalToken: null }, { label: 'run', expiresInMinutes: 60, paths: ['market/dev'] })).token;
  assert.equal((await proxied('/use/api/v1/thing', handle)).status, 204);
  await clientFor(deps, ROOT).access.set(`user:${LEFT}`, { 'market/dev': null });
  // The environment's URL, the stable URL in one call, and in two (`/use/<credential>/<x>` may name an environment's plan:
  // its handle's check first, `handle`, then the use).
  for (const url of ['/use/market/dev/api/v1/thing', '/use/api/v1/thing', '/use/api/thing']) {
    const [before, now] = await both((at) => proxied(url, handle, at));
    assert.deepEqual(now, before, url);
    assert.ok(now!.entries.some((entry) => entry.includes('deny')), `${url}: the refusal logged: ${JSON.stringify(now)}`);
  }
});

test("the stable URL refuses as its route does before the request's own refusals: a handle of two environments, POST to a GET-only credential (review r2 of #412)", async () => {
  await clientFor(deps, ROOT).access.set(`user:${DEV}`, { 'market/prod': 'developer' });
  const handle = (await runtime.signin!.issueHandle({ ...(await contextFor(deps, DEV)), personalToken: null }, { label: 'run', expiresInMinutes: 60, paths: ['market/dev', 'market/prod'] })).token;
  const post = (at: CoffreRuntime) => pluginRoute(new Request(`${ORIGIN}/use/ro/v1/thing`, { method: 'POST', headers: { 'x-api-key': handle }, body: '{}' }), at, '203.0.113.7')!
    .then(async (response) => ({ status: response.status, body: await response.text() }));
  const [before, now] = await both(post);
  assert.deepEqual(now, before);
  assert.equal(now!.answer.status, 409, now!.answer.body);
  // A body whose stream breaks: the route's refusal still, which never read it (review r3 of #412).
  const broken = (at: CoffreRuntime) => {
    const body = new ReadableStream<Uint8Array>({ pull: (controller) => controller.error(new Error('the stream broke')) });
    const request = new Request(`${ORIGIN}/use/api/v1/thing`, { method: 'POST', headers: { 'x-api-key': handle }, body, duplex: 'half' } as RequestInit);
    return pluginRoute(request, at, '203.0.113.7')!.then(async (response) => ({ status: response.status, body: await response.text() }));
  };
  const [old, fresh] = await both(broken);
  assert.deepEqual(fresh, old);
  assert.equal(fresh!.answer.status, 409, fresh!.answer.body);
});

test("a service's bearer token on a strict instance (useOnly) is refused by its kind before the vault is asked: nothing used, nothing counted (review r3 of #412)", async () => {
  const root = clientFor(deps, ROOT);
  await root.members.add('token:strict');
  await root.access.set('token:strict', { 'market/dev': 'viewer' });
  const service = (await runtime.signin!.issueServiceToken(await contextFor(deps, ROOT), 'strict', { label: 'strict', expiresInDays: 1 })).token;
  const config = resolveConfig({
    publicUrl: ORIGIN, vault: counted(deps.vault, true), auth: signin({ providers: [github({ clientId: 'a', clientSecret: 'b' })], workloads: { limits: processLimits(), useOnly: true } }),
    auditChainKey: deps.chainKey.toString('base64'),
  });
  const strict = createRuntime(config, deps.db, counted(deps.vault, true), { json: async (url) => { throw new Error(`no fetch of ${url.href} here`); } });
  const [uses, bulk] = [(await db.owner.select().from(logUses)).length, (await db.owner.select().from(logBulk)).length];
  named = 0;
  for (const body of [{ path: 'market/dev/API_KEY' }, { path: 'market/dev', keys: ['API_KEY'] }]) {
    const read = await reveal(service, body, strict);
    assert.equal(read.status, 401, JSON.stringify(read.body));
    assert.equal(read.body.reason, 'use_only');
  }
  assert.equal(named, 0, 'the vault asked nothing');
  assert.deepEqual([(await db.owner.select().from(logUses)).length, (await db.owner.select().from(logBulk)).length], [uses, bulk], 'no use, no row of the cap');
});
