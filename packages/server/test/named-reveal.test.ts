// A request of one key is the vault's one call by name (T145, PR B; src/named-use.ts, `useByName`): a reveal of
// `market/dev/API_KEY`, of `market/dev` with `keys: ['API_KEY']`, a handle's /use. The vault resolves the names and
// decides on the caller as its sealed rows have them; the app checks the credential's row, its MAC over the token's
// hash and a handle's places among it, on the rows the use answered, before any value leaves. Several keys go as before until PR B2. With
// 0.15's log whichever log the suite runs, as a deployment of 0.15 keeps it.
import test, { after, before, mock } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

import { cloudflareAccess, github, google, hashToken, signin } from '@coffre/core/identity';
import type { Vault } from '@coffre/core/vault';
import { and, eq, gt, sql } from 'drizzle-orm';

import { resolveConfig } from '../src/config.ts';
import { fetchApi } from '../src/fetch-api.ts';
import { checkPlugins, pluginRoute } from '../src/plugins.ts';
import { credentialProxy, header } from '../src/plugins/credential-proxy.ts';
import { createRuntime, type CoffreRuntime } from '../src/runtime.ts';
import { processLimits } from '../src/workloads/limits.ts';
import { clientFor, contextFor, openTestDatabase, resetDatabase, sealedNow, nothingHeld, testDeps, testVault, usesLogged, type FixtureDeps } from './api-fixture.ts';
import { auditLog, credentials as credentialRows, environments, logBulk, logFence, logUses, vaultGrants } from './db/tables.ts';
import { TEST_ENGINE } from './db/engine.ts';

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
/** The vault's calls by name, as the runtime makes them, and every call of the vault's, by method. */
let named = 0;
const calls: string[] = [];
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

/**
 * `auth`: the deployment's sign-in: coffre's own through GitHub, or Google once it stops configuring GitHub, or
 * Cloudflare Access, under which no coffre token is a credential.
 */
function runtimeOver(vault: Vault, auth: 'github' | 'google' | 'access' = 'github'): CoffreRuntime {
  const config = resolveConfig({
    publicUrl: ORIGIN, vault,
    auth: auth === 'access'
      ? cloudflareAccess({ teamDomain: 'acme.cloudflareaccess.com', audience: 'coffre-aud' })
      : signin({ providers: [(auth === 'github' ? github : google)({ clientId: 'a', clientSecret: 'b' })] }),
    auditChainKey: deps.chainKey.toString('base64'),
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
      if (typeof value !== 'function') return value;
      return (...args: unknown[]) => {
        if (key === 'useNamed') named += 1;
        calls.push(String(key));
        return (value as (...callArgs: unknown[]) => unknown).apply(target, args);
      };
    },
  });
}

before(async () => {
  db = await openTestDatabase();
  await resetDatabase(db.owner);
  await db.owner.update(logFence).set({ atFloor: Date.now() - 60_000 });
  deps = testDeps(db.runtime, [ROOT], { vault: testVault([ROOT], {}, { kek }, {}, { log: '0.15', sealThrough: sealedNow, heldOutside: nothingHeld }) });
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

test('one key, by its path or as a list of one, a person\'s CLI session or token or a service\'s, is the vault\'s one call by name; several are not', async () => {
  const token = await personalToken(DEV);
  const root = clientFor(deps, ROOT);
  await root.members.add('token:ci');
  await root.access.set('token:ci', { 'market/dev': 'viewer' });
  const service = (await runtime.signin!.issueServiceToken(await contextFor(deps, ROOT), 'ci', { label: 'ci', expiresInDays: 1 })).token;
  const cli = await cliSession(DEV);
  const browser = await browserSession(DEV);
  // Warm: the isolate's map holds the names, so that each read below is one call whatever it held before.
  for (const caller of [token, service, cli, browser]) await reveal(caller, { path: 'market/dev/API_KEY' });
  for (const [name, caller, body] of [
    ['its path', token, { path: 'market/dev/API_KEY' }],
    ['a list of one', token, { path: 'market/dev', keys: ['API_KEY'] }],
    ["a CLI session's", cli, { path: 'market/dev/API_KEY' }],
    ["a browser session's", browser, { path: 'market/dev/API_KEY' }],
    ["a service's", service, { path: 'market/dev/API_KEY' }],
  ] as const) {
    named = 0;
    calls.length = 0;
    const read = await reveal(caller, body);
    assert.equal(read.status, 200, JSON.stringify(read.body));
    assert.deepEqual(read.body.values, { API_KEY: DEV_KEY }, name);
    assert.deepEqual(calls, ['useNamed'], `${name}: the vault's one call, by name`);
  }
  named = 0;
  const several = await reveal(token, { path: 'market/dev', keys: ['API_KEY', 'OTHER'] });
  assert.deepEqual(several.body.values, { API_KEY: DEV_KEY, OTHER: 'other' });
  assert.equal(named, 0, 'several keys: as before, until PR B2');
});

test('a key the place does not hold is answered as every refusal of a key is, and logged as before; a sensitive one a list of one leaves out, as before (D153)', async () => {
  const token = await personalToken(DEV);
  for (const body of [{ path: 'market/dev/NEVER_MADE' }, { path: 'market/dev', keys: ['NEVER_MADE'] }, { path: 'market/dev', keys: ['TOKEN'] }]) {
    const answers: { status: number; values: unknown; sensitive: unknown; error: unknown; entries: string[] }[] = [];
    for (const at of [unnamed, runtime]) {
      const since = await newest();
      const read = await reveal(token, body, at);
      answers.push({ status: read.status, values: read.body.values, sensitive: read.body.sensitive, error: read.body.error, entries: await entriesSince(since) });
    }
    const [before, now] = answers;
    // By its path, a key never made: no such key, or no access to it, alike; the log says which, as before.
    assert.deepEqual(now, body.path.endsWith('NEVER_MADE') ? { ...before!, error: 'not_available' } : before, JSON.stringify(body));
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
  const busy = runtimeOver(testVault([ROOT], {}, { kek }, {}, { log: '0.15', sealThrough: sealedNow, heldOutside: nothingHeld, uses: { inFlight: 0 } }));
  for (const at of [runtime, busy]) {
    const logged = (await usesLogged(db.owner)).length;
    for (const ask of [(key: string) => ({ path: `market/dev/${key}` }), (key: string) => ({ path: 'market/dev', keys: [key] })]) {
      const since = await newest();
      const made = await reveal(token, ask('MADE_SINCE'), at);
      const recorded = await entriesSince(since);
      const between = await newest();
      const never = await reveal(token, ask('NEVER_MADE'), at);
      assert.equal(made.status, at === busy ? 503 : 404, JSON.stringify(made.body));
      if (at !== busy) assert.deepEqual(made.body, { error: 'not_available', message: 'not available: no such key, or no access to it' });
      assert.deepEqual(made, never, 'alike');
      // The app records each request alike, refused (R53); busy, as ever.
      assert.deepEqual(recorded, await entriesSince(between), 'logged alike');
      if (at !== busy) assert.ok(recorded.some((entry) => entry.includes('deny')), JSON.stringify(recorded));
    }
    // A key made since has no row of the cap's of hers: its use would take her principal's lock, so her standing decides
    // first and refuses her there, as for the key never made, and the vault's log has no entry of either (T158).
    assert.equal((await usesLogged(db.owner)).length - logged, 0);
  }
});

test("revoked, with their principal's lock held, someone is answered byte for byte alike, at once, for a key made since, one used before, one deleted since and one never made, by the API and the proxy (T158; review r4 of #412)", async () => {
  const root = clientFor(deps, ROOT);
  const PROBE = 'probe@acme.example';
  const places = ['market/t158-used', 'market/t158-gone', 'market/t158-made', 'market/t158-never'];
  for (const path of places) await root.environments.create(path);
  // The proxy's credential injects `API_KEY`: each place holds it, or not, as its name says.
  for (const path of ['market/t158-used', 'market/t158-gone']) await root.secrets.set(path, { API_KEY: 'sk_t158' });
  await root.secrets.set('market/dev', { T158_USED: 'used', T158_GONE: 'gone' });
  await root.members.add(`user:${PROBE}`);
  await root.access.set(`user:${PROBE}`, Object.fromEntries([...places, 'market/dev'].map((path) => [path, 'developer' as const])));
  const token = await personalToken(PROBE, Object.fromEntries([...places, 'market/dev'].map((path) => [path, 'developer' as const])));
  const handle = (await runtime.signin!.issueHandle({ ...(await contextFor(deps, PROBE)), personalToken: null }, { label: 'run', expiresInMinutes: 60, paths: places })).token;
  // Used while they stood there, each fresh in their cap's set since.
  for (const key of ['T158_USED', 'T158_GONE']) assert.equal((await reveal(token, { path: `market/dev/${key}` })).status, 200);
  for (const path of ['market/t158-used', 'market/t158-gone']) assert.equal((await proxied(`/use/${path}/api/v1/thing`, handle)).status, 204);
  await root.access.set(`user:${PROBE}`, Object.fromEntries([...places, 'market/dev'].map((path) => [path, null])));
  await root.secrets.set('market/dev', { T158_GONE: null, T158_MADE: 'made' });
  await root.secrets.set('market/t158-gone', { API_KEY: null });
  await root.secrets.set('market/t158-made', { API_KEY: 'sk_t158_made' });
  const asked = async () => {
    const answers: { what: string; answer: unknown; ms: number }[] = [];
    for (const key of ['T158_MADE', 'T158_USED', 'T158_GONE', 'T158_NEVER']) {
      for (const body of [{ path: `market/dev/${key}` }, { path: 'market/dev', keys: [key] }]) {
        const started = performance.now();
        const answer = await reveal(token, body);
        answers.push({ what: `${key} ${body.keys === undefined ? 'path' : 'keys'}`, answer, ms: performance.now() - started });
      }
    }
    for (const path of ['market/t158-made', 'market/t158-used', 'market/t158-gone', 'market/t158-never']) {
      const started = performance.now();
      const answer = await proxied(`/use/${path}/api/v1/thing`, handle);
      answers.push({ what: path, answer, ms: performance.now() - started });
    }
    return answers;
  };
  // Their principal's lock (0022: 1668244066, hashtext(principal)), held on a connection of its own: a use that took it
  // would wait past the hot login's 1 s lock_timeout, and answer 503.
  let release!: () => void;
  const released = new Promise<void>((resolve) => { release = resolve; });
  const held = TEST_ENGINE === 'postgres'
    ? db.owner.transaction(async (tx) => {
      await tx.execute(sql`SELECT pg_advisory_xact_lock(1668244066, hashtext(${`user:${PROBE}`}))`);
      await released;
    })
    : Promise.resolve();
  await new Promise((resolve) => setTimeout(resolve, 50));
  // Twice, held all the while: the first asks with names this isolate has not read yet, the second with each mapped,
  // an id or none; a key whose first use wrote its row of the cap's would wait no more by the second.
  const rounds: Awaited<ReturnType<typeof asked>>[] = [];
  try {
    for (let round = 0; round < 2; round += 1) rounds.push(await asked());
  } finally {
    release();
    await held;
  }
  for (const answers of rounds) {
    const api = answers.filter(({ what }) => what.startsWith('T158_'));
    const proxy = answers.filter(({ what }) => what.startsWith('market/'));
    assert.equal((api[0]!.answer as { status: number }).status, 404, JSON.stringify(api[0]));
    assert.equal((proxy[0]!.answer as { status: number }).status, 404, JSON.stringify(proxy[0]));
    for (const { what, answer } of api) assert.deepEqual(answer, api[what.endsWith('path') ? 0 : 1]!.answer, what);
    for (const { what, answer } of proxy) assert.deepEqual(answer, proxy[0]!.answer, what);
    for (const { what, ms } of answers) assert.ok(ms < 900, `${what}: ${Math.round(ms)} ms, no lock waited for`);
  }
});

// D154 (R64): the one exception to answering every key alike, pinned so that a change to it is deliberate. A credential
// is checked twice: the vault checks its own seal over the row (`routeOf`), the app its MAC (APP_KEY) on the rows the
// vault's named call answered, after that call. A row whose seal holds and whose MAC does not, which only a database
// writer can make, is decided by the vault first: a held key its caller has not used this window takes the principal's
// lock, a key never made does not. So under contention the one answers 503, the other 401. Such a writer reads every
// key's name in the database already; what must hold is that the request fails closed, 401 and no value, whatever the key.
test("a credential whose MAC a writer broke, its seal intact, is refused 401 for every key and reads nothing; only under its principal's lock does a held key's 503 differ (D154, R64)", async () => {
  const root = clientFor(deps, ROOT);
  const PINNED = 'pinned@acme.example';
  await root.members.add(`user:${PINNED}`);
  await root.access.set(`user:${PINNED}`, { 'market/dev': 'developer' });
  const token = await personalToken(PINNED);
  await db.owner.update(credentialRows).set({ authMac: randomBytes(32) }).where(eq(credentialRows.tokenHash, hashToken(token)));
  const ask = async (key: string) => {
    const read = await reveal(token, { path: `market/dev/${key}` });
    assert.ok(!JSON.stringify(read.body).includes(DEV_KEY), `${key}: no value`);
    return read.status;
  };
  if (TEST_ENGINE === 'postgres') {
    let release!: () => void;
    const released = new Promise<void>((resolve) => { release = resolve; });
    const held = db.owner.transaction(async (tx) => {
      await tx.execute(sql`SELECT pg_advisory_xact_lock(1668244066, hashtext(${`user:${PINNED}`}))`);
      await released;
    });
    await new Promise((resolve) => setTimeout(resolve, 50));
    try {
      assert.deepEqual([await ask('API_KEY'), await ask('NEVER_MADE')], [503, 401], "the held key waits for the lock, before the app's check");
    } finally {
      release();
      await held;
    }
  }
  const logged = (await usesLogged(db.owner)).length;
  assert.deepEqual([await ask('API_KEY'), await ask('NEVER_MADE')], [401, 401]);
  // The vault made the held key's use before the app's check refused the request: its entry, and nothing else.
  assert.equal((await usesLogged(db.owner)).length - logged, 1, "the held key's use, in the vault's log");
});

// Reviews r6 and r7 of D153 (formal/Probing.tla, AcceptedFirst): the vault's "authenticated" is the app's. The named
// call carries what the deployment's config accepts of a credential, and the vault holds the token's to it first: a
// browser session whose sign-in provider the deployment no longer configures, or any coffre token once it signs in
// through Cloudflare Access, is answered as a token no credential has, in that one call, alike for every key, its
// principal's lock held or not: nothing of the key read, no lock waited for, no use made.
async function heldAlike(at: CoffreRuntime, ask: (key: string) => Promise<{ status: number }>, person: string) {
  const asked = async () => {
    const answers = [];
    const work = [];
    for (const key of ['API_KEY', 'NEVER_MADE']) {
      calls.length = 0;
      const started = performance.now();
      answers.push(await ask(key));
      work.push({ calls: [...calls], fast: performance.now() - started < 900 });
    }
    return { answers, work };
  };
  // Warm, as an isolate that served one already: what it keeps of the log's version and of the caller, asked once.
  await ask('WARM');
  const logged = (await usesLogged(db.owner)).length;
  const rounds = [];
  if (TEST_ENGINE === 'postgres') {
    let release!: () => void;
    const released = new Promise<void>((resolve) => { release = resolve; });
    const held = db.owner.transaction(async (tx) => {
      await tx.execute(sql`SELECT pg_advisory_xact_lock(1668244066, hashtext(${`user:${person}`}))`);
      await released;
    });
    await new Promise((resolve) => setTimeout(resolve, 50));
    try {
      rounds.push(await asked());
    } finally {
      release();
      await held;
    }
  }
  rounds.push(await asked());
  for (const { answers, work } of rounds) {
    assert.equal(answers[0]!.status, 401, JSON.stringify(answers[0]));
    assert.deepEqual(answers[1], answers[0], 'the held key and one never made alike');
    assert.deepEqual(work[1], work[0], 'in the same calls of the vault, none waiting');
    assert.ok(work[0]!.fast, 'no lock waited for');
    assert.ok(!work[0]!.calls.some((method) => method === 'use' || method === 'unwrap'), `nothing used by ids: ${work[0]!.calls.join(', ')}`);
  }
  assert.equal((await usesLogged(db.owner)).length, logged, 'no use made');
}

test("a browser session whose sign-in provider the deployment no longer configures is refused 401 alike for every key, by the vault's one call, before anything of the key (review r6 of D153)", async () => {
  // Someone who has used no key yet, so that a use of API_KEY would take their principal's lock.
  const SIGNED = 'signed@acme.example';
  const root = clientFor(deps, ROOT);
  await root.members.add(`user:${SIGNED}`);
  await root.access.set(`user:${SIGNED}`, { 'market/dev': 'developer' });
  const session = await browserSession(SIGNED);
  const google = runtimeOver(counted(deps.vault, true), 'google');
  await heldAlike(google, (key) => reveal(session, { path: `market/dev/${key}` }, google), SIGNED);
  // Its provider configured, it is served by name, as every other kind.
  named = 0;
  const live = await reveal(session, { path: 'market/dev/API_KEY' });
  assert.deepEqual([live.status, live.body.values, named], [200, { API_KEY: DEV_KEY }, 1]);
});

test("behind Cloudflare Access, no coffre token is a credential: a handle at the proxy is refused 401 alike for every key, before anything of the key (review r7 of D153)", async () => {
  const PROXIED = 'proxied@acme.example';
  const root = clientFor(deps, ROOT);
  for (const path of ['market/r7-held', 'market/r7-never']) await root.environments.create(path);
  await root.members.add(`user:${PROXIED}`);
  await root.access.set(`user:${PROXIED}`, { 'market/r7-held': 'developer', 'market/r7-never': 'developer' });
  await root.secrets.set('market/r7-held', { API_KEY: 'sk_r7' });
  const handle = (await runtime.signin!.issueHandle({ ...(await contextFor(deps, PROXIED)), personalToken: null }, { label: 'run', expiresInMinutes: 60, paths: ['market/r7-held', 'market/r7-never'] })).token;
  // A handle the deployment took under its sign-in, which has used no key yet: a use of API_KEY would take its
  // principal's lock.
  assert.equal((await proxied('/use/market/r7-never/api/v1/thing', handle)).status, 404, 'checked under sign-in');
  const access = runtimeOver(counted(deps.vault, true), 'access');
  await heldAlike(access, (key) => proxied(`/use/market/${key === 'API_KEY' ? 'r7-held' : 'r7-never'}/api/v1/thing`, handle, access), PROXIED);
});

// Review r8 of D153 (formal/Probing.tla, OneClock): the vault judges a credential's end at the use's `at`, and the app's
// own check after it judges its expiry at that same instant. A token live when its request began is that request's:
// every key is answered as for a live credential, the held one served and one never made refused as any, never the
// vault's work for a use followed by the app's 401 (a key held, its use made and logged, then refused) beside a key
// never made refused at once. Here the clock passes the token's expiry between the vault's call and the app's check.
test("a token that expires during its request is that request's, judged at its one instant by the vault and the app alike: every key answered as for a live credential (review r8 of D153)", async () => {
  const EXPIRING = 'expiring@acme.example';
  const root = clientFor(deps, ROOT);
  await root.members.add(`user:${EXPIRING}`);
  await root.access.set(`user:${EXPIRING}`, { 'market/dev': 'developer' });
  const issued = await runtime.signin!.issuePersonalToken(await contextFor(deps, EXPIRING), { label: 'expiring', expiresInMinutes: 1, scope: { 'market/dev': 'developer' } });
  const expiresAt = Date.parse(issued.expiresAt);
  const real = deps.vault.useNamed!;
  const ask = async (key: string) => {
    // Just before its expiry when the request begins, and past it once the vault has answered.
    mock.timers.enable({ apis: ['Date'], now: expiresAt - 300 });
    deps.vault.useNamed = async (input) => {
      const answered = await real.call(deps.vault, input);
      mock.timers.setTime(expiresAt + 700);
      return answered;
    };
    try {
      return await reveal(issued.token, { path: `market/dev/${key}` });
    } finally {
      deps.vault.useNamed = real;
      mock.timers.reset();
    }
  };
  const logged = (await usesLogged(db.owner)).length;
  const asked = [await ask('API_KEY'), await ask('NEVER_MADE')];
  assert.deepEqual([asked[0]!.status, asked[0]!.body.values], [200, { API_KEY: DEV_KEY }], JSON.stringify(asked[0]));
  assert.deepEqual([asked[1]!.status, asked[1]!.body.error], [404, 'not_available'], JSON.stringify(asked[1]));
  assert.equal((await usesLogged(db.owner)).length, logged + 1, 'the held key used, as the vault decided');
});

// Review r12 of D153: a key revealed while its grant stood, then refused once it is revoked, is refused as a key never
// made is, request after request: the vault's named call never runs the cached form an earlier use's seals would choose
// (use-named.test.ts holds the form; the matrices its buffers). Byte for byte, in one call by name each.
test("after a key's reveal and its grant's revoke, it and a key never made are refused alike, request after request (review r12 of D153)", async () => {
  const REVEALED = 'revealed@acme.example';
  const root = clientFor(deps, ROOT);
  await root.members.add(`user:${REVEALED}`);
  await root.access.set(`user:${REVEALED}`, { 'market/dev': 'developer' });
  const token = await personalToken(REVEALED);
  assert.deepEqual((await reveal(token, { path: 'market/dev/API_KEY' })).body.values, { API_KEY: DEV_KEY });
  await root.access.set(`user:${REVEALED}`, { 'market/dev': null });
  for (let round = 0; round < 3; round += 1) {
    named = 0;
    const [held, missing] = [await reveal(token, { path: 'market/dev/API_KEY' }), await reveal(token, { path: 'market/dev/NEVER_MADE' })];
    assert.equal(held.status, 404, JSON.stringify(held));
    assert.deepEqual(held, missing, `round ${round}`);
    assert.equal(named, 2, 'each one call by name');
  }
});

/** A person's browser session, signed in through GitHub. */
async function browserSession(person: string): Promise<string> {
  const signed = await runtime.signin!.completeSignin({ provider: 'github', subject: `browser-${person}`, emails: [person], name: null }, { requestId: crypto.randomUUID(), sourceIp: null, label: 'Firefox' });
  assert.ok(signed.ok);
  return signed.credential.token;
}

/** A person's CLI session, from a device login they approved. */
async function cliSession(person: string): Promise<string> {
  const started = await runtime.signin!.startDevice({ clientLabel: 'laptop', sourceIp: null });
  await runtime.signin!.decideDevice(await contextFor(deps, person), started.userCode, true);
  const polled = await runtime.signin!.pollDevice(started.deviceCode, { requestId: crypto.randomUUID(), sourceIp: null });
  if (polled.status !== 'approved') throw new Error('the device login was not approved');
  return polled.credential.token;
}

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

test('a grant a writer put back after its revoke stands for nothing: the request asks the vault, and is answered as before, and reported (review r1 of #412)', async () => {
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

test("the proxy's use of a plain value is answered and logged as before; of a key its environment does not hold, as every refusal of a key is (review r1 of #412; D153)", async () => {
  const root = clientFor(deps, ROOT);
  for (const path of ['market/plain', 'market/empty']) await root.environments.create(path);
  await root.secrets.set('market/plain', { API_KEY: { value: 'pk_public_0123', sensitivity: 'plain' } });
  await root.secrets.set('market/empty', { OTHER: 'other' });
  await root.access.set(`user:${DEV}`, { 'market/dev': 'developer', 'market/plain': 'developer', 'market/empty': 'developer' });
  for (const env of ['plain', 'empty']) {
    const handle = (await runtime.signin!.issueHandle({ ...(await contextFor(deps, DEV)), personalToken: null }, { label: 'run', expiresInMinutes: 60, paths: [`market/${env}`] })).token;
    for (const url of [`/use/market/${env}/api/v1/thing`, '/use/api/v1/thing']) {
      const [before, now] = await both((at) => proxied(url, handle, at));
      if (env === 'plain') assert.deepEqual(now, before, `${env}: ${url}`);
      // Its credential's key not held there: no such key, or no access to it, logged as a refusal of it.
      else assert.deepEqual(now, { answer: { status: 404, body: '{"error":"credential_proxy","message":"not available: no such key, or no access to it","reason":"not_available"}' }, entries: ['secret.read deny'] }, `${env}: ${url}`);
      // Its entry names the credential, its host, and the egress it left through (review r2 of #412).
      if (now!.answer.status === 204) assert.ok(now!.entries.some((entry) => entry.startsWith('credential.use') && entry.includes('"egress":true')), `${env}: ${url}: ${JSON.stringify(now)}`);
    }
  }
});

test("a handle whose person lost their grant is refused by the use, as every refusal of a key is, and logged: the handle's check decides nothing of what they may do (review r1 of #412; D153)", async () => {
  const handle = (await runtime.signin!.issueHandle({ ...(await contextFor(deps, LEFT)), personalToken: null }, { label: 'run', expiresInMinutes: 60, paths: ['market/dev'] })).token;
  assert.equal((await proxied('/use/api/v1/thing', handle)).status, 204);
  await clientFor(deps, ROOT).access.set(`user:${LEFT}`, { 'market/dev': null });
  // The environment's URL, the stable URL in one call, and in two (`/use/<credential>/<x>` may name an environment's plan:
  // its handle's check first, `handle`, then the use).
  for (const url of ['/use/market/dev/api/v1/thing', '/use/api/v1/thing', '/use/api/thing']) {
    const [before, now] = await both((at) => proxied(url, handle, at));
    assert.deepEqual(now!.entries, before!.entries, `${url}: logged as before`);
    assert.ok(now!.entries.some((entry) => entry.includes('deny')), `${url}: the refusal logged: ${JSON.stringify(now)}`);
    assert.deepEqual(now!.answer, { status: 404, body: '{"error":"credential_proxy","message":"not available: no such key, or no access to it","reason":"not_available"}' }, url);
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

// T165 (B2): a fork's key and `dev@me`'s are the vault's one call by name too (migration 0050): the vault finds the place
// (the fork; the caller's personal config of dev, or dev while they have none) and resolves the key through what it
// inherits. Answered as before, every refusal of a key one answer, in one call (formal/Probing.tla, Where).
const FORKER = 'forker@acme.example';
let forked = false;
async function fork(): Promise<void> {
  if (forked) return;
  forked = true;
  const root = clientFor(deps, ROOT);
  await root.environments.create('market/feature', { from: 'dev', inherit: true });
  await root.secrets.set('market/feature', { OWN: 'feature-own' });
  await root.access.set(`user:${DEV}`, { 'market/dev': 'developer', 'market/feature': 'developer' });
  await root.members.add(`user:${FORKER}`);
  await root.access.set(`user:${FORKER}`, { 'market/feature': 'developer' });
  await clientFor(deps, DEV).secrets.set('market/dev@me', { MINE: 'mine-value' });
}

test("a fork's key, its own or one it inherits, and `dev@me`'s, by its path or a list of one, are the vault's one call by name, answered as before (T165)", async () => {
  await fork();
  const token = await personalToken(DEV, { 'market/dev': 'developer', 'market/feature': 'developer' });
  const reads = [
    [{ path: 'market/feature/OWN' }, { OWN: 'feature-own' }],
    [{ path: 'market/feature/API_KEY' }, { API_KEY: DEV_KEY }],
    [{ path: 'market/feature', keys: ['API_KEY'] }, { API_KEY: DEV_KEY }],
    [{ path: 'market/dev@me/MINE' }, { MINE: 'mine-value' }],
    [{ path: 'market/dev@me/API_KEY' }, { API_KEY: DEV_KEY }],
    [{ path: 'market/dev@me', keys: ['MINE'] }, { MINE: 'mine-value' }],
  ] as const;
  // Warm: the isolate's map holds the names.
  for (const [body] of reads) await reveal(token, body);
  for (const [body, values] of reads) {
    const [before, now] = await both((at) => reveal(token, body, at));
    assert.equal(now!.answer.status, 200, JSON.stringify([body, now]));
    assert.deepEqual(now!.answer.body.values, values, JSON.stringify(body));
    const { operationId: _now, ...answered } = now!.answer.body;
    const { operationId: _before, ...was } = before!.answer.body;
    assert.deepEqual(answered, was, `${JSON.stringify(body)}: answered as before`);
    calls.length = 0;
    await reveal(token, body);
    assert.deepEqual(calls, ['useNamed'], `${JSON.stringify(body)}: the vault's one call, by name`);
  }
  // Another person's `dev@me`, who has no personal config: dev, read as dev, by name.
  const root = clientFor(deps, ROOT);
  await root.members.add('user:fallback@acme.example');
  await root.access.set('user:fallback@acme.example', { 'market/dev': 'developer' });
  const other = await personalToken('fallback@acme.example');
  calls.length = 0;
  const fallback = await reveal(other, { path: 'market/dev@me/API_KEY' });
  assert.deepEqual([fallback.status, fallback.body.values], [200, { API_KEY: DEV_KEY }]);
  assert.deepEqual(calls, ['useNamed']);
});

test("at a fork, every refusal of a key is one answer in one vault call: one inherited from a parent its caller does not read, one never made; revoked, their own too (T165; D153)", async () => {
  await fork();
  const token = await personalToken(FORKER, { 'market/feature': 'developer' });
  const answer = async (path: string) => {
    calls.length = 0;
    const read = await reveal(token, { path });
    return { status: read.status, body: read.body, calls: [...calls] };
  };
  // Theirs: the fork's own.
  assert.equal((await answer('market/feature/OWN')).status, 200);
  const no = { status: 404, body: { error: 'not_available', message: 'not available: no such key, or no access to it' }, calls: ['useNamed'] };
  // dev's, which they do not read, and a key never made: alike, one call each (before: the app's path, `parent_unreadable`).
  for (const path of ['market/feature/API_KEY', 'market/feature/NEVER_MADE']) assert.deepEqual(await answer(path), no, path);
  const [before] = await both((at) => reveal(token, { path: 'market/feature/API_KEY' }, at));
  assert.equal(before!.answer.status, 404, 'as the app\'s own path answers it');
  await clientFor(deps, ROOT).access.set(`user:${FORKER}`, { 'market/feature': null });
  for (const path of ['market/feature/OWN', 'market/feature/API_KEY', 'market/feature/NEVER_MADE']) assert.deepEqual(await answer(path), no, `revoked: ${path}`);
  await clientFor(deps, ROOT).access.set(`user:${FORKER}`, { 'market/feature': 'developer' });
});

test("the proxy's use of a key a fork inherits, on the fork's URL and at a handle's stable URL, is the vault's one call by name (T165)", async () => {
  await fork();
  const handle = (await runtime.signin!.issueHandle({ ...(await contextFor(deps, DEV)), personalToken: null }, { label: 'run', expiresInMinutes: 60, paths: ['market/feature'] })).token;
  for (const url of ['/use/market/feature/api/v1/thing', '/use/api/v1/thing']) {
    await proxied(url, handle);
    sent.length = 0;
    calls.length = 0;
    const used = await proxied(url, handle);
    assert.equal(used.status, 204, `${url}: ${used.body}`);
    assert.deepEqual(sent, [DEV_KEY], `${url}: dev's key, inherited`);
    assert.deepEqual(calls, ['useNamed'], `${url}: one call`);
  }
});
