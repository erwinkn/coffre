// The Proxy tab's API (0.16, T186; docs/design/proxy-ui.md, sections 6 and 8): an environment's proxy definitions read
// by whoever lists it, and saved by a person holding proxy.edit there, which Owners hold as roles ship and a role an
// Owner gives it to. Each item's keys are cleared for its editor at save, where a use will find them: an inherited key
// takes reading the parent, a reference's sensitive source owning its project, a sensitive key owning the place's. No
// token or handle saves; the deployment's code says whether the tab writes, and wins every name it defines. And the
// version gate at the API: a vault on another release answers a signed-in request 503 `deploying`, with Retry-After: 1.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import { createClient, type CoffreClient } from '@coffre/client';
import { defineSignin, github, signin } from '@coffre/core/identity';
import { RELEASE, versioned, type ProxyDefinition, type VaultEntry } from '@coffre/core/vault';
import { and, asc, eq } from 'drizzle-orm';

import { keeps015 } from '../src/api/changes.ts';
import { SigninService } from '../src/api/signin.ts';
import { resolveConfig } from '../src/config.ts';
import { fetchApi } from '../src/fetch-api.ts';
import { createRuntime, type CoffreRuntime } from '../src/runtime.ts';
import { LOG } from './api-fixture.ts';
import { auditLog } from './db/tables.ts';
import { clientFor, openTestDatabase, resetDatabase, testDeps, waitUntil, type FixtureDeps } from './api-fixture.ts';

const ORIGIN = 'https://secrets.acme.example';
const ROOT = 'admin@acme.example';
const ADA = 'user:ada@acme.example';
const LIN = 'user:lin@acme.example';
const PAT = 'user:pat@acme.example';
const VIC = 'user:vic@acme.example';
const CI = 'token:ci';
const SIGNIN = defineSignin({ publicUrl: ORIGIN, providers: [github({ clientId: 'a', clientSecret: 'b' })] });
const ON_015 = { skip: LOG === '0.14' ? "proxy definitions are 0.15's log's objects" : false };

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;
let runtime: CoffreRuntime;
let root: CoffreClient;
/** A Developer of market: no proxy.edit. */
let ada: CoffreClient;
/** A Router of market/dev-eu alone (read, use, proxy.edit), a role an Owner made. */
let lin: CoffreClient;
/** An Owner of market alone. */
let pat: CoffreClient;
/** A Viewer of market. */
let vic: CoffreClient;

before(async () => {
  db = await openTestDatabase();
});
after(() => db.close());

/** A route, `name`, sending `keys` (the first in its authorization header, any others in headers of their own). */
function route(name: string, keys: readonly string[] = ['OPENAI_API_KEY'], host = 'api.openai.com'): ProxyDefinition {
  return {
    kind: 'route', name, upstream: `https://${host}/v1`,
    inject: keys.map((key, i) => ({ kind: 'header' as const, name: i === 0 ? 'authorization' : `x-key-${i}`, template: i === 0 ? `Bearer {${key}}` : `{${key}}` })),
    allow: [], limit: { perMinute: null, perDay: null }, placeholder: null, egress: null,
  };
}

/** Code's `stripe`, as the Proxy tab shows it locked. */
const STRIPE = { definition: { ...route('stripe', ['STRIPE_SECRET_KEY'], 'api.stripe.com'), allow: null }, environments: ['market/prod'], limitPerService: false, bound: false };

beforeEach(async () => {
  await resetDatabase(db.owner);
  deps = testDeps(db.runtime, [ROOT]);
  deps.proxy = { editable: true, insecureUpstreams: false, names: ['stripe'], items: [STRIPE], cacheSeconds: 60 };
  const signin = new SigninService({ db: deps.db, chainKey: deps.chainKey, vault: deps.vault, signin: SIGNIN });
  deps.signin = signin;
  runtime = {
    db: deps.db, vault: deps.vault, chainKey: deps.chainKey, previousChainKeys: [], signin, workloads: null, mcp: null,
    auth: { mode: 'signin', signin: SIGNIN }, publicUrl: ORIGIN, verifier: signin, waitUntil,
    schema: { migrated: true }, appKey: { settled: true }, rotateAfterDays: 365, plugins: [],
  } as CoffreRuntime;
  root = clientFor(deps, ROOT);
  ada = clientFor(deps, 'ada@acme.example');
  lin = clientFor(deps, 'lin@acme.example');
  pat = clientFor(deps, 'pat@acme.example');
  vic = clientFor(deps, 'vic@acme.example');
  if (LOG === '0.14') return;
  await root.projects.create('market');
  await root.projects.create('billing');
  for (const path of ['market/dev', 'billing/prod']) await root.environments.create(path);
  await root.environments.create('market/dev-eu', { from: 'dev', inherit: true });
  await root.secrets.set('billing/prod', { BILLING_KEY: 'billing-secret', BILLING_SENSITIVE: { value: 'billing-sensitive', sensitivity: 'sensitive' } });
  await root.secrets.set('market/dev', { OPENAI_API_KEY: 'sk-dev', STRIPE_SECRET_KEY: { value: 'sk_live_x', sensitivity: 'sensitive' }, BILLING_REF: { ref: 'billing/prod/BILLING_KEY' }, SENSITIVE_REF: { ref: 'billing/prod/BILLING_SENSITIVE' } });
  await root.secrets.set('market/dev-eu', { EU_KEY: 'eu-key' });
  await root.roles.set('router', { name: 'Router', description: 'routes keys', permissions: ['secret.read', 'secret.use', 'proxy.edit'], protected: ['secret.use'] });
  for (const [member, access] of [[ADA, { market: 'developer' }], [LIN, { 'market/dev-eu': 'router' }], [PAT, { market: 'owner' }], [VIC, { market: 'viewer' }], [CI, { market: 'viewer' }]] as const) {
    await root.members.add(member);
    await root.access.set(member, access);
  }
});

/** The status and reason a call is refused with, or 200. */
async function refusal(call: Promise<unknown>): Promise<{ status: number; reason?: string; message?: string }> {
  try {
    await call;
    return { status: 200 };
  } catch (error) {
    const { status, reason, message } = error as { status: number; reason?: string; message: string };
    return { status, ...(reason === undefined ? {} : { reason }), message };
  }
}

async function denials(action: string): Promise<string[]> {
  const rows = await db.owner.select({ metadata: auditLog.metadata, code: auditLog.code }).from(auditLog)
    .where(and(eq(auditLog.action, action), eq(auditLog.decision, 'deny'))).orderBy(asc(auditLog.seq));
  return rows.map((row) => row.code ?? (JSON.parse(row.metadata) as { reason?: string }).reason ?? '?');
}

/** The API as a request with this bearer token sees it, through the app's front door. */
function bearer(token: string, over: CoffreRuntime = runtime): CoffreClient {
  return createClient({ url: ORIGIN, headers: () => ({ authorization: `Bearer ${token}` }), transport: (request) => fetchApi(request, over, { sourceIp: null }) });
}

test('whoever lists an environment reads its definitions, which no holdings cross; an Owner saves, a Viewer and a Developer cannot', ON_015, async () => {
  const empty = await vic.proxy.get('market/dev');
  assert.deepEqual([empty.items, empty.seal, empty.state, empty.editable, empty.code], [[], null, 'ok', false, [STRIPE]]);
  // What the page says of its reader: why they may not save, and that they route no sensitive key and release no name.
  assert.deepEqual([empty.readOnly, empty.routesSensitive, empty.releases], [{ reason: 'missing_proxy_edit', message: 'editing proxy definitions takes proxy.edit here: Owners hold it' }, false, false]);
  const owner = await root.proxy.get('market/dev');
  assert.deepEqual([owner.editable, owner.readOnly, owner.routesSensitive, owner.releases], [true, null, true, true]);
  assert.deepEqual([(await pat.proxy.get('market/dev')).routesSensitive, (await pat.proxy.get('market/dev')).releases], [true, false]);
  const saved = await root.proxy.save('market/dev', { seal: null, items: { openai: route('openai') } });
  assert.deepEqual(saved.items.map((item) => [item.definition.name, item.keys, item.savedBy, item.routesSensitive]), [['openai', ['OPENAI_API_KEY'], `user:${ROOT}`, true]]);
  const read = await vic.proxy.get('market/dev');
  // As saved, and each item cleared: the read alone says whether it routes now.
  assert.deepEqual(read.items, saved.items.map((item) => ({ ...item, notCleared: null })));
  assert.equal(JSON.stringify(read).includes('holdings'), false);
  assert.deepEqual(await refusal(vic.proxy.save('market/dev', { seal: saved.seal, items: { maps: route('maps', ['MAPS_KEY']) } })), { status: 403, reason: 'missing_proxy_edit', message: 'editing proxy definitions takes proxy.edit here: Owners hold it' });
  assert.equal((await refusal(ada.proxy.save('market/dev', { seal: saved.seal, items: { maps: route('maps', ['MAPS_KEY']) } }))).status, 403);
  assert.deepEqual(await denials('proxy.save'), ['missing_proxy_edit', 'missing_proxy_edit']);
  // A page behind another save: 409, nothing changed.
  assert.deepEqual(await refusal(root.proxy.save('market/dev', { seal: null, items: { maps: route('maps', ['MAPS_KEY']) } })),
    { status: 409, reason: 'proxy_changed', message: "this environment's proxy definitions changed since they were loaded: review the change, then save again" });
  assert.deepEqual((await root.proxy.get('market/dev')).items.map((item) => item.definition.name), ['openai']);
});

test("a role an Owner gives proxy.edit routes what its holder reads, where the use finds it: an inherited key takes reading the parent", ON_015, async () => {
  // Lin holds the role on market/dev-eu alone: its own key, and one not made yet, she routes.
  const own = await lin.proxy.save('market/dev-eu', { seal: null, items: { eu: route('eu', ['EU_KEY']), later: route('later', ['NOT_MADE_YET']) } });
  assert.deepEqual(own.items.map((item) => [item.definition.name, item.savedBy, item.routesSensitive]), [['eu', LIN, false], ['later', LIN, false]]);
  // OPENAI_API_KEY, which dev-eu inherits from dev, where she reads nothing (R8).
  const inherited = await refusal(lin.proxy.save('market/dev-eu', { seal: own.seal, items: { openai: route('openai') } }));
  assert.equal(inherited.status, 403);
  assert.equal(inherited.reason, 'route_not_cleared');
  assert.match(inherited.message!, /OPENAI_API_KEY: its editor does not read it in dev/);
  // Given read of dev, she routes it from dev-eu.
  await root.access.set(LIN, { 'market/dev-eu': 'router', 'market/dev': 'viewer' });
  const routed = await lin.proxy.save('market/dev-eu', { seal: own.seal, items: { openai: route('openai') } });
  assert.deepEqual(routed.items.map((item) => item.definition.name), ['eu', 'later', 'openai']);
  // A sensitive key routes only by an Owner covering its place (R66): never by her; by an Owner of market, audited.
  await root.access.set(LIN, { 'market/dev': 'router' });
  const sensitive = await refusal(lin.proxy.save('market/dev', { seal: null, items: { stripe2: route('stripe2', ['STRIPE_SECRET_KEY']) } }));
  assert.equal(sensitive.reason, 'route_not_cleared');
  assert.match(sensitive.message!, /STRIPE_SECRET_KEY is sensitive: an Owner of its project may route sensitive keys/);
  const owner = await pat.proxy.save('market/dev', { seal: null, items: { stripe2: route('stripe2', ['STRIPE_SECRET_KEY']) } });
  assert.deepEqual(owner.items.map((item) => [item.savedBy, item.routesSensitive]), [[PAT, true]]);
  const [entry] = await db.owner.select({ metadata: auditLog.metadata }).from(auditLog).where(and(eq(auditLog.action, 'proxy.save'), eq(auditLog.actor, PAT)));
  assert.deepEqual((JSON.parse(entry!.metadata) as { proxy: { saved: { routesSensitive: string[] }[] } }).proxy.saved[0]!.routesSensitive, ['STRIPE_SECRET_KEY']);
});

test("the tab marks an item that would not route now, until someone who reads its keys saves it again (decision 5)", ON_015, async () => {
  await root.access.set(LIN, { 'market/dev': 'router' });
  const saved = await lin.proxy.save('market/dev', { seal: null, items: { openai: route('openai'), maps: route('maps', ['MAPS_KEY']) } });
  // A save's answer leaves the mark out: the tab reads it.
  assert.deepEqual(saved.items.map((item) => item.notCleared), [undefined, undefined]);
  const marks = async () => (await vic.proxy.get('market/dev')).items.map((item) => [item.definition.name, item.notCleared?.key ?? null]);
  assert.deepEqual(await marks(), [['maps', null], ['openai', null]]);
  // Lin loses her role on dev: what she saved there no longer routes the keys she no longer reads. MAPS_KEY, which dev
  // lacks, is decided at use.
  await root.access.set(LIN, { 'market/dev': null });
  assert.deepEqual(await marks(), [['maps', null], ['openai', 'OPENAI_API_KEY']]);
  assert.match((await vic.proxy.get('market/dev')).items[1]!.notCleared!.reason, /OPENAI_API_KEY: its editor does not read it in dev/);
  // Her offboarding preview names what she saved, each stopped once she no longer reads its keys.
  assert.deepEqual((await root.members.get(LIN)).proxy, [
    { project: 'market', environment: 'dev', name: 'maps', kind: 'route', keys: ['MAPS_KEY'] },
    { project: 'market', environment: 'dev', name: 'openai', kind: 'route', keys: ['OPENAI_API_KEY'] },
  ]);
  // An Owner saves it again, as it is, under their own standing: cleared.
  const page = await pat.proxy.get('market/dev');
  await pat.proxy.save('market/dev', { seal: page.seal, items: { openai: route('openai') } });
  assert.deepEqual(await marks(), [['maps', null], ['openai', null]]);
  assert.deepEqual((await root.members.get(LIN)).proxy.map((item) => item.name), ['maps']);
  // The key made sensitive since a Router's save: what that save froze does not route it, even given back her role.
  await root.access.set(LIN, { 'market/dev': 'router' });
  const again = await lin.proxy.save('market/dev', { seal: (await lin.proxy.get('market/dev')).seal, items: { openai: route('openai') } });
  assert.equal(again.items.find((item) => item.definition.name === 'openai')!.savedBy, LIN);
  await root.secrets.set('market/dev', { OPENAI_API_KEY: { value: 'sk-dev-2', sensitivity: 'sensitive' } });
  const mark = (await vic.proxy.get('market/dev')).items.find((item) => item.definition.name === 'openai')!.notCleared;
  assert.equal(mark?.key, 'OPENAI_API_KEY');
});

test("a fork's inherited item is marked where the fork resolves its keys: its own value over its parent's", ON_015, async () => {
  await root.access.set(LIN, { 'market/dev': 'router', 'market/dev-eu': null });
  await lin.proxy.save('market/dev', { seal: null, items: { openai: route('openai') } });
  const inherited = async () => (await vic.proxy.get('market/dev-eu')).inheritedNotCleared;
  // dev-eu inherits dev's OPENAI_API_KEY, which Lin reads: cleared in both.
  assert.deepEqual(await inherited(), {});
  // dev-eu sets its own, which Lin does not read: dev's item, inherited, would not route there, though it does in dev.
  await root.secrets.set('market/dev-eu', { OPENAI_API_KEY: 'sk-eu' });
  assert.equal((await vic.proxy.get('market/dev')).items[0]!.notCleared, null);
  assert.equal((await inherited())?.openai?.key, 'OPENAI_API_KEY');
  assert.match((await inherited())!.openai!.reason, /its editor does not read it in dev-eu/);
});

test("a reference is decided where it lives, its source's sensitive value only by an Owner of the source's project", ON_015, async () => {
  await root.access.set(LIN, { 'market/dev': 'router' });
  // BILLING_REF reads billing/prod's secret: her read of market/dev covers it (R20).
  const seal = (await lin.proxy.save('market/dev', { seal: null, items: { billing: route('billing', ['BILLING_REF']) } })).seal;
  // SENSITIVE_REF reads billing's sensitive value: an Owner of market alone may not route it; an Owner of the instance may.
  assert.equal((await refusal(pat.proxy.save('market/dev', { seal, items: { leak: route('leak', ['SENSITIVE_REF']) } }))).reason, 'route_not_cleared');
  const instance = await root.proxy.save('market/dev', { seal, items: { leak: route('leak', ['SENSITIVE_REF']) } });
  assert.deepEqual(instance.items.map((item) => item.definition.name), ['billing', 'leak']);
  // What the tab checks first: the Secrets list says, of each reference, whether you own its source's project.
  const ownsSource = async (client: CoffreClient) => (await client.secrets.list('market/dev')).keys.find((one) => one.key === 'SENSITIVE_REF')!.reference!.ownsSource;
  assert.deepEqual([await ownsSource(pat), await ownsSource(root)], [false, true]);
});

test('who may save at all: the tab writes only where the deployment says, a person on a session of theirs, never a name code defines', ON_015, async () => {
  // A name code defines wins in every environment: no UI item takes it.
  assert.deepEqual(await refusal(root.proxy.save('market/dev', { seal: null, items: { stripe: route('stripe') } })),
    { status: 409, reason: 'reserved', message: "stripe is defined in this deployment's code, which wins the name in every environment" });
  // An egress, a binding of the deployment's code, which declares none.
  assert.equal((await refusal(root.proxy.save('market/dev', { seal: null, items: { sch: { ...route('sch'), egress: 'schuman-prod' } as ProxyDefinition } }))).status, 400);
  // A definition the vault refuses, in its words.
  assert.deepEqual(await refusal(root.proxy.save('market/dev', { seal: null, items: { meta: { ...route('meta'), upstream: 'https://169.254.169.254/latest' } as ProxyDefinition } })),
    { status: 400, reason: 'invalid', message: 'meta: upstream is a private, loopback or link-local address, or localhost, which no UI definition reaches' });
  // A service account, which holds no session of a person's: refused, its entry naming why.
  const ci = clientFor(deps, 'ci', 'service');
  assert.equal((await refusal(ci.proxy.save('market/dev', { seal: null, items: { openai: route('openai') } }))).status, 403);
  // Under `editable: false`, the default: the deployment's code keeps them.
  deps.proxy = { editable: false, insecureUpstreams: false, names: [], items: [], cacheSeconds: 60 };
  assert.equal((await root.proxy.get('market/dev')).editable, false);
  assert.deepEqual(await refusal(root.proxy.save('market/dev', { seal: null, items: { openai: route('openai') } })),
    { status: 409, reason: 'not_editable', message: "this deployment's code keeps its proxy definitions: credentialProxy({ editable: true }) lets the UI write them" });
  // No credential proxy at all: the same.
  deps.proxy = null;
  assert.equal((await refusal(root.proxy.save('market/dev', { seal: null, items: { openai: route('openai') } }))).status, 409);
  // The vault's refusal of the private upstream is the vault's entry; the app's, its own.
  assert.deepEqual(await denials('proxy.save'), ['reserved', 'invalid', 'not_a_person', 'not_editable', 'not_editable']);
  // A personal token, at the front door: refused there, before any handler.
  const token = await root.tokens.issue(`user:${ROOT}`, { label: 'agent', expiresInMinutes: 60, scope: { market: 'maintainer' } });
  deps.proxy = { editable: true, insecureUpstreams: false, names: [], items: [], cacheSeconds: 60 };
  assert.equal((await refusal(bearer(token.token).proxy.save('market/dev', { seal: null, items: { openai: route('openai') } }))).status, 403);
  assert.deepEqual((await bearer(token.token).proxy.get('market/dev')).items, []);
});

test('a name code reserved is freed by an Owner of the whole instance, never one this code still defines', ON_015, async () => {
  const seal = (await root.proxy.save('market/dev', { seal: null, items: { maps: route('maps', ['MAPS_KEY']) } })).seal;
  const reserved = await deps.vault.reserveProxy({ names: ['maps', 'stripe'] });
  assert.ok(reserved.ok && reserved.cleared.length === 1);
  const view = await root.proxy.get('market/dev');
  assert.deepEqual([view.items, view.reserved], [[], ['maps', 'stripe']]);
  assert.deepEqual(await refusal(root.proxy.save('market/dev', { seal: view.seal, items: { maps: route('maps', ['MAPS_KEY']) } })),
    { status: 409, reason: 'reserved', message: "maps is reserved by the deployment's code: an instance Owner may release it" });
  assert.notEqual(view.seal, seal);
  assert.equal((await refusal(pat.proxy.release('maps'))).status, 403);
  assert.equal((await refusal(root.proxy.release('stripe'))).status, 409);
  assert.deepEqual(await root.proxy.release('maps'), { reserved: ['stripe'] });
  assert.equal((await refusal(root.proxy.release('maps'))).status, 400);
  assert.deepEqual((await root.proxy.save('market/dev', { seal: view.seal, items: { maps: route('maps', ['MAPS_KEY']) } })).items.map((item) => item.definition.name), ['maps']);
  assert.deepEqual(await denials('proxy.release'), ['requires_instance_owner', 'defined_in_code', 'invalid']);
});

test("a vault on another release: a signed-in request answers 503 deploying, Retry-After 1, and nobody is signed out; matched again, it is served", ON_015, async () => {
  const token = await root.tokens.issue(`user:${ROOT}`, { label: 'agent', expiresInMinutes: 60, scope: { market: 'viewer' } });
  let theirs = RELEASE;
  const calls: string[] = [];
  const entry: VaultEntry = {
    call: async (release, method, args) => {
      calls.push(method);
      return theirs === RELEASE ? deps.vault.call(release, method, args) : { release: theirs };
    },
  };
  const over = { ...runtime, vault: versioned(entry) } as CoffreRuntime;
  assert.deepEqual((await bearer(token.token, over).proxy.get('market/dev')).items, []);
  theirs = '9.9.9';
  const response = await fetchApi(new Request(`${ORIGIN}/api/projects/market/dev/proxy`, { headers: { authorization: `Bearer ${token.token}` } }), over, { sourceIp: null });
  assert.equal(response.status, 503);
  assert.equal(response.headers.get('retry-after'), '1');
  assert.deepEqual(await response.json(), { error: 'deploying', message: 'coffre is deploying a new release: try again in a second' });
  theirs = RELEASE;
  assert.deepEqual((await bearer(token.token, over).proxy.get('market/dev')).items, [], 'the same credential, served again: never signed out');
  assert.ok(calls.length > 0);
});

test('two runtimes over one vault binding, as a Worker makes one per request, ask the vault about() once: one versioned vault per entry', async () => {
  const asked: string[] = [];
  const entry: VaultEntry = { call: async (release, method, args) => (asked.push(method), deps.vault.call(release, method, args)) };
  const config = resolveConfig({ publicUrl: ORIGIN, vault: entry, auth: signin({ providers: [github({ clientId: 'a', clientSecret: 'b' })] }), auditChainKey: deps.chainKey.toString('base64') });
  const transport = { json: async () => ({}) };
  const first = createRuntime(config, deps.db, versioned(entry), transport);
  const second = createRuntime(config, deps.db, versioned(entry), transport);
  assert.equal(first.vault, second.vault);
  await keeps015(first.vault);
  await keeps015(second.vault);
  assert.deepEqual(asked.filter((method) => method === 'about'), ['about']);
});
