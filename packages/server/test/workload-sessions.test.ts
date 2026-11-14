// What a workload's session reaches, as 0.14.7 held it
// (test/workload-sessions.test.ts at v0.14.7): every route of the API
// answers it as it answers its service's own token, and so none that only a
// person reaches; a plugin's `use` takes only the caller coffre made for
// this request; and a proof signs the request on coffre's public URL,
// whatever host the platform handed it over on. How a session's request is
// held to its proof and gate is test/workload-requests.test.ts's; what the
// vault decides of a session, packages/vault/test/caller.test.ts's.
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { after, beforeEach, test } from 'node:test';

import { createProof, generateProofKey, thumbprint, type ProofKey } from '@coffre/client/dpop';
import { generateToken, github, signin } from '@coffre/core/identity';
import { rowsOf } from '@coffre/db/dialect';
import { amend, binding, credential, emptyDatabase, environment, grant, instance, principal, project, role, rows, secret, session, value, write } from '@coffre/vault/testing';
import { sql } from 'drizzle-orm';

// The router before its table: the table's modules import it back (mcp/tools.ts), so the table loads through it.
import '../src/api/router.ts';
import { routes } from '../src/api/routes.ts';
import { unservedRoutes } from '../src/api/routes/unserved.ts';
import { processGates } from '../src/gate.ts';
import type { CoffrePlugin, PluginContext, WorkloadUse } from '../src/plugins.ts';
import { signedUrl } from '../src/sessions.ts';
import { processLimits } from '../src/workloads/limits.ts';
import { openApp, PUBLIC_URL } from './app-fixture.ts';

const DEPLOY = 'token:deploy';

/** What the probe's requests were given: the caller `workload` made for each, and the context it was made in. */
const seen: { caller: WorkloadUse | null; context: PluginContext }[] = [];
/** A plugin that only asks who its request's workload is, and keeps what it was given. */
const probe: CoffrePlugin = {
  name: 'probe',
  routes: {
    prefix: '/probe',
    async fetch(request, coffre) {
      const caller = await coffre.workload(request, { place: 'market/prod' });
      seen.push({ caller, context: coffre });
      return new Response(JSON.stringify({ caller: caller?.principal ?? null }), { headers: { 'content-type': 'application/json' } });
    },
  },
};

let gates = processGates();
const auth = signin({ providers: [github({ clientId: 'gh-id', clientSecret: 'gh-secret' })], workloads: { limits: processLimits({ perSource: 100_000, total: 100_000 }) }, mcp: { limits: processLimits({ perSource: 100_000, perConnection: 100_000, total: 100_000 }) } });
const app = await openApp({ auth, workloads: {}, gates: (service) => gates(service), plugins: [probe] });
const { world } = app;
after(() => app.close());

const market = project('market');
const prod = environment(market, 'prod');
const VIEWER = JSON.stringify([{ projectId: market.id, environmentId: null, role: 'viewer' }]);
const STRIPE = 'STRIPE_SECRET_KEY';

/** `deploy` views market: a session of its workload's binding, and a token of its own, each reaching market as a Viewer. */
let token: string;
let key: ProofKey;
let keyed: ReturnType<typeof binding>;
const SERVICE_TOKEN = 'deploy-token';

beforeEach(async () => {
  await emptyDatabase(world.owner);
  for (const kept of [world.memory.reads, world.memory.callers, world.memory.logged, world.memory.touched, world.refused]) kept.clear();
  gates = processGates();
  seen.length = 0;
  key = await generateProofKey();
  token = generateToken('workload');
  keyed = binding(DEPLOY, { policy: '{}', scope: VIEWER });
  await write(
    world,
    ...rows('policy', instance()),
    ...rows('roles', role(true, 'owner', ['secret.read']), role(true, 'member', []), role(false, 'viewer', ['secret.read', 'secret.use'], [])),
    ...rows('projects', market),
    ...rows('environments', prod),
    ...rows('secrets', value(world, secret(prod, STRIPE), 'sk_live_1')),
    ...rows('principals', principal(DEPLOY)),
    ...rows('grants', grant(DEPLOY, 'viewer', { project: market })),
    ...rows('bindings', keyed),
    ...rows('credentials',
      session(token, keyed, { jkt: await thumbprint(key.jwk), scope: VIEWER, places: JSON.stringify([{ environmentId: prod.id }]), expiresAt: new Date(Date.now() + 3_600_000) }),
      credential(SERVICE_TOKEN, DEPLOY, { scope: VIEWER })),
  );
  await app.request('/livez');
  await app.request('/api/me', { headers: { authorization: 'Bearer nobody' } });
  app.calls.length = 0;
});

type Answer = { status: number; body: { error?: string; reason?: string; message?: string; caller?: string | null; principal?: { id: string } } };
const read = async (response: Response): Promise<Answer> => {
  const text = await response.text();
  return { status: response.status, body: text === '' ? {} : (JSON.parse(text) as Answer['body']) };
};

/** `method url` as the session: its token as DPoP, with a proof of its key for `signed` (the URL itself unless told), under the gate's current nonce. */
async function asSession(method: string, url: string, options: { body?: string; signed?: string } = {}): Promise<Answer> {
  const proof = await createProof(key, { method, url: options.signed ?? url, token, nonce: await gates(DEPLOY).nonce() });
  const path = url.startsWith(PUBLIC_URL) ? url.slice(PUBLIC_URL.length) : url;
  return read(await app.request(path, { method, headers: { authorization: `DPoP ${token}`, dpop: proof, ...(options.body === undefined ? {} : { 'content-type': 'application/json' }) }, ...(options.body === undefined ? {} : { body: options.body }) }));
}

/** `method path` on the service's own token, as a bearer. */
async function asToken(method: string, path: string, body?: string): Promise<Answer> {
  return read(await app.request(path, { method, headers: { authorization: `Bearer ${SERVICE_TOKEN}`, ...(body === undefined ? {} : { 'content-type': 'application/json' }) }, ...(body === undefined ? {} : { body }) }));
}

/** Each route's parameters, named as the sweep fills them: places deploy reads, deploy itself, and IDs nothing has. */
const NOTHING = randomUUID();
const PARAMS: Record<string, string> = {
  project: 'market', environment: 'prod', key: STRIPE, folder: 'shared', member: DEPLOY, id: NOTHING, code: 'BCDF-GHJK',
  role: 'viewer', target: encodeURIComponent(`service:${DEPLOY.slice('token:'.length)}`), enrollment: NOTHING,
};
/**
 * The routes only a person reaches, signed in as themselves: their sessions and accounts, their apps' authorizations,
 * device logins, and what they issue. Those that end one by its ID are swept too, but an ID nothing has is not found
 * whoever asks.
 */
const PERSON_ONLY = [
  'GET /sessions', 'GET /identities', 'GET /device-logins/:code', 'POST /device-logins/:code',
  'GET /oauth/authorizations', 'POST /oauth/authorizations', 'POST /handles', 'POST /members/:member/tokens',
];

/** A body that gets past a route's own validation, for those only a person reaches and those 0.14.7 held a session from, as issuing or changing access: else `{}`. */
const ROLE = { name: 'Viewer', description: '', permissions: ['secret.read', 'secret.use'], protected: [] };
const BODIES: Record<string, unknown> = {
  'PATCH /access/:member': { 'market/prod': 'viewer' },
  'PUT /roles/:role': ROLE,
  'PUT /instance-roles/:role': ROLE,
  'PUT /settings': { serviceAccounts: {} },
  'PATCH /projects/:project/:environment': { protected: true },
  'POST /device-logins/:code': { approve: true },
  'POST /oauth/authorizations': { request: {}, approve: true },
  'POST /handles': { label: 'run', paths: ['market/prod'] },
  'POST /members/:member/tokens': { label: 'more', expiresInDays: 1 },
};

/** What no request of a workload's may grow: its service's credentials, bindings and grants. */
const holdings = async () => (await rowsOf<{ credentials: number; bindings: number; grants: number }>(world.owner, sql`
  SELECT (SELECT count(*)::int FROM credentials) AS credentials, (SELECT count(*)::int FROM bindings) AS bindings, (SELECT count(*)::int FROM grants) AS grants
`))[0]!;

test("a session reaches every route of the API as its service's own token does, and none only a person reaches; it issues nothing and changes no one's access", async () => {
  const before = await holdings();
  const served = Object.entries(routes).filter(([name, def]) => def !== unservedRoutes[name as keyof typeof unservedRoutes]).map(([name]) => name);
  assert.ok(served.length > 50, `${served.length} routes`);
  const answers = new Map<string, Answer>();
  const differ: string[] = [];
  for (const name of served) {
    const [method, pattern] = name.split(' ') as [string, string];
    const path = `/api${pattern.replace(/:([a-z]+)/g, (_, param: string) => PARAMS[param] ?? assert.fail(`no value for :${param} in ${name}`))}`;
    const body = method === 'GET' || method === 'DELETE' ? undefined : JSON.stringify(BODIES[name] ?? {});
    const [held, issued] = [await asSession(method, `${PUBLIC_URL}${path}`, body === undefined ? {} : { body }), await asToken(method, path, body)];
    answers.set(name, held);
    const shown = (answer: Answer) => `${answer.status} ${answer.body.error ?? ''} ${answer.body.reason ?? ''}`;
    if (shown(held) !== shown(issued)) differ.push(`${name}: session ${shown(held)}, token ${shown(issued)}`);
  }
  // Where a session would issue a credential or change someone's access, the vault refuses it for being a workload's,
  // before it weighs what its service holds: 403 workload_cannot_issue, where the token, a Viewer's, is refused 403 for
  // what it holds. 0.14.7 answered a session 403 workload_cannot_issue on every route that issues or changes access
  // (`ISSUING_ROUTES`, api/workload-routes.ts), before the route ran: so these are its word, kept. Where the vault
  // weighs the place first, or refuses any credential with a scope, which every session has, or the route's own
  // validation comes first, a session is answered as the token is: removing a binding and protecting an environment
  // are 403 no_access (0.14.7: workload_cannot_issue), as a scoped credential manages no service
  // (vault/src/ops/services.ts) and a Viewer protects nothing.
  const cannot = ([name, refused]: [string, string]) => `${name}: session 403 forbidden workload_cannot_issue, token 403 ${refused}`;
  assert.deepEqual(differ, ([
    ['PUT /members/:member', 'vault_refused no_access'],
    ['DELETE /members/:member', 'vault_refused no_access'],
    ['PATCH /access/:member', 'vault_refused no_access'],
    ['PUT /roles/:role', 'vault_refused no_access'],
    ['DELETE /roles/:role', 'vault_refused no_access'],
    ['PUT /settings', 'vault_refused no_access'],
    ['DELETE /freezes/:target', 'vault_refused no_access'],
    ['POST /members/:member/tokens', 'vault_refused no_access'],
    ['POST /handles', 'forbidden not_a_person'],
  ] as [string, string][]).map(cannot));
  // What a service reads, the session reads.
  for (const name of ['GET /me', 'GET /projects', 'GET /secrets/:project/:environment']) assert.equal(answers.get(name)!.status, 200, name);
  // A caller's own connected apps, which only a person makes: a service's list is empty (0.14.7 refused a session 403 `workload`).
  assert.deepEqual([answers.get('GET /apps')!.status, (answers.get('GET /apps')!.body as { apps?: unknown[] }).apps], [200, []]);
  // None a person alone reaches: each refused, before or by the vault.
  for (const name of PERSON_ONLY) {
    const answer = answers.get(name)!;
    assert.ok([401, 403].includes(answer.status), `${name}: ${answer.status} ${JSON.stringify(answer.body)}`);
  }
  assert.deepEqual(await holdings(), before);
  // Its own binding, the one ID whose row the caller's own read also found while token.unbind's part shared its name:
  // refused as its token is, and the binding stands.
  const own = `/api/members/${DEPLOY}/bindings/${keyed.id}`;
  for (const answer of [await asSession('DELETE', `${PUBLIC_URL}${own}`), await asToken('DELETE', own)]) assert.deepEqual([answer.status, answer.body.reason], [403, 'no_access']);
  const [standing] = await rowsOf<{ revoked: boolean }>(world.owner, sql`SELECT revoked_at IS NOT NULL AS revoked FROM bindings WHERE id = ${keyed.id}`);
  assert.equal(standing!.revoked, false);
  assert.equal((await asSession('GET', `${PUBLIC_URL}/api/me`)).status, 200);
});

test("`use` takes back only the caller coffre made for its own request: not a lookalike, nor one another request's context made", async () => {
  const use = (context: PluginContext, caller: WorkloadUse) => context.use(caller, { path: 'market/prod', keys: [STRIPE], purpose: 'use', upstream: { credential: 'probe' } });
  // A request that carries no session is no workload's.
  assert.deepEqual((await read(await app.request('/probe', { method: 'POST' }))).body, { caller: null });
  const first = await asSession('POST', `${PUBLIC_URL}/probe`);
  assert.deepEqual([first.status, first.body.caller], [200, DEPLOY]);
  const earlier = seen.at(-1)! as { caller: WorkloadUse; context: PluginContext };
  assert.equal((await use(earlier.context, earlier.caller)).values[STRIPE], 'sk_live_1');
  // A copy of it, field for field, is no caller coffre authenticated: refused before the vault is asked.
  const calls = app.calls.length;
  await assert.rejects(use(earlier.context, { ...earlier.caller }), { status: 401 });
  assert.equal(app.calls.length, calls, 'no vault call');
  // A later request's context takes its own caller, and not the earlier one.
  assert.equal((await asSession('POST', `${PUBLIC_URL}/probe`)).status, 200);
  const later = seen.at(-1)! as { caller: WorkloadUse; context: PluginContext };
  assert.equal((await use(later.context, later.caller)).values[STRIPE], 'sk_live_1');
  await assert.rejects(use(later.context, earlier.caller), { status: 401 });
  await assert.rejects(use(earlier.context, later.caller), { status: 401 });
  assert.equal(app.calls.length, calls + 1, 'one vault call: the later caller\'s own use');
});

test("a proof signs the request on coffre's public URL, its path and query as received, whatever host it came in on; one naming that host is refused", async () => {
  const inside = 'http://10.0.0.7:8080/api/me?full=1';
  const signed = `${PUBLIC_URL}/api/me?full=1`;
  assert.equal(signedUrl(new Request(inside), PUBLIC_URL), signed);
  // A path that starts like a host stays a path.
  assert.equal(signedUrl(new Request('http://10.0.0.7:8080//evil.example/api/me'), PUBLIC_URL), `${PUBLIC_URL}//evil.example/api/me`);
  const taken = await asSession('GET', inside, { signed });
  assert.deepEqual([taken.status, taken.body.principal?.id], [200, 'deploy']);
  // The same request, its proof made for the host it came in on: no proof of a request to coffre, and the vault is not asked.
  const calls = app.calls.length;
  const refused = await asSession('GET', inside);
  assert.deepEqual([refused.status, refused.body.error], [401, 'unauthenticated'], JSON.stringify(refused.body));
  assert.equal(app.calls.length, calls);
});

