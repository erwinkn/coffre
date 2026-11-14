// The change tools past a value's (docs/design/mcp.md, section 6; docs/design/0.16.md,
// "An MCP client's changes"): each asks for an approval, and its person's Approve on
// coffre's page runs the API's own route, once, on their browser session with the
// connection named. A token's or a binding's approval is bound to what the vault
// weighs it would reach: changed since the page opened, Approve is refused.
import assert from 'node:assert/strict';
import { beforeEach, test } from 'node:test';

import { rowsOf } from '@coffre/db/dialect';
import { credential, emptyDatabase, environment, grant, identity, instance, principal, project, role, rows, secret, signerOf, user, value, write } from '@coffre/vault/testing';
import { sql } from 'drizzle-orm';

import { approvalWait } from '../src/mcp/approvals.ts';
import { randomOf } from '../src/mcp/changes.ts';
import { app, callRaw, connect, fromPage, KUBE } from './mcp-fixture.ts';

const { world } = app;
const [root, dev, other] = [user('root'), user('dev'), user('other')];
const ci = 'token:ci';
const ALL = 'read write manage-access';
approvalWait.ms = 50;

/**
 * market/prod holds API_KEY and OLD_KEY. Root owns the instance; dev leads
 * market, so manages ci, a service account that views market/prod and holds
 * a token, `ci-token`; other views market/prod. Each person has a browser
 * session, `<name>-web`.
 */
beforeEach(async () => {
  await emptyDatabase(world.owner);
  for (const kept of [world.memory.reads, world.memory.callers, world.memory.logged, world.memory.touched, world.refused]) kept.clear();
  const market = project('market');
  const prod = environment(market, 'prod');
  const people = [root, dev, other].map((who) => [who, identity(who)] as const);
  await write(
    world,
    ...rows('policy', instance()),
    ...rows('projects', market),
    ...rows('environments', prod),
    ...rows('secrets', value(world, secret(prod, 'API_KEY'), 'v1'), value(world, secret(prod, 'OLD_KEY'), 'old')),
    ...rows('roles',
      role(false, 'viewer', ['secret.read', 'secret.use'], []),
      role(false, 'lead', ['secret.read', 'secret.use', 'secret.write', 'secret.archive', 'environment.manage', 'project.manage', 'grant.manage']),
      role(true, 'owner', ['secret.read', 'secret.use', 'secret.write', 'secret.archive', 'environment.manage', 'project.manage', 'grant.manage', 'audit.read']),
      role(true, 'member', [])),
    ...rows('principals', principal(root, { role: 'owner' }), principal(dev), principal(other), principal(ci)),
    ...rows('grants', grant(dev, 'lead', { project: market }), grant(other, 'viewer', { environment: prod }), grant(ci, 'viewer', { environment: prod })),
    ...rows('identities', ...people.map(([, id]) => id)),
    ...rows('credentials',
      ...people.map(([who, id]) => credential(`${who.slice(5, who.indexOf('@'))}-web`, who, { kind: 'browser', identityId: id.id })),
      credential('ci-token', ci, { kind: 'service', label: 'deploy' })),
  );
  app.calls.length = 0;
});

type Line = { label: string; value: string; warn?: true };
type View = { digest: string; basis: string | null; status: string; summary: string; details: Line[] };
type Decided = { status: string; outcome: { text: string; result?: Record<string, unknown> }; shown: Line[]; message?: string };

/** What a call asked: its approval's id, or the tool's error, as the client reads it. */
async function asked(token: string, tool: string, args: Record<string, unknown>): Promise<string> {
  const { body } = await callRaw(token, tool, args);
  assert.equal(body.result?.isError, undefined, JSON.stringify(body));
  return (body.result!.structuredContent!.approval as { id: string }).id;
}

/** The tool's error, as the client reads it: nothing asked. */
async function refused(token: string, tool: string, args: Record<string, unknown>): Promise<string> {
  const { body } = await callRaw(token, tool, args);
  assert.equal(body.result?.isError, true, JSON.stringify(body));
  return body.result!.content[0]!.text!;
}

async function view(id: string, session: string): Promise<View> {
  const response = await app.request(`/api/approvals/${id}`, { headers: fromPage(session) });
  assert.equal(response.status, 200);
  return ((await response.json()) as { approval: View }).approval;
}

/** The person's Approve, with the digest and basis the page showed (`shown`, or the page as it reads now). */
async function approve(id: string, session: string, shown?: View): Promise<{ status: number; body: Decided }> {
  const page = shown ?? (await view(id, session));
  const response = await app.request(`/api/approvals/${id}`, {
    method: 'POST',
    headers: { ...fromPage(session), 'content-type': 'application/json' },
    body: JSON.stringify({ approve: true, digest: page.digest, basis: page.basis }),
  });
  return { status: response.status, body: (await response.json()) as Decided };
}

/** The API as a person on coffre's page. */
async function api<T>(session: string, method: string, path: string, body?: unknown): Promise<T> {
  const response = await app.request(`/api${path}`, { method, headers: { ...fromPage(session), 'content-type': 'application/json' }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  assert.ok(response.status < 300, `${method} ${path}: ${response.status} ${await response.clone().text()}`);
  return (await response.json()) as T;
}

type Key = { key: string; version: number | null; archived: boolean };
const keys = async () => (await api<{ keys: Key[] }>('root-web', 'GET', '/secrets/market/prod')).keys;
const valueOf = async (key: string) => {
  world.memory.reads.clear();
  return (await api<{ values: Record<string, string> }>('root-web', 'POST', '/reveals', { path: `market/prod/${key}` })).values[key];
};
const entries = async (action: string) => (await rowsOf<{ body: string }>(world.owner, sql`SELECT body FROM log_pending ORDER BY id`)).map((row) => JSON.parse(row.body) as { action: string }).filter((entry) => entry.action === action);

test('generate_secret_value sets a value nobody saw, its recipe kept so that Regenerate makes the next alike; a length no recipe encodes exactly is drawn whole, and keeps none', async () => {
  const token = await connect('dev-web', ALL);
  const id = await asked(token, 'generate_secret_value', { secret: 'market/prod/NEW_KEY', alphabet: 'hex' });
  const page = await view(id, 'dev-web');
  assert.ok(page.details.some((line) => line.label === 'New value' && line.value.startsWith('64 random hex characters, made by coffre: nobody sees it')), JSON.stringify(page.details));
  const decided = await approve(id, 'dev-web', page);
  assert.deepEqual([decided.status, decided.body.status, decided.body.shown], [200, 'approved', []], 'nothing shown to the person either');
  const made = await valueOf('NEW_KEY');
  assert.match(made!, /^[0-9a-f]{64}$/);
  const heard = await callRaw(token, 'generate_secret_value', { secret: 'market/prod/NEW_KEY', alphabet: 'hex', approval: id });
  assert.equal(heard.body.result!.structuredContent!.status, 'approved');
  assert.ok(!JSON.stringify(heard.body).includes(made!), 'the value never reaches the client');
  const { versions } = await api<{ versions: { recipe: string | null }[] }>('root-web', 'GET', '/secrets/market/prod/NEW_KEY/versions');
  assert.equal(versions[0]!.recipe, 'bytes:32:hex');

  assert.deepEqual(Object.keys(randomOf('alphanumeric')).sort(), ['generated', 'value']);
  assert.equal(randomOf('alphanumeric').generated!.recipe, 'bytes:32:base62');
  assert.equal(randomOf('base64url').value.length, 43);
  // No number of bytes is 17 base64url characters, nor 17 hex ones: drawn whole, cut to length, and no recipe.
  for (const alphabet of ['base64url', 'hex'] as const) {
    const drawn = randomOf(alphabet, 17);
    assert.deepEqual([drawn.value.length, drawn.generated], [17, undefined]);
  }
});

test("a secret renamed, archived, brought back and restored to a version, each on its person's Approve, and only then", async () => {
  const token = await connect('dev-web', ALL);
  const rename = await asked(token, 'rename_secret', { secret: 'market/prod/OLD_KEY', newKey: 'RENAMED' });
  assert.ok((await keys()).some((key) => key.key === 'OLD_KEY'), 'nothing changes when it is asked');
  assert.equal((await approve(rename, 'dev-web')).body.status, 'approved');
  assert.deepEqual((await keys()).map((key) => key.key).sort(), ['API_KEY', 'RENAMED']);

  assert.equal((await approve(await asked(token, 'archive_secret', { secret: 'market/prod/RENAMED' }), 'dev-web')).body.status, 'approved');
  assert.equal((await keys()).find((key) => key.key === 'RENAMED')!.archived, true);
  assert.equal((await approve(await asked(token, 'unarchive_secret', { secret: 'market/prod/RENAMED' }), 'dev-web')).body.status, 'approved');
  assert.equal((await keys()).find((key) => key.key === 'RENAMED')!.archived, false);

  await api('root-web', 'PATCH', '/secrets/market/prod', { API_KEY: 'v2' });
  const restore = await asked(token, 'restore_secret_version', { secret: 'market/prod/API_KEY', version: 1 });
  const page = await view(restore, 'dev-web');
  assert.ok(page.details.some((line) => line.label === 'Restores' && line.value.startsWith(`version 1, set by`)), JSON.stringify(page.details));
  assert.equal((await approve(restore, 'dev-web', page)).body.status, 'approved');
  assert.equal(await valueOf('API_KEY'), 'v1');
  assert.equal((await keys()).find((key) => key.key === 'API_KEY')!.version, 3);
});

test('create_project is refused before anyone is asked unless the person makes projects; create_environment makes a fork that inherits', async () => {
  assert.match(await refused(await connect('dev-web', ALL), 'create_project', { project: 'billing' }), /only an admin or owner whose scope takes in new projects/);
  const project = await asked(await connect('root-web', ALL), 'create_project', { project: 'billing' });
  assert.equal((await approve(project, 'root-web')).body.status, 'approved');
  const listed = await api<{ projects: { slug: string; environments: { slug: string; parent: string | null }[] }[] }>('root-web', 'GET', '/projects');
  assert.ok(listed.projects.some((entry) => entry.slug === 'billing'));

  const fork = await asked(await connect('dev-web', ALL), 'create_environment', { environment: 'market/prod-eu', inherits: 'prod' });
  assert.equal((await view(fork, 'dev-web')).summary, 'create the environment market/prod-eu, inheriting market/prod');
  assert.equal((await approve(fork, 'dev-web')).body.status, 'approved');
  const market = (await api<typeof listed>('root-web', 'GET', '/projects')).projects.find((entry) => entry.slug === 'market')!;
  assert.deepEqual(market.environments.find((entry) => entry.slug === 'prod-eu')?.parent, 'prod');
});

test("set_access gives what the page showed it replaces: a grant changed since the page opened refuses Approve, and the approval still waits", async () => {
  const token = await connect('dev-web', ALL);
  const id = await asked(token, 'set_access', { member: other, changes: { market: 'viewer' } });
  const page = await view(id, 'dev-web');
  assert.deepEqual(page.details.find((line) => line.label === 'market'), { label: 'market', value: 'nothing → viewer' });
  // Another manager gives them more meanwhile: what the person read is no longer what it replaces.
  await api('root-web', 'PATCH', `/access/${other}`, { market: 'lead' });
  const stale = await approve(id, 'dev-web', page);
  assert.deepEqual([stale.status, stale.body.message], [409, 'this changed since you opened it: open the approval again']);
  assert.equal((await view(id, 'dev-web')).status, 'pending');
  const fresh = await approve(id, 'dev-web');
  assert.equal(fresh.body.status, 'approved', JSON.stringify(fresh.body));
  const { members } = await api<{ members: { member: string; grants: { project: string; environment: string | null; role: string }[] }[] }>('root-web', 'GET', '/members');
  assert.deepEqual(members.find((entry) => entry.member === other)!.grants.map(({ project, environment, role }) => [project, environment, role]), [['market', 'prod', 'viewer'], ['market', null, 'viewer']]);
});

test('admit_member admits a service account with its first grants, and a person; one who does not run the instance sets up none until the policy row is served', async () => {
  // dev leads market, and under 0.14.7's policy could add one there: 0.16 keeps it to whoever runs the instance for now.
  assert.match(await refused(await connect('dev-web', ALL), 'admit_member', { member: 'service:deploy', access: { 'market/prod': 'viewer' } }), /you set up no service account/);
  assert.match(await refused(await connect('dev-web', ALL), 'admit_member', { member: 'user:new@acme.example' }), /only an admin or owner of the whole instance/);
  const token = await connect('root-web', ALL);
  assert.equal((await approve(await asked(token, 'admit_member', { member: 'service:deploy', access: { 'market/prod': 'viewer' } }), 'root-web')).body.status, 'approved');
  assert.equal((await approve(await asked(token, 'admit_member', { member: 'user:new@acme.example' }), 'root-web')).body.status, 'approved');
  const { members } = await api<{ members: { member: string; grants: { role: string }[] }[] }>('root-web', 'GET', '/members');
  assert.deepEqual(members.find((entry) => entry.member === 'token:deploy')?.grants.map((entry) => entry.role), ['viewer']);
  assert.ok(members.some((entry) => entry.member === 'user:new@acme.example'));
});

test('offboard_member: its page counts what ends, and Approve removes the member', async () => {
  const id = await asked(await connect('root-web', ALL), 'offboard_member', { member: other });
  const page = await view(id, 'root-web');
  assert.ok(page.details.some((line) => line.label === 'Ends' && line.value.startsWith('1 grants, 1 sessions')), JSON.stringify(page.details));
  assert.equal((await approve(id, 'root-web', page)).body.status, 'approved');
  const { members } = await api<{ members: { member: string }[] }>('root-web', 'GET', '/members');
  assert.ok(!members.some((entry) => entry.member === other));
});

test("issue_service_token binds its approval to what the vault weighs it would reach: a grant given the account since refuses Approve, and Approve makes it with the scope read, its value shown on the page alone", async () => {
  const token = await connect('dev-web', ALL);
  const args = { service: 'ci', label: 'release', expiresInDays: 7 };
  const id = await asked(token, 'issue_service_token', args);
  const page = await view(id, 'dev-web');
  assert.equal(page.details.find((line) => line.label === 'Reaches')?.value, 'viewer on market/prod');
  const tokens = async () => (await api<{ tokens: { label: string | null; scope: Record<string, string> | null }[] }>('dev-web', 'GET', `/members/${ci}/tokens`)).tokens;
  assert.equal((await tokens()).length, 1);

  // The planted change: ci is given all of market, so a token of all it holds would reach more than the page said.
  await api('root-web', 'PATCH', `/access/${ci}`, { market: 'viewer' });
  const stale = await approve(id, 'dev-web', page);
  assert.deepEqual([stale.status, stale.body.message], [409, 'this changed since you opened it: open the approval again']);
  assert.equal((await tokens()).length, 1, 'no token made');

  const again = await view(id, 'dev-web');
  assert.equal(again.details.find((line) => line.label === 'Reaches')?.value, 'viewer on market, market/prod');
  const decided = await approve(id, 'dev-web', again);
  assert.equal(decided.body.status, 'approved');
  const shown = decided.body.shown.find((line) => line.label === 'Token')!.value;
  assert.match(shown, /^coffre_/);
  assert.deepEqual((await tokens()).find((entry) => entry.label === 'release')?.scope, { market: 'viewer', 'market/prod': 'viewer' });
  const heard = await callRaw(token, 'issue_service_token', { ...args, approval: id });
  assert.match(heard.body.result!.content[0]!.text!, /^A token for service:ci is issued, good until .+ coffre showed it to the person, once; it is not here\.$/);
  assert.ok(!JSON.stringify(heard.body).includes(shown) && !JSON.stringify(await rowsOf(world.owner, sql`SELECT * FROM mcp_approvals`)).includes(shown), 'the token reaches neither the client nor a row');
});

for (const [tool, args, op, made] of [
  ['issue_service_token', { service: 'ci', label: 'release', expiresInDays: 7 }, 'token.create', async () => (await api<{ tokens: { label: string | null; scope: Record<string, string> | null }[] }>('dev-web', 'GET', `/members/${ci}/tokens`)).tokens.find((entry) => entry.label === 'release')?.scope],
  ['trust_workload', { service: 'ci', profile: 'custom', issuer: KUBE, claims: { sub: 'system:serviceaccount:ci:runner' } }, 'token.bind', async () => (await api<{ bindings: { scope: Record<string, string> | null }[] }>('dev-web', 'GET', `/members/${ci}/bindings`)).bindings[0]?.scope],
] as const) {
  test(`${tool}: a grant given the account between Approve's weigh and its change reaches nothing it makes, which has the scope the page showed`, async () => {
    const id = await asked(await connect('dev-web', ALL), tool, args);
    const page = await view(id, 'dev-web');
    assert.equal(page.details.find((line) => line.label === 'Reaches')?.value, 'viewer on market/prod');
    app.beforeChange.next = async (input) => {
      assert.equal((input as { op: string }).op, op);
      await api('root-web', 'PATCH', `/access/${ci}`, { market: 'viewer' });
    };
    assert.equal((await approve(id, 'dev-web', page)).body.status, 'approved');
    assert.equal(app.beforeChange.next, null, 'the grant came between');
    assert.deepEqual(await made(), { 'market/prod': 'viewer' });
  });
}

test('revoke_service_token ends the token the page names; who does not manage the account is refused before anyone is asked', async () => {
  const [held] = (await api<{ tokens: { id: string }[] }>('dev-web', 'GET', `/members/${ci}/tokens`)).tokens;
  // ci given all of market, which other does not hold: other, who views market/prod alone, no longer manages it.
  await api('root-web', 'PATCH', `/access/${ci}`, { market: 'viewer' });
  for (const tool of ['revoke_service_token', 'untrust_workload']) {
    assert.match(await refused(await connect('other-web', ALL), tool, { service: 'ci', id: held!.id }), /^you do not manage service:ci/);
  }
  assert.deepEqual(await entries('mcp.ask'), []);
  const id = await asked(await connect('dev-web', ALL), 'revoke_service_token', { service: 'ci', id: held!.id });
  assert.ok((await view(id, 'dev-web')).details.some((line) => line.label === 'Token' && line.value.startsWith('deploy (…')));
  assert.equal((await approve(id, 'dev-web')).body.status, 'approved');
  assert.deepEqual((await api<{ tokens: unknown[] }>('dev-web', 'GET', `/members/${ci}/tokens`)).tokens, []);
});

test('trust_workload binds CI runs with the scope the page showed, its unfamiliar issuer warned of; untrust_workload removes the binding', async () => {
  const token = await connect('dev-web', ALL);
  const id = await asked(token, 'trust_workload', { service: 'ci', profile: 'custom', issuer: KUBE, claims: { sub: 'system:serviceaccount:ci:runner' } });
  const page = await view(id, 'dev-web');
  assert.equal(page.details.find((line) => line.label === 'Runs from')?.warn, true);
  assert.equal(page.details.find((line) => line.label === 'Reaches')?.value, 'viewer on market/prod');
  assert.equal((await approve(id, 'dev-web', page)).body.status, 'approved');
  const bindings = async () => (await api<{ bindings: { id: string; scope: Record<string, string> | null; jwksUri: string }[] }>('dev-web', 'GET', `/members/${ci}/bindings`)).bindings;
  const [bound] = await bindings();
  assert.deepEqual([bound!.scope, bound!.jwksUri], [{ 'market/prod': 'viewer' }, `${KUBE}/openid/v1/jwks`]);

  const remove = await asked(token, 'untrust_workload', { service: 'ci', id: bound!.id });
  assert.ok((await view(remove, 'dev-web')).details.some((line) => line.label === 'Runs from' && line.value === KUBE));
  assert.equal((await approve(remove, 'dev-web')).body.status, 'approved');
  assert.deepEqual(await bindings(), []);
});

test("read_audit_log reads the log as the person, for whoever holds audit.read; a call too long for an approval is the tool's error, and asks nothing", async () => {
  await (await signerOf(world)).sign();
  const { body } = await callRaw(await connect('root-web'), 'read_audit_log', { limit: 5 });
  const read = body.result!.structuredContent!.entries as unknown[];
  assert.ok(Array.isArray(read) && read.length > 0 && read.length <= 5, JSON.stringify(body));
  const unread = (await callRaw(await connect('dev-web'), 'read_audit_log', {})).body.result!;
  assert.deepEqual([unread.isError, unread.content[0]!.text], [true, 'you do not hold audit.read on any project'], "the API's refusal, as the tool's error");

  const changes = Object.fromEntries(Array.from({ length: 50 }, (_, i) => [`market/env-${String(i).padStart(2, '0')}-${'x'.repeat(80)}`, 'viewer']));
  assert.match(await refused(await connect('root-web', ALL), 'set_access', { member: other, changes }), /too long to ask for an approval/);
  assert.deepEqual(await entries('mcp.ask'), []);
});
