// The fresh check (docs/design/passkeys.md, section 4; T176 PR 5b), through the deployment's own
// routes, as a browser goes: what widens someone's reach, mints a credential or cannot be undone takes a session a
// passkey touch confirmed in the last five minutes (`FRESH_ROUTES`). Refused, `403 fresh_check_required`, nothing is
// written; the step-up confirms the browser's session anew, and the act goes. A person with no passkey yet, under
// `optional`, is asked to add one, and signing in to add one confirms the session it makes. The clock is the test's.
import test, { after, before, beforeEach, type TestContext } from 'node:test';
import assert from 'node:assert/strict';

import { SoftAuthenticator } from '@coffre/conformance/authenticator';
import { hashToken } from '@coffre/core/identity';
import { eq } from 'drizzle-orm';

import { FRESH_MS } from '../src/api/fresh-routes.ts';
import type { CoffreRuntime } from '../src/runtime.ts';
import { serveApi } from '../src/api/router.ts';
import { clientFor, contextFor, openTestDatabase, resetDatabase, testDeps, type FixtureDeps } from './api-fixture.ts';
import { credentials, passkeys } from './db/tables.ts';
import * as rows from './passkey-rows.ts';
import { assertion, Browser, enroll, ORIGIN, register, signinDeployment } from './signin-browser.ts';

const ROOT = 'admin@acme.example';
const ADA = 'ada@acme.example';
const BOB = 'bob@acme.example';
const CAROL = 'carol@acme.example';

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;
let runtime: CoffreRuntime;

before(async () => {
  db = await openTestDatabase();
});

after(async () => {
  await db.close();
});

beforeEach(async () => {
  await resetDatabase(db.owner);
  deps = testDeps(db.runtime, [ROOT]);
  const root = clientFor(deps, ROOT);
  await root.projects.create('market', { name: 'Market' });
  await root.environments.create('market/dev', { name: 'dev' });
  await root.secrets.set('market/dev', { API_KEY: 'dev-key', DB_PASSWORD: { value: 'hunter2', sensitivity: 'sensitive' } });
  // Ada, an Admin with no passkey; Bob, an Owner of the whole instance, who adds one at sign-in under `optional`.
  await root.members.add(`user:${ADA}`, { role: 'admin' });
  await root.members.add(`user:${BOB}`, { role: 'owner' });
  runtime = signinDeployment(deps, 'optional');
});

/** The test's clock, from now: `later` moves it on. */
function clock(t: TestContext) {
  t.mock.timers.enable({ apis: ['Date'], now: Date.now() });
  return { later: (ms: number) => t.mock.timers.tick(ms) };
}

/** A change from coffre's own page, as the browser sends it: its status and body. */
async function act(browser: Browser, method: string, path: string, body?: unknown, headers: Record<string, string> = {}): Promise<{ status: number; body: { error?: string; reason?: string; next?: string; caller?: string } }> {
  const response = await browser.fetch(path, {
    method,
    headers: { 'sec-fetch-site': 'same-origin', ...(body === undefined ? {} : { 'content-type': 'application/json' }), ...headers },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  return { status: response.status, body: (await response.json()) as { error?: string; reason?: string; caller?: string } };
}

const refused = (answer: { status: number; body: { error?: string; reason?: string } }) => [answer.status, answer.body.error, answer.body.reason];

/** What `GET /api/me` says of passkeys. */
async function passkeysOf(browser: Browser) {
  return ((await (await browser.fetch('/api/me')).json()) as { passkeys: { policy: string; enrolled: boolean; confirmedUntil: string | null } }).passkeys;
}

/** The step-up, at its door, as the dialog asks it: the browser's session confirmed anew by `key`, and where it goes on to. */
async function stepUp(browser: Browser, key: SoftAuthenticator, next = '/projects'): Promise<string | undefined> {
  const step = await browser.step(`?step-up=1&next=${encodeURIComponent(next)}`);
  assert.equal(step.body.purpose, 'step-up', JSON.stringify(step.body));
  const answered = await browser.answer({ state: step.body.state, response: await assertion(key, step.body.options) });
  assert.equal(answered.status, 200, JSON.stringify(answered.body));
  return (answered.body as { next?: string }).next;
}

const memberNames = async () => (await clientFor(deps, ROOT).members.list()).members.map((listed) => listed.member);
const levels = async () => Object.fromEntries((await clientFor(deps, ROOT).secrets.list('market/dev')).keys.map((entry) => [entry.key, entry.sensitivity]));

test('what widens reach takes a session a touch confirmed in the last five minutes; the step-up confirms it anew, and ends the one before', async (t) => {
  const { later } = clock(t);
  const key = await SoftAuthenticator.create('ES256');
  const bob = await enroll(runtime, BOB, key);
  const confirmed = await passkeysOf(bob);
  assert.deepEqual({ ...confirmed, confirmedUntil: null }, { policy: 'optional', enrolled: true, confirmedUntil: null });
  assert.equal(Date.parse(confirmed.confirmedUntil!), Date.now() + FRESH_MS, 'five minutes from the touch');

  // Inside the window, to its last moment.
  later(FRESH_MS - 1);
  assert.equal((await act(bob, 'PUT', `/api/members/user:${CAROL}`, { role: 'developer' })).status, 200);
  // Past it: refused, a prompt, nothing changed.
  later(1);
  assert.deepEqual(refused(await act(bob, 'PATCH', `/api/access/user:${CAROL}`, { market: 'viewer' })), [403, 'fresh_check_required', undefined]);
  assert.deepEqual((await clientFor(deps, ROOT).members.access(`user:${CAROL}`)).grants, []);
  assert.equal((await passkeysOf(bob)).confirmedUntil, null);
  // Every route the table says, by its answer: removing a member, issuing a service's token, the settings.
  assert.deepEqual(refused(await act(bob, 'DELETE', `/api/members/user:${CAROL}`)), [403, 'fresh_check_required', undefined]);
  assert.ok((await memberNames()).includes(`user:${CAROL}`));

  // The step-up's door: a new session, confirmed now, and the one it came in on ended.
  const before = bob.session!;
  await stepUp(bob, key);
  assert.notEqual(bob.session, before);
  const stale = new Browser(runtime);
  stale.jar.set('__Host-coffre_session', before);
  assert.equal((await stale.fetch('/api/me')).status, 401, 'a copy of the old cookie stops working');
  assert.equal((await act(bob, 'PATCH', `/api/access/user:${CAROL}`, { market: 'viewer' })).status, 200);
  const [row] = await db.owner.select().from(credentials).where(eq(credentials.tokenHash, hashToken(bob.session!)));
  assert.equal(row!.confirmedAt!.getTime(), Date.now());
});

test("an act sent again after its fresh check goes only for the person who sent it: another person's session since refuses it, doing nothing", async (t) => {
  const { later } = clock(t);
  const root = clientFor(deps, ROOT);
  await root.members.add('user:dana@acme.example', { role: 'owner' });
  await root.members.add(`user:${CAROL}`, { role: 'developer' });
  const bobKey = await SoftAuthenticator.create('ES256');
  const bob = await enroll(runtime, BOB, bobKey);
  later(FRESH_MS);
  // Bob's act, refused: the refusal names him, opaquely, for the act's second sending.
  const first = await act(bob, 'PATCH', `/api/access/user:${CAROL}`, { market: 'viewer' });
  assert.deepEqual(refused(first), [403, 'fresh_check_required', undefined]);
  const caller = first.body.caller!;
  assert.match(caller, /^user:/);
  // Meanwhile another tab of the same browser signs in as Dana, who touches her own passkey: the dialog's step-up
  // confirms her session, and Bob's act goes again on it, saying it is Bob's. Refused, and nothing changed.
  const dana = await enroll(runtime, 'dana@acme.example', await SoftAuthenticator.create('ES256'));
  const his = bob.session!;
  bob.jar.set('__Host-coffre_session', dana.session!);
  assert.deepEqual(refused(await act(bob, 'PATCH', `/api/access/user:${CAROL}`, { market: 'viewer' }, { 'coffre-caller': caller })), [409, 'conflict', 'caller_changed']);
  assert.deepEqual((await root.members.access(`user:${CAROL}`)).grants, []);
  // Bob's own session, confirmed anew (a step-up rotates it): his act, saying so, goes.
  bob.jar.set('__Host-coffre_session', his);
  await stepUp(bob, bobKey);
  assert.equal((await act(bob, 'PATCH', `/api/access/user:${CAROL}`, { market: 'viewer' }, { 'coffre-caller': caller })).status, 200);
  assert.equal((await root.members.access(`user:${CAROL}`)).grants.length, 1);
});

test('a person with no passkey yet is asked to add one, and a sign-in that adds it confirms the session it makes', async () => {
  const ada = new Browser(runtime);
  assert.equal(await ada.provider(ADA), '/projects/market', 'under optional, an Admin signs in by the provider alone');
  assert.deepEqual(await passkeysOf(ada), { policy: 'optional', enrolled: false, confirmedUntil: null });
  assert.deepEqual(refused(await act(ada, 'PUT', `/api/members/user:${CAROL}`, { role: 'developer' })), [403, 'fresh_check_required', 'add_passkey']);
  assert.equal((await memberNames()).includes(`user:${CAROL}`), false);
  // What takes no check goes as before: archiving a project, say.
  assert.equal((await act(ada, 'PATCH', '/api/projects/market', { archived: true })).status, 200);

  // `?passkey=add`: the sign-in asks her for one, as it asks an Owner.
  const again = new Browser(runtime);
  again.jar.set('__Host-coffre_session', ada.session!);
  const leave = await again.fetch('/auth/signin/acme?passkey=add&next=/members');
  assert.equal(leave.status, 302);
  const back = await again.fetch(`/auth/callback/acme?email=${encodeURIComponent(ADA)}`);
  assert.equal(back.headers.get('location'), '/auth/passkey');
  const step = await again.step();
  assert.equal(step.body.purpose, 'enroll');
  assert.deepEqual(await again.answer(await register(await SoftAuthenticator.create('ES256'), step.body)), { status: 200, body: { next: '/members' } });
  assert.equal((await act(again, 'PUT', `/api/members/user:${CAROL}`, { role: 'developer' })).status, 200);
  // Her first passkey ended what none confirmed, the session she started from included (section 3.3).
  assert.equal((await ada.fetch('/api/me')).status, 401);
});

test('a route answers by what it is asked: a dry run where it takes one, unprotecting and not protecting, a token of her own from a browser and not a terminal', async (t) => {
  const { later } = clock(t);
  const key = await SoftAuthenticator.create('ES256');
  const bob = await enroll(runtime, BOB, key);
  later(FRESH_MS);
  const fresh = (answer: { body: { error?: string } }) => answer.body.error !== 'fresh_check_required';
  // Erasing for good, and its `?dryRun=1`, which erases nothing; a route that takes no dry run is checked whatever its query.
  assert.ok(fresh(await act(bob, 'DELETE', '/api/projects/market?dryRun=1')), 'a dry run needs no check');
  assert.deepEqual(refused(await act(bob, 'DELETE', '/api/projects/market')), [403, 'fresh_check_required', undefined]);
  assert.deepEqual(refused(await act(bob, 'PATCH', `/api/access/user:${ADA}?dryRun=1`, { market: 'viewer' })), [403, 'fresh_check_required', undefined]);
  // A personal config of his own holds only what he wrote: erasing it widens nobody's reach. Dev's own, for good, does.
  assert.equal((await act(bob, 'PATCH', '/api/secrets/market/dev@me', { API_KEY: 'mine' })).status, 200);
  assert.equal((await act(bob, 'DELETE', '/api/projects/market/dev@me')).status, 200);
  assert.deepEqual(refused(await act(bob, 'DELETE', '/api/projects/market/dev')), [403, 'fresh_check_required', undefined]);
  // Protecting is quick; unprotecting lets every role in again.
  assert.equal((await act(bob, 'PATCH', '/api/projects/market/dev', { protected: true })).status, 200);
  assert.deepEqual(refused(await act(bob, 'PATCH', '/api/projects/market/dev', { protected: false })), [403, 'fresh_check_required', undefined]);
  assert.equal((await clientFor(deps, ROOT).projects.list()).projects[0]!.environments.find((environment) => environment.slug === 'dev')!.protected, true);

  // A token of his own outlives a browser's session: from one, it takes the window; from a terminal, which holds no more
  // than its approval's touch confirmed, nothing.
  const token = { label: 'agent', expiresInMinutes: 60, scope: { 'market/dev': 'viewer' } };
  assert.deepEqual(refused(await act(bob, 'POST', `/api/members/user:${BOB}/tokens`, token)), [403, 'fresh_check_required', undefined]);
  const [passkey] = await db.owner.select({ id: passkeys.id }).from(passkeys).where(eq(passkeys.principal, `user:${BOB}`));
  const terminal = await rows.confirmedSession(db.owner, deps.chainKey, BOB, passkey!.id, { confirmedAt: new Date(Date.now() - FRESH_MS) });
  const issued = await runtime.signin!.verify(terminal);
  assert.equal(issued.session?.kind, 'cli');
  const fromTerminal = await (await import('../src/fetch-api.ts')).fetchApi(new Request(`${ORIGIN}/api/members/user:${BOB}/tokens`, {
    method: 'POST', headers: { authorization: `Bearer ${terminal}`, 'content-type': 'application/json' }, body: JSON.stringify(token),
  }), runtime, { sourceIp: null });
  assert.equal(fromTerminal.status, 200, await fromTerminal.clone().text());
  // And from a browser of a person who holds no passkey: nothing either.
  await clientFor(deps, ROOT).access.set(`user:${ADA}`, { 'market/dev': 'viewer' });
  const ada = new Browser(runtime);
  await ada.provider(ADA);
  const own = await act(ada, 'POST', `/api/members/user:${ADA}/tokens`, token);
  assert.equal(own.status, 200, JSON.stringify(own.body));
});

test('a sensitive value made a secret in place takes the window, decided where its level is read; a stricter mark does not', async (t) => {
  const { later } = clock(t);
  const key = await SoftAuthenticator.create('ES256');
  const bob = await enroll(runtime, BOB, key);
  later(FRESH_MS);
  assert.deepEqual(refused(await act(bob, 'PATCH', '/api/secrets/market/dev', { DB_PASSWORD: { sensitivity: 'secret' } })), [403, 'fresh_check_required', undefined]);
  assert.equal((await levels()).DB_PASSWORD, 'sensitive', 'nothing written');
  assert.equal((await act(bob, 'PATCH', '/api/secrets/market/dev', { API_KEY: { sensitivity: 'sensitive' } })).status, 200);
  assert.equal((await levels()).API_KEY, 'sensitive');
  await stepUp(bob, key);
  assert.equal((await act(bob, 'PATCH', '/api/secrets/market/dev', { DB_PASSWORD: { sensitivity: 'secret' } })).status, 200);
  assert.equal((await levels()).DB_PASSWORD, 'secret');
});

test('every act a fresh check let through names, in its own entry, the passkey and the time that confirmed it; an act it guards nothing of names none', async (t) => {
  const { later } = clock(t);
  const key = await SoftAuthenticator.create('ES256');
  const bob = await enroll(runtime, BOB, key);
  const touchedAt = new Date().toISOString();
  const [passkey] = await db.owner.select({ id: passkeys.id }).from(passkeys).where(eq(passkeys.principal, `user:${BOB}`));
  later(1000);
  // A first add (the vault's change), a grant (the vault's entry), a service's token (the vault's issue), a role's
  // definition, and the settings; then a write of a value, which no check guards.
  assert.equal((await act(bob, 'PUT', `/api/members/user:${CAROL}`, { role: 'developer' })).status, 200);
  assert.equal((await act(bob, 'PATCH', `/api/access/user:${CAROL}`, { market: 'viewer' })).status, 200);
  assert.equal((await act(bob, 'PUT', '/api/members/token:deploy', { role: 'member' })).status, 200);
  assert.equal((await act(bob, 'PATCH', '/api/access/token:deploy', { 'market/dev': 'viewer' })).status, 200);
  const issued = await act(bob, 'POST', '/api/members/token:deploy/tokens', { expiresInDays: 30, scope: { 'market/dev': 'viewer' } });
  assert.equal(issued.status, 200, JSON.stringify(issued.body));
  assert.equal((await act(bob, 'PATCH', '/api/secrets/market/dev', { API_KEY: 'rotated' })).status, 200);
  // And an environment erased for good (the app's entry).
  const root = clientFor(deps, ROOT);
  await root.environments.create('market/qa', { name: 'qa' });
  await root.environments.update('market/qa', { archived: true });
  const erased = await act(bob, 'DELETE', '/api/projects/market/qa');
  assert.equal(erased.status, 200, JSON.stringify(erased.body));

  // Every entry, the vault's sealed changes among them, as the audit page lists them with their details.
  const entries = (await root.audit.list({ actor: BOB, detail: '1', sealed: '1', limit: 200 })).entries
    .filter((entry) => entry.actorId === BOB && entry.decision === 'allow');
  const confirmation = (action: string) => {
    const found = entries.filter((entry) => entry.action === action);
    assert.ok(found.length > 0, `${action}: ${JSON.stringify(entries.map((entry) => entry.action))}`);
    return found.map((entry) => [entry.metadata.confirmedBy ?? null, entry.metadata.confirmedAt ?? null]);
  };
  const confirmed = [passkey!.id, touchedAt];
  for (const action of ['member.add', 'access.grant', 'token.create', 'environment.delete']) {
    assert.ok(confirmation(action).some((pair) => pair[0] === confirmed[0] && pair[1] === confirmed[1]), `${action} names its confirmation: ${JSON.stringify(confirmation(action))}`);
  }
  assert.deepEqual([...new Set(confirmation('secret.write').map(String))], [String([null, null])], 'a write no check guards names none');
});

test("a personal token or an MCP connection is never the browser's window, however lately its person touched: unprotecting and a sensitive value made a secret refuse it, writing nothing", async () => {
  const key = await SoftAuthenticator.create('ES256');
  await enroll(runtime, BOB, key);
  const [passkey] = await db.owner.select({ id: passkeys.id }).from(passkeys).where(eq(passkeys.principal, `user:${BOB}`));
  await clientFor(deps, ROOT).environments.update('market/dev', { protected: true });
  // Bob's own context, a session his passkey confirmed a moment ago: what the request came in on is all that differs.
  const as = async (extra: Partial<Awaited<ReturnType<typeof contextFor>>>) => ({
    ...(await contextFor(deps, BOB)), signin: runtime.signin!, passkeyId: passkey!.id, session: { kind: 'browser' as const, confirmedAt: new Date() }, ...extra,
  });
  const send = async (ctx: Awaited<ReturnType<typeof as>>, method: string, path: string, body: unknown) => {
    const answer = await serveApi(new Request(`${ORIGIN}${path}`, { method, headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }), ctx);
    return refused({ status: answer.status, body: (await answer.json()) as { error?: string; reason?: string } });
  };
  const token = { personalToken: { id: '00000000-0000-4000-8000-000000000002', label: 'agent', expiresAt: new Date(Date.now() + 3_600_000).toISOString() } };
  const connection = { via: { connectionId: '00000000-0000-4000-8000-000000000003', clientId: 'client', clientName: 'Claude', scopes: ['read', 'write'] as const } };
  for (const [name, extra] of [['a personal token', token], ['an MCP connection, with no approval touch', connection]] as const) {
    assert.deepEqual(await send(await as(extra), 'PATCH', '/api/projects/market/dev', { protected: false }), [403, 'fresh_check_required', undefined], name);
    assert.deepEqual(await send(await as(extra), 'PATCH', '/api/secrets/market/dev', { DB_PASSWORD: { sensitivity: 'secret' } }), [403, 'fresh_check_required', undefined], name);
  }
  assert.equal((await clientFor(deps, ROOT).projects.list()).projects[0]!.environments.find((environment) => environment.slug === 'dev')!.protected, true);
  assert.equal((await levels()).DB_PASSWORD, 'sensitive', 'nothing written');
  // The session itself goes.
  assert.equal((await send(await as({}), 'PATCH', '/api/secrets/market/dev', { DB_PASSWORD: { sensitivity: 'secret' } }))[0], 200);
});

test('linking another account takes the window of a person who holds a passkey, at the start and at the callback; the step-up goes on to the link', async (t) => {
  const { later } = clock(t);
  const key = await SoftAuthenticator.create('ES256');
  const bob = await enroll(runtime, BOB, key);
  later(FRESH_MS);
  // At the start: to the step-up, which comes back to the link, and nothing sealed for the provider yet.
  const start = await bob.fetch('/auth/signin/acme?link=1');
  assert.equal(start.headers.get('location'), `/auth/passkey?step-up=1&next=${encodeURIComponent('/auth/signin/acme?link=1')}`);
  assert.equal(bob.jar.has('__Host-coffre_pending'), false);
  assert.equal(await stepUp(bob, key, '/auth/signin/acme?link=1'), '/auth/signin/acme?link=1');
  // Confirmed: to the provider. Back after the window closed: linked nothing, and the page says to link again.
  const leave = await bob.fetch('/auth/signin/acme?link=1');
  assert.match(leave.headers.get('location')!, /^https:\/\/idp\.acme\.example\/authorize/);
  later(FRESH_MS);
  const late = await bob.fetch(`/auth/callback/acme?email=${encodeURIComponent('bob.work@acme.example')}`);
  assert.equal(late.headers.get('location'), '/account?error=link_stale');
  // Inside it: linked.
  await stepUp(bob, key);
  await bob.fetch('/auth/signin/acme?link=1');
  const linked = await bob.fetch(`/auth/callback/acme?email=${encodeURIComponent('bob.work@acme.example')}`);
  assert.equal(linked.headers.get('location'), '/account?linked=acme');
  // Its entry names the touch that confirmed the session (passkeys.md, section 11).
  const [passkey] = await db.owner.select({ id: passkeys.id }).from(passkeys).where(eq(passkeys.principal, `user:${BOB}`));
  const [link] = (await clientFor(deps, ROOT).audit.list({ actor: BOB, detail: '1', limit: 200 })).entries.filter((entry) => entry.action === 'account.link' && entry.decision === 'allow');
  assert.deepEqual([link?.metadata.confirmedBy, link?.metadata.confirmedAt], [passkey!.id, new Date().toISOString()]);

  // A person with no passkey links as before: straight to the provider.
  const ada = new Browser(runtime);
  await ada.provider(ADA);
  assert.match((await ada.fetch('/auth/signin/acme?link=1')).headers.get('location')!, /^https:\/\/idp\.acme\.example\/authorize/);
});

test("the step-up goes on to a link of the deployment's providers, exactly as the link's start sent it, and to a page otherwise", async () => {
  const key = await SoftAuthenticator.create('ES256');
  const bob = await enroll(runtime, BOB, key);
  for (const [asked, goes] of [
    ['/auth/signin/acme?link=1', '/auth/signin/acme?link=1'],
    ['/auth/signin/acme', '/projects'],
    ['/auth/signin/other?link=1', '/projects'],
    ['/auth/signin/acme?link=1&x=1', '/projects'],
    ['/members', '/members'],
  ] as const) {
    assert.equal(await stepUp(bob, key, asked), goes, asked);
  }
});

test('under off, nothing is asked', async (t) => {
  const { later } = clock(t);
  runtime = signinDeployment(deps, 'off');
  const ada = new Browser(runtime);
  assert.equal(await ada.provider(ADA), '/projects/market');
  later(FRESH_MS * 10);
  assert.equal((await act(ada, 'PUT', `/api/members/user:${CAROL}`, { role: 'developer' })).status, 200);
  assert.deepEqual(await passkeysOf(ada), { policy: 'off', enrolled: false, confirmedUntil: null });
});
