// Managing passkeys (docs/design/passkeys.md, sections 3.6 and 3.7; T176 PR 6), through the
// deployment's own routes, as a browser goes: a person lists their passkeys, adds another from a session a touch
// confirmed in the last five minutes, renames one, and removes one with a touch of one they keep, which signs them out
// everywhere else and gives this browser a new session; an Owner of the whole instance resets someone's, which ends
// everything that person is signed in with. The clock is the test's.
import { randomUUID } from 'node:crypto';
import test, { after, before, beforeEach, type TestContext } from 'node:test';
import assert from 'node:assert/strict';

import { SoftAuthenticator } from '@coffre/conformance/authenticator';
import { hashToken } from '@coffre/core/identity';
import { eq } from 'drizzle-orm';

import { FRESH_MS } from '../src/api/fresh-routes.ts';
import { MAX_PASSKEYS } from '../src/api/signin.ts';
import { passkeyName } from '../src/passkey-names.ts';
import type { CoffreRuntime } from '../src/runtime.ts';
import { clientFor, openTestDatabase, resetDatabase, testDeps, type FixtureDeps } from './api-fixture.ts';
import { auditLog, credentials, deviceLogins, mcpConnections, passkeys } from '@coffre/db/schema';
import * as rows from './passkey-rows.ts';
import { assertion, Browser, bytes, enroll, me, register, RP, signinDeployment, touch } from './signin-browser.ts';

const ROOT = 'admin@acme.example';
const ADA = 'ada@acme.example';
const BOB = 'bob@acme.example';
const DANA = 'dana@acme.example';

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
  // Ada, an Admin with no passkey; Bob and Dana, Owners of the whole instance, who add one at sign-in under `optional`.
  await root.members.add(`user:${ADA}`, { role: 'admin' });
  await root.members.add(`user:${BOB}`, { role: 'owner' });
  await root.members.add(`user:${DANA}`, { role: 'owner' });
  await root.projects.create('market', { name: 'Market' });
  await root.environments.create('market/prod', { name: 'Production' });
  runtime = signinDeployment(deps, 'optional');
});

/** The test's clock, from now: `later` moves it on. */
function clock(t: TestContext) {
  t.mock.timers.enable({ apis: ['Date'], now: Date.now() });
  return { later: (ms: number) => t.mock.timers.tick(ms) };
}

type Answer = { status: number; body: any };

/** A request from coffre's own page, as the browser sends it: its status and body. */
async function act(browser: Browser, method: string, path: string, body?: unknown): Promise<Answer> {
  const response = await browser.fetch(path, {
    method,
    headers: { 'sec-fetch-site': 'same-origin', ...(body === undefined ? {} : { 'content-type': 'application/json' }) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  return { status: response.status, body: await response.json() };
}

const refused = (answer: Answer) => [answer.status, answer.body.error, answer.body.reason];

/** A person's passkeys, as their Passkeys tab reads them. */
async function listed(browser: Browser, email: string) {
  const answer = await act(browser, 'GET', `/api/members/user:${email}/passkeys`);
  assert.equal(answer.status, 200, JSON.stringify(answer.body));
  return answer.body as { passkeys: { id: string; name: string; provider: string | null; synced: boolean }[]; ends: Record<string, number>; reset: { by: string; at: string } | null; max: number };
}

/** Another passkey, `key`, added from the browser's session: the options, `create()`, and the answer. */
async function add(browser: Browser, email: string, key: SoftAuthenticator): Promise<Answer> {
  const asked = await act(browser, 'POST', `/api/members/user:${email}/passkeys/options`);
  if (asked.status !== 200) return asked;
  const response = await key.register({ ...RP, challenge: bytes(asked.body.options.challenge), userHandle: bytes(asked.body.options.user.id) });
  return act(browser, 'POST', `/api/members/user:${email}/passkeys`, { state: asked.body.state, response });
}

/** Removing passkey `id` at the passkey page's door, with a touch of `key`, or none: what the door answered. */
async function remove(browser: Browser, id: string, key: SoftAuthenticator | null): Promise<Answer> {
  const step = await browser.step(`?remove=${id}`);
  if (step.status !== 200) return step;
  return browser.answer(key === null ? { state: step.body.state } : { state: step.body.state, response: await assertion(key, step.body.options) });
}

/** The browser's session row. */
async function sessionRow(browser: Browser) {
  const [row] = await db.owner.select().from(credentials).where(eq(credentials.tokenHash, hashToken(browser.session!)));
  return row!;
}

/** Whether a terminal polling with `deviceCode` gets a session. */
async function redeems(deviceCode: string): Promise<boolean> {
  return (await runtime.signin!.pollDevice(deviceCode, { requestId: randomUUID(), sourceIp: null })).status === 'approved';
}

/** What an approved device code's row and a connection's say once a change to the person's passkeys ended them. */
async function endedRows(approval: string, connection: string) {
  const [code] = await db.owner.select().from(deviceLogins).where(eq(deviceLogins.id, approval));
  const [app] = await db.owner.select().from(mcpConnections).where(eq(mcpConnections.id, connection));
  return { decision: code!.decision, passkeyId: code!.passkeyId, connectionRevoked: app!.revokedAt !== null };
}

/** Run `meanwhile` once, as the vault is next asked about `principal`: before it answers, or with `after`, once it has. */
function onNextAccess(principal: string, meanwhile: () => Promise<unknown>, { after = false } = {}): void {
  const access = deps.vault.access;
  deps.vault.access = async (asked, ...rest) => {
    if (asked !== principal) return access(asked, ...rest);
    deps.vault.access = access;
    if (!after) await meanwhile();
    const answer = await access(asked, ...rest);
    if (after) await meanwhile();
    return answer;
  };
}

/** The entries of `action`, oldest first. */
async function entries(action: string) {
  return (await db.owner.select().from(auditLog).where(eq(auditLog.action, action))).map((entry) => ({ ...entry, metadata: JSON.parse(entry.metadata ?? '{}') }));
}

test("a person lists their passkeys, adds another from a fresh session, and renames one; a first passkey is added at sign-in, and ten at most", async (t) => {
  const { later } = clock(t);
  const first = await SoftAuthenticator.create('ES256');
  const bob = await enroll(runtime, BOB, first);
  const [one] = (await listed(bob, BOB)).passkeys;
  assert.equal(one!.name, 'Passkey 1');

  // Another, a moment after the touch: its options exclude the first, and its name is its provider's. They last as long
  // as the session stays fresh, which the add is held to too, here the ceremony's whole five minutes.
  const asked = await act(bob, 'POST', `/api/members/user:${BOB}/passkeys/options`);
  assert.equal(asked.status, 200, JSON.stringify(asked.body));
  assert.equal(asked.body.options.timeout, FRESH_MS);
  assert.deepEqual(asked.body.options.excludeCredentials.map((d: { id: string }) => d.id), [Buffer.from(first.credentialId).toString('base64url')]);
  const onePassword = await SoftAuthenticator.create('ES256', { synced: true, aaguid: new Uint8Array(Buffer.from('bada5566a7aa401fbd9645619a55120d', 'hex')) });
  const created = await onePassword.register({ ...RP, challenge: bytes(asked.body.options.challenge), userHandle: bytes(asked.body.options.user.id) });
  const added = await act(bob, 'POST', `/api/members/user:${BOB}/passkeys`, { state: asked.body.state, response: created });
  assert.equal(added.status, 200, JSON.stringify(added.body));
  assert.deepEqual({ name: added.body.passkey.name, provider: added.body.passkey.provider, synced: added.body.passkey.synced }, { name: '1Password', provider: '1Password', synced: true });
  assert.deepEqual((await listed(bob, BOB)).passkeys.map((row) => row.name), ['Passkey 1', '1Password']);
  const entry = (await entries('passkey.add')).at(-1);
  assert.deepEqual([entry!.actor, entry!.metadata.passkeyId, typeof entry!.metadata.confirmedBy], [`user:${BOB}`, added.body.passkey.id, 'string']);
  // The same answer again, as when the first reply was lost, adds nothing and says it was added (review r1 of #539).
  assert.deepEqual(refused(await act(bob, 'POST', `/api/members/user:${BOB}/passkeys`, { state: asked.body.state, response: created })), [409, 'conflict', 'passkey_exists']);
  assert.equal((await listed(bob, BOB)).passkeys.length, 2);
  // Another answer to options asked before a passkey was added is a change's: new options, and a new `create()`.
  const before = await act(bob, 'POST', `/api/members/user:${BOB}/passkeys/options`);
  await rows.addPasskey(db.owner, deps.chainKey, BOB);
  const stale = await (await SoftAuthenticator.create('ES256')).register({ ...RP, challenge: bytes(before.body.options.challenge), userHandle: bytes(before.body.options.user.id) });
  assert.deepEqual(refused(await act(bob, 'POST', `/api/members/user:${BOB}/passkeys`, { state: before.body.state, response: stale })), [409, 'conflict', 'state_mismatch']);
  // Asked a second before the session stops being fresh, options last that second: a `create()` answered after it would
  // meet a step-up, which replaces the session they name, and leave a passkey on the device coffre never stored.
  later(FRESH_MS - 1000);
  const late = await act(bob, 'POST', `/api/members/user:${BOB}/passkeys/options`);
  assert.equal(late.status, 200, JSON.stringify(late.body));
  assert.equal(late.body.options.timeout, 1000);
  later(1000);

  // Renaming takes no check, past the window too; a name with a control character is no name.
  const renamed = await act(bob, 'PATCH', `/api/members/user:${BOB}/passkeys/${one!.id}`, { name: 'YubiKey 5C' });
  assert.deepEqual(renamed, { status: 200, body: { passkey: { id: one!.id, name: 'YubiKey 5C' } } });
  assert.equal((await act(bob, 'PATCH', `/api/members/user:${BOB}/passkeys/${one!.id}`, { name: 'a\u0007b' })).status, 400);
  const unknown = await act(bob, 'PATCH', `/api/members/user:${BOB}/passkeys/not-a-uuid`, { name: 'x' });
  assert.equal(unknown.status, 400, JSON.stringify(unknown.body));
  assert.equal((await act(bob, 'PATCH', `/api/members/user:${BOB}/passkeys/${crypto.randomUUID()}`, { name: 'x' })).status, 404);
  // Adding one past the window is a fresh check's.
  assert.deepEqual(refused(await act(bob, 'POST', `/api/members/user:${BOB}/passkeys/options`)), [403, 'fresh_check_required', undefined]);

  // Ada holds none: a first passkey is added at sign-in (`add_passkey`), never from a session.
  const ada = new Browser(runtime);
  assert.equal(await ada.provider(ADA), '/projects/market');
  assert.deepEqual(refused(await act(ada, 'POST', `/api/members/user:${ADA}/passkeys/options`)), [403, 'fresh_check_required', 'add_passkey']);
  // Nor anyone else's: Ada lists Bob's no more than she adds to them.
  assert.equal((await act(ada, 'GET', `/api/members/user:${BOB}/passkeys`)).status, 403);
  assert.equal((await act(ada, 'PATCH', `/api/members/user:${BOB}/passkeys/${one!.id}`, { name: 'mine' })).status, 403);

  // Ten at most.
  const dana = await enroll(runtime, DANA, await SoftAuthenticator.create('ES256'));
  for (let held = 2; held < MAX_PASSKEYS; held++) await rows.addPasskey(db.owner, deps.chainKey, DANA);
  // The tenth, its reply lost: sent again, it is the one added, not one too many (review r1 of #539).
  const tenth = await act(dana, 'POST', `/api/members/user:${DANA}/passkeys/options`);
  const made = await (await SoftAuthenticator.create('ES256')).register({ ...RP, challenge: bytes(tenth.body.options.challenge), userHandle: bytes(tenth.body.options.user.id) });
  assert.equal((await act(dana, 'POST', `/api/members/user:${DANA}/passkeys`, { state: tenth.body.state, response: made })).status, 200);
  assert.deepEqual(refused(await act(dana, 'POST', `/api/members/user:${DANA}/passkeys`, { state: tenth.body.state, response: made })), [409, 'conflict', 'passkey_exists']);
  assert.deepEqual(refused(await act(dana, 'POST', `/api/members/user:${DANA}/passkeys/options`)), [409, 'conflict', 'too_many_passkeys']);
});

test('a passkey is named by its provider where its AAGUID names one, else by how many the person has had', () => {
  assert.equal(passkeyName(new Uint8Array(Buffer.from('fbfc3007154e4ecc8c0b6e020557d7bd', 'hex')), 0), 'Apple Passwords');
  assert.equal(passkeyName(new Uint8Array(16), 2), 'Passkey 3');
  assert.equal(passkeyName(null, 0), 'Passkey 1');
});

test('removing a passkey takes a touch of one the person keeps, signs them out everywhere else, and gives this browser a new session', async (t) => {
  const { later } = clock(t);
  const yubikey = await SoftAuthenticator.create('ES256');
  const phone = await SoftAuthenticator.create('ES256', { synced: true });
  const bob = await enroll(runtime, BOB, yubikey);
  assert.equal((await add(bob, BOB, phone)).status, 200);
  const [kept, removed] = [(await listed(bob, BOB)).passkeys[1]!, (await listed(bob, BOB)).passkeys[0]!];
  // Elsewhere: another browser, signed in with the YubiKey, and a terminal. Each touch a moment after the one before:
  // a challenge no newer than the last one answered is a replay (section 7.3).
  later(1);
  const laptop = await touch(runtime, BOB, yubikey);
  const terminal = await rows.confirmedSession(db.owner, deps.chainKey, BOB, removed.id);
  const token = await act(bob, 'POST', `/api/members/user:${BOB}/tokens`, { label: 'agent', expiresInMinutes: 60, scope: { market: 'viewer' } });
  assert.equal(token.status, 200, JSON.stringify(token.body));
  const handle = await act(bob, 'POST', '/api/handles', { label: 'agent', paths: ['market/prod'] });
  assert.equal(handle.status, 200, JSON.stringify(handle.body));
  // A terminal code approved with the passkey removed, not yet redeemed, and an app connected with it (review r1 of #529).
  const approval = await rows.approvedCode(db.owner, deps.chainKey, BOB, removed.id);
  const app = await rows.connectedApp(db.owner, deps.chainKey, BOB, removed.id);
  assert.deepEqual((await listed(bob, BOB)).ends, { sessions: 2, tokens: 1, handles: 1, apps: 1 });

  // What the door asks: a touch of the one kept, never of the one removed.
  later(1);
  const step = await bob.step(`?remove=${removed.id}`);
  assert.equal(step.status, 200, JSON.stringify(step.body));
  assert.deepEqual(step.body.options.allowCredentials.map((d: { id: string }) => d.id), [Buffer.from(phone.credentialId).toString('base64url')]);
  assert.deepEqual(await bob.answer({ state: step.body.state, response: await assertion(yubikey, step.body.options) }), { status: 401, body: { error: 'passkey_failed' } });

  const before = bob.session!;
  assert.deepEqual(await bob.answer({ state: step.body.state, response: await assertion(phone, step.body.options) }), { status: 200, body: { next: '/account/passkeys' } });
  assert.notEqual(bob.session, before);
  // This browser: a new session, confirmed now by the passkey touched. Everywhere else, and the old cookie, ended.
  const row = await sessionRow(bob);
  assert.deepEqual([row.passkeyId, row.confirmedAt?.getTime()], [kept.id, Date.now()]);
  assert.equal(await me(bob), 'ok');
  const copy = new Browser(runtime);
  copy.jar.set('__Host-coffre_session', before);
  assert.equal(await me(copy), 'unauthenticated');
  assert.equal(await me(laptop), 'unauthenticated');
  for (const ended of [terminal, token.body.token, handle.body.token]) {
    const [row] = await db.owner.select().from(credentials).where(eq(credentials.tokenHash, hashToken(ended)));
    assert.notEqual(row!.revokedAt, null);
  }
  // The code, denied, names neither person nor passkey, and redeems nothing; the app, disconnected.
  assert.deepEqual(await endedRows(approval.id, app), { decision: 'denied', passkeyId: null, connectionRevoked: true });
  assert.equal(await redeems(approval.deviceCode), false);
  assert.deepEqual((await listed(bob, BOB)).passkeys.map((row) => row.id), [kept.id]);
  const [entry] = await entries('passkey.remove');
  assert.deepEqual([entry!.decision, entry!.metadata.passkeyId, entry!.metadata.touched, entry!.metadata.ended], ['allow', removed.id, kept.id, { credentials: 5, connections: 1, approvals: 1 }]);
  // The removed passkey signs nobody in.
  const again = new Browser(runtime);
  assert.equal(await again.provider(BOB), '/auth/passkey');
  const signin = await again.step();
  assert.deepEqual(signin.body.options.allowCredentials.map((d: { id: string }) => d.id), [Buffer.from(phone.credentialId).toString('base64url')]);
  assert.equal((await again.answer({ response: await assertion(yubikey, signin.body.options) })).status, 401);
  // The same answer again: its session ended with it.
  assert.equal((await bob.answer({ state: step.body.state, response: await assertion(phone, step.body.options) })).status, 401);
});

test("the last passkey: under `optional` a touch of it removes it and leaves a session naming none; under `required` it stays; under `off` none is asked", async (t) => {
  const { later } = clock(t);
  const key = await SoftAuthenticator.create('ES256');
  const bob = await enroll(runtime, BOB, key);
  later(1);
  const [only] = (await listed(bob, BOB)).passkeys;

  // Under `required`, the last one stays: add another first.
  const strict = signinDeployment(deps, 'required');
  bob.runtime = strict;
  assert.deepEqual(await bob.step(`?remove=${only!.id}`), { status: 409, body: { error: 'last_passkey' } });
  bob.runtime = runtime;

  // Under `optional`, a touch of the last one, and the new session names none: the provider alone signs them in again.
  const step = await bob.step(`?remove=${only!.id}`);
  assert.deepEqual(step.body.options.allowCredentials.map((d: { id: string }) => d.id), [Buffer.from(key.credentialId).toString('base64url')]);
  // A state asked under `optional` removes nothing once the deployment says `required`.
  bob.runtime = strict;
  assert.equal((await bob.answer({ state: step.body.state, response: await assertion(key, step.body.options) })).status, 409);
  bob.runtime = runtime;
  assert.equal((await bob.answer({ state: step.body.state, response: await assertion(key, step.body.options) })).status, 200);
  const row = await sessionRow(bob);
  assert.deepEqual([row.passkeyId, row.confirmedAt], [null, null]);
  assert.equal(await me(bob), 'ok');
  assert.deepEqual((await listed(bob, BOB)).passkeys, []);

  // Under `off`, no touch: Dana removes hers with her session alone.
  const dana = await enroll(runtime, DANA, await SoftAuthenticator.create('ES256'));
  const [hers] = (await listed(dana, DANA)).passkeys;
  dana.runtime = signinDeployment(deps, 'off');
  const off = await dana.step(`?remove=${hers!.id}`);
  assert.equal(off.body.options, null);
  assert.deepEqual(await dana.answer({ state: off.body.state }), { status: 200, body: { next: '/account/passkeys' } });
  assert.deepEqual((await listed(dana, DANA)).passkeys, []);
});

test("an Owner of the whole instance resets someone's passkeys from a fresh session, ending everything they are signed in with", async (t) => {
  const { later } = clock(t);
  const danaKey = await SoftAuthenticator.create('ES256');
  const dana = await enroll(runtime, DANA, danaKey);
  const danaPasskey = (await listed(dana, DANA)).passkeys[0]!.id;
  const terminal = await rows.confirmedSession(db.owner, deps.chainKey, DANA, danaPasskey);
  const approval = await rows.approvedCode(db.owner, deps.chainKey, DANA, danaPasskey);
  const app = await rows.connectedApp(db.owner, deps.chainKey, DANA, danaPasskey);
  const bobKey = await SoftAuthenticator.create('ES256');
  let bob = await enroll(runtime, BOB, bobKey);

  // What Bob weighs first: Dana's passkeys, and what a reset ends.
  const weighed = await listed(bob, DANA);
  assert.deepEqual([weighed.passkeys.length, weighed.ends, weighed.reset], [1, { sessions: 2, tokens: 0, handles: 0, apps: 1 }, null]);
  // Never his own, nor someone with none, and only from a fresh session.
  assert.deepEqual(refused(await act(bob, 'DELETE', `/api/members/user:${BOB}/passkeys`)), [403, 'forbidden', 'own_passkeys']);
  assert.deepEqual(refused(await act(bob, 'DELETE', `/api/members/user:${ADA}/passkeys`)), [409, 'conflict', 'no_passkeys']);
  later(FRESH_MS);
  assert.deepEqual(refused(await act(bob, 'DELETE', `/api/members/user:${DANA}/passkeys`)), [403, 'fresh_check_required', undefined]);
  assert.equal(await me(dana), 'ok');

  bob = await touch(runtime, BOB, bobKey);
  const reset = await act(bob, 'DELETE', `/api/members/user:${DANA}/passkeys`);
  assert.deepEqual(reset, { status: 200, body: { reset: 1, ended: { credentials: 2, connections: 1, approvals: 1 } } });
  assert.deepEqual(await endedRows(approval.id, app), { decision: 'denied', passkeyId: null, connectionRevoked: true });
  assert.equal(await redeems(approval.deviceCode), false);
  // Everything Dana was signed in with, ended; her passkey, removed by Bob.
  assert.equal(await me(dana), 'unauthenticated');
  const [cli] = await db.owner.select().from(credentials).where(eq(credentials.tokenHash, hashToken(terminal)));
  assert.notEqual(cli!.revokedAt, null);
  const [row] = await db.owner.select().from(passkeys).where(eq(passkeys.principal, `user:${DANA}`));
  assert.deepEqual([row!.removedBy, row!.removedAt?.getTime()], [BOB, Date.now()]);
  const [denial, entry] = await entries('passkey.reset');
  assert.deepEqual([denial!.decision, denial!.metadata.reason], ['deny', 'own_passkeys']);
  assert.deepEqual([entry!.actor.replace('user:', ''), entry!.metadata.principalId, entry!.metadata.passkeys, typeof entry!.metadata.confirmedBy], [BOB, DANA, [row!.id], 'string']);
  // Her passkey signs nobody in; an Owner under `optional` adds a new one at the next sign-in, which says who reset hers.
  const back = new Browser(runtime);
  assert.equal(await back.provider(DANA), '/auth/passkey');
  const step = await back.step();
  assert.deepEqual([step.body.purpose, step.body.reset], ['enroll', { by: BOB, at: new Date(Date.now()).toISOString() }]);
  assert.equal((await back.answer(await register(await SoftAuthenticator.create('ES256'), step.body))).status, 200);
  assert.equal((await listed(back, DANA)).reset, null, 'a passkey added since: the reset is no news');
  assert.deepEqual((await listed(bob, DANA)).passkeys.length, 1);

  // Only an Owner of the whole instance resets: Ada, an Admin, signed in a moment ago with a passkey of her own, may not.
  const ada = new Browser(runtime);
  assert.equal((await ada.fetch('/auth/signin/acme?passkey=add&next=/projects')).status, 302);
  assert.equal((await ada.fetch(`/auth/callback/acme?email=${encodeURIComponent(ADA)}`)).headers.get('location'), '/auth/passkey');
  const adding = await ada.step();
  assert.equal(adding.body.purpose, 'enroll');
  assert.equal((await ada.answer(await register(await SoftAuthenticator.create('ES256'), adding.body))).status, 200);
  const logged = (await entries('passkey.reset')).length;
  // Reading someone's list is no attempt at a reset: refused, and nothing logged as one.
  assert.deepEqual((await act(ada, 'GET', `/api/members/user:${DANA}/passkeys`)).status, 403);
  assert.equal((await entries('passkey.reset')).length, logged);
  assert.deepEqual(refused(await act(ada, 'DELETE', `/api/members/user:${DANA}/passkeys`)), [403, 'forbidden', 'not_owner']);
  const refusals = await entries('passkey.reset');
  assert.deepEqual([refusals.length, refusals.at(-1)!.decision, refusals.at(-1)!.metadata.reason], [logged + 1, 'deny', 'not_owner']);
  assert.equal((await listed(bob, DANA)).passkeys.length, 1);
});

test('a reset shows where its person reads their passkeys until they add one', async (t) => {
  clock(t);
  const dana = await enroll(runtime, DANA, await SoftAuthenticator.create('ES256'));
  const bob = await enroll(runtime, BOB, await SoftAuthenticator.create('ES256'));
  assert.equal((await act(bob, 'DELETE', `/api/members/user:${DANA}/passkeys`)).status, 200);
  void dana;
  // Under `optional`, an Admin's reset would let the provider alone sign them in again; an Owner adds one, so read it
  // from the vault's side here: Bob's view of Dana's names the reset.
  const seen = await listed(bob, DANA);
  assert.deepEqual([seen.passkeys, seen.reset?.by, seen.reset?.at], [[], BOB, new Date(Date.now()).toISOString()]);
});

test("an Owner demoted while resetting someone's passkeys resets nothing: weighed as the vault answers, committed only while still so", async (t) => {
  const { later } = clock(t);
  const dana = await enroll(runtime, DANA, await SoftAuthenticator.create('ES256'));
  const bobKey = await SoftAuthenticator.create('ES256');
  later(1);
  let bob = await enroll(runtime, BOB, bobKey);
  const root = clientFor(deps, ROOT);

  // Demoted after the vault weighed him for the reset, before it commits: 409, asked again.
  onNextAccess(`user:${DANA}`, () => root.members.add(`user:${BOB}`, { role: 'admin' }));
  assert.deepEqual(refused(await act(bob, 'DELETE', `/api/members/user:${DANA}/passkeys`)), [409, 'conflict', 'access_changed']);
  assert.equal((await db.owner.select().from(passkeys).where(eq(passkeys.principal, `user:${DANA}`)))[0]!.removedAt, null);
  assert.equal(await me(dana), 'ok');
  // Asked again, he is weighed as he is now: an Admin, who resets no one.
  assert.deepEqual(refused(await act(bob, 'DELETE', `/api/members/user:${DANA}/passkeys`)), [403, 'forbidden', 'not_owner']);

  // Demoted after his request was let in, before the reset weighs him: an Admin by then, refused.
  await root.members.add(`user:${BOB}`, { role: 'owner' });
  later(1);
  bob = await touch(runtime, BOB, bobKey);
  // The request's own ask answers him as an Owner; he is demoted before the reset weighs him.
  onNextAccess(`user:${BOB}`, () => root.members.add(`user:${BOB}`, { role: 'admin' }), { after: true });
  assert.deepEqual(refused(await act(bob, 'DELETE', `/api/members/user:${DANA}/passkeys`)), [403, 'forbidden', 'not_owner']);
  assert.equal((await db.owner.select().from(passkeys).where(eq(passkeys.principal, `user:${DANA}`)))[0]!.removedAt, null);
  assert.equal(await me(dana), 'ok');
});

test('a passkey row failing its MAC refuses adding another and removing one, 409 `tampered`, changing nothing', async (t) => {
  const { later } = clock(t);
  const key = await SoftAuthenticator.create('ES256');
  const bob = await enroll(runtime, BOB, key);
  assert.equal((await add(bob, BOB, await SoftAuthenticator.create('ES256'))).status, 200);
  later(1);
  const [backing, other] = (await listed(bob, BOB)).passkeys;
  // The one behind the session stays whole; the other's signature no longer matches it.
  await db.owner.update(passkeys).set({ algorithm: -257 }).where(eq(passkeys.id, other!.id));
  assert.deepEqual(refused(await act(bob, 'POST', `/api/members/user:${BOB}/passkeys/options`)), [409, 'conflict', 'tampered']);
  assert.deepEqual(await bob.step(`?remove=${backing!.id}`), { status: 409, body: { error: 'tampered' } });
  assert.deepEqual(await bob.step(`?remove=${other!.id}`), { status: 409, body: { error: 'tampered' } });
  assert.equal((await db.owner.select().from(passkeys).where(eq(passkeys.principal, `user:${BOB}`))).filter((row) => row.removedAt === null).length, 2);
  assert.equal(await me(bob), 'ok');
});

test('a passkey row that fails its MAC by the time an add, a removal or a reset commits refuses it, 409 `tampered`, changing nothing', async (t) => {
  const { later } = clock(t);
  const key = await SoftAuthenticator.create('ES256');
  const bob = await enroll(runtime, BOB, key);
  assert.equal((await add(bob, BOB, await SoftAuthenticator.create('ES256'))).status, 200);
  later(1);
  const [, other] = (await listed(bob, BOB)).passkeys;
  // Both asked while every row is whole: another passkey's `create()`, and the removal of one with a touch of the other.
  const asked = await act(bob, 'POST', `/api/members/user:${BOB}/passkeys/options`);
  const created = await (await SoftAuthenticator.create('ES256')).register({ ...RP, challenge: bytes(asked.body.options.challenge), userHandle: bytes(asked.body.options.user.id) });
  const step = await bob.step(`?remove=${other!.id}`);
  assert.equal(step.status, 200);
  const touched = await assertion(key, step.body.options);
  // Then a row's signature stops matching, before either answer arrives.
  await db.owner.update(passkeys).set({ algorithm: -257 }).where(eq(passkeys.id, other!.id));
  assert.deepEqual(refused(await act(bob, 'POST', `/api/members/user:${BOB}/passkeys`, { state: asked.body.state, response: created })), [409, 'conflict', 'tampered']);
  assert.deepEqual(await bob.answer({ state: step.body.state, response: touched }), { status: 409, body: { error: 'tampered' } });
  // Dana, an Owner, resets Bob's: refused the same.
  const dana = await enroll(runtime, DANA, await SoftAuthenticator.create('ES256'));
  assert.deepEqual(refused(await act(dana, 'DELETE', `/api/members/user:${BOB}/passkeys`)), [409, 'conflict', 'tampered']);
  assert.equal((await db.owner.select().from(passkeys).where(eq(passkeys.principal, `user:${BOB}`))).filter((row) => row.removedAt === null).length, 2);
  assert.equal(await me(bob), 'ok');
});
