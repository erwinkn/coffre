// Signing in with a passkey (docs/design/passkeys.md, sections 3.1, 3.2, 6.1,
// 6.2 and 7), on both engines, through the deployment's own routes, as a
// browser goes: to the provider and back, to the passkey page's question,
// and its answer, made by a software authenticator. The callback writes
// nothing; a touch issues a session its passkey confirmed, once; a first
// passkey ends what no passkey stood behind; a step-up replaces the session
// it came in on.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';

import { SoftAuthenticator, type Tweak } from '@coffre/conformance/authenticator';
import { defineSignin, SigninError, type PasskeysOptions, type SigninProvider } from '@coffre/core/identity';
import type { Vault } from '@coffre/core/vault';
import { and, eq, isNull } from 'drizzle-orm';

import { CEREMONY_TTL_SECONDS, CeremonyStates, creationOptions, remainingMs, requestOptions, type StepUpState } from '../src/api/ceremony.ts';
import { SigninService } from '../src/api/signin.ts';
import { coffreRoute } from '../src/app.ts';
import type { CoffreRuntime } from '../src/runtime.ts';
import { clientFor, openTestDatabase, resetDatabase, testDeps, testVault, waitUntil, type FixtureDeps } from './api-fixture.ts';
import { auditLog, credentials, deviceAuthorizations, identities, passkeys, vaultMembers } from './db/tables.ts';
import * as rows from './passkey-rows.ts';

const ORIGIN = 'https://secrets.acme.example';
const ROOT = 'admin@acme.example';
/** An Owner the deployment names whom no sign-in has admitted yet. */
const NAMED = 'named@acme.example';
/** An Owner a later configuration names, whom no vault has declared yet. */
const LATER = 'later@acme.example';
const ADA = 'ada@acme.example';
const BOB = 'bob@acme.example';

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;
let kek: Buffer;

before(async () => {
  db = await openTestDatabase();
});

after(async () => {
  await db.close();
});

beforeEach(async () => {
  await resetDatabase(db.owner);
  // NAMED: an Owner the deployment's configuration names beside ROOT, whom the vault declares as it starts (R3).
  kek = randomBytes(32);
  deps = testDeps(db.runtime, [ROOT], { vault: testVault([ROOT], { owners: [ROOT, NAMED] }, { kek }) });
  const root = clientFor(deps, ROOT);
  await root.members.add(`user:${ADA}`, { role: 'developer' });
  await root.members.add(`user:${BOB}`, { role: 'owner' });
});

/** A provider of the test's own: it asks nothing, and vouches for the email the callback names. */
function provider(issuer = 'https://idp.acme.example'): SigninProvider {
  return {
    id: 'acme',
    issuer,
    label: 'Acme',
    brand: 'oidc',
    start: async () => ({ url: new URL(`${issuer}/authorize`), pending: { state: 'state', codeVerifier: 'verifier', nonce: null } }),
    finish: async (callback) => {
      const email = callback.searchParams.get('email');
      if (email === null) throw new SigninError('provider_denied', 'no email');
      return { subject: email, emails: [email], name: callback.searchParams.get('name') ?? email.split('@')[0]! };
    },
  };
}

/** The deployment under `passkeys`: its runtime, which answers coffre's own routes. */
function deployment(passkeys: PasskeysOptions, issuer?: string, vault: Vault = deps.vault) {
  const config = defineSignin({ publicUrl: ORIGIN, providers: [provider(issuer)], passkeys });
  const signin = new SigninService({ db: deps.db, chainKey: deps.chainKey, vault, signin: config });
  return {
    db: deps.db, vault, chainKey: deps.chainKey, previousChainKeys: [], signin, workloads: null, mcp: null,
    auth: { mode: 'signin', signin: config }, publicUrl: ORIGIN, verifier: signin, waitUntil,
    schema: { migrated: true }, appKey: { settled: true }, rotateAfterDays: 365, plugins: [],
  } as unknown as CoffreRuntime;
}

/** A browser at the deployment: its cookies, and its requests, which coffre's routes answer. */
class Browser {
  readonly jar = new Map<string, string>();
  runtime: CoffreRuntime;

  constructor(runtime: CoffreRuntime) {
    this.runtime = runtime;
  }

  async fetch(path: string, init: RequestInit = {}): Promise<Response> {
    const headers = new Headers(init.headers);
    if (this.jar.size > 0) headers.set('cookie', [...this.jar].map(([name, value]) => `${name}=${value}`).join('; '));
    if (init.method === 'POST') headers.set('origin', ORIGIN);
    const response = await coffreRoute(new Request(new URL(path, ORIGIN), { ...init, headers }), this.runtime, null);
    assert.ok(response !== null, `${path} is coffre's`);
    for (const cookie of response.headers.getSetCookie()) {
      const [pair = ''] = cookie.split(';');
      const at = pair.indexOf('=');
      if (/max-age=0/i.test(cookie) || pair.slice(at + 1) === '') this.jar.delete(pair.slice(0, at));
      else this.jar.set(pair.slice(0, at), pair.slice(at + 1));
    }
    return response;
  }

  get session(): string | undefined {
    return this.jar.get('__Host-coffre_session');
  }

  /** To the provider and back: where the callback sends the browser. */
  async provider(email: string): Promise<string> {
    const leave = await this.fetch('/auth/signin/acme?next=/projects/market');
    assert.equal(leave.status, 302);
    const back = await this.fetch(`/auth/callback/acme?email=${encodeURIComponent(email)}`);
    assert.equal(back.status, 302, await back.clone().text());
    return back.headers.get('location')!;
  }

  /** What the passkey page asks for. */
  async step(query = ''): Promise<{ status: number; body: any }> {
    const response = await this.fetch(`/api/auth/passkey${query}`);
    return { status: response.status, body: await response.json() };
  }

  /** The page's answer. */
  async answer(body: unknown): Promise<{ status: number; body: any }> {
    const response = await this.fetch('/api/auth/passkey', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
    return { status: response.status, body: await response.json() };
  }
}

const RP = { rpId: 'secrets.acme.example', origin: ORIGIN };
const bytes = (value: string) => new Uint8Array(Buffer.from(value, 'base64url'));

/** `create()` of a step's options, answered by `key`: the page's answer, with the step's sealed user handle. */
async function register(key: SoftAuthenticator, step: any, tweak?: Tweak) {
  const response = await key.register({ ...RP, challenge: bytes(step.options.challenge), userHandle: bytes(step.options.user.id) }, tweak);
  return { response, state: step.state };
}

/** `get()`, answered by `key`. */
function assertion(key: SoftAuthenticator, options: any, tweak?: Tweak) {
  return key.assert({ ...RP, challenge: bytes(options.challenge) }, tweak);
}

/** Sign in as `email`, adding `key` as their first passkey on the way: the browser, with its session. */
async function enroll(runtime: CoffreRuntime, email: string, key: SoftAuthenticator): Promise<Browser> {
  const browser = new Browser(runtime);
  assert.equal(await browser.provider(email), '/auth/passkey');
  const step = await browser.step();
  assert.equal(step.body.purpose, 'enroll');
  const done = await browser.answer(await register(key, step.body));
  assert.deepEqual(done, { status: 200, body: { next: '/projects/market' } });
  return browser;
}

/** Sign in as `email` with a touch of `key`. */
async function touch(runtime: CoffreRuntime, email: string, key: SoftAuthenticator): Promise<Browser> {
  const browser = new Browser(runtime);
  assert.equal(await browser.provider(email), '/auth/passkey');
  const step = await browser.step();
  assert.equal(step.body.purpose, 'signin');
  assert.deepEqual(await browser.answer({ response: await assertion(key, step.body.options) }), { status: 200, body: { next: '/projects/market' } });
  return browser;
}

/** What `/api/me` answers the browser: 200, or the error's code. */
async function me(browser: Browser): Promise<string> {
  const response = await browser.fetch('/api/me');
  return response.ok ? 'ok' : ((await response.json()) as { error: string }).error;
}

async function sessionRow(browser: Browser) {
  const { hashToken } = await import('@coffre/core/identity');
  const [row] = await db.owner.select().from(credentials).where(eq(credentials.tokenHash, hashToken(browser.session!)));
  return row!;
}

async function counts() {
  const [members, bound, keys, sessions] = await Promise.all([
    db.owner.select().from(vaultMembers),
    db.owner.select().from(identities),
    db.owner.select().from(passkeys),
    db.owner.select().from(credentials),
  ]);
  return { members: members.length, bound: bound.length, keys: keys.length, sessions: sessions.length };
}

test('under optional, a Developer with no passkey signs in by the provider alone; an Owner of the whole instance adds one first (section 2)', async () => {
  const runtime = deployment('optional');
  const ada = new Browser(runtime);
  assert.equal(await ada.provider(ADA), '/projects/market');
  assert.equal(await me(ada), 'ok');
  assert.equal(ada.jar.has('__Host-coffre_passkey'), false);

  const bob = new Browser(runtime);
  assert.equal(await bob.provider(BOB), '/auth/passkey', 'an unscoped Owner adds a passkey at sign-in');
  assert.equal(bob.session, undefined, 'and has no session before it');
  assert.equal((await bob.step()).body.purpose, 'enroll');
});

/**
 * A deployment that names LATER an Owner too, now: a vault of that configuration, over the same database and keys,
 * which declares them as it starts (R3), and that vault as a cold isolate's callback meets it, its `about` answered as
 * the configuration says without it starting (review r1 of #500).
 */
function laterOwner() {
  const later = testVault([ROOT], { owners: [ROOT, NAMED, LATER] }, { kek });
  const cold = new Proxy(later, {
    get(target, key) {
      if (key === 'about') return async () => ({ ...(await deps.vault.about()), owners: [ROOT, NAMED, LATER] });
      return Reflect.get(target, key, target);
    },
  });
  return { later, cold };
}

test("an Owner the deployment names, never admitted, passes the provider and stops: the callback writes nothing, the vault's members included; the passkey's answer admits and enrolls them, and they sign in again with it (sections 3.1, 13.22, 13.27)", async () => {
  // The deployment names LATER too, now: a vault of that configuration, over the same database and keys, which
  // declares them as it starts (R3). On a cold isolate the callback reads the members beside the vault's first call,
  // whose start lands after: here, its `about`, which settles it, answered as the configuration says without it, and
  // the vault started by the post's own call. Held first (review r1 of #500): named, and no row of theirs.
  const { cold } = laterOwner();
  const runtime = deployment('required', undefined, cold);
  assert.ok((await cold.about()).owners?.includes(LATER), 'the deployment names them an Owner');
  assert.deepEqual(await db.owner.select().from(vaultMembers).where(eq(vaultMembers.principal, `user:${LATER}`)), [], 'no row of theirs');
  const before = await counts();
  const browser = new Browser(runtime);
  assert.equal(await browser.provider(LATER), '/auth/passkey');
  const sealed = runtime.signin!.ceremonies.open(browser.jar.get('__Host-coffre_passkey') ?? null, ['signin', 'enroll']);
  assert.equal(sealed?.generation, 0, "the step names a first admission's generation: no row is theirs yet");
  const step = await browser.step();
  assert.equal(step.status, 200);
  assert.equal(step.body.purpose, 'enroll');
  assert.equal(step.body.email, LATER);
  assert.equal(step.body.options.rp.id, 'secrets.acme.example');
  assert.equal(step.body.options.authenticatorSelection.userVerification, 'required');
  assert.deepEqual(step.body.options.pubKeyCredParams.map(({ alg }: { alg: number }) => alg), [-8, -7, -257]);
  assert.deepEqual(await counts(), before, 'nothing written before the passkey answered');

  const key = await SoftAuthenticator.create('ES256');
  const done = await browser.answer(await register(key, step.body));
  assert.deepEqual(done, { status: 200, body: { next: '/projects/market' } });
  assert.equal(browser.jar.has('__Host-coffre_passkey'), false, 'the pending cookie is cleared');
  assert.equal(await me(browser), 'ok');
  const session = await sessionRow(browser);
  const [added] = await db.owner.select().from(passkeys).where(eq(passkeys.principal, `user:${LATER}`));
  assert.equal(session.passkeyId, added!.id);
  assert.ok(session.confirmedAt !== null, 'a touch confirmed it');
  assert.equal(Buffer.from(added!.userHandle).toString('base64url'), step.body.options.user.id, 'the handle create() was given is the row\'s');
  const actions = (await db.owner.select().from(auditLog)).map((entry) => entry.action);
  for (const action of ['account.link', 'passkey.add', 'sign_in']) assert.ok(actions.includes(action), action);

  // Again, with the passkey added there.
  const again = await touch(runtime, LATER, key);
  assert.equal(await me(again), 'ok');
  assert.equal((await sessionRow(again)).passkeyId, added!.id);
});

test("an enrollment begun before an Owner's first admission adds nothing once they were admitted, removed and admitted again: it was for their first membership, never a later one (section 3.1; review r3 of #500)", async () => {
  const { later, cold } = laterOwner();
  const runtime = deployment('required', undefined, cold);
  const browser = new Browser(runtime);
  assert.equal(await browser.provider(LATER), '/auth/passkey');
  const step = await browser.step();
  assert.equal(step.body.purpose, 'enroll');

  // Within its five minutes: the vault admits them at generation 0, a deployment that no longer names them removes
  // them, and an Owner adds them back, at the generation their removal left, 1.
  assert.equal((await later.access(`user:${LATER}`)).generation, 0);
  const root = clientFor(deps, ROOT);
  await root.members.remove(`user:${LATER}`);
  await root.members.add(`user:${LATER}`, { role: 'owner' });
  const [row] = await db.owner.select().from(vaultMembers).where(eq(vaultMembers.principal, `user:${LATER}`));
  assert.deepEqual([row!.status, row!.generation], ['active', 1]);
  const before = await counts();

  const done = await browser.answer(await register(await SoftAuthenticator.create('ES256'), step.body));
  assert.deepEqual(done, { status: 400, body: { error: 'state_mismatch' } });
  assert.equal(browser.session, undefined, 'no session');
  assert.deepEqual(await counts(), before, 'no passkey, no session, nothing bound');
});

test('a touch signs in once: the same assertion again, a key of another person, another origin, or no user verification signs nobody in (sections 7.2, 7.3, 13.1-13.6)', async () => {
  const runtime = deployment('required');
  const key = await SoftAuthenticator.create('Ed25519');
  await enroll(runtime, NAMED, key);
  const other = await SoftAuthenticator.create('ES256');
  await enroll(runtime, BOB, other);

  const browser = new Browser(runtime);
  await browser.provider(NAMED);
  const { body } = await browser.step();
  assert.equal(body.options.allowCredentials.length, 1);
  assert.equal(body.options.userVerification, 'required');
  for (const [why, response] of [
    ["Bob's passkey", await assertion(other, body.options)],
    ['another origin', await assertion(key, body.options, { clientData: { origin: 'https://evil.acme.example' } })],
    ['another RP ID', await assertion(key, body.options, { rpId: 'evil.example' })],
    ['presence alone', await assertion(key, body.options, { flags: 0x01 })],
  ] as const) {
    assert.deepEqual(await browser.answer({ response }), { status: 401, body: { error: 'passkey_failed' } }, why);
    assert.equal(browser.session, undefined, why);
  }
  const answer = await assertion(key, body.options);
  assert.equal((await browser.answer({ response: answer })).status, 200, 'a failed answer leaves the sign-in to try again');
  assert.equal(await me(browser), 'ok');
});

test("the same assertion, sent twice with its sealed state, signs in once (sections 7.3, 13.3)", async () => {
  const runtime = deployment('required');
  const key = await SoftAuthenticator.create('ES256');
  await enroll(runtime, NAMED, key);
  const browser = new Browser(runtime);
  await browser.provider(NAMED);
  const cookie = browser.jar.get('__Host-coffre_passkey')!;
  const response = await assertion(key, (await browser.step()).body.options);
  const twice = [new Browser(runtime), new Browser(runtime)];
  for (const copy of twice) copy.jar.set('__Host-coffre_passkey', cookie);
  const answers = await Promise.all(twice.map((copy) => copy.answer({ response })));
  assert.deepEqual(answers.map(({ status, body }) => `${status} ${body.error ?? ''}`).sort(), ['200 ', '400 state_mismatch']);
});

test("a touch whose sign-in committed but whose answer was lost ends that sign-in at the next touch, which cannot pass, and a new one signs in (section 7.3; review r5 of #500)", async () => {
  const runtime = deployment('required');
  const key = await SoftAuthenticator.create('ES256');
  await enroll(runtime, NAMED, key);
  const browser = new Browser(runtime);
  await browser.provider(NAMED);
  const { body } = await browser.step();
  // Committed, its answer and cookies lost on the way (a gateway's 502, say): the browser is as it was before it.
  const before = new Map(browser.jar);
  assert.equal((await browser.answer({ response: await assertion(key, body.options) })).status, 200);
  browser.jar.clear();
  for (const [name, value] of before) browser.jar.set(name, value);

  // The page asks for another touch: it signs the spent challenge, and ends the sign-in rather than ask again.
  assert.deepEqual(await browser.answer({ response: await assertion(key, body.options) }), { status: 400, body: { error: 'state_mismatch' } });
  assert.equal(browser.jar.get('__Host-coffre_passkey'), undefined, 'the pending sign-in is cleared');
  assert.equal(browser.session, undefined);
  assert.equal((await browser.step()).status, 404, 'nothing to ask: the page sends the person to sign in again');

  assert.equal(await browser.provider(NAMED), '/auth/passkey');
  const again = await browser.step();
  assert.equal((await browser.answer({ response: await assertion(key, again.body.options) })).status, 200);
  assert.equal(await me(browser), 'ok');
});

test("a first passkey whose enrollment committed but whose answer was lost, sent again as the page sends it, ends that sign-in, and is the one the person signs in with (section 3.2; review r7 of #500)", async () => {
  const runtime = deployment('required');
  const key = await SoftAuthenticator.create('ES256');
  const browser = new Browser(runtime);
  assert.equal(await browser.provider(ADA), '/auth/passkey');
  const { body } = await browser.step();
  const answer = await register(key, body);
  // Committed, its answer and cookies lost on the way: the browser is as it was before it.
  const before = new Map(browser.jar);
  assert.equal((await browser.answer(answer)).status, 200);
  browser.jar.clear();
  for (const [name, value] of before) browser.jar.set(name, value);

  // The page sends the same passkey again, not a new one: the step ends, nothing more is added or issued.
  const { keys, sessions } = await counts();
  assert.deepEqual(await browser.answer(answer), { status: 400, body: { error: 'passkey_exists' } });
  assert.equal(browser.jar.get('__Host-coffre_passkey'), undefined, 'the pending sign-in is cleared');
  assert.equal(browser.session, undefined);
  assert.deepEqual(await counts().then(({ keys, sessions }) => ({ keys, sessions })), { keys, sessions });

  // The key on the device is the one coffre holds.
  assert.equal(await me(await touch(runtime, ADA, key)), 'ok');
});

test("each GET of an enrollment's options draws its own user handle, sealed in its state: two tabs never hand create() the same one, and the row stores the handle of the create() that answered (section 3.2; D173, reviews r7 to r12 of #500)", async () => {
  const runtime = deployment('required');
  const browser = new Browser(runtime);
  assert.equal(await browser.provider(ADA), '/auth/passkey');
  const cookie = browser.jar.get('__Host-coffre_passkey')!;
  const first = (await browser.step()).body;
  const second = (await browser.step()).body;
  assert.equal(first.options.challenge, second.options.challenge, 'one enrollment, one challenge');
  assert.notEqual(first.options.user.id, second.options.user.id, 'but a user handle for each create()');
  assert.equal(Buffer.from(first.options.user.id, 'base64url').length, 16);

  // No state, or another enrollment's, is no answer of coffre's page: refused before anything is written.
  const before = await counts();
  const key = await SoftAuthenticator.create('ES256');
  const { response } = await register(key, first);
  assert.deepEqual(await browser.answer({ response }), { status: 400, body: { error: 'state_mismatch' } });
  browser.jar.set('__Host-coffre_passkey', cookie);
  const elsewhere = new Browser(runtime);
  await elsewhere.provider(ADA);
  const foreign = (await elsewhere.step()).body.state;
  assert.deepEqual(await browser.answer({ response, state: foreign }), { status: 400, body: { error: 'state_mismatch' } });
  assert.deepEqual(await counts(), before);

  // The first tab's passkey is added, under its own handle.
  browser.jar.set('__Host-coffre_passkey', cookie);
  assert.equal((await browser.answer({ response, state: first.state })).status, 200);
  const [added] = await db.owner.select().from(passkeys).where(eq(passkeys.principal, `user:${ADA}`));
  assert.equal(Buffer.from(added!.userHandle).toString('base64url'), first.options.user.id);

  // The second tab's create(), another handle, replaces nothing on the device; coffre adds nothing for it.
  const tab = new Browser(runtime);
  tab.jar.set('__Host-coffre_passkey', cookie);
  assert.deepEqual(await tab.answer(await register(await SoftAuthenticator.create('ES256'), second)), { status: 400, body: { error: 'passkey_exists' } });
  assert.equal((await db.owner.select().from(passkeys).where(eq(passkeys.principal, `user:${ADA}`))).length, 1);
  assert.equal(await me(await touch(runtime, ADA, key)), 'ok', 'the first passkey signs in');
});

test('a first passkey ends everything of the person\'s no passkey stood behind, approved device codes included; the sign-in that adds it does not (sections 6.1, 13.23)', async () => {
  const off = deployment('off');
  const earlier = new Browser(off);
  assert.equal(await earlier.provider(ADA), '/projects/market');
  // A device code Ada approved with that session, not yet redeemed.
  const code = randomUUID();
  const { hashToken } = await import('@coffre/core/identity');
  const { authMac } = await import('../src/auth-rows.ts');
  const generation = (await db.owner.select().from(vaultMembers).where(eq(vaultMembers.principal, `user:${ADA}`)))[0]!.generation;
  const approval = {
    id: randomUUID(), deviceCodeHash: hashToken(code), userCode: 'ABCD-EFGH', decision: 'approved', decidedAt: new Date(), principal: `user:${ADA}`, generation,
    expiresAt: new Date(Date.now() + 600_000), consumedAt: null, passkeyId: null,
  };
  await db.owner.insert(deviceAuthorizations).values({ ...approval, clientLabel: null, clientIp: null, authMac: authMac(deps.chainKey, 'device_authorizations', approval) });

  const runtime = deployment('required');
  const browser = await enroll(runtime, ADA, await SoftAuthenticator.create('RS256'));
  assert.equal(await me(browser), 'ok');
  assert.equal(await me(Object.assign(earlier, { runtime: off })), 'unauthenticated', 'revoked, even under off');
  const [denied] = await db.owner.select().from(deviceAuthorizations).where(eq(deviceAuthorizations.id, approval.id));
  assert.equal(denied!.decision, 'denied');
  const live = await db.owner.select().from(credentials).where(and(eq(credentials.principal, `user:${ADA}`), isNull(credentials.revokedAt)));
  assert.deepEqual(live.map(({ id }) => id), [(await sessionRow(browser)).id], 'the new session alone is left');
  const [added] = (await db.owner.select().from(auditLog)).filter((entry) => entry.action === 'passkey.add');
  assert.deepEqual((JSON.parse(added!.metadata) as { ended: unknown }).ended, { credentials: 1, connections: 0, approvals: 1 });
});

test('an enrollment state adds a first passkey once, ever: again after a reset, within its five minutes, it adds nothing (sections 3.2, 13.13, 13.29)', async () => {
  const runtime = deployment('required');
  const browser = new Browser(runtime);
  await browser.provider(ADA);
  const cookie = browser.jar.get('__Host-coffre_passkey')!;
  const step = (await browser.step()).body;
  assert.equal((await browser.answer(await register(await SoftAuthenticator.create(), step))).status, 200);

  const replay = new Browser(runtime);
  replay.jar.set('__Host-coffre_passkey', cookie);
  assert.deepEqual(await replay.answer(await register(await SoftAuthenticator.create(), step)), { status: 400, body: { error: 'passkey_exists' } });

  // An Owner resets it; the saved state is no way back in.
  const [row] = await db.owner.select().from(passkeys).where(eq(passkeys.principal, `user:${ADA}`));
  await rows.removePasskey(db.owner, deps.chainKey, row!.id);
  replay.jar.set('__Host-coffre_passkey', cookie);
  assert.deepEqual(await replay.answer(await register(await SoftAuthenticator.create(), step)), { status: 400, body: { error: 'passkey_exists' } });
  assert.equal((await db.owner.select().from(passkeys).where(eq(passkeys.principal, `user:${ADA}`))).length, 1);
});

test('a profile too long for the cookie that carries it to the passkey is refused, not dropped by the browser unsaid (RFC 6265, section 6.1)', async () => {
  const browser = new Browser(deployment('required'));
  await browser.fetch('/auth/signin/acme?next=/projects/market');
  const back = await browser.fetch(`/auth/callback/acme?email=${encodeURIComponent(ADA)}&name=${'a'.repeat(4096)}`);
  assert.equal(back.status, 302);
  assert.equal(new URL(back.headers.get('location')!, ORIGIN).searchParams.get('error'), 'profile_too_long');
  assert.equal(browser.jar.has('__Host-coffre_passkey'), false);
  // A long name that fits rides whole: nothing cuts it to a length of coffre's own.
  await browser.fetch('/auth/signin/acme?next=/projects/market');
  await browser.fetch(`/auth/callback/acme?email=${encodeURIComponent(ADA)}&name=${'a'.repeat(1000)}`);
  assert.equal((await browser.step()).body.options.user.displayName, 'a'.repeat(1000));
});

test("a pending sign-in whose provider's issuer the deployment replaced completes nothing (sections 3.1, 13.28)", async () => {
  const browser = new Browser(deployment('required'));
  await browser.provider(ADA);
  const step = (await browser.step()).body;
  browser.runtime = deployment('required', 'https://other-idp.acme.example');
  assert.deepEqual(await browser.answer(await register(await SoftAuthenticator.create(), step)), { status: 400, body: { error: 'state_mismatch' } });
  assert.equal(browser.session, undefined);
});

test('a session no passkey stands behind steps up with a touch: a new session, confirmed, ending when the old would have; the old one ends, and a second touch on it signs in nothing (sections 6.2, 6.5, 13.20, 13.21)', async () => {
  const key = await SoftAuthenticator.create('ES256');
  await enroll(deployment('required'), ADA, key);
  // Made while passkeys were off: no passkey stands behind it.
  const browser = new Browser(deployment('off'));
  assert.equal(await browser.provider(ADA), '/projects/market');
  const old = await sessionRow(browser);
  browser.runtime = deployment('optional');
  assert.equal(await me(browser), 'passkey_required');

  const step = await browser.step('?step-up=1&next=/audit');
  assert.equal(step.body.purpose, 'step-up');
  const response = await assertion(key, step.body.options);
  const oldCookies = new Map(browser.jar);
  assert.deepEqual(await browser.answer({ state: step.body.state, response }), { status: 200, body: { next: '/audit' } });
  assert.equal(await me(browser), 'ok');
  const fresh = await sessionRow(browser);
  assert.ok(fresh.confirmedAt !== null && fresh.passkeyId !== null);
  assert.equal(fresh.expiresAt.getTime(), old.expiresAt.getTime(), "the provider sign-in's lifetime, not a new one");
  assert.equal(fresh.identityId, old.identityId);

  const stale = new Browser(browser.runtime);
  for (const [name, value] of oldCookies) stale.jar.set(name, value);
  assert.equal(await me(stale), 'unauthenticated', 'the session it came in on ended');
  const again = await assertion(key, step.body.options);
  assert.deepEqual(await stale.answer({ state: step.body.state, response: again }), { status: 401, body: { error: 'session_ended' } });
  const checks = (await db.owner.select().from(auditLog)).filter((entry) => entry.action === 'passkey.check');
  assert.deepEqual(checks.map(({ decision }) => decision), ['allow']);
});

test('a step-up a newer challenge overtook ends at its touch, keeping the session it came in on: no touch on it could ever count (section 6.5; review r12 of #500)', async () => {
  const key = await SoftAuthenticator.create('ES256');
  await enroll(deployment('required'), ADA, key);
  const browser = new Browser(deployment('off'));
  await browser.provider(ADA);
  const old = await sessionRow(browser);
  browser.runtime = deployment('optional');
  const step = await browser.step('?step-up=1');
  assert.equal(step.body.purpose, 'step-up');
  // Another browser signs in with the same passkey after: its newer challenge moves the replay mark past this one's.
  const elsewhere = new Browser(browser.runtime);
  await elsewhere.provider(ADA);
  assert.deepEqual(await elsewhere.answer({ response: await assertion(key, (await elsewhere.step()).body.options) }), { status: 200, body: { next: '/projects/market' } });
  assert.deepEqual(await browser.answer({ state: step.body.state, response: await assertion(key, step.body.options) }), { status: 400, body: { error: 'state_mismatch' } });
  assert.equal((await sessionRow(browser)).id, old.id, 'the session it came in on stands');
  assert.equal(await me(browser), 'passkey_required');
  // A fresh step-up, a newer challenge, does.
  const again = await browser.step('?step-up=1');
  assert.deepEqual(await browser.answer({ state: again.body.state, response: await assertion(key, again.body.options) }), { status: 200, body: { next: '/projects' } });
  assert.equal(await me(browser), 'ok');
});

test("a touch at sign-in ends the session the browser came in on in its own transaction: a copy of the old cookie is dead even when the sign-out after it fails (section 6.5; review r3 of #500)", async () => {
  const key = await SoftAuthenticator.create('ES256');
  const runtime = deployment('required');
  const browser = await enroll(runtime, ADA, key);
  const copy = new Browser(runtime);
  for (const [name, value] of browser.jar) copy.jar.set(name, value);
  const old = await sessionRow(browser);
  assert.equal(await me(copy), 'ok');

  // The sign-out the route asks after the new session, made to fail: the vault down, or the process gone, then.
  const signin = runtime.signin as unknown as { signOut: () => Promise<void> };
  let signOuts = 0;
  signin.signOut = async () => {
    signOuts++;
    throw new Error('the vault is unreachable');
  };
  assert.equal(await browser.provider(ADA), '/auth/passkey');
  const step = await browser.step();
  assert.equal(step.body.purpose, 'signin');
  assert.deepEqual(await browser.answer({ response: await assertion(key, step.body.options) }), { status: 200, body: { next: '/projects/market' } });
  assert.equal(await me(browser), 'ok');
  assert.notEqual((await sessionRow(browser)).id, old.id);
  assert.equal(await me(copy), 'unauthenticated', 'the old session ended with the new one');
  assert.equal(signOuts, 0, 'nothing left to sign out after');
  const [ended] = await db.owner.select().from(credentials).where(eq(credentials.id, old.id));
  assert.ok(ended!.revokedAt !== null);
});

test('nothing to ask: no pending sign-in, or a step-up for a session whose person holds no passkey, answers 404 (section 3.1)', async () => {
  const runtime = deployment('optional');
  const browser = new Browser(runtime);
  assert.equal((await browser.step()).status, 404);
  assert.equal(await browser.provider(ADA), '/projects/market');
  assert.deepEqual(await browser.step('?step-up=1'), { status: 404, body: { error: 'state_mismatch', message: 'this sign-in expired or was finished elsewhere: sign in again' } });
  const cross = await coffreRoute(new Request(`${ORIGIN}/api/auth/passkey`, { method: 'POST', headers: { origin: 'https://evil.example', 'content-type': 'application/json' }, body: '{"response":{}}' }), runtime, null);
  assert.equal(cross!.status, 403, 'an answer comes from coffre\'s own page');
});

test("a HEAD asks what a GET asks, and answers nothing: it never reads a body, nor ends the sign-in (review r8 of #500)", async () => {
  const runtime = deployment('required');
  const browser = new Browser(runtime);
  assert.equal((await browser.fetch('/api/auth/passkey', { method: 'HEAD' })).status, 404, 'nothing waits: as a GET');
  assert.equal(await browser.provider(ADA), '/auth/passkey');
  assert.equal((await browser.fetch('/api/auth/passkey', { method: 'HEAD' })).status, 200);
  // The sign-in still waits, and completes.
  const step = await browser.step();
  assert.equal(step.body.purpose, 'enroll');
  assert.deepEqual(await browser.answer(await register(await SoftAuthenticator.create('ES256'), step.body)), { status: 200, body: { next: '/projects/market' } });
});

test("a person promoted to an Owner of the whole instance between the callback's answer and its sign-in is asked for a first passkey, not signed in by the provider alone (section 2; review r1 of #500)", async () => {
  const root = clientFor(deps, ROOT);
  // The vault answers about Ada, a Developer, then she is promoted, before the sign-in's transaction.
  let promoted = false;
  const racing = new Proxy(deps.vault, {
    get(target, key) {
      const value: unknown = Reflect.get(target, key, target);
      if (key !== 'access') return value;
      return async (principal: string) => {
        const answer = await (value as Vault['access']).call(target, principal);
        if (principal === `user:${ADA}` && !promoted) {
          promoted = true;
          await root.members.add(`user:${ADA}`, { role: 'owner' });
        }
        return answer;
      };
    },
  });
  const browser = new Browser(deployment('optional', undefined, racing));
  assert.equal(await browser.provider(ADA), '/auth/passkey', 'decided again on the answer that is hers now');
  assert.ok(promoted);
  assert.equal(browser.session, undefined);
  assert.equal((await browser.step()).body.purpose, 'enroll');
  assert.deepEqual(await db.owner.select().from(credentials).where(eq(credentials.principal, `user:${ADA}`)), [], 'nothing issued');
});

test("a new passkey whose credential ID is another person's already is refused as a passkey that did not answer, not a database error (section 3.2; review r1 of #500)", async () => {
  const runtime = deployment('required');
  const key = await SoftAuthenticator.create('ES256');
  await enroll(runtime, NAMED, key);
  const browser = new Browser(runtime);
  assert.equal(await browser.provider(BOB), '/auth/passkey');
  const step = await browser.step();
  // The same authenticator's credential, answering Bob's create(): its ID the one NAMED's passkey has.
  const taken = await browser.answer(await register(key, step.body));
  assert.deepEqual(taken, { status: 401, body: { error: 'passkey_failed' } });
  assert.ok(browser.jar.has('__Host-coffre_passkey'), 'another passkey may be tried while the sign-in lasts');
  assert.equal(browser.session, undefined);
  assert.equal((await db.owner.select().from(passkeys).where(eq(passkeys.principal, `user:${BOB}`))).length, 0);
  const other = await SoftAuthenticator.create('Ed25519');
  const done = await browser.answer(await register(other, (await browser.step()).body));
  assert.deepEqual(done, { status: 200, body: { next: '/projects/market' } });
});

test("a passkey's removal forged in the database, its MAC left as it was, refuses: neither another first passkey nor the provider alone signs its person in (R64; review r2 of #500)", async () => {
  await enroll(deployment('required'), ADA, await SoftAuthenticator.create());
  // Removed in the database alone: what the app signed says live.
  await db.owner.update(passkeys).set({ removedAt: new Date(), removedBy: `user:${ROOT}` }).where(eq(passkeys.principal, `user:${ADA}`));
  const before = await counts();

  // The callback reads the rows unchecked, and asks for a first passkey; the answer, under the head, reads them checked.
  const again = new Browser(deployment('required'));
  assert.equal(await again.provider(ADA), '/auth/passkey');
  const step = await again.step();
  assert.equal(step.body.purpose, 'enroll');
  assert.deepEqual(await again.answer(await register(await SoftAuthenticator.create(), step.body)), { status: 400, body: { error: 'tampered' } });
  assert.equal(again.session, undefined);

  // Under optional, the callback reads no passkey and signs in by the provider alone, which, under the head, refuses.
  const alone = new Browser(deployment('optional'));
  await alone.fetch('/auth/signin/acme?next=/projects/market');
  const back = await alone.fetch(`/auth/callback/acme?email=${encodeURIComponent(ADA)}`);
  assert.equal(back.headers.get('location'), '/login?error=tampered');
  assert.equal(alone.session, undefined);
  assert.deepEqual(await counts(), before, 'no passkey, session or identity written');
});


test("a session no passkey stands behind is taken under optional only while its person holds none: a removal or a generation forged in the database, its MAC left as it was, does not pass it; the same removal made by the app does (sections 6.2, R64; reviews r3 and r5 of #500)", async () => {
  await enroll(deployment('required'), ADA, await SoftAuthenticator.create());
  // Made while passkeys were off: no passkey stands behind it, and its person holds one.
  const browser = new Browser(deployment('off'));
  assert.equal(await browser.provider(ADA), '/projects/market');
  browser.runtime = deployment('optional');
  assert.equal(await me(browser), 'passkey_required');

  const [held] = await db.owner.select().from(passkeys).where(eq(passkeys.principal, `user:${ADA}`));
  // Moved to another generation in the database alone: no longer live at hers, and no longer removed-at-hers either.
  await db.owner.update(passkeys).set({ generation: held!.generation + 1 }).where(eq(passkeys.id, held!.id));
  assert.equal(await me(browser), 'unauthenticated', 'a forged generation refuses, as a tampered row does');
  await db.owner.update(passkeys).set({ generation: held!.generation }).where(eq(passkeys.id, held!.id));
  assert.equal(await me(browser), 'passkey_required', 'put back, the row is hers again');

  await db.owner.update(passkeys).set({ removedAt: new Date(), removedBy: `user:${ROOT}` }).where(eq(passkeys.id, held!.id));
  assert.equal(await me(browser), 'unauthenticated', 'a forged removal refuses, as a tampered row does');

  await rows.removePasskey(db.owner, deps.chainKey, held!.id);
  assert.equal(await me(browser), 'ok', 'removed by the app, its person holds none');
});

test("a step's options say what is left of its five minutes, from its challenge, which its sealed state lasts as long as: the page asks nothing past it (review r9 of #500)", () => {
  const TTL = CEREMONY_TTL_SECONDS * 1000;
  assert.equal(remainingMs({ issuedAt: 1_000 }, 1_000), TTL);
  assert.equal(remainingMs({ issuedAt: 1_000 }, 61_000), TTL - 60_000);
  assert.equal(remainingMs({ issuedAt: 1_000 }, 1_000 + TTL + 1), 0);

  const config = { policy: 'optional', rpId: 'secrets.acme.example', origin: ORIGIN } as const;
  const state: StepUpState = { purpose: 'step-up', credentialId: randomUUID(), principal: `user:${ADA}`, generation: 0, next: '/', challenge: 'c', issuedAt: Date.now() - 4 * 60_000 };
  for (const { timeout } of [
    requestOptions(config, state, []),
    creationOptions(config, { ...state, userHandle: 'h' }, { email: ADA, name: null, site: 'coffre' }, []),
  ]) {
    assert.ok(timeout <= 60_000 && timeout > 50_000, `about a minute left of five: ${timeout}`);
  }

  const states = new CeremonyStates(randomBytes(32));
  assert.notEqual(states.open(states.seal(state), ['step-up']), null, 'a minute left: it opens');
  assert.equal(states.open(states.seal({ ...state, issuedAt: Date.now() - TTL - 1 }), ['step-up']), null, 'sealed now, but its challenge is older than five minutes');
});
