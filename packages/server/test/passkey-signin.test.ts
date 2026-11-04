// Signing in with a passkey (docs/design/passkeys.md, sections 3.1, 3.2, 6.1,
// 6.2 and 7), on both engines, through the deployment's own routes, as a
// browser goes: to the provider and back, to the passkey page's question,
// and its answer, made by a software authenticator. The callback writes
// nothing; a touch issues a session its passkey confirmed, once; a first
// passkey ends what no passkey stood behind; a step-up replaces the session
// it came in on.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';

import { SoftAuthenticator, type Tweak } from '@coffre/conformance/authenticator';
import { defineSignin, SigninError, type PasskeysOptions, type SigninProvider } from '@coffre/core/identity';
import { and, eq, isNull } from 'drizzle-orm';

import { SigninService } from '../src/api/signin.ts';
import { coffreRoute } from '../src/app.ts';
import type { CoffreRuntime } from '../src/runtime.ts';
import { clientFor, openTestDatabase, resetDatabase, testDeps, waitUntil, type FixtureDeps } from './api-fixture.ts';
import { auditLog, credentials, deviceAuthorizations, identities, passkeys, vaultMembers } from './db/tables.ts';
import * as rows from './passkey-rows.ts';

const ORIGIN = 'https://secrets.acme.example';
const ROOT = 'admin@acme.example';
/** An Owner the deployment names whom no sign-in has admitted yet. */
const NAMED = 'named@acme.example';
const ADA = 'ada@acme.example';
const BOB = 'bob@acme.example';

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;

before(async () => {
  db = await openTestDatabase();
});

after(async () => {
  await db.close();
});

beforeEach(async () => {
  await resetDatabase(db.owner);
  deps = testDeps(db.runtime, [ROOT, NAMED]);
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
function deployment(passkeys: PasskeysOptions, issuer?: string) {
  const config = defineSignin({ publicUrl: ORIGIN, providers: [provider(issuer)], passkeys });
  const signin = new SigninService({ db: deps.db, chainKey: deps.chainKey, vault: deps.vault, signin: config });
  return {
    db: deps.db, vault: deps.vault, chainKey: deps.chainKey, previousChainKeys: [], signin, workloads: null, mcp: null,
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

/** `create()`, answered by `key`. */
function register(key: SoftAuthenticator, options: any, tweak?: Tweak) {
  return key.register({ ...RP, challenge: bytes(options.challenge), userHandle: bytes(options.user.id) }, tweak);
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
  const done = await browser.answer({ response: await register(key, step.body.options) });
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

test("an Owner the deployment names, never admitted, passes the provider and stops: the callback writes nothing, the vault's members included; the passkey's answer admits and enrolls them, and they sign in again with it (sections 3.1, 13.22, 13.27)", async () => {
  const runtime = deployment('required');
  const before = await counts();
  const browser = new Browser(runtime);
  assert.equal(await browser.provider(NAMED), '/auth/passkey');
  const step = await browser.step();
  assert.equal(step.status, 200);
  assert.equal(step.body.purpose, 'enroll');
  assert.equal(step.body.email, NAMED);
  assert.equal(step.body.options.rp.id, 'secrets.acme.example');
  assert.equal(step.body.options.authenticatorSelection.userVerification, 'required');
  assert.deepEqual(step.body.options.pubKeyCredParams.map(({ alg }: { alg: number }) => alg), [-8, -7, -257]);
  assert.deepEqual(await counts(), before, 'nothing written before the passkey answered');

  const key = await SoftAuthenticator.create('ES256');
  const done = await browser.answer({ response: await register(key, step.body.options) });
  assert.deepEqual(done, { status: 200, body: { next: '/projects/market' } });
  assert.equal(browser.jar.has('__Host-coffre_passkey'), false, 'the pending cookie is cleared');
  assert.equal(await me(browser), 'ok');
  const session = await sessionRow(browser);
  const [added] = await db.owner.select().from(passkeys).where(eq(passkeys.principal, `user:${NAMED}`));
  assert.equal(session.passkeyId, added!.id);
  assert.ok(session.confirmedAt !== null, 'a touch confirmed it');
  assert.equal(Buffer.from(added!.userHandle).toString('base64url'), step.body.options.user.id, 'the handle create() was given is the row\'s');
  const actions = (await db.owner.select().from(auditLog)).map((entry) => entry.action);
  for (const action of ['account.link', 'passkey.add', 'sign_in']) assert.ok(actions.includes(action), action);

  // Again, with the passkey added there.
  const again = await touch(runtime, NAMED, key);
  assert.equal(await me(again), 'ok');
  assert.equal((await sessionRow(again)).passkeyId, added!.id);
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
  assert.deepEqual(answers.map(({ status }) => status).sort(), [200, 401]);
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
  assert.equal((await browser.answer({ response: await register(await SoftAuthenticator.create(), step.options) })).status, 200);

  const replay = new Browser(runtime);
  replay.jar.set('__Host-coffre_passkey', cookie);
  assert.deepEqual(await replay.answer({ response: await register(await SoftAuthenticator.create(), step.options) }), { status: 400, body: { error: 'passkey_exists' } });

  // An Owner resets it; the saved state is no way back in.
  const [row] = await db.owner.select().from(passkeys).where(eq(passkeys.principal, `user:${ADA}`));
  await rows.removePasskey(db.owner, deps.chainKey, row!.id);
  replay.jar.set('__Host-coffre_passkey', cookie);
  assert.deepEqual(await replay.answer({ response: await register(await SoftAuthenticator.create(), step.options) }), { status: 400, body: { error: 'passkey_exists' } });
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
  assert.deepEqual(await browser.answer({ response: await register(await SoftAuthenticator.create(), step.options) }), { status: 400, body: { error: 'state_mismatch' } });
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

test('nothing to ask: no pending sign-in, or a step-up for a session whose person holds no passkey, answers 404 (section 3.1)', async () => {
  const runtime = deployment('optional');
  const browser = new Browser(runtime);
  assert.equal((await browser.step()).status, 404);
  assert.equal(await browser.provider(ADA), '/projects/market');
  assert.deepEqual(await browser.step('?step-up=1'), { status: 404, body: { error: 'state_mismatch', message: 'this sign-in expired or was finished elsewhere: sign in again' } });
  const cross = await coffreRoute(new Request(`${ORIGIN}/api/auth/passkey`, { method: 'POST', headers: { origin: 'https://evil.example', 'content-type': 'application/json' }, body: '{"response":{}}' }), runtime, null);
  assert.equal(cross!.status, 403, 'an answer comes from coffre\'s own page');
});
