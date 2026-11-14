// Sign-in's paths on the 0.16 contract (docs/design/0.16.md, "Signing in
// from the server"): the browser's round trip through a provider, linking
// and unlinking an account, signing out, and the device login over HTTP,
// each one call to the vault, with the real vault. Cases from 0.14.7's
// signin-service tests where they still hold.
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { after, beforeEach, test } from 'node:test';

import { cloudflareAccess, SigninError, signin, type SigninProfile, type SigninProvider } from '@coffre/core/identity';
import { rowsOf } from '@coffre/db/dialect';
import { credential, emptyDatabase, identity, instance, principal, role, rows, user, write } from '@coffre/vault/testing';
import { sql, type SQL } from 'drizzle-orm';

import { openApp, PUBLIC_URL, SESSION } from './app-fixture.ts';

const ISSUER = 'https://sso.acme.example';
/** What the provider vouches for, by the code its callback carries. */
const profiles = new Map<string, SigninProfile>();

/** A provider of the test's own: its callback's `code` names the profile it vouches for, and `denied` refuses. */
const acme: SigninProvider = {
  id: 'acme',
  issuer: ISSUER,
  label: 'Acme SSO',
  brand: 'oidc',
  async start(redirectUri) {
    const state = randomUUID();
    return { url: new URL(`${ISSUER}/authorize?${new URLSearchParams({ state, redirect_uri: redirectUri })}`), pending: { state, codeVerifier: 'verifier', nonce: null } };
  },
  async finish(callback, redirectUri, pending) {
    assert.equal(redirectUri, `${PUBLIC_URL}/auth/callback/acme`);
    if (callback.searchParams.get('state') !== pending.state) throw new SigninError('state_mismatch', 'the state does not match');
    const profile = profiles.get(callback.searchParams.get('code') ?? '');
    if (profile === undefined) throw new SigninError('provider_denied', 'the person cancelled');
    return profile;
  },
};

/** A second provider, the same but for its id: a round trip that left for one comes back from it alone. */
const globex: SigninProvider = { ...acme, id: 'globex', label: 'Globex' };

const app = await openApp({ auth: signin({ providers: [acme, globex] }) });
const { world } = app;
after(() => app.close());

const [ada, bo, cy, dee] = [user('ada'), user('bo'), user('cy'), user('dee')];
const hex = (token: string) => createHash('sha256').update(token).digest('hex');

/**
 * Ada, Bo and Dee are members, Cy was removed. Bo and Dee sign in with Acme already,
 * through an account 0.14 bound, as its upgrade leaves it: its issuer the
 * hash of the provider's, byte for byte (`issuer_hash`). He has a browser
 * session on it, a CLI's and a personal token; Ada has a CLI session, Dee a
 * browser's.
 */
let bos: ReturnType<typeof identity>;
async function instanceOf(...more: Parameters<typeof write>[1][]) {
  bos = identity(bo, { provider: 'acme', issuerHash: hex(ISSUER), subject: 'acme-bo', email: 'bo@acme.example' });
  const dees = identity(dee, { provider: 'acme', issuerHash: hex(ISSUER), subject: 'acme-dee' });
  await write(
    world,
    ...rows('policy', instance()),
    ...rows('roles', role(true, 'owner', ['secret.read']), role(true, 'member', [])),
    ...rows('principals', principal(ada), principal(bo), principal(cy, { status: 'removed', generation: 1 }), principal(dee)),
    ...rows('identities', bos, dees),
    ...rows('credentials',
      credential('bo-web', bo, { kind: 'browser', identityId: bos.id }), credential('bo-cli', bo), credential('ada-cli', ada),
      credential('bo-pat', bo, { kind: 'personal', scope: '[]' }), credential('dee-web', dee, { kind: 'browser', identityId: dees.id })),
    ...more,
  );
}
beforeEach(async () => {
  await emptyDatabase(world.owner);
  for (const kept of [world.memory.reads, world.memory.callers, world.memory.logged, world.memory.touched, world.refused]) kept.clear();
  profiles.clear();
  await instanceOf();
  // The schema's question, asked once of a fresh app.
  await app.request('/api/auth');
  app.calls.length = 0;
});

/** What a request cost: the vault's calls and the app's statements. */
async function cost<T>(request: () => Promise<T>): Promise<[T, string[], number]> {
  app.calls.length = 0;
  const before = app.statements;
  const answer = await request();
  return [answer, [...app.calls], app.statements - before];
}

/** The cookies a response sets, by name: their value and their attributes. */
function cookiesOf(response: Response): Record<string, { value: string; attributes: string }> {
  return Object.fromEntries(response.headers.getSetCookie().map((line) => {
    const [pair, ...attributes] = line.split('; ');
    const at = pair!.indexOf('=');
    return [pair!.slice(0, at), { value: pair!.slice(at + 1), attributes: attributes.join('; ') }];
  }));
}

const PENDING = '__Host-coffre_signin';

/**
 * A browser's round trip: leave for Acme (`/auth/signin/acme`), and come
 * back from it with `profile`, the cookies `cookie` names sent both ways.
 * Answers the callback's response.
 */
async function roundTrip(profile: SigninProfile | null, { cookie = '', query = '', tamper }: { cookie?: string; query?: string; tamper?: (pending: string) => string } = {}): Promise<Response> {
  const left = await app.request(`/auth/signin/acme${query}`, { headers: { cookie } });
  assert.equal(left.status, 302, left.headers.get('location') ?? '');
  const location = new URL(left.headers.get('location')!);
  assert.equal(location.origin, ISSUER);
  const pending = cookiesOf(left)[PENDING]!.value;
  const code = randomUUID();
  if (profile !== null) profiles.set(code, profile);
  const back = `/auth/callback/acme?${new URLSearchParams({ state: location.searchParams.get('state')!, code })}`;
  return app.request(back, { headers: { cookie: [`${PENDING}=${tamper?.(pending) ?? pending}`, cookie].filter(Boolean).join('; ') } });
}

const account = (subject: string, ...emails: string[]): SigninProfile => ({ subject, emails, name: null });
/** Where a response sends the browser, and the cookies it sets. */
const landed = (response: Response) => [response.status, response.headers.get('location')];
/** Who a token is, as `GET /api/me` answers it with the session's cookie: their principal, or the error. */
async function whoIs(cookie: string): Promise<string> {
  const response = await app.request('/api/me', { headers: { cookie } });
  const body = (await response.json()) as { principal?: { id: string }; error?: string };
  return body.principal?.id ?? `${response.status} ${body.error}`;
}
const dbRows = <T>(query: SQL) => rowsOf<T>(world.owner, query);

test('the sign-in page reads how the instance signs people in, before anyone is signed in: no vault call, no statement', async () => {
  const [response, calls, statements] = await cost(() => app.request('/api/auth'));
  assert.deepEqual([response.status, calls, statements], [200, [], 0]);
  assert.deepEqual(await response.json(), { signin: { title: 'Sign in to coffre', note: null, providers: [{ id: 'acme', label: 'Acme SSO', brand: 'oidc' }, { id: 'globex', label: 'Globex', brand: 'oidc' }] }, access: null });
  assert.equal((await app.request('/api/auth', { method: 'POST' })).status, 405);
});

test("a first sign-in binds the account by its verified email and opens a browser session: one vault call, no statement of the app's", async () => {
  const [response, calls, statements] = await cost(() => roundTrip(account('acme-ada', 'Ada@Acme.Example'), { query: '?next=/projects/market' }));
  assert.deepEqual(landed(response), [302, '/projects/market']);
  assert.deepEqual([calls, statements], [['change'], 0]);
  const cookies = cookiesOf(response);
  // The pending state goes, whatever the way out; the session comes, for the deployment's 12 hours.
  assert.deepEqual(cookies[PENDING], { value: '', attributes: 'Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Secure' });
  const session = cookies[SESSION]!;
  assert.match(session.value, /^coffre_web_/);
  const maxAge = Number(/Max-Age=(\d+)/.exec(session.attributes)![1]);
  assert.ok(maxAge > 12 * 3600 - 60 && maxAge <= 12 * 3600, session.attributes);
  assert.equal(await whoIs(`${SESSION}=${session.value}`), 'ada@acme.example');
  // Bound by the provider's id, its issuer hashed as 0.14 kept it, and the subject.
  assert.deepEqual(await dbRows(sql`SELECT provider, issuer_hash, subject FROM identities WHERE principal = ${ada}`), [{ provider: 'acme', issuer_hash: hex(ISSUER), subject: 'acme-ada' }]);
  // Where to land is a path of this origin's, or the projects.
  for (const next of ['//evil.example', 'https://evil.example/x', '/login']) {
    assert.deepEqual(landed(await roundTrip(account('acme-ada', 'ada@acme.example'), { query: `?${new URLSearchParams({ next })}` })), [302, '/projects']);
  }
});

test('an account 0.14 bound signs in as its person after the upgrade, and signing in again on a browser ends the session it had', async () => {
  // Bo's account, from before: found by its bytes, whatever its email says today.
  const response = await roundTrip(account('acme-bo', 'bo@elsewhere.example'), { cookie: `${SESSION}=bo-web` });
  assert.deepEqual(landed(response), [302, '/projects']);
  const fresh = cookiesOf(response)[SESSION]!.value;
  assert.equal(await whoIs(`${SESSION}=${fresh}`), 'bo@acme.example');
  // The session the browser showed ended in the same change.
  assert.equal(await whoIs(`${SESSION}=bo-web`), '401 unauthenticated');
  assert.equal(await whoIs(`${SESSION}=bo-cli`), 'bo@acme.example');
});

test('a sign-in refused lands on the sign-in page with its reason, and nothing is bound', async () => {
  const refused = async (profile: SigninProfile | null, more: Parameters<typeof roundTrip>[1] = {}) => {
    const [response, calls] = await cost(() => roundTrip(profile, more));
    assert.equal(cookiesOf(response)[SESSION], undefined);
    assert.equal(cookiesOf(response)[PENDING]?.value, '');
    return [...landed(response), calls.length];
  };
  // Nobody invited ed; an account with no verified email matches nobody, and is told so.
  assert.deepEqual(await refused(account('acme-ed', 'ed@acme.example')), [302, '/login?error=not_registered', 1]);
  assert.deepEqual(await refused(account('acme-ed', 'not an address'), {}), [302, '/login?error=no_verified_email', 1]);
  // Cy was removed.
  assert.deepEqual(await refused(account('acme-cy', 'cy@acme.example')), [302, '/login?error=deactivated', 1]);
  // Bo signs in with an account already: another one of his email's is not bound to him on its word.
  assert.deepEqual(await refused(account('acme-bo-2', 'bo@acme.example')), [302, '/login?error=account_mismatch', 1]);
  // Before the vault asks anything: the person cancelled; the pending state is another browser's, forged, or gone.
  assert.deepEqual(await refused(null), [302, '/login?error=provider_denied', 0]);
  assert.deepEqual(await refused(account('acme-ada', 'ada@acme.example'), { tamper: (pending) => `${pending.slice(0, -2)}AA` }), [302, '/login?error=state_mismatch', 0]);
  // A round trip that left for Acme comes back from Acme: another provider's callback takes none of its state.
  const left = await app.request('/auth/signin/acme');
  profiles.set('elsewhere', account('acme-ada', 'ada@acme.example'));
  const state = new URL(left.headers.get('location')!).searchParams.get('state')!;
  const [crossed, crossedCalls] = await cost(() => app.request(`/auth/callback/globex?state=${state}&code=elsewhere`, { headers: { cookie: `${PENDING}=${cookiesOf(left)[PENDING]!.value}` } }));
  assert.deepEqual([...landed(crossed), crossedCalls], [302, '/login?error=state_mismatch', []]);
  const stranger = await app.request('/auth/callback/acme?state=x&code=y');
  assert.deepEqual(landed(stranger), [302, '/login?error=state_mismatch']);
  assert.deepEqual(landed(await app.request('/auth/signin/github')), [302, '/login?error=unknown_provider']);
  assert.deepEqual(await dbRows(sql`SELECT principal FROM identities ORDER BY principal`), [{ principal: bo }, { principal: dee }]);
  assert.equal((await app.request('/auth/callback/acme', { method: 'POST' })).status, 405);
});

test('before the vault has adopted the database nobody signs in: 503 adopting, asked again in a moment', async () => {
  await emptyDatabase(world.owner);
  await write(world, ...rows('principals', principal(ada)));
  const response = await roundTrip(account('acme-ada', 'ada@acme.example'));
  assert.deepEqual([response.status, response.headers.get('retry-after')], [503, '5']);
  assert.equal(((await response.json()) as { error: string }).error, 'adopting');
  assert.equal(cookiesOf(response)[PENDING]?.value, '');
  assert.equal(cookiesOf(response)[SESSION], undefined);
});

test("a sign-in on a row the vault did not write is a fault: 500 tampered, said once in the server's log by route and request, naming no row", async (t) => {
  const logged = t.mock.method(console, 'error', () => {});
  await world.owner.execute(sql`UPDATE principals SET mac = '\\x'::bytea WHERE id = ${ada}`);
  const response = await roundTrip(account('acme-ada', 'ada@acme.example'));
  const body = (await response.json()) as { error: string; message: string };
  assert.deepEqual([response.status, body.error], [500, 'tampered']);
  assert.doesNotMatch(body.message, /principal|ada|identit/i);
  assert.equal(logged.mock.callCount(), 1);
  const [what, where] = logged.mock.calls[0]!.arguments as [string, { route: string; request: string }];
  assert.match(what, /did not write/);
  assert.equal(where.route, 'GET /auth/callback/acme');
  assert.match(where.request, /^[0-9a-f-]{36}$/);
  // An API route words it the same way, and names its route by its pattern, never the code typed in it.
  logged.mock.resetCalls();
  const login = await started();
  await world.owner.execute(sql`UPDATE device_logins SET mac = '\\x'::bytea`);
  const decided = await decide(login.user_code, true);
  assert.deepEqual([decided.status, ((await decided.json()) as { error: string }).error], [500, 'tampered']);
  assert.equal(logged.mock.callCount(), 1);
  assert.deepEqual(Object.keys(logged.mock.calls[0]!.arguments[1] as object), ['route', 'request']);
  assert.equal((logged.mock.calls[0]!.arguments[1] as { route: string }).route, 'POST /device-logins/:code');
});

test('a person links a second account on the session that asked, and it signs them in after; one vault call', async () => {
  const [response, calls, statements] = await cost(() => roundTrip(account('acme-bo-work', 'bo@work.example'), { cookie: `${SESSION}=bo-web`, query: '?link=1' }));
  assert.deepEqual(landed(response), [302, '/account?linked=acme']);
  assert.deepEqual([calls, statements], [['change'], 0]);
  assert.equal(cookiesOf(response)[SESSION], undefined);
  const again = await roundTrip(account('acme-bo-work'));
  assert.equal(await whoIs(`${SESSION}=${cookiesOf(again)[SESSION]!.value}`), 'bo@acme.example');
});

test('a link is refused for another session than the one that asked, an account bound to anyone, and a session that is no browser', async () => {
  // Signed out: sign in first, then come back to the account page.
  assert.deepEqual(landed(await app.request('/auth/signin/acme?link=1')), [302, '/login?next=/account']);
  // The browser's session changed while it was at the provider, to another person's browser: nothing is asked.
  const left = await app.request('/auth/signin/acme?link=1', { headers: { cookie: `${SESSION}=bo-web` } });
  const state = new URL(left.headers.get('location')!).searchParams.get('state')!;
  profiles.set('c', account('acme-other'));
  const [switched, calls] = await cost(() => app.request(`/auth/callback/acme?state=${state}&code=c`, { headers: { cookie: `${PENDING}=${cookiesOf(left)[PENDING]!.value}; ${SESSION}=dee-web` } }));
  assert.deepEqual([...landed(switched), calls], [302, '/account?error=link_session', []]);
  // Bo's own account, already his: bound to someone, himself included.
  assert.deepEqual(landed(await roundTrip(account('acme-bo'), { cookie: `${SESSION}=bo-web`, query: '?link=1' })), [302, '/account?error=already_linked']);
  // A CLI's session in the cookie is no browser's: the vault takes a link on a browser's alone.
  assert.deepEqual(landed(await roundTrip(account('acme-bo-3'), { cookie: `${SESSION}=bo-cli`, query: '?link=1' })), [302, '/account?error=link_session']);
  assert.deepEqual(await dbRows(sql`SELECT subject FROM identities ORDER BY subject`), [{ subject: 'acme-bo' }, { subject: 'acme-dee' }]);
});

test('a person unlinks an account of theirs, and the sessions it opened end with it: one change, no statement', async () => {
  const unlink = (label: string, id: string) => app.request(`/api/identities/${id}`, { method: 'DELETE', headers: { authorization: `Bearer ${label}` } });
  // Ada cannot unlink Bo's.
  const [refused, calls, statements] = await cost(() => unlink('ada-cli', bos.id));
  assert.deepEqual([refused.status, await refused.json(), calls, statements], [404, { error: 'not_found', message: 'that account: unknown sign-in account', reason: 'unknown_identity' }, ['change'], 0]);
  const answered = await unlink('bo-cli', bos.id);
  assert.deepEqual([answered.status, await answered.json()], [200, { unlinked: true }]);
  assert.equal(await whoIs(`${SESSION}=bo-web`), '401 unauthenticated');
  assert.equal((await unlink('bo-cli', bos.id)).status, 404);
  assert.equal((await unlink('bo-cli', 'not-an-id')).status, 400);
});

test('signing out ends the browser session and clears its cookie, posted from coffre itself', async () => {
  const signOut = (cookie: string, site = 'same-origin') => app.request('/auth/signout', { method: 'POST', headers: { cookie, 'sec-fetch-site': site } });
  // Another site's page cannot sign anyone out.
  const [crossed, crossedCalls] = await cost(() => signOut(`${SESSION}=bo-web`, 'cross-site'));
  assert.deepEqual([crossed.status, ((await crossed.json()) as { error: string }).error, crossedCalls], [403, 'cross_origin', []]);
  const [response, calls, statements] = await cost(() => signOut(`${SESSION}=bo-web`));
  assert.deepEqual([...landed(response), calls, statements], [303, '/login', ['change'], 0]);
  assert.deepEqual(cookiesOf(response)[SESSION], { value: '', attributes: 'Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Secure' });
  assert.equal(await whoIs(`${SESSION}=bo-web`), '401 unauthenticated');
  // A session already ended is signed out all the same; no cookie asks nothing.
  assert.deepEqual(landed(await signOut(`${SESSION}=bo-web`)), [303, '/login']);
  const [none, noneCalls] = await cost(() => signOut(''));
  assert.deepEqual([...landed(none), noneCalls], [303, '/login', []]);
  assert.equal((await app.request('/auth/signout')).status, 405);
});

test('`coffre logout` ends the token it sends, and one that no longer stands is signed out already', async () => {
  const logout = (headers: Record<string, string>) => app.request('/api/auth/logout', { method: 'POST', headers });
  const [response, calls, statements] = await cost(() => logout({ authorization: 'Bearer bo-cli' }));
  assert.deepEqual([response.status, await response.json(), calls, statements], [200, { signedOut: true }, ['change'], 0]);
  assert.equal((await app.request('/api/me', { headers: { authorization: 'Bearer bo-cli' } })).status, 401);
  assert.deepEqual(await (await logout({ authorization: 'Bearer bo-cli' })).json(), { signedOut: true });
  assert.equal(await whoIs(`${SESSION}=bo-web`), 'bo@acme.example');
  assert.equal((await logout({})).status, 401);
  assert.equal((await logout({ cookie: `${SESSION}=bo-web`, 'sec-fetch-site': 'cross-site' })).status, 403);
});

/** A CLI's device login, started: its codes. */
async function started(label = 'laptop'): Promise<{ device_code: string; user_code: string; [more: string]: unknown }> {
  const response = await app.request('/api/auth/device', { method: 'POST', body: JSON.stringify({ client_label: label }) });
  assert.equal(response.status, 200);
  return (await response.json()) as { device_code: string; user_code: string };
}
const poll = async (code: string) => {
  const response = await app.request('/api/auth/device/token', { method: 'POST', body: JSON.stringify({ device_code: code }) });
  return [response.status, await response.json()] as [number, Record<string, unknown>];
};
const asBo = { cookie: `${SESSION}=bo-web`, 'sec-fetch-site': 'same-origin' };
const decide = (code: string, approve: boolean, headers: Record<string, string> = asBo) =>
  app.request(`/api/device-logins/${code}`, { method: 'POST', headers, body: JSON.stringify({ approve }) });

test('a device login over HTTP: the CLI starts it, Bo sees and approves it, the CLI collects a session of his, once', async () => {
  const [login, calls, statements] = await cost(() => started());
  // The cap's one statement, then the vault's one change.
  assert.deepEqual([calls, statements], [['change'], 1]);
  assert.match(login.user_code, /^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/);
  assert.deepEqual({ ...login, device_code: undefined, user_code: undefined }, {
    device_code: undefined, user_code: undefined, verification_uri: `${PUBLIC_URL}/auth/device`, verification_uri_complete: `${PUBLIC_URL}/auth/device?code=${login.user_code}`, expires_in: 600, interval: 5,
  });
  assert.deepEqual(await poll(login.device_code), [400, { error: 'authorization_pending' }]);

  // The page `coffre login` opens, the code typed as a person types it: one caller, one statement.
  const typed = login.user_code.replace('-', '').toLowerCase();
  const [page, pageCalls, pageStatements] = await cost(() => app.request(`/api/device-logins/${typed}`, { headers: { cookie: `${SESSION}=bo-web` } }));
  const shown = (await page.json()) as { request: Record<string, unknown>; sessionDays: number };
  assert.deepEqual([page.status, pageCalls, pageStatements], [200, ['caller'], 1]);
  assert.deepEqual({ ...shown, request: { ...shown.request, createdAt: undefined, expiresAt: undefined } }, {
    request: { userCode: login.user_code, clientLabel: 'laptop', clientIp: '192.0.2.7', createdAt: undefined, expiresAt: undefined }, sessionDays: 30,
  });
  // Shown to a person on a session of theirs alone, as `device.decide` takes: never to a token.
  const token = await app.request(`/api/device-logins/${typed}`, { headers: { authorization: 'Bearer bo-pat' } });
  assert.deepEqual([token.status, ((await token.json()) as { reason: string }).reason], [403, 'no_access']);
  assert.equal((await app.request(`/api/device-logins/${typed}`)).status, 401);

  const [decided, decideCalls, decideStatements] = await cost(() => decide(typed, true));
  assert.deepEqual([decided.status, await decided.json(), decideCalls, decideStatements], [200, { decided: true }, ['change'], 0]);
  const [status, session] = await poll(login.device_code);
  assert.equal(status, 200);
  assert.match(String(session.access_token), /^coffre_cli_/);
  assert.deepEqual({ ...session, access_token: undefined, expires_at: undefined }, { access_token: undefined, token_type: 'Bearer', expires_at: undefined, principal: { type: 'user', id: 'bo@acme.example' } });
  const days = (Date.parse(String(session.expires_at)) - Date.now()) / 86_400_000;
  assert.ok(days > 29.99 && days <= 30, String(days));
  assert.equal((await (await app.request('/api/me', { headers: { authorization: `Bearer ${String(session.access_token)}` } })).json() as { principal: { id: string } }).principal.id, 'bo@acme.example');
  // Once: collected, it is gone; decided, the page shows it no more.
  assert.deepEqual(await poll(login.device_code), [400, { error: 'expired_token' }]);
  assert.deepEqual(((await (await app.request(`/api/device-logins/${typed}`, { headers: { cookie: `${SESSION}=bo-web` } })).json()) as { request: unknown }).request, null);
});

test("a device login denied polls as denied; a code that is no code, or nobody's, is unknown; a token decides none", async () => {
  const login = await started();
  assert.equal((await decide(login.user_code, true, { authorization: 'Bearer bo-pat' })).status, 403);
  assert.equal((await decide(login.user_code, false)).status, 200);
  assert.deepEqual(await poll(login.device_code), [400, { error: 'access_denied' }]);
  assert.deepEqual(await poll('no-such-code'), [400, { error: 'expired_token' }]);
  // Decided already, or never there: one answer. Not a code at all: the vault is not asked.
  for (const code of [login.user_code, 'BCDF-GHJK']) {
    const response = await decide(code, true);
    assert.deepEqual([response.status, ((await response.json()) as { reason: string }).reason], [404, 'unknown_code']);
  }
  const [nonsense, calls] = await cost(() => decide('AEIOU', true));
  assert.deepEqual([nonsense.status, calls], [404, []]);
  // A session's cookie from another site decides nothing.
  assert.equal((await decide(login.user_code, true, { cookie: `${SESSION}=bo-web`, 'sec-fetch-site': 'cross-site' })).status, 403);
  // A label is short text; a body is small.
  for (const body of [{ client_label: 'x'.repeat(121) }, { client_label: '\ud800' }]) {
    assert.equal((await app.request('/api/auth/device', { method: 'POST', body: JSON.stringify(body) })).status, 400);
  }
  assert.equal((await app.request('/api/auth/device', { method: 'POST', body: 'x'.repeat(5000) })).status, 400);
  assert.equal((await app.request('/api/auth/device')).status, 405);
});

test('a user code another login holds is drawn again, four times at most; then the CLI is told to try again', async (t) => {
  await write(world, ...waiting(1, '198.51.100.1', { userCode: 'BBBB-BBBB' }));
  // Until the vault is first asked, every 16 bytes drawn are zeros: the user code, which is BBBB-BBBB, taken (and the page's nonce). The draws after it are random.
  const random = crypto.getRandomValues.bind(crypto);
  const userCodes = (zeros: () => boolean) => <T extends ArrayBufferView | null>(array: T): T => (array!.byteLength === 16 && zeros() ? array : random(array as never));
  const mocked = t.mock.method(crypto, 'getRandomValues', userCodes(() => app.calls.length === 0));
  const [response, calls] = await cost(() => app.request('/api/auth/device', { method: 'POST', body: '{}' }));
  const login = (await response.json()) as { user_code: string };
  assert.deepEqual([response.status, calls], [200, ['change', 'change']]);
  assert.notEqual(login.user_code, 'BBBB-BBBB');
  // Every draw taken.
  mocked.mock.mockImplementation(userCodes(() => true));
  const [given, givenCalls] = await cost(() => app.request('/api/auth/device', { method: 'POST', body: '{}' }));
  assert.deepEqual([given.status, given.headers.get('retry-after'), ((await given.json()) as { error: string }).error, givenCalls.length], [503, '5', 'unavailable', 4]);
});

/** Device logins waiting for a decision, from `ip`, written as the vault writes them. */
const waiting = (count: number, ip: string | null, more: Record<string, unknown> = {}) =>
  rows('deviceLogins', ...Array.from({ length: count }, () => ({
    id: randomUUID(), deviceCodeHash: Buffer.from(hex(randomUUID()), 'hex'), userCode: randomUUID(), clientLabel: null, clientIp: ip,
    createdAt: new Date(), expiresAt: new Date(Date.now() + 600_000), decidedAt: null, decision: null, generation: 0, principal: null, consumedAt: null, ...more,
  })));

test('device logins waiting are capped, 5 from an address and 200 in all, by one statement read before the vault is asked, whatever waits', async () => {
  const start = async () => {
    const [response, calls, statements] = await cost(() => app.request('/api/auth/device', { method: 'POST', body: '{}' }));
    // The cap's statement answers one row, a count, however many wait.
    const [counted] = app.executed.slice(-1) as SQL[];
    const read = await rowsOf(world.owner, counted!);
    return [response.status, calls, statements, read.length];
  };
  assert.deepEqual(await start(), [200, ['change'], 1, 1]);
  // Three more from here wait; one decided and one past its time do not count, nor one from elsewhere: the fifth is let in, the sixth is one too many.
  await write(world, ...waiting(3, '192.0.2.7'), ...waiting(1, '192.0.2.7', { decidedAt: new Date(), decision: 'denied' }), ...waiting(1, '192.0.2.7', { expiresAt: new Date(Date.now() - 1000) }), ...waiting(1, '198.51.100.1'));
  assert.deepEqual(await start(), [200, ['change'], 1, 1]);
  const refused = await app.request('/api/auth/device', { method: 'POST', body: '{}' });
  assert.deepEqual([refused.status, ((await refused.json()) as { error: string }).error], [429, 'slow_down']);
  assert.deepEqual(await start(), [429, [], 1, 1]);
  // 200 in all, from everywhere: the same statement, the same one row.
  await emptyDatabase(world.owner);
  await instanceOf(...waiting(199, '198.51.100.1'));
  assert.deepEqual(await start(), [200, ['change'], 1, 1]);
  assert.deepEqual(await start(), [429, [], 1, 1]);
});

test('a device login waits for an adopted, untampered instance; the CLI is told as any caller is', async (t) => {
  t.mock.method(console, 'error', () => {});
  await world.owner.execute(sql`UPDATE policy SET mac = '\\x'::bytea`);
  const tampered = await app.request('/api/auth/device', { method: 'POST', body: '{}' });
  assert.deepEqual([tampered.status, ((await tampered.json()) as { error: string }).error], [500, 'tampered']);
  assert.deepEqual(await poll('any'), [500, { error: 'tampered', message: "a record coffre's vault reads failed its integrity check: whoever runs coffre has the details in its server log", reason: 'tampered' }]);
  await world.owner.execute(sql`DELETE FROM policy`);
  const adopting = await app.request('/api/auth/device', { method: 'POST', body: '{}' });
  assert.deepEqual([adopting.status, adopting.headers.get('retry-after'), ((await adopting.json()) as { error: string }).error], [503, '5', 'adopting']);
});

test('behind Cloudflare Access there is no device login and no coffre sign-in: Access signs people in and out', async () => {
  const behind = await openApp({ auth: cloudflareAccess({ teamDomain: 'acme.cloudflareaccess.com', audience: 'a'.repeat(64) }) });
  try {
    assert.deepEqual(await (await behind.request('/api/auth', { headers: { 'cf-access-jwt-assertion': 'x' } })).json(), { signin: null, access: { assertion: true } });
    assert.equal((await behind.request('/api/auth/device', { method: 'POST', body: '{}' })).status, 404);
    assert.equal((await behind.request('/api/auth/device/token', { method: 'POST', body: '{"device_code":"x"}' })).status, 404);
    assert.deepEqual(landed(await behind.request('/auth/signin/acme')), [302, '/login']);
    const out = await behind.request('/auth/signout', { method: 'POST', headers: { 'sec-fetch-site': 'same-origin' } });
    assert.deepEqual(landed(out), [303, '/cdn-cgi/access/logout']);
    assert.deepEqual(behind.calls, []);
  } finally {
    await behind.close();
  }
});
