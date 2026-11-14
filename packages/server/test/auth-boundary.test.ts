// Where a request meets who it is, on the 0.16 contract: the app reads the
// credential and hashes it, and the vault says who that is. What the app
// still holds there: a vault it cannot ask is an outage, never a sign-out;
// the address it vouches for; a page's render that meets an outage keeps its
// headers; and in sign-in mode an Access assertion is nobody. 0.14.7's
// `auth-boundary.test.ts` and `offboarding.test.ts` held the same.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { after, beforeEach, test } from 'node:test';

import { CoffreError } from '@coffre/client';
import { amend, credential, emptyDatabase, identity, instance, principal, role, rows, user, write } from '@coffre/vault/testing';
import { credentials } from '@coffre/db/schema';
import { sql } from 'drizzle-orm';

import { cloudflareSourceIp } from '../src/auth.ts';
import { openApp, SESSION } from './app-fixture.ts';

const app = await openApp();
const { world } = app;
after(() => app.close());

const bo = user('bo');
const hex = (token: string) => createHash('sha256').update(token).digest('hex');

beforeEach(async () => {
  await emptyDatabase(world.owner);
  for (const kept of [world.memory.reads, world.memory.callers, world.memory.logged, world.memory.touched, world.refused]) kept.clear();
  const bos = identity(bo, { provider: 'github', subject: 'gh-bo', email: 'bo@acme.example' });
  await write(
    world,
    ...rows('policy', instance()),
    ...rows('roles', role(true, 'owner', ['secret.read']), role(true, 'member', [])),
    ...rows('principals', principal(bo)),
    ...rows('identities', bos),
    ...rows('credentials', credential('bo-web', bo, { kind: 'browser', identityId: bos.id }), credential('bo-cli', bo)),
  );
  // The schema's question, asked once of a fresh app.
  await app.request('/api/auth');
  app.calls.length = 0;
});

type Body = { error?: string; principal?: { id: string } };
/** The ways a request carries a session: the CLI's bearer token, and the browser's cookie. */
const SESSIONS = [
  ['bearer', { authorization: 'Bearer bo-cli' }],
  ['cookie', { cookie: `${SESSION}=bo-web` }],
] as const;
const me = async (headers: Record<string, string>) => {
  const response = await app.request('/api/me', { headers });
  return { response, body: (await response.json()) as Body };
};

/**
 * What a vault that cannot be asked throws, as the app meets it: the Node
 * vault's socket refused (`connectVault`), a Worker's RPC cut (Workers'
 * words), and the vault's own database down, which its RPC answers with
 * Postgres's code (`failureOf`).
 */
const OUTAGES = [
  ['a socket refused', () => new Error('the vault at /run/coffre/vault.sock is unreachable: connect ECONNREFUSED', { cause: Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' }) })],
  ['an RPC cut', () => new Error('Network connection lost.')],
  ['a call Workers cancelled as hung', () => new Error("The Workers runtime canceled this request because it detected that your Worker's code had hung")],
  ['its database down', () => Object.assign(new Error('vault caller: Connection terminated unexpectedly'), { code: '08006' })],
] as const;

test('a vault that cannot say who is calling is an outage: 503 unavailable, said once in the log, never a sign-out; the same session works once it answers', async (t) => {
  const logged = t.mock.method(console, 'error', () => {});
  for (const [outage, error] of OUTAGES) {
    const down = t.mock.method(app.vault, 'caller', async () => {
      throw error();
    });
    for (const [carried, headers] of SESSIONS) {
      logged.mock.resetCalls();
      const { response, body } = await me(headers);
      const at = `${outage}, ${carried}`;
      assert.deepEqual([response.status, body.error, response.headers.get('retry-after')], [503, 'unavailable', '5'], at);
      // Nothing that signs the browser out: no cookie cleared.
      assert.deepEqual(response.headers.getSetCookie(), [], at);
      assert.equal(logged.mock.callCount(), 1, at);
      assert.match(logged.mock.calls[0]!.arguments[0] as string, /did not answer/, at);
      // Any API route, not `/me` alone.
      const listed = await app.request('/api/projects', { headers });
      assert.equal(listed.status, 503, at);
    }
    down.mock.restore();
    for (const [carried, headers] of SESSIONS) {
      const { response, body } = await me(headers);
      assert.deepEqual([response.status, body.principal?.id], [200, 'bo@acme.example'], `${outage}, ${carried}, once it answers`);
    }
  }
});

test('a session the vault checked and refused is signed out, not an outage: revoked, expired, or on a row it did not write', async () => {
  const refused = async (headers: Record<string, string>) => {
    world.memory.callers.clear();
    const { response, body } = await me(headers);
    return `${response.status} ${body.error}`;
  };
  const [cli, web] = SESSIONS.map(([, headers]) => headers);
  const hashOf = (label: string) => sql`${credentials.tokenHash} = decode(${hex(label)}, 'hex')`;
  await amend(world, 'credentials', hashOf('bo-cli'), { revokedAt: new Date(), revokedBy: bo });
  await amend(world, 'credentials', hashOf('bo-web'), { expiresAt: new Date(Date.UTC(2026, 0, 1)) });
  assert.deepEqual([await refused(cli), await refused(web)], ['401 unauthenticated', '401 unauthenticated']);
  // Put back as they were, then one edited behind the vault, its expiry moved on: its MAC no longer holds, and the vault reads no credential there.
  await amend(world, 'credentials', hashOf('bo-cli'), { revokedAt: null, revokedBy: null });
  await amend(world, 'credentials', hashOf('bo-web'), { expiresAt: new Date(Date.UTC(2027, 0, 1)) });
  assert.deepEqual([await refused(cli), await refused(web)], ['200 undefined', '200 undefined']);
  await world.owner.execute(sql`UPDATE credentials SET expires_at = expires_at + interval '1 year' WHERE token_hash = decode(${hex('bo-cli')}, 'hex')`);
  assert.equal(await refused(cli), '401 unauthenticated');
});

test("on Workers the caller's address is Cloudflare's header, when it is an address", () => {
  const from = (value: string) => cloudflareSourceIp(new Request('https://coffre.test/api/me', { headers: { 'cf-connecting-ip': value } }));
  assert.equal(from('203.0.113.10'), '203.0.113.10');
  assert.equal(from('2001:db8::1'), '2001:db8::1');
  for (const junk of ['300.1.1.1', '1.2.3', 'not an address', '203.0.113.10, 198.51.100.1', `${'a:'.repeat(30)}1`, '']) assert.equal(from(junk), null, junk);
  assert.equal(cloudflareSourceIp(new Request('https://coffre.test/api/me')), null);
});

/** A page as Start renders one: its loader asks the API, and a loader that throws makes its error page, a 500. */
const page = (ask: (client: Parameters<Parameters<typeof app.render>[1]>[0]['client']) => Promise<unknown>) =>
  app.render({ headers: { cookie: `${SESSION}=bo-web` } }, async ({ client }) => {
    try {
      return { shown: await ask(client) };
    } catch (error) {
      return { error: error instanceof CoffreError ? error.code : String(error) };
    }
  });
const SECURED = ['content-security-policy', 'x-frame-options', 'x-content-type-options', 'strict-transport-security', 'cache-control'];

test("a page whose render met a vault outage shows its error state, with the security headers; a page's own bug is a 500 with them too", async (t) => {
  t.mock.method(console, 'error', () => {});
  t.mock.method(app.vault, 'caller', async () => {
    throw new Error('Network connection lost.');
  });
  const outage = await page((client) => client.me());
  assert.deepEqual(await outage.json(), { error: 'unavailable' });
  for (const header of SECURED) assert.ok(outage.headers.get(header), header);

  const bug = await app.render({ headers: { cookie: `${SESSION}=bo-web` } }, async () => {
    throw new Error('a bug in the page');
  });
  assert.deepEqual([bug.status, ((await bug.json()) as Body).error], [500, 'internal_error']);
  for (const header of SECURED) assert.ok(bug.headers.get(header), header);
});

test("in sign-in mode an Access assertion is nobody's credential: alone it is signed out, beside a session it changes nothing", async () => {
  const assertion = { 'cf-access-jwt-assertion': 'eyJhbGciOiJSUzI1NiJ9.e30.c2ln' };
  const alone = await me(assertion);
  assert.deepEqual([alone.response.status, alone.body.error, app.calls], [401, 'unauthenticated', []]);
  for (const [carried, headers] of SESSIONS) {
    const { response, body } = await me({ ...assertion, ...headers });
    assert.deepEqual([response.status, body.principal?.id], [200, 'bo@acme.example'], carried);
  }
  // The same through a page's render: its client forwards the session cookie alone.
  const rendered = await app.render({ headers: assertion }, ({ client }) => client.me().then(() => 'answered', (error: unknown) => (error instanceof CoffreError ? error.code : String(error))));
  assert.equal(await rendered.json(), 'unauthenticated');
});
