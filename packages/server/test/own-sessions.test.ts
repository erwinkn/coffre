// A person's own sessions and accounts, listed (`GET /sessions`,
// `GET /identities`; docs/design/0.16.md, "Signing in from the server"):
// one `caller` and one statement each, the caller's own rows only, live as
// the vault takes them, in 0.14.7's shapes. What each costs as the
// instance grows, request-cost.test.ts holds.
import assert from 'node:assert/strict';
import { after, beforeEach, test } from 'node:test';

import { credential, emptyDatabase, identity, instance, principal, rows, user, write } from '@coffre/vault/testing';

import type { ApiContext } from '../src/api/context.ts';
import type { ApiError } from '../src/api/errors.ts';
// The router before its table: the table's modules import it back (mcp/tools.ts), so the table loads through it.
import '../src/api/router.ts';
import { routes } from '../src/api/routes.ts';
import { IDENTITIES_LISTED, SESSIONS_LISTED } from '../src/db/queries/signin.ts';
import { openApp } from './app-fixture.ts';

const app = await openApp();
const { world } = app;
after(() => app.close());

const [bo, cy] = ['bo', 'cy'].map(user) as [string, string];
const ci = 'token:ci';
const day = (n: number) => new Date(Date.UTC(2026, 10, n));

/**
 * Bo was removed and let back in: generation 1. He has a GitHub account
 * and an OIDC one (`acme`), linked now; one he unlinked; one of before
 * he was removed. His live sessions: a browser's through GitHub, used
 * last; two CLI sessions, `bo-cli` and `bo-cli2`. Not live: one revoked,
 * one expired, one frozen, a browser's through the unlinked account, a
 * browser's through none, a CLI session of before he was removed, a CLI
 * session a trust binding issued, and his personal token (made on his
 * GitHub session, it names the account) and handle, which are no
 * sessions. Cy
 * has an account and a session of hers.
 */
let ids: Record<string, string> = {};
beforeEach(async () => {
  await emptyDatabase(world.owner);
  for (const kept of [world.memory.reads, world.memory.callers, world.memory.logged, world.memory.touched, world.refused]) kept.clear();
  const accounts = {
    github: identity(bo, { generation: 1, provider: 'github', email: 'bo@acme.example', createdAt: day(2), lastSignInAt: day(9) }),
    acme: identity(bo, { generation: 1, provider: 'acme', email: null, createdAt: day(3) }),
    unlinked: identity(bo, { generation: 1, provider: 'gitlab', createdAt: day(1), revokedAt: day(4), revokedBy: bo }),
    before: identity(bo, { generation: 0, provider: 'github', createdAt: day(1) }),
    cys: identity(cy, { provider: 'github' }),
  };
  const sessions = {
    browser: credential('bo-browser', bo, { kind: 'browser', generation: 1, identityId: accounts.github.id, tokenHint: 'coffre_brw_…b001', createdAt: day(5), lastUsedAt: day(9), lastUsedIp: '192.0.2.7' }),
    cli: credential('bo-cli', bo, { generation: 1, label: 'laptop', tokenHint: 'coffre_cli_…c001', createdAt: day(6), lastUsedAt: day(8) }),
    cli2: credential('bo-cli2', bo, { generation: 1, identityId: accounts.acme.id, createdAt: day(7) }),
  };
  ids = Object.fromEntries([...Object.entries(accounts), ...Object.entries(sessions)].map(([name, row]) => [name, row.id]));
  await write(
    world,
    ...rows('policy', instance()),
    ...rows('principals', principal(bo, { generation: 1 }), principal(cy), principal(ci)),
    ...rows('identities', ...Object.values(accounts)),
    ...rows('credentials',
      ...Object.values(sessions),
      credential('bo-ended', bo, { generation: 1, revokedAt: day(4), revokedBy: bo }),
      credential('bo-lapsed', bo, { generation: 1, expiresAt: new Date('2020-01-01T00:00:00Z') }),
      credential('bo-frozen', bo, { generation: 1, frozenAt: day(4) }),
      credential('bo-unlinked', bo, { kind: 'browser', generation: 1, identityId: accounts.unlinked.id }),
      credential('bo-before', bo, { generation: 0 }),
      credential('bo-issued', bo, { generation: 1, createdBy: 'binding:00000000-0000-4000-8000-000000000000' }),
      credential('bo-orphan', bo, { kind: 'browser', generation: 1 }),
      credential('bo-pat', bo, { kind: 'personal', generation: 1, scope: '[]', identityId: accounts.github.id }),
      credential('bo-handle', bo, { kind: 'handle', generation: 1, scope: '[]', places: '[]' }),
      credential('cy-cli', cy, { identityId: accounts.cys.id }),
      credential('ci-token', ci)),
  );
  await app.request('/livez');
  await app.request('/api/me', { headers: { authorization: 'Bearer nobody' } });
  app.calls.length = 0;
});

type Body = { error?: string; reason?: string } & Record<string, unknown>;
const call = async (bearer: string, path: string): Promise<[number, Body]> => {
  const got = await app.request(`/api${path}`, { headers: { authorization: `Bearer ${bearer}` } });
  return [got.status, (await got.json()) as Body];
};
async function cost<T>(run: () => Promise<T>): Promise<[T, string[], number]> {
  const [calls, statements] = [app.calls.length, app.statements];
  const result = await run();
  return [result, app.calls.slice(calls), app.statements - statements];
}

test("a person's live sessions, the one last used first, the request's own marked: one `caller` and one statement", async () => {
  const [[status, body], calls, statements] = await cost(() => call('bo-cli2', '/sessions'));
  assert.equal(status, 200, JSON.stringify(body));
  assert.deepEqual([calls, statements], [['caller'], 1]);
  const sessions = body.sessions as Record<string, unknown>[];
  // The request's own was used just now; those never used go by when they were made.
  assert.deepEqual(sessions.map((session) => session.id), [ids.cli2, ids.browser, ids.cli]);
  assert.equal(body.more, false);
  assert.deepEqual(sessions[1], {
    id: ids.browser, kind: 'browser', label: 'bo-browser', hint: 'coffre_brw_…b001', provider: 'github',
    createdAt: day(5).toISOString(), expiresAt: '2027-01-01T00:00:00.000Z', lastUsedAt: day(9).toISOString(), lastUsedIp: '192.0.2.7', current: false,
  });
  // A CLI session approved from a device login names no account; one opened through an account names its provider.
  assert.deepEqual(sessions.map((session) => [session.kind, session.provider, session.hint, session.current]), [['cli', 'acme', '', true], ['browser', 'github', 'coffre_brw_…b001', false], ['cli', null, 'coffre_cli_…c001', false]]);
  const [, again] = await call('bo-cli', '/sessions');
  assert.deepEqual((again.sessions as Record<string, unknown>[]).filter((session) => session.current).map((session) => session.id), [ids.cli]);
});

test("a person's linked accounts, the oldest first: one `caller` and one statement", async () => {
  const [[status, body], calls, statements] = await cost(() => call('bo-cli', '/identities'));
  assert.equal(status, 200, JSON.stringify(body));
  assert.deepEqual([calls, statements], [['caller'], 1]);
  assert.deepEqual(body.identities, [
    { id: ids.github, provider: 'github', email: 'bo@acme.example', createdAt: day(2).toISOString(), lastSignInAt: day(9).toISOString() },
    { id: ids.acme, provider: 'acme', email: null, createdAt: day(3).toISOString(), lastSignInAt: null },
  ]);
  assert.equal(body.more, false);
  // Cy's own, and nothing of Bo's.
  const [, hers] = await call('cy-cli', '/identities');
  assert.deepEqual((hers.identities as { id: string }[]).map((account) => account.id), [ids.cys]);
});

test('a person who signs in from a script lists their 200 sessions last used, and 50 oldest accounts, and is told there are more: still one statement', async () => {
  // Bo's three live sessions were used on days 7 to 9, and his two accounts made on days 2 and 3: these come after both.
  const scripts = Array.from({ length: SESSIONS_LISTED }, (_, n) => credential(`bo-script-${n}`, bo, { generation: 1, createdAt: new Date(Date.UTC(2026, 9, 1, 0, n)) }));
  await write(
    world,
    ...rows('identities', ...Array.from({ length: IDENTITIES_LISTED }, (_, n) => identity(bo, { generation: 1, provider: 'acme', createdAt: new Date(Date.UTC(2026, 10, 4, 0, n)) }))),
    ...rows('credentials', ...scripts),
  );
  // The statement reads one row past the cap, never all of them.
  const read = app.sent.rows;
  const [[, sessions], , sessionStatements] = await cost(() => call('bo-cli', '/sessions'));
  const listed = sessions.sessions as { id: string; current: boolean }[];
  assert.deepEqual([listed.length, sessions.more, sessionStatements, app.sent.rows - read], [SESSIONS_LISTED, true, 1, SESSIONS_LISTED + 1]);
  // The request's own, used just now, then the two used last, then the scripts' newest first: the three made first are past the cap.
  assert.deepEqual(listed.map((session) => session.id), [ids.cli, ids.browser, ids.cli2, ...scripts.slice(3).reverse().map((row) => row.id)]);
  assert.ok(listed[0]!.current);
  const readBefore = app.sent.rows;
  const [[, accounts], , accountStatements] = await cost(() => call('bo-cli', '/identities'));
  const linked = accounts.identities as { id: string }[];
  assert.deepEqual([linked.length, accounts.more, accountStatements, app.sent.rows - readBefore], [IDENTITIES_LISTED, true, 1, IDENTITIES_LISTED + 1]);
  assert.deepEqual(linked.slice(0, 2).map((account) => account.id), [ids.github, ids.acme]);
});

test('an unlinked account, and the sessions it opened, are gone from both lists', async () => {
  const ended = await app.request(`/api/identities/${ids.acme}`, { method: 'DELETE', headers: { authorization: 'Bearer bo-cli' } });
  assert.equal(ended.status, 200);
  const [, accounts] = await call('bo-cli', '/identities');
  assert.deepEqual((accounts.identities as { id: string }[]).map((account) => account.id), [ids.github]);
  const [, sessions] = await call('bo-cli', '/sessions');
  assert.deepEqual((sessions.sessions as { id: string }[]).map((session) => session.id), [ids.cli, ids.browser]);
});

test('only a person on a session of theirs lists them: a personal token and a service account are refused, with no statement', async () => {
  for (const bearer of ['bo-pat', 'ci-token']) {
    for (const path of ['/sessions', '/identities']) {
      const [[status, body], calls, statements] = await cost(() => call(bearer, path));
      assert.deepEqual([status, body.error, calls, statements], [403, 'forbidden', ['caller'], 0], `${bearer} ${path}`);
    }
  }
  // A credential that does not stand is no caller, nor a handle, which only the credential proxy takes.
  for (const bearer of ['bo-handle', 'bo-ended', 'bo-lapsed', 'bo-frozen', 'bo-unlinked', 'bo-orphan', 'bo-before', 'bo-issued']) assert.equal((await call(bearer, '/sessions'))[0], 401, bearer);
});

test("behind Cloudflare Access there are no sessions or accounts of coffre's to list: 404, before the vault is asked", async () => {
  const asked: string[] = [];
  const ctx = { auth: { mode: 'cloudflare' }, vault: new Proxy({}, { get: (_, name) => () => asked.push(String(name)) }), caller: async () => asked.push('caller') } as unknown as ApiContext;
  for (const key of ['GET /sessions', 'GET /identities'] as const) {
    await assert.rejects((routes[key].run as (ctx: ApiContext, call: unknown) => Promise<unknown>)(ctx, { params: {}, query: {} }), (error: ApiError) => error.code === 'not_found', key);
  }
  assert.deepEqual(asked, []);
});
