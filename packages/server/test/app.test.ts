// The app on the 0.16 contract (docs/design/0.16.md, "The server"): a
// request's credential hashed and handed to the vault, which decides. In
// process, with the real vault; app-workers.test.ts holds the same through
// the Workers themselves.
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { after, beforeEach, test } from 'node:test';

import { CoffreError } from '@coffre/client';
import { DEFAULT_POLICY } from '@coffre/core/access';
import { cloudflareAccess } from '@coffre/core/identity';
import type { Called } from '@coffre/core/vault';
import { rowsOf } from '@coffre/db/dialect';
import { credential, emptyDatabase, environment, grant, identity, principal, project, role, rows, secret, user, value, write } from '@coffre/vault/testing';
import { sql, type SQL } from 'drizzle-orm';
import { PgDialect } from 'drizzle-orm/pg-core';

import { can, placeOf, projectsReached } from '../src/api/caller.ts';
import { openApp, SESSION } from './app-fixture.ts';

const app = await openApp();
const { world } = app;
after(() => app.close());

const [ada, bo, cy] = [user('ada'), user('bo'), user('cy')];
const HANDLE = `coffre_use_${'a'.repeat(43)}`;
const BROWSER = `coffre_web_${'b'.repeat(43)}`;
const PERSONAL = `coffre_pat_${'c'.repeat(43)}`;

/**
 * market: prod, Ada's personal config of it, and staging, protected.
 * billing: prod. Ada views market, Bo develops it, Cy owns the instance.
 * Bo's instance role, which holds nothing, reaches every project but billing.
 * A viewer holds nothing in a protected environment.
 */
let market: ReturnType<typeof project>;
beforeEach(async () => {
  await emptyDatabase(world.owner);
  for (const kept of [world.memory.reads, world.memory.callers, world.memory.logged, world.memory.touched, world.refused]) kept.clear();
  market = project('market');
  const billing = project('billing');
  const prod = environment(market, 'prod');
  const adas = environment(market, 'prod-ada', { parentId: prod.id, owner: ada });
  const staging = environment(market, 'staging', { protected: true });
  // A config of an environment its owner does not read is no place of theirs.
  const stagings = environment(market, 'staging-ada', { parentId: staging.id, owner: ada });
  // A fork of staging: it inherits staging's key, which a viewer does not read, and holds a reference to a key since archived.
  const fork = environment(market, 'fork', { parentId: staging.id });
  const old = await value(world, secret(prod, 'OLD', { archivedAt: new Date(0) }), 'gone');
  const inherited = await value(world, secret(staging, 'S_KEY'), 'staging only');
  const fine = await value(world, secret(fork, 'FINE'), 'fine');
  const [billed, deleted] = [environment(billing, 'prod'), environment(billing, 'old~deleted-2026-11-01')];
  const own = await value(world, secret(adas, 'OWN'), 'hers alone');
  const url = await value(world, secret(prod, 'DATABASE_URL'), 'postgres://märkt');
  const stripe = await value(world, secret(prod, 'STRIPE_KEY'), 'sk_live', { sensitive: true });
  const flag = await value(world, secret(prod, 'FLAG'), 'on', { plain: true });
  const used = { lastUsedAt: new Date() };
  // A browser's session is an account's, always.
  const github = identity(bo);
  await write(
    world,
    ...rows('projects', market, billing),
    ...rows('environments', prod, adas, staging, stagings, fork, billed, deleted),
    ...rows('secrets', url, stripe, flag, own, old, inherited, fine, secret(fork, 'A_LINK', { sourceId: old.id }), secret(prod, 'EMPTY')),
    ...rows('roles', role(false, 'viewer', ['secret.read'], []), role(false, 'developer', ['secret.read', 'secret.write']), role(true, 'owner', ['secret.read', 'secret.write', 'audit.read']), role(true, 'member', [])),
    ...rows('principals', principal(ada), principal(bo, { scope: JSON.stringify({ projects: { except: [billing.id] }, environments: 'all' }) }), principal(cy, { role: 'owner' })),
    ...rows('grants', grant(ada, 'viewer', { project: market }), grant(bo, 'developer', { project: market })),
    ...rows('identities', github),
    ...rows('credentials', credential('ada-cli', ada, used), credential('bo-cli', bo, used), credential('cy-cli', cy, used), credential(HANDLE, ada, { ...used, kind: 'handle' }), credential(BROWSER, bo, { ...used, kind: 'browser', identityId: github.id }), credential(PERSONAL, bo, { ...used, kind: 'personal', scope: JSON.stringify([{ projectId: market.id, environmentId: null, role: 'viewer' }]) })),
  );
  // The database's migrations are known from the first request on: none of a test's counts is that question.
  await app.request('/livez');
  await app.request('/api/me', { headers: { authorization: 'Bearer nobody' } });
  app.calls.length = 0;
});

type Body = { error?: string; reason?: string; message?: string } & Record<string, unknown>;
const json = (body: unknown) => ({ method: 'POST', body: JSON.stringify(body) });
const as = (label: string, init: RequestInit = {}) => ({ ...init, headers: { authorization: `Bearer ${label}`, ...(init.headers as Record<string, string> | undefined) } });
const answered = async (response: Promise<Response>): Promise<[number, Body]> => {
  const got = await response;
  return [got.status, (await got.json()) as Body];
};
const reveal = (label: string, path: string, keys?: string[]) => answered(app.request('/api/reveals', as(label, json(keys === undefined ? { path } : { path, keys }))));
const pending = async () => (await rowsOf<{ n: number }>(world.owner, sql`SELECT count(*)::int AS n FROM log_pending`))[0]!.n;
/** What one request cost: the vault's calls it made, and the app's statements. */
async function cost<T>(run: () => Promise<T>): Promise<[T, string[], number]> {
  const [calls, statements] = [app.calls.length, app.statements];
  const result = await run();
  return [result, app.calls.slice(calls), app.statements - statements];
}

test('a reveal is one call to the vault and no statement of the app: the token hashed, never looked up', async () => {
  const [[status, body], calls, statements] = await cost(() => reveal('ada-cli', 'market/prod/DATABASE_URL'));
  assert.deepEqual([status, calls, statements], [200, ['use'], 0], JSON.stringify(body));
  assert.deepEqual({ ...body, operationId: 'x' }, { operationId: 'x', values: { DATABASE_URL: 'postgres://märkt' }, sensitive: [], useOnly: [], version: null });
  assert.match(String(body.operationId), /^[0-9a-f-]{36}$/);
  // The vault's entry names the request by the id the app answered with.
  const [entry] = await rowsOf<{ body: string }>(world.owner, sql`SELECT body FROM log_pending ORDER BY id DESC LIMIT 1`);
  assert.ok(entry!.body.includes(String(body.operationId)) && entry!.body.includes('192.0.2.7') && entry!.body.includes('"purpose":"reveal"'), entry!.body);
  // An environment's read says so in the log: what `coffre run` and an export make.
  await reveal('ada-cli', 'market/prod', ['FLAG']);
  const [ran] = await rowsOf<{ body: string }>(world.owner, sql`SELECT body FROM log_pending ORDER BY id DESC LIMIT 1`);
  assert.ok(ran!.body.includes('"purpose":"run"'), ran!.body);
});

test('every answer carries coffre\'s security headers, a refusal\'s too', async () => {
  for (const response of [await app.request('/api/reveals', as('ada-cli', json({ path: 'market/prod/FLAG' }))), await app.request('/api/reveals', json({ path: 'market/prod/FLAG' }))]) {
    assert.ok(response.headers.has('content-security-policy'), 'a policy');
    assert.deepEqual(['cache-control', 'x-content-type-options', 'x-frame-options', 'strict-transport-security'].map((name) => response.headers.get(name)), ['no-store', 'nosniff', 'DENY', 'max-age=31536000; includeSubDomains']);
  }
});

test('an environment read answers what its caller is given and names what it left out; its version moves with what a read opens', async () => {
  const [status, whole] = await reveal('ada-cli', 'market/prod');
  assert.equal(status, 200, JSON.stringify(whole));
  // A person is handed no sensitive value: named, not opened. A key with no value is not there.
  assert.deepEqual([whole.values, whole.sensitive, whole.useOnly], [{ DATABASE_URL: 'postgres://märkt', FLAG: 'on' }, ['STRIPE_KEY'], []]);
  assert.match(String(whole.version), /^[A-Za-z0-9_-]{43}$/);
  // Of some keys only: one the environment does not hold is left out, not refused.
  const [, some] = await reveal('ada-cli', 'market/prod', ['FLAG', 'NOPE', 'STRIPE_KEY']);
  assert.deepEqual([some.values, some.sensitive], [{ FLAG: 'on' }, ['STRIPE_KEY']]);
  assert.notEqual(some.version, whole.version);
  assert.equal((await reveal('ada-cli', 'market/prod'))[1].version, whole.version, 'the same read, the same version');
  await app.request('/api/secrets/market/prod', as('bo-cli', { method: 'PATCH', body: JSON.stringify({ FLAG: { value: 'off', sensitivity: 'plain' } }) }));
  world.memory.reads.clear();
  assert.notEqual((await reveal('ada-cli', 'market/prod'))[1].version, whole.version);
  // Her personal config of prod: its own key, and prod's.
  assert.deepEqual((await reveal('ada-cli', 'market/prod@me'))[1].values, { DATABASE_URL: 'postgres://märkt', FLAG: 'off', OWN: 'hers alone' });
  assert.deepEqual((await reveal('bo-cli', 'market/prod@me'))[1].values, { DATABASE_URL: 'postgres://märkt', FLAG: 'off' }, 'who has none reads the environment itself');
});

test('a refusal is the vault\'s word with a status: nothing says whether a place exists, and nothing was written', async () => {
  const before = await pending();
  const refused = async (label: string, path: string) => {
    const [status, body] = await reveal(label, path);
    return [status, body.error, body.reason];
  };
  assert.deepEqual(await refused('ada-cli', 'market/prod/STRIPE_KEY'), [403, 'forbidden', 'sensitive']);
  assert.deepEqual(await refused('ada-cli', 'market/prod/NOPE'), [404, 'not_found', 'unknown_key']);
  assert.deepEqual(await refused('ada-cli', 'market/prod/EMPTY'), [404, 'not_found', 'no_value']);
  assert.deepEqual(await refused('nobody', 'market/prod/FLAG'), [401, 'unauthenticated', 'unauthenticated']);
  // A project she holds nothing in, an environment that is not there, a project that is not: one answer.
  const [held, ...others] = await Promise.all(['billing/prod', 'market/nope', 'nope/prod'].map((path) => reveal('ada-cli', path)));
  assert.deepEqual([held![0], held![1].error, held![1].reason], [403, 'vault_refused', 'no_access']);
  for (const [status, body] of others) assert.deepEqual([status, body.error, body.reason, String(body.message).split(': ')[1]], [403, 'vault_refused', 'no_access', String(held![1].message).split(': ')[1]]);
  assert.equal(await pending(), before);

  // An environment's read stops on a key it cannot read, rather than run without it: a parent its reader does not read
  // before anything else, as 0.14, then a reference whose source is gone. Named apart, the key it can read is read.
  assert.deepEqual(await refused('ada-cli', 'market/fork'), [403, 'forbidden', 'parent_unreadable']);
  assert.deepEqual(await refused('bo-cli', 'market/fork'), [409, 'conflict', 'unreadable']);
  assert.deepEqual((await reveal('bo-cli', 'market/fork', ['FINE', 'S_KEY']))[1].values, { FINE: 'fine', S_KEY: 'staging only' });
  // What the vault opened for the app it logged, though the app then handed none of it on: the log never says less than what left the vault.
  assert.equal(await pending(), before + 2, "Ada's read and Bo's, each once");

  // A name the vault could not take is refused here, not left to fault there.
  app.calls.length = 0;
  for (const path of [`market/prod/${'A'.repeat(300)}`, `${'m'.repeat(300)}/prod`, 'market\u0000/prod', 'Market/prod', 'market/prod@you', 'market/prod/not a key', 'market']) {
    assert.deepEqual((await refused('ada-cli', path)).slice(0, 2), [400, 'bad_request'], path.slice(0, 30));
  }
  assert.deepEqual(app.calls, []);
});

test('what only the app sees of a request, it holds before the vault is asked: no credential, a handle, a change from another site', async () => {
  const body = json({ path: 'market/prod/FLAG' });
  const cookie = (token: string, more: Record<string, string> = {}) => ({ ...body, headers: { cookie: `${SESSION}=${token}`, ...more } });
  const tried = async (init: RequestInit) => {
    const [[status, answer], calls] = await cost(() => answered(app.request('/api/reveals', init)));
    return [status, answer.error, answer.reason, calls];
  };
  assert.deepEqual(await tried(body), [401, 'unauthenticated', undefined, []]);
  // A handle is the proxy's: the vault would open values for it.
  assert.deepEqual(await tried(as(HANDLE, body)), [403, 'forbidden', 'handle', []]);
  // A cookie rides along with any site's request: a change with one comes from coffre's own pages, or not at all.
  assert.deepEqual(await tried(cookie(BROWSER)), [403, 'cross_origin', undefined, []]);
  assert.deepEqual(await tried(cookie(BROWSER, { 'sec-fetch-site': 'cross-site' })), [403, 'cross_origin', undefined, []]);
  assert.deepEqual(await tried(cookie(BROWSER, { 'sec-fetch-site': 'same-origin' })), [200, undefined, undefined, ['use']]);
  assert.deepEqual(await tried(cookie(BROWSER, { origin: 'https://secrets.acme.example' })), [200, undefined, undefined, ['use']]);
  // A header is only there when its caller put it there.
  assert.deepEqual(await tried(as('bo-cli', body)), [200, undefined, undefined, ['use']]);
  // A personal token is a bearer's: planted in the cookie, it is no session.
  assert.deepEqual(await tried(cookie(PERSONAL, { 'sec-fetch-site': 'same-origin' })), [401, 'unauthenticated', undefined, []]);
  assert.deepEqual(await tried(as(PERSONAL, body)), [200, undefined, undefined, ['use']]);
});

test('a write is one change of the vault and no statement of the app; what it refuses, and what is not served yet', async () => {
  const patch = (label: string, path: string, values: unknown) => answered(app.request(`/api/secrets/${path}`, as(label, { method: 'PATCH', body: JSON.stringify(values) })));
  const [[status, body], calls, statements] = await cost(() => patch('bo-cli', 'market/prod', { API_KEY: 'k1', FLAG: { value: 'off', sensitivity: 'plain' }, STRIPE_KEY: { value: 'sk_2', sensitivity: 'sensitive' } }));
  assert.deepEqual([status, calls, statements], [200, ['change'], 0], JSON.stringify(body));
  assert.deepEqual(body.keys, { API_KEY: { version: 1, sensitivity: 'secret' }, FLAG: { version: 2, sensitivity: 'plain' }, STRIPE_KEY: { version: 2, sensitivity: 'sensitive' } });
  world.memory.reads.clear();
  assert.deepEqual((await reveal('bo-cli', 'market/prod'))[1].values, { API_KEY: 'k1', DATABASE_URL: 'postgres://märkt', FLAG: 'off' });
  // A bare value keeps a sensitive key sensitive, and makes a plain one a secret: plain is kept only where a write says so.
  const [, bare] = await patch('bo-cli', 'market/prod', { STRIPE_KEY: 'sk_3', FLAG: 'on' });
  assert.deepEqual(bare.keys, { STRIPE_KEY: { version: 3, sensitivity: 'sensitive' }, FLAG: { version: 3, sensitivity: 'secret' } });
  // So does a fork's over a sensitive key it inherits: what a person was not handed there, they are not after.
  assert.equal((await patch('cy-cli', 'market/staging', { SIGNING: { value: 'sig', sensitivity: 'sensitive' } }))[0], 200);
  const [, forked] = await patch('cy-cli', 'market/fork', { SIGNING: 'sig 2' });
  assert.deepEqual(forked.keys, { SIGNING: { version: 1, sensitivity: 'sensitive' } });

  // A viewer writes nothing, and is told no more than for a place that is not there.
  for (const path of ['market/prod', 'nope/prod']) {
    const [refused, said] = await patch('ada-cli', path, { API_KEY: 'k2' });
    assert.deepEqual([refused, said.error, said.reason], [403, 'vault_refused', 'no_access']);
  }
  // A key that is archived is brought back before it is written: 0.14's answer.
  const [archived, why] = await patch('bo-cli', 'market/prod', { OLD: 'x' });
  assert.deepEqual([archived, why.error, why.reason], [409, 'conflict', 'archived']);
  // What the vault would call a fault, the app refuses first, and what is not served yet it says: the vault is not asked.
  app.calls.length = 0;
  const shapes: [string, unknown, number][] = [
    ['market/prod', { API_KEY: 'a\0b' }, 400], ['market/prod', { API_KEY: '\ud800' }, 400], ['market/prod', { API_KEY: 'x'.repeat(64 * 1024 + 1) }, 400], ['market/prod', { 'not a key': 'x' }, 400], ['market/prod', {}, 400],
    ['market/prod', { API_KEY: { ref: 'market/prod' } }, 400],
    ['market/prod', { API_KEY: { ref: 'market/prod@me/FLAG' } }, 400], ['market/prod', { API_KEY: { ref: 'market/prod/FLAG', value: 'x' } }, 400], ['market/prod', { API_KEY: { sensitivity: 'sensitive' } }, 400],
    ['market/prod?dryRun=1', { API_KEY: 'x' }, 400], ['market/prod@me', { API_KEY: 'x' }, 501], ['Market/prod', { API_KEY: 'x' }, 400],
  ];
  for (const [path, values, expected] of shapes) assert.equal((await patch('bo-cli', path, values))[0], expected, `${path} ${JSON.stringify(values).slice(0, 40)}`);
  // `__proto__`, which a schema would drop without a word, is refused in the body itself.
  assert.equal((await app.request('/api/secrets/market/prod', as('bo-cli', { method: 'PATCH', body: '{"__proto__":"v","A":"1"}' }))).status, 400);
  assert.deepEqual(app.calls, []);
});

test('a key made a reference, and a reference broken, is one change each: it reads its source, until broken', async () => {
  const patch = (label: string, path: string, values: unknown) => answered(app.request(`/api/secrets/${path}`, as(label, { method: 'PATCH', body: JSON.stringify(values) })));
  const unlink = (label: string, path: string) => cost(() => answered(app.request(`/api/secrets/${path}/reference`, as(label, { method: 'DELETE' }))));
  const [[status, body], calls, statements] = await cost(() => patch('bo-cli', 'market/prod', { LINK: { ref: 'market/prod/DATABASE_URL' }, API_KEY: 'k1' }));
  assert.deepEqual([status, calls, statements], [200, ['change'], 0], JSON.stringify(body));
  assert.deepEqual(body.keys, { API_KEY: { version: 1, sensitivity: 'secret' }, LINK: { reference: 'market/prod/DATABASE_URL' } });
  world.memory.reads.clear();
  assert.deepEqual((await reveal('ada-cli', 'market/prod/LINK'))[1].values, { LINK: 'postgres://märkt' }, 'whoever reads here reads it');
  const refused: [unknown, number, string][] = [
    [{ LINK2: { ref: 'market/prod/LINK' } }, 409, 'reference_to_reference'], [{ DATABASE_URL: { ref: 'market/prod/DATABASE_URL' } }, 409, 'reference_to_itself'],
    [{ DATABASE_URL: { ref: 'market/prod/FLAG' } }, 409, 'referenced'], [{ LINK2: { ref: 'market/prod/NOPE' } }, 404, 'unknown_key'],
    // A sensitive source is used by its maker, which a developer here does not; billing is past Bo's reach.
    [{ LINK2: { ref: 'market/prod/STRIPE_KEY' } }, 403, 'no_access'], [{ LINK2: { ref: 'billing/prod/X' } }, 403, 'no_access'],
  ];
  for (const [values, code, reason] of refused) {
    const [got, said] = await patch('bo-cli', 'market/prod', values);
    assert.deepEqual([got, said.reason], [code, reason], JSON.stringify(values));
  }

  assert.deepEqual((await unlink('ada-cli', 'market/prod/LINK'))[0].slice(0, 1), [403], 'a viewer breaks nothing');
  const [[broke, broken], did, ran] = await unlink('bo-cli', 'market/prod/LINK');
  assert.deepEqual([broke, did, ran], [200, ['change'], 0], JSON.stringify(broken));
  assert.deepEqual({ ...broken, operationId: 'x' }, { operationId: 'x', reference: { holder: 'market/prod/LINK', source: 'market/prod/DATABASE_URL', state: 'broken' } });
  for (const path of ['market/prod/LINK', 'market/prod/DATABASE_URL', 'market/prod@me/LINK']) {
    const [[got, said]] = await unlink('bo-cli', path);
    assert.deepEqual([got, said.error, said.reason], [404, 'not_found', 'no_reference'], path);
  }
  world.memory.reads.clear();
  assert.deepEqual((await reveal('ada-cli', 'market/prod/LINK')).map((part, i) => (i === 0 ? part : (part as Body).reason)), [404, 'no_value']);
});

test('a key archived, brought back or filed, and a folder of keys renamed or emptied, is one change each', async () => {
  // Dee maintains market: she archives and brings back, which a developer does not.
  const dee = user('dee');
  await write(world, ...rows('roles', role(false, 'maintainer', ['secret.read', 'secret.write', 'secret.archive'])), ...rows('principals', principal(dee)),
    ...rows('grants', grant(dee, 'maintainer', { project: market })), ...rows('credentials', credential('dee-cli', dee, { lastUsedAt: new Date() })));
  const call = (label: string, method: string, path: string, body?: unknown) =>
    cost(() => answered(app.request(`/api/${path}`, as(label, { method, ...(body === undefined ? {} : { body: JSON.stringify(body) }) }))));
  const filed = async () => Object.fromEntries((await rowsOf<{ key: string; folder: string | null; archived: boolean }>(world.owner,
    sql`SELECT s.key, s.folder, s.archived_at IS NOT NULL AS archived FROM secrets s JOIN environments e ON e.id = s.environment_id WHERE e.slug = 'prod' AND s.key IN ('DATABASE_URL', 'FLAG', 'OLD') ORDER BY s.key`)).map((row) => [row.key, [row.folder, row.archived]]));

  // `null` archives a key, beside a value written: one change.
  const [[status, body], calls, statements] = await call('dee-cli', 'PATCH', 'secrets/market/prod', { DATABASE_URL: null, API_KEY: 'k1' });
  assert.deepEqual([status, calls, statements], [200, ['change'], 0], JSON.stringify(body));
  assert.deepEqual(body.keys, { API_KEY: { version: 1, sensitivity: 'secret' }, DATABASE_URL: { archived: true } });
  world.memory.reads.clear();
  assert.deepEqual((await reveal('dee-cli', 'market/prod/DATABASE_URL')).map((part, i) => (i === 0 ? part : (part as Body).reason)), [404, 'unknown_key']);
  // A developer archives nothing.
  assert.deepEqual((await call('bo-cli', 'PATCH', 'secrets/market/prod', { FLAG: null }))[0].map((part, i) => (i === 0 ? part : (part as Body).reason)), [403, 'no_access']);

  // One key: brought back and filed at once, or filed alone, archived or not.
  const [[back, brought], did, ran] = await call('dee-cli', 'PATCH', 'secrets/market/prod/DATABASE_URL', { archived: false, folder: 'db' });
  assert.deepEqual([back, did, ran], [200, ['change'], 0], JSON.stringify(brought));
  assert.deepEqual({ ...brought, operationId: 'x' }, { operationId: 'x', key: 'DATABASE_URL', archived: false, folder: 'db' });
  for (const key of ['FLAG', 'OLD']) assert.equal((await call('bo-cli', 'PATCH', `secrets/market/prod/${key}`, { folder: 'db' }))[0][0], 200, key);
  // Its own name beside what is asked is no rename.
  assert.deepEqual((await call('bo-cli', 'PATCH', 'secrets/market/prod/FLAG', { key: 'FLAG', folder: 'db' }))[0][1].folder, 'db');
  assert.deepEqual(await filed(), { DATABASE_URL: ['db', false], FLAG: ['db', false], OLD: ['db', true] });
  const refused: [string, string, unknown, number, string][] = [
    // A developer brings back nothing, a viewer files nothing, and a key not there is not filed.
    ['bo-cli', 'OLD', { archived: false }, 403, 'no_access'], ['ada-cli', 'FLAG', { folder: 'x' }, 403, 'no_access'], ['bo-cli', 'NOPE', { folder: 'x' }, 404, 'unknown_key'],
  ];
  for (const [label, key, patch, code, reason] of refused) {
    const [[got, said]] = await call(label, 'PATCH', `secrets/market/prod/${key}`, patch);
    assert.deepEqual([got, said.reason], [code, reason], `${label} ${key}`);
  }
  // What the app refuses by its shape, and what is not served yet: the vault is not asked.
  app.calls.length = 0;
  const unserved: [string, unknown, number][] = [
    ['market/prod/FLAG', { key: 'NEW_FLAG' }, 501], ['market/prod/FLAG', { key: 'FLAG' }, 501], ['market/prod/FLAG', { inherit: true }, 501], ['market/prod@me/FLAG', { folder: 'x' }, 501],
    ['market/prod/FLAG', {}, 400], ['market/prod/FLAG', { inherit: true, folder: 'x' }, 400], ['market/prod/FLAG', { folder: ' x' }, 400], ['market/prod/FLAG', { folder: '\ud800' }, 400], ['market/prod/FLAG', { archived: 'yes' }, 400], ['market/prod/FLAG', { sensitivity: 'plain' }, 400],
  ];
  for (const [path, patch, code] of unserved) assert.equal((await call('bo-cli', 'PATCH', `secrets/${path}`, patch))[0][0], code, `${path} ${JSON.stringify(patch)}`);
  assert.deepEqual(app.calls, []);

  // A folder renamed: every key in it, archived ones too, by whoever writes there; then emptied, and gone.
  assert.equal((await call('ada-cli', 'PATCH', 'folders/market/prod/db', { name: 'data' }))[0][0], 403);
  // A key moved out of it behind the vault: none is left behind, so none moves.
  const behind = (folder: string) => world.owner.execute(sql`UPDATE secrets SET folder = ${folder} WHERE key = 'FLAG' AND environment_id = (SELECT e.id FROM environments e JOIN projects p ON p.id = e.project_id WHERE p.slug = 'market' AND e.slug = 'prod')`);
  await behind('hidden');
  const [[tampered, said]] = await call('bo-cli', 'PATCH', 'folders/market/prod/db', { name: 'data' });
  assert.deepEqual([tampered, said.error, said.reason], [409, 'conflict', 'unreadable']);
  await behind('db');
  assert.deepEqual(await filed(), { DATABASE_URL: ['db', false], FLAG: ['db', false], OLD: ['db', true] });
  const [[renamed, moved], asked, queried] = await call('bo-cli', 'PATCH', 'folders/market/prod/db', { name: 'data' });
  assert.deepEqual([renamed, asked, queried], [200, ['change'], 0], JSON.stringify(moved));
  assert.deepEqual({ ...moved, operationId: 'x' }, { operationId: 'x', folder: 'data', moved: ['DATABASE_URL', 'FLAG', 'OLD'] });
  assert.deepEqual(await filed(), { DATABASE_URL: ['data', false], FLAG: ['data', false], OLD: ['data', true] });
  const [[emptied, out]] = await call('bo-cli', 'DELETE', 'folders/market/prod/data');
  assert.deepEqual([emptied, out.folder, out.moved], [200, null, ['DATABASE_URL', 'FLAG', 'OLD']]);
  assert.deepEqual(await filed(), { DATABASE_URL: [null, false], FLAG: [null, false], OLD: [null, true] });
  const [[gone, why]] = await call('bo-cli', 'DELETE', 'folders/market/prod/data');
  assert.deepEqual([gone, why.error, why.reason], [404, 'not_found', 'no_folder']);
  app.calls.length = 0;
  const shapes: [string, string, unknown, number][] = [['DELETE', 'folders/market/prod@me/data', undefined, 501], ['PATCH', 'folders/market/prod/%20data', { name: 'x' }, 400], ['PATCH', 'folders/market/prod/data', { name: 'a/b' }, 400], ['PATCH', 'folders/market/prod/data', { name: '\ud800' }, 400]];
  for (const [method, path, input, code] of shapes) assert.equal((await call('bo-cli', method, path, input))[0][0], code, path);
  assert.deepEqual(app.calls, []);
});

test('a path is a route or it is not: its method, its segments and its body are held before any handler runs', async () => {
  const tried = async (path: string, init: RequestInit = {}) => {
    const response = await app.request(path, as('ada-cli', init));
    return [response.status, ((await response.json()) as Body).error, response.headers.get('allow')];
  };
  assert.deepEqual(await tried('/api/nope'), [404, 'not_found', null]);
  assert.deepEqual(await tried('/api/reveals'), [405, 'method_not_allowed', 'POST']);
  assert.deepEqual(await tried('/api/me', { method: 'POST' }), [405, 'method_not_allowed', 'GET']);
  assert.deepEqual(await tried('/api/%E0%A4%A'), [400, 'bad_request', null]);
  assert.deepEqual(await tried('/api/reveals', { method: 'POST', body: '{' }), [400, 'bad_request', null]);
  assert.deepEqual(await tried('/api/reveals', json({ path: 'market/prod', keys: [], extra: 1 })), [400, 'bad_request', null]);
  assert.deepEqual(await tried('/api/reveals', json({ path: 'market' })), [400, 'bad_request', null]);
  assert.deepEqual(await tried('/api/reveals', json({ path: 'market/prod', keys: Array.from({ length: 1001 }, (_, i) => `K${i}`) })), [400, 'bad_request', null]);
  assert.deepEqual(await tried('/api/secrets/market/prod', { method: 'PATCH', body: JSON.stringify(Object.fromEntries(Array.from({ length: 2001 }, (_, i) => [`K${i}`, 'x']))) }), [400, 'bad_request', null]);
  assert.deepEqual(await tried('/api/secrets/market/prod', { method: 'PATCH', body: JSON.stringify({ A: 'x'.repeat(1024 * 1024) }) }), [400, 'bad_request', null]);
  assert.deepEqual(app.calls, []);
  // Outside the API: health, sign-in (signin.test.ts), and no MCP yet.
  assert.deepEqual(await tried('/livez'), [200, undefined, null]);
  assert.deepEqual(await answered(app.request('/readyz')), [200, { ok: true }]);
  assert.equal((await app.request('/livez', { method: 'HEAD' })).status, 200);
  assert.deepEqual(await tried('/livez', { method: 'POST' }), [405, 'method_not_allowed', 'GET']);
  assert.deepEqual(await tried('/mcp', { method: 'POST' }), [404, 'not_found', null]);
});

test('who is asking, and where they hold something: one call to the vault, one statement, scoped by its answer', async () => {
  const me = (label: string) => answered(app.request('/api/me', as(label)));
  const [[status, mine], calls, statements] = await cost(() => me('ada-cli'));
  assert.deepEqual([status, calls, statements], [200, ['caller'], 1], JSON.stringify(mine));
  assert.deepEqual(
    { principal: mine.principal, registered: mine.registered, instanceRole: mine.instanceRole, runsInstance: mine.runsInstance, canReadAudit: mine.canReadAudit, scope: mine.scope, credentialExpiresAt: mine.credentialExpiresAt },
    { principal: { type: 'user', id: 'ada@acme.example' }, registered: true, instanceRole: 'member', runsInstance: false, canReadAudit: false, scope: { projects: 'all', environments: 'all' }, credentialExpiresAt: '2027-01-01T00:00:00.000Z' },
  );
  // What she views; her own config of prod, as `prod@me`, whose values are hers; not staging, protected, nor billing.
  assert.deepEqual(mine.environments, [
    { project: 'market', environment: 'fork', permissions: ['secret.read'] },
    { project: 'market', environment: 'prod', permissions: ['secret.read'] },
    { project: 'market', environment: 'prod@me', permissions: ['secret.read', 'secret.use', 'secret.write', 'secret.archive'] },
  ]);
  // The fields other areas answer say none, until they are served.
  assert.deepEqual([mine.setsUpServices, mine.serviceSetup, mine.features, mine.personalToken], [false, null, { mcp: null, workloads: false }, null]);

  // Bo's role holds its permissions in a protected environment too. Nobody else's personal config is a place of his.
  const [, bos] = await me('bo-cli');
  assert.deepEqual((bos.environments as { environment: string }[]).map((at) => at.environment), ['fork', 'prod', 'staging']);
  // Her statement read her one project, by its id; an Owner's, every project.
  const params = (query: unknown) => new PgDialect().sqlToQuery(query as SQL).params;
  const [market] = await rowsOf<{ id: string }>(world.owner, sql`SELECT id FROM projects WHERE slug = 'market'`);
  app.executed.length = 0;
  await me('ada-cli');
  assert.deepEqual(params(app.executed.at(-1)), [[market!.id]]);
  // Whoever runs the instance reads every project, in one statement still.
  const [[, owner], , all] = await cost(() => me('cy-cli'));
  assert.equal(all, 1);
  assert.deepEqual(params(app.executed.at(-1)), []);
  assert.deepEqual([owner.runsInstance, owner.canReadAudit, owner.setsUpServices], [true, true, true]);
  // Not Ada's personal config, which is hers alone, nor what a deletion left behind.
  assert.deepEqual((owner.environments as { project: string; environment: string }[]).map((at) => `${at.project}/${at.environment}`), ['billing/prod', 'market/fork', 'market/prod', 'market/staging']);
  // On a token scoped to market as a viewer, Bo is a viewer of market, and runs nothing.
  const [, scoped] = await me(PERSONAL);
  assert.deepEqual([(scoped.environments as { environment: string; permissions: string[] }[]).find((at) => at.environment === 'prod')?.permissions, scoped.runsInstance], [['secret.read'], false]);
  // His own scope is told as it is, on the token as on his session: billing, which the token does not reach, by its name.
  assert.deepEqual([scoped.scope, bos.scope], [{ projects: { except: ['billing'] }, environments: 'all' }, { projects: { except: ['billing'] }, environments: 'all' }]);
  assert.deepEqual(await me('nobody'), [401, { error: 'unauthenticated', message: 'that credential is unknown, expired or revoked', reason: 'unauthenticated' }]);
});

test('an archived place is not listed, and a protected environment the vault\'s answer lacks is protected still, by its row', async () => {
  const listed = async () => ((await answered(app.request('/api/me', as('ada-cli'))))[1].environments as { environment: string }[]).map((at) => at.environment);
  // staging's row edited behind the vault: it is no row of the vault's, and its answer protects nothing there. Neither staging nor her config of it is listed.
  await world.owner.execute(sql`UPDATE environments SET mac = decode(repeat('00', 36), 'hex') WHERE slug = 'staging'`);
  world.memory.callers.clear();
  assert.deepEqual(await listed(), ['fork', 'prod', 'prod@me']);
  // prod archived: neither it nor her config of it is a place any more.
  await world.owner.execute(sql`UPDATE environments SET archived_at = now() WHERE slug = 'prod' AND project_id = (SELECT id FROM projects WHERE slug = 'market')`);
  assert.deepEqual(await listed(), ['fork']);
  const owners = async () => ((await answered(app.request('/api/me', as('cy-cli'))))[1].environments as { project: string; environment: string }[]).map((at) => `${at.project}/${at.environment}`);
  assert.deepEqual(await owners(), ['billing/prod', 'market/fork', 'market/staging']);
  await world.owner.execute(sql`UPDATE projects SET archived_at = now() WHERE slug = 'billing'`);
  assert.deepEqual(await owners(), ['market/fork', 'market/staging']);
});

test("a personal config's values are its owner's alone, whatever anyone else holds; what else is asked of it is asked of its parent", async () => {
  const called = async (label: string) => {
    const who = await app.vault.caller({ token: createHash('sha256').update(label).digest('hex'), proof: null, request: null, ip: null });
    assert.ok(!('refused' in who));
    return who;
  };
  const [project] = await rowsOf<{ id: string }>(world.owner, sql`SELECT id FROM projects WHERE slug = 'market'`);
  const [prod] = await rowsOf<{ id: string }>(world.owner, sql`SELECT id FROM environments WHERE slug = 'prod' AND project_id = ${project!.id}`);
  const config = (owner: string) => placeOf({ id: project!.id }, { id: randomUUID(), slug: 'prod-x', protected: false, owner, parent: { id: prod!.id, slug: 'prod', protected: false } });
  const [hers, owners] = [await called('ada-cli'), await called('cy-cli')];
  assert.deepEqual([can(hers, 'secret.read', config(ada)), can(hers, 'secret.write', config(ada)), can(hers, 'audit.read', config(ada))], [true, true, false]);
  // An Owner of the instance reads prod, and its log; never Ada's values.
  assert.deepEqual([can(owners, 'secret.read', config(ada)), can(owners, 'secret.write', config(ada)), can(owners, 'audit.read', config(ada))], [false, false, true]);
  // A config of an environment its owner does not read, staging, protected, is no more theirs.
  const [staging] = await rowsOf<{ id: string }>(world.owner, sql`SELECT id FROM environments WHERE slug = 'staging'`);
  const of = (parent: { id: string; slug: string; protected: boolean }) => placeOf({ id: project!.id }, { id: randomUUID(), slug: `${parent.slug}-x`, protected: false, owner: ada, parent });
  assert.equal(can(hers, 'secret.read', of({ id: staging!.id, slug: 'staging', protected: true })), false);
  // By its parent's own row too: one the vault's answer does not list as protected is protected still.
  assert.deepEqual([can(hers, 'secret.read', of({ id: prod!.id, slug: 'prod', protected: false })), can(hers, 'secret.read', of({ id: prod!.id, slug: 'prod', protected: true }))], [true, false]);
});

test("a page's render asks the vault who its visitor is once, for all its calls, and changes nothing", async () => {
  const session = { headers: { cookie: `${SESSION}=${BROWSER}; theme=dark` } };
  const [response, calls, statements] = await cost(() => app.render(session, async ({ client, cspNonce }) => {
    const [first, second] = await Promise.all([client.me(), client.me()]);
    // A change during a render has no origin to show: refused as from any other site.
    const change = await client.secrets.set('market/prod', { API_KEY: 'x' }).then(() => 'written', (error: unknown) => (error instanceof CoffreError ? error.code : String(error)));
    return { same: JSON.stringify(first) === JSON.stringify(second), who: first.principal.id, change, nonce: cspNonce.length > 0 };
  }));
  assert.deepEqual(await response.json(), { same: true, who: 'bo@acme.example', change: 'cross_origin', nonce: true });
  assert.deepEqual([calls, statements], [['caller'], 2]);
  // Nobody signed in: each call is answered so, and the vault is not asked.
  const anonymous = await cost(() => app.render({}, ({ client }) => client.me().then(() => 'answered', (error: unknown) => (error instanceof CoffreError ? error.code : String(error)))));
  assert.deepEqual([await anonymous[0].json(), anonymous[1]], ['unauthenticated', []]);
});

test('below its migrations the app serves nothing but its health, and asks the vault nothing', async () => {
  // A database with no ledger: never migrated.
  const below = await openApp({ database: 'postgres' });
  try {
    const api = await below.request('/api/me', as('ada-cli'));
    assert.deepEqual([api.status, ((await api.json()) as Body).error, api.headers.get('retry-after'), api.headers.has('content-security-policy')], [503, 'migrating', '30', true]);
    const page = await below.request('/projects', { headers: { accept: 'text/html' } });
    assert.deepEqual([page.status, page.headers.get('content-type')], [503, 'text/html; charset=utf-8']);
    assert.match(await page.text(), /coffre migrate/);
    assert.equal((await below.request('/livez')).status, 200);
    assert.deepEqual(await answered(below.request('/readyz')), [503, { ok: false }]);
    assert.deepEqual(below.calls, []);
  } finally {
    await below.close();
  }
});

test('behind Cloudflare Access nothing of the API is served yet: an assertion is no credential of the vault', async () => {
  const behind = await openApp({ auth: cloudflareAccess({ teamDomain: 'acme.cloudflareaccess.com', audience: 'a'.repeat(64) }) });
  try {
    const answers = await Promise.all([
      behind.request('/api/me', { headers: { 'cf-access-jwt-assertion': 'ada-cli' } }),
      behind.request('/api/me', as('ada-cli')),
    ]);
    for (const response of answers) assert.deepEqual([response.status, ((await response.json()) as Body).error], [501, 'not_implemented']);
    assert.deepEqual(behind.calls, []);
  } finally {
    await behind.close();
  }
});

test('the projects a page reads are those its caller reaches: every one for whoever runs the instance or holds a role across it', () => {
  const holds = (more: Partial<Called['holds']>): Called => ({
    principal: ada,
    credential: { id: 'c', kind: 'cli', expiresAt: '' },
    holds: { role: 'member', scope: { projects: 'all', environments: 'all' }, grants: [], credentialScope: null, service: false, kind: 'person', policy: DEFAULT_POLICY, ...more },
  });
  assert.deepEqual(projectsReached(holds({})), []);
  assert.deepEqual(projectsReached(holds({ grants: [{ projectId: 'p1', environmentId: null, role: 'viewer' }, { projectId: 'p2', environmentId: 'e1', role: 'viewer' }, { projectId: 'p1', environmentId: 'e2', role: 'viewer' }] })), ['p1', 'p2']);
  assert.equal(projectsReached(holds({ role: 'owner' })), null);
  // An Owner on a token reaches what the token does, and a role scoped to some projects, those.
  assert.deepEqual(projectsReached(holds({ role: 'owner', credentialScope: [{ projectId: 'p3', environmentId: null, role: 'viewer' }] })), ['p3']);
  // With what their own scope lists, which `GET /me` names: a token narrows what they do, not who they are.
  assert.deepEqual(projectsReached(holds({ role: 'auditor', scope: { projects: { except: ['p4'] }, environments: 'all' }, credentialScope: [{ projectId: 'p3', environmentId: null, role: 'viewer' }] })), ['p3', 'p4']);
  assert.deepEqual(projectsReached(holds({ role: 'auditor', scope: { projects: { only: ['p4'] }, environments: 'all' } })), ['p4']);
  assert.equal(projectsReached(holds({ role: 'auditor', scope: { projects: { except: ['p4'] }, environments: 'all' } })), null);
  assert.equal(projectsReached(holds({ role: 'auditor' })), null);
});
