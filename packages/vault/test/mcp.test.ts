// MCP connections and OAuth clients (src/ops/mcp.ts, docs/design/0.16.md,
// "MCP connections"): a person approves a client, the client redeems its
// code, then refreshes; each access token is a row under its connection,
// and stands while the connection does. Through the contract as the app
// calls it, with the signer reading what it wrote.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';
import { after, beforeEach, test } from 'node:test';

import { MAX_CLIENTS, MAX_CONNECTIONS, type McpScope } from '@coffre/core/mcp';
import type { Asked, McpClient, Presented } from '@coffre/core/vault';
import { rowsOf } from '@coffre/db/dialect';
import { principals } from '@coffre/db/schema';
import { eq, sql } from 'drizzle-orm';

import { commit, prepare, WRITE_MS } from '../src/change.ts';
import { entryOf } from '../src/entry.ts';
import { openLocalVault } from '../src/local.ts';
import { OPERATIONS } from '../src/ops/index.ts';
import { Signer } from '../src/signer.ts';
import { emptyDatabase, memoryStore, openTestVault } from './database.ts';
import { amend, credential, environment, grant, identity, instance, oauthClient, principal, project, role, rows, secret, tokenOf, user, value, write } from './world.ts';

const world = await openTestVault();
const vault = openLocalVault(world.db, world, { wake: world.wake, now: world.now });
after(() => world.close());

const [root, ada, bo, cy] = [user('root'), user('ada'), user('bo'), user('cy')];
const ci = 'token:ci';
const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;
let signer: Signer;
/** Cursor, as it registered. */
let cursor: ReturnType<typeof oauthClient>;

/**
 * Root runs the instance. Ada reads market's values, on a browser session,
 * a CLI's, a personal token and a handle; Bo is a member; Cy was removed.
 * The service account `ci` has a token. Cursor registered as a client.
 */
beforeEach(async () => {
  await emptyDatabase(world.owner);
  for (const kept of [world.memory.reads, world.memory.callers, world.memory.logged, world.memory.touched, world.refused]) kept.clear();
  world.woken.length = 0;
  signer = await Signer.open({ db: world.db, keys: world.keys, now: world.now, store: memoryStore(), keepUsesDays: 90 });
  const market = project('market');
  const prod = environment(market, 'prod');
  const adas = identity(ada, { provider: 'github', issuerHash: 'issuer-of-github', subject: 'gh-ada' });
  const database = await value(world, secret(prod, 'DATABASE_URL'), 'postgres://market');
  cursor = oauthClient('Cursor', { redirectUris: '["http://127.0.0.1/callback","https://cursor.example/cb"]' });
  await write(
    world,
    ...rows('policy', instance()),
    ...rows('roles', role(true, 'owner', ['secret.read']), role(true, 'member', []), role(false, 'viewer', ['secret.read'])),
    ...rows('principals', principal(root, { role: 'owner' }), principal(ada), principal(bo), principal(cy, { status: 'removed', generation: 1 }), principal(ci)),
    ...rows('identities', adas),
    ...rows('projects', market),
    ...rows('environments', prod),
    ...rows('secrets', database),
    ...rows('grants', grant(ada, 'viewer', { project: market })),
    ...rows('credentials',
      credential('ada-web', ada, { kind: 'browser', identityId: adas.id }),
      credential('ada-cli', ada),
      credential('ada-pat', ada, { kind: 'personal', scope: '[]' }),
      credential('ada-handle', ada, { kind: 'handle', scope: '[]', places: '[]' }),
      credential('bo-cli', bo),
      credential('cy-cli', cy),
      credential('ci-token', ci, { scope: '[]' }),
    ),
    ...rows('oauthClients', cursor),
  );
  assert.deepEqual(await checked(), []);
});

const from = { request: 'req-1', ip: '192.0.2.7' };
const hex = (label: string) => tokenOf(label).toString('hex');
const shown = (label: string): Presented => ({ token: hex(label), proof: null, ...from });
/** A PKCE verifier only the client that drew it holds, and its S256 challenge. */
const verifierOf = (label: string) => createHash('sha256').update(`verifier:${label}`).digest('base64url');
const challengeOf = (label: string) => createHash('sha256').update(verifierOf(label)).digest('base64url');

const CLAUDE: McpClient = { id: 'https://claude.ai/oauth/mcp-client.json', name: 'Claude', host: 'claude.ai', registration: 'cimd', redirectUri: 'https://claude.ai/api/mcp/auth_callback' };
const OTHER: McpClient = { id: 'https://other.example/client.json', name: 'Other', host: 'other.example', registration: 'cimd', redirectUri: 'https://other.example/cb' };
const MONTH = 30 * 24 * 60;

/** `label` approves `client` for `scopes`; the code is `code`, its verifier drawn for it. */
const connect = (label: string, code: string, scopes: McpScope[] = ['read'], client: McpClient = CLAUDE): Asked<'mcp.connect'> =>
  ({ ...shown(label), op: 'mcp.connect', client, scopes, code: hex(code), challenge: challengeOf(code) });
/** The client redeems `code` for `access` and `refresh`. */
const byCode = (code: string, access: string, refresh: string, more: { client?: string; redirectUri?: string; verifier?: string; minutes?: number } = {}): Asked<'mcp.token'> => ({
  ...from, op: 'mcp.token', client: more.client ?? CLAUDE.id, tokens: { access: hex(access), refresh: hex(refresh) },
  grant: 'authorization_code', code: hex(code), verifier: more.verifier ?? verifierOf(code), redirectUri: more.redirectUri ?? CLAUDE.redirectUri, minutes: more.minutes ?? MONTH,
});
/** The client refreshes `held` for `access` and `next`. */
const byRefresh = (held: string, access: string, next: string, scopes: McpScope[] | null = null, client = CLAUDE.id): Asked<'mcp.token'> =>
  ({ ...from, op: 'mcp.token', client, tokens: { access: hex(access), refresh: hex(next) }, grant: 'refresh_token', refresh: hex(held), scopes });
const register = (name = 'Zed', redirectUris = ['http://127.0.0.1/callback']): Asked<'oauth.register'> => ({ ...from, ip: '198.51.100.9', op: 'oauth.register', name, redirectUris });

/** Who a token is, as the vault answers any request that shows it. */
const who = async (label: string) => {
  world.memory.callers.clear();
  const answer = await vault.caller(shown(label));
  return 'refused' in answer ? answer.refused : `${answer.principal} ${answer.credential.kind}`;
};
const entries = async () => (await rowsOf<{ kept: boolean; body: string; mac: Buffer }>(world.owner, sql`SELECT kept, body, mac FROM log_pending ORDER BY id`)).map((row) => ({ kept: row.kept, ...entryOf(world.keys, row)! }));
type Stored = { id: string; token_hash: string; previous_token_hash: string | null; challenge: string | null; expires_at: number; revoked_at: number | null; revoked_by: string | null; ancestors: string | null; client: string; label: string; generation: number };
const stored = async (id: string) => (await rowsOf<Stored>(world.owner, sql`SELECT id::text, encode(token_hash, 'hex') AS token_hash, encode(previous_token_hash, 'hex') AS previous_token_hash, challenge, (extract(epoch FROM expires_at) * 1000)::float8 AS expires_at, (extract(epoch FROM revoked_at) * 1000)::float8 AS revoked_at, revoked_by, ancestors, client, label, generation FROM credentials WHERE id = ${id}::uuid`))[0]!;
/** Everything the vault told the signer of, signed, and the rows held to its mirror: what it found. */
async function checked() {
  for (const hash of world.woken.splice(0)) await signer.wake(hash);
  await signer.run(true);
  return (await signer.take()).map((finding) => finding.found);
}
/** A change's answer, which the test needs made. */
async function made<O extends 'mcp.connect' | 'mcp.token' | 'oauth.register' | 'credential.end'>(input: Asked<O>) {
  const done = await vault.change(input);
  assert.ok(!('refused' in done), JSON.stringify(done));
  return done.answer;
}
/** A code redeemed: the tokens it made. */
async function redeemed(input: Asked<'mcp.token'>) {
  const answer = await made(input);
  assert.equal(answer.ended, false);
  return answer as Extract<typeof answer, { ended: false }>;
}
const reveal = (label: string) => vault.use({ ...shown(label), project: 'market', environment: 'prod', mine: false, keys: ['DATABASE_URL'], purpose: 'reveal', upstream: null });

test('Ada connects Claude: a code for a minute, then an access token that is Ada as her session is, with its scopes, and a refresh that moves both on', async () => {
  const before = (await entries()).length;
  const connected = await made(connect('ada-web', 'code-1', ['read', 'reveal']));
  assert.equal(connected.expiresAt, new Date(world.now() + MINUTE).toISOString());
  // The connection's own token is what the client redeems, never a bearer.
  assert.equal(await who('code-1'), 'unauthenticated');
  const row = await stored(connected.connection);
  assert.deepEqual([row.token_hash, row.challenge, row.label, JSON.parse(row.client)], [hex('code-1'), challengeOf('code-1'), 'Claude',
    { id: CLAUDE.id, host: 'claude.ai', registration: 'cimd', redirectUri: CLAUDE.redirectUri, scopes: 'read reveal' }]);

  world.tick(10_000);
  const first = await redeemed(byCode('code-1', 'acc-1', 'ref-1'));
  assert.deepEqual(first, { ended: false, principal: ada, connection: connected.connection, credential: first.credential, expiresAt: new Date(world.now() + HOUR).toISOString(), scopes: ['read', 'reveal'] });
  const redeemedRow = await stored(connected.connection);
  assert.deepEqual([redeemedRow.token_hash, redeemedRow.previous_token_hash, redeemedRow.challenge, redeemedRow.expires_at], [hex('ref-1'), hex('code-1'), null, world.now() + MONTH * MINUTE]);
  const access = await stored(first.credential);
  assert.deepEqual([access.ancestors, access.label, JSON.parse(access.client).scopes], [JSON.stringify([connected.connection]), 'Claude', 'read reveal']);

  world.memory.callers.clear();
  const called = await vault.caller(shown('acc-1'));
  assert.ok(!('refused' in called));
  assert.deepEqual([called.principal, called.credential.kind, called.credential.connection, called.credential.scopes, called.holds.credentialScope, called.holds.kind], [ada, 'mcp', connected.connection, ['read', 'reveal'], null, 'person']);
  assert.equal(called.holds.grants.length, 1);
  assert.equal(await who('ref-1'), 'unauthenticated', 'a refresh token is no bearer either');
  // Its use is its connection's, which Connected apps lists.
  const [touched] = await rowsOf<{ connection: number | null; token: number | null }>(world.owner, sql`SELECT (SELECT (extract(epoch FROM last_used_at) * 1000)::float8 FROM credentials WHERE id = ${connected.connection}::uuid) AS connection, (SELECT last_used_at FROM credentials WHERE id = ${first.credential}::uuid) AS token`);
  assert.deepEqual([touched!.connection, touched!.token], [world.now(), null]);

  // With `reveal` it is handed values; narrowed to `read` at a refresh, it is handed none.
  const shownValue = await reveal('acc-1');
  assert.ok(!('refused' in shownValue));
  assert.deepEqual(shownValue.values.map((item) => ('refused' in item ? item.refused : item.value)), ['postgres://market']);
  world.tick(50 * MINUTE);
  const second = await redeemed(byRefresh('ref-1', 'acc-2', 'ref-2', ['read']));
  assert.deepEqual([second.scopes, second.connection], [['read'], connected.connection]);
  assert.deepEqual(await reveal('acc-2'), { refused: 'mcp_no_reveal' });
  assert.equal(await who('acc-1'), `${ada} mcp`, 'the token before stands until its hour is up');
  world.tick(10 * MINUTE);
  assert.equal(await who('acc-1'), 'unauthenticated');
  assert.equal(await who('acc-2'), `${ada} mcp`);

  const written = (await entries()).slice(before);
  // The value it was handed is logged as any read is, on the access token.
  assert.deepEqual(written.map((entry) => [entry.action, entry.actor, entry.kept]), [['mcp.connect', ada, true], ['mcp.token', ada, false], ['secret.read', ada, false], ['mcp.token', ada, false]]);
  assert.equal(written[2]!.credential, first.credential);
  assert.deepEqual(written[0]!.detail, { connection: connected.connection, client: CLAUDE.id, name: 'Claude', host: 'claude.ai', registration: 'cimd', redirectHost: 'claude.ai', scopes: 'read reveal' });
  assert.deepEqual(written[3]!.detail, { connection: connected.connection, client: CLAUDE.id, grant: 'refresh_token', credential: second.credential, scopes: 'read' });
  assert.deepEqual(await checked(), []);
});

test('a code is good for its minute, its client, its redirect and its verifier only; refused, it writes nothing', async () => {
  const { connection } = await made(connect('ada-web', 'code-1'));
  const before = (await entries()).length;
  assert.deepEqual(await vault.change(byCode('code-1', 'a', 'r', { client: OTHER.id })), { refused: 'wrong_client' });
  assert.deepEqual(await vault.change(byCode('code-1', 'a', 'r', { redirectUri: 'https://claude.ai/elsewhere' })), { refused: 'wrong_redirect' });
  assert.deepEqual(await vault.change(byCode('code-1', 'a', 'r', { verifier: verifierOf('someone-else') })), { refused: 'wrong_verifier' });
  assert.deepEqual(await vault.change(byCode('code-0', 'a', 'r')), { refused: 'unknown_grant' });
  // A code is no refresh token.
  assert.deepEqual(await vault.change(byRefresh('code-1', 'a', 'r')), { refused: 'unknown_grant' });
  // Within its minute less a write's time (`WRITE_MS`): a write may wait that long on a lock.
  world.tick(55 * 1000);
  assert.deepEqual(await vault.change(byCode('code-1', 'a', 'r')), { refused: 'expired' });
  assert.equal((await entries()).length, before);
  assert.equal((await stored(connection)).token_hash, hex('code-1'));
  // What does not cross the contract as it says is a fault, not a refusal.
  await assert.rejects(vault.change(byCode('code-1', 'a', 'r', { verifier: 'short' })), TypeError);
  await assert.rejects(vault.change(byCode('code-1', 'a', 'r', { minutes: 366 * 24 * 60 })), TypeError);
  await assert.rejects(vault.change(byCode('code-1', 'a', 'a')), TypeError);
});

test('a code presented again after it was redeemed ends the connection, and every access token under it, by its row alone', async () => {
  const { connection } = await made(connect('ada-web', 'code-1'));
  const tokens = await redeemed(byCode('code-1', 'acc-1', 'ref-1'));
  assert.equal(await who('acc-1'), `${ada} mcp`);
  assert.deepEqual(await vault.change(byCode('code-1', 'acc-x', 'ref-x')), { answer: { ended: true, connection } });
  assert.equal(await who('acc-1'), 'unauthenticated');
  assert.equal(await who('acc-x'), 'unauthenticated');
  const [ended, access] = [await stored(connection), await stored(tokens.credential)];
  assert.deepEqual([ended.revoked_by, ended.revoked_at], ['system:vault', world.now()]);
  assert.equal(access.revoked_at, null, 'its access token ends with the connection, with no write of its own');
  assert.deepEqual(await vault.change(byRefresh('ref-1', 'acc-2', 'ref-2')), { refused: 'unknown_grant' });
  assert.deepEqual(await vault.change(byCode('code-1', 'acc-y', 'ref-y')), { refused: 'unknown_grant' }, 'ended once');
  const [entry] = (await entries()).filter((one) => one.action === 'mcp.disconnect');
  assert.deepEqual([entry!.actor, entry!.kept, entry!.detail], [null, true, { connection, client: CLAUDE.id, principal: ada, reason: 'code_reused' }]);
  assert.deepEqual(await checked(), []);
});

test('a refresh token presented after it was replaced ends the connection; two refreshes racing on one token never leave two tokens', async () => {
  const { connection } = await made(connect('ada-web', 'code-1'));
  await redeemed(byCode('code-1', 'acc-1', 'ref-1'));
  await redeemed(byRefresh('ref-1', 'acc-2', 'ref-2'));
  assert.deepEqual(await vault.change(byRefresh('ref-1', 'acc-3', 'ref-3')), { answer: { ended: true, connection } });
  for (const label of ['acc-1', 'acc-2', 'acc-3']) assert.equal(await who(label), 'unauthenticated', label);
  assert.deepEqual(await vault.change(byRefresh('ref-2', 'acc-4', 'ref-4')), { refused: 'unknown_grant' });
  assert.equal((await entries()).filter((one) => one.action === 'mcp.disconnect')[0]!.detail.reason, 'refresh_reused');

  for (let round = 0; round < 5; round += 1) {
    await made(connect('ada-web', `code-r${round}`));
    await redeemed(byCode(`code-r${round}`, `acc-r${round}`, `ref-r${round}`));
    const answers = await Promise.all([1, 2].map((n) => vault.change(byRefresh(`ref-r${round}`, `acc-r${round}-${n}`, `ref-r${round}-${n}`))));
    const live = [];
    for (const n of [1, 2]) if ((await who(`acc-r${round}-${n}`)) !== 'unauthenticated') live.push(n);
    const ended = answers.some((answer) => 'answer' in answer && answer.answer.ended);
    // One new token, or the connection ended and none: never two.
    assert.ok(live.length <= 1, JSON.stringify(answers));
    if (ended) assert.deepEqual(live, [], JSON.stringify(answers));
    else assert.equal(live.length, 1, JSON.stringify(answers));
  }
  assert.deepEqual(await checked(), []);
});

test('a refresh narrows what its token holds, never widens it, and stops before its connection ends', async () => {
  await made(connect('ada-web', 'code-1', ['read', 'write']));
  const first = await redeemed(byCode('code-1', 'acc-1', 'ref-1', { minutes: 2 * 60 }));
  assert.deepEqual(first.scopes, ['read', 'write']);
  assert.deepEqual(await vault.change(byRefresh('ref-1', 'acc-2', 'ref-2', ['read', 'reveal'])), { refused: 'invalid_scope' });
  assert.deepEqual(await vault.change(byRefresh('ref-1', 'acc-2', 'ref-2', ['read', 'write'], OTHER.id)), { refused: 'wrong_client' });
  world.tick(90 * MINUTE);
  const second = await redeemed(byRefresh('ref-1', 'acc-2', 'ref-2', ['read']));
  // Never past its connection.
  assert.equal(second.expiresAt, new Date(world.now() + 30 * MINUTE).toISOString());
  world.tick(30 * MINUTE - 5000);
  assert.deepEqual(await vault.change(byRefresh('ref-2', 'acc-3', 'ref-3')), { refused: 'expired' });
  world.tick(5000);
  assert.equal(await who('acc-2'), 'unauthenticated');
});

test('a person removed since they connected redeems nothing, and their tokens stop; one ending a connection ends its tokens', async () => {
  await made(connect('ada-web', 'code-1'));
  await redeemed(byCode('code-1', 'acc-1', 'ref-1'));
  const second = await made(connect('ada-web', 'code-2'));
  const third = await made(connect('ada-web', 'code-3'));
  await redeemed(byCode('code-3', 'acc-3', 'ref-3'));
  // Ada ends the third from Connected apps: its tokens end with it.
  await made({ ...shown('ada-web'), op: 'credential.end', credential: third.connection, of: null });
  assert.equal(await who('acc-3'), 'unauthenticated');
  assert.deepEqual(await vault.change(byRefresh('ref-3', 'acc-4', 'ref-4')), { refused: 'unknown_grant' });

  // Removed, in the generation she connected in, she redeems nothing either.
  await amend(world, 'principals', eq(principals.id, ada), { status: 'removed' });
  assert.deepEqual(await vault.change(byCode('code-2', 'acc-5', 'ref-5')), { refused: 'deactivated' });
  await amend(world, 'principals', eq(principals.id, ada), { status: 'removed', generation: 1 });
  assert.equal(await who('acc-1'), 'unauthenticated');
  assert.deepEqual(await vault.change(byRefresh('ref-1', 'acc-2', 'ref-2')), { refused: 'deactivated' });
  assert.deepEqual(await vault.change(byCode('code-2', 'acc-5', 'ref-5')), { refused: 'deactivated' });
  // Let back in, in a new generation: nothing from before comes back.
  await amend(world, 'principals', eq(principals.id, ada), { status: 'active' });
  assert.deepEqual(await vault.change(byRefresh('ref-1', 'acc-2', 'ref-2')), { refused: 'deactivated' });
  assert.equal(await who('acc-1'), 'unauthenticated');
  assert.equal((await stored(second.connection)).generation, 0);
});

test('a step-up ends the earlier connections of the same client it grants all of and more; one with the same scopes, or of another client, stays', async () => {
  const narrow = await made(connect('ada-web', 'code-a', ['read']));
  await redeemed(byCode('code-a', 'acc-a', 'ref-a'));
  // Its code waiting, a connection supersedes nothing yet.
  const same = await made(connect('ada-web', 'code-b', ['read', 'write']));
  assert.equal(await who('acc-a'), `${ada} mcp`);
  await redeemed(byCode('code-b', 'acc-b', 'ref-b'));
  await made(connect('ada-web', 'code-o', ['read'], OTHER));
  await redeemed(byCode('code-o', 'acc-o', 'ref-o', { client: OTHER.id, redirectUri: OTHER.redirectUri }));
  // Bo's own connection of Claude is his.
  await made(connect('bo-cli', 'code-bo', ['read']));
  await redeemed(byCode('code-bo', 'acc-bo', 'ref-bo'));

  // A second laptop with the same scopes: both stand.
  await made(connect('ada-web', 'code-c', ['read', 'write']));
  await redeemed(byCode('code-c', 'acc-c', 'ref-c'));
  assert.deepEqual(await Promise.all(['acc-a', 'acc-b', 'acc-o', 'acc-bo', 'acc-c'].map(who)), ['unauthenticated', `${ada} mcp`, `${ada} mcp`, `${bo} mcp`, `${ada} mcp`]);
  assert.deepEqual([(await stored(narrow.connection)).revoked_by, (await stored(same.connection)).revoked_at], [ada, null]);
  const redeeming = (await entries()).filter((one) => one.action === 'mcp.token');
  assert.deepEqual(redeeming.map((one) => [one.detail.connection === same.connection, one.kept, one.detail.superseded ?? null]),
    [[false, false, null], [true, true, [narrow.connection]], [false, false, null], [false, false, null], [false, false, null]]);
  assert.deepEqual(await checked(), []);
});

test('only a person, on a session of theirs, connects an app; an MCP connection changes nothing, and weighs nothing', async () => {
  for (const label of ['ada-pat', 'ci-token']) assert.deepEqual(await vault.change(connect(label, 'code-x')), { refused: 'no_access' }, label);
  for (const label of ['ada-handle', 'cy-cli', 'nobody']) assert.deepEqual(await vault.change(connect(label, 'code-x')), { refused: 'unauthenticated' }, label);
  await made(connect('ada-cli', 'code-1'));
  await redeemed(byCode('code-1', 'acc-1', 'ref-1'));
  // Every change it asks for waits for its person, who makes it on their own session.
  assert.deepEqual(await vault.change(connect('acc-1', 'code-x')), { refused: 'unauthenticated' });
  assert.deepEqual(await vault.weigh(connect('acc-1', 'code-x')), { refused: 'unauthenticated' });
  assert.deepEqual(await vault.change({ ...shown('acc-1'), op: 'credential.end', credential: null, of: null }), { refused: 'unauthenticated' });
  assert.equal(await who('acc-1'), `${ada} mcp`, 'and still stands');
});

test(`${MAX_CONNECTIONS} connections at most, a code waiting among them; one whose code lapsed is not`, async () => {
  for (let n = 0; n < MAX_CONNECTIONS; n += 1) await made(connect('ada-web', `code-${n}`));
  assert.deepEqual(await vault.change(connect('ada-web', 'code-x')), { refused: 'too_many_connections' });
  // Bo holds his own.
  await made(connect('bo-cli', 'code-bo'));
  await redeemed(byCode('code-0', 'acc-0', 'ref-0'));
  await redeemed(byCode('code-1', 'acc-1', 'ref-1'));
  world.tick(MINUTE);
  for (let n = 2; n < MAX_CONNECTIONS; n += 1) await made(connect('ada-web', `code-again-${n}`));
  assert.deepEqual(await vault.change(connect('ada-web', 'code-x')), { refused: 'too_many_connections' });
  const [refused] = (await entries()).filter((one) => one.detail.refused !== undefined);
  assert.deepEqual([refused!.action, refused!.actor, refused!.kept], ['mcp.connect', ada, false]);
});

test("a registered client is its row's: its redirects, on any loopback port, and its name; one revoked, gone or written behind the vault connects nothing", async () => {
  const dcr = (more: Partial<McpClient> = {}): McpClient => ({ id: cursor.id, name: 'Not Cursor', host: null, registration: 'dcr', redirectUri: 'http://127.0.0.1:53111/callback', ...more });
  const { connection } = await made({ ...connect('ada-web', 'code-1'), client: dcr() });
  assert.equal((await stored(connection)).label, 'Cursor', 'its own claim, as its row keeps it');
  await redeemed(byCode('code-1', 'acc-1', 'ref-1', { client: cursor.id, redirectUri: 'http://127.0.0.1:53111/callback' }));
  assert.equal(await who('acc-1'), `${ada} mcp`);
  assert.deepEqual(await vault.change({ ...connect('ada-web', 'code-2'), client: dcr({ redirectUri: 'https://evil.example/cb' }) }), { refused: 'wrong_redirect' });
  assert.deepEqual(await vault.change({ ...connect('ada-web', 'code-2'), client: dcr({ id: '00000000-0000-4000-8000-000000000000' }) }), { refused: 'unknown_client' });
  await amend(world, 'oauthClients', sql`id = ${cursor.id}::uuid`, { revokedAt: new Date(world.now()) });
  assert.deepEqual(await vault.change({ ...connect('ada-web', 'code-2'), client: dcr() }), { refused: 'unknown_client' });
  await world.owner.execute(sql`UPDATE oauth_clients SET revoked_at = NULL, redirect_uris = '["https://evil.example/cb"]' WHERE id = ${cursor.id}::uuid`);
  assert.deepEqual(await vault.change({ ...connect('ada-web', 'code-2'), client: dcr({ redirectUri: 'https://evil.example/cb' }) }), { refused: 'tampered' });
  // A registration names no host, and its id is the vault's.
  await assert.rejects(vault.change({ ...connect('ada-web', 'code-2'), client: dcr({ host: 'cursor.example' }) }), TypeError);
  await assert.rejects(vault.change({ ...connect('ada-web', 'code-2'), client: dcr({ id: 'cursor' }) }), TypeError);
  await assert.rejects(vault.change({ ...connect('ada-web', 'code-2'), client: { ...CLAUDE, redirectUri: 'cursor://callback' } }), TypeError);
  await assert.rejects(vault.change({ ...connect('ada-web', 'code-2'), scopes: ['write'] }), TypeError);
});

test('a connection, its member or an access token written behind the vault stands for nothing', async () => {
  const { connection } = await made(connect('ada-web', 'code-1'));
  await world.owner.execute(sql`UPDATE credentials SET expires_at = expires_at + interval '1 day' WHERE id = ${connection}::uuid`);
  assert.deepEqual(await vault.change(byCode('code-1', 'acc-1', 'ref-1')), { refused: 'tampered' });

  const second = await made(connect('ada-web', 'code-2', ['read']));
  const tokens = await redeemed(byCode('code-2', 'acc-2', 'ref-2'));
  await world.owner.execute(sql`UPDATE credentials SET client = replace(client, '"read"', '"read reveal"') WHERE id = ${tokens.credential}::uuid`);
  assert.equal(await who('acc-2'), 'unauthenticated', 'its scopes are its row\'s, under its MAC');
  const third = await redeemed(byRefresh('ref-2', 'acc-3', 'ref-3'));
  assert.equal(await who('acc-3'), `${ada} mcp`);
  await world.owner.execute(sql`UPDATE credentials SET client = replace(client, '"read"', '"read reveal"') WHERE id = ${second.connection}::uuid`);
  assert.equal(await who('acc-3'), 'unauthenticated', 'nor stands under a connection that is not the vault\'s');
  assert.deepEqual(await vault.change(byRefresh('ref-3', 'acc-4', 'ref-4')), { refused: 'tampered' });
  assert.equal((await stored(third.credential)).revoked_at, null);

  await made(connect('bo-cli', 'code-bo'));
  await world.owner.execute(sql`UPDATE principals SET role = 'owner' WHERE id = ${bo}`);
  assert.deepEqual(await vault.change(byCode('code-bo', 'acc-bo', 'ref-bo')), { refused: 'tampered' });
  // An access token with no connection above it, or another member's, is none.
  await world.owner.execute(sql`UPDATE credentials SET ancestors = NULL WHERE id = ${third.credential}::uuid`);
  assert.equal(await who('acc-3'), 'unauthenticated');
});

test('anyone registers a client, up to the table\'s ceiling; two racing for its last place do not both have it', async () => {
  const before = (await entries()).length;
  const { client, createdAt } = await made(register('Zed', ['http://127.0.0.1/callback', 'https://zed.dev/cb']));
  assert.equal(createdAt, new Date(world.now()).toISOString());
  const [row] = await rowsOf<{ name: string; redirect_uris: string; created_ip: string }>(world.owner, sql`SELECT name, redirect_uris, created_ip FROM oauth_clients WHERE id = ${client}::uuid`);
  assert.deepEqual(row, { name: 'Zed', redirect_uris: '["http://127.0.0.1/callback","https://zed.dev/cb"]', created_ip: '198.51.100.9' });
  const [entry] = (await entries()).slice(before);
  assert.deepEqual([entry!.action, entry!.actor, entry!.kept, entry!.objects], ['oauth.register', null, false, [`oauth_client:${client}`]]);
  for (const bad of [register('Zed', []), register('Zed', ['cursor://cb']), register('Zed', ['https://a.example/cb', 'https://a.example/cb']), register('Ze‮d'), register('')]) {
    await assert.rejects(vault.change(bad), TypeError);
  }

  // Up to the last place, the vault's rows or not: Cursor and Zed are two.
  await world.owner.execute(sql`INSERT INTO oauth_clients (id, name, redirect_uris, created_at, mac) SELECT gen_random_uuid(), 'filler', '[]', now(), ''::bytea FROM generate_series(1, ${MAX_CLIENTS - 3})`);
  const raced = await Promise.all([1, 2].map((n) => vault.change(register(`Racer ${n}`))));
  assert.deepEqual(raced.map((answer) => ('refused' in answer ? answer.refused : 'made')).sort(), ['full', 'made']);
  assert.deepEqual(await vault.change(register()), { refused: 'full' });
  const [{ count }] = (await rowsOf<{ count: number }>(world.owner, sql`SELECT count(*)::int AS count FROM oauth_clients`)) as [{ count: number }];
  assert.equal(count, MAX_CLIENTS);
  // Refused, a stranger writes nothing at all.
  assert.equal((await entries()).length, before + 2);

  // Before the vault adopted the database, nobody registers.
  await world.owner.execute(sql`DELETE FROM oauth_clients WHERE name = 'filler'`);
  await world.owner.execute(sql`DELETE FROM policy`);
  assert.deepEqual(await vault.change(register()), { refused: 'adopting' });
  assert.deepEqual(await vault.change(byCode('code-1', 'acc-1', 'ref-1')), { refused: 'adopting' });
});

test('a code redeemed, or a refresh made, in its last moments is written only if it starts a write\'s time before the end, by the database\'s clock', async () => {
  await made(connect('ada-web', 'code-1'));
  await made(connect('ada-web', 'code-2'));
  await redeemed(byCode('code-2', 'acc-2', 'ref-2', { minutes: 2 }));
  // 50 ms before a write's time is left of the code's minute, and of the connection's two: each is decided, and its write waits longer than that.
  world.tick(MINUTE - WRITE_MS - 50);
  const deciding = { workloads: world.workloads, owners: world.owners };
  const late = [await prepare(world, OPERATIONS['mcp.token'](byCode('code-1', 'acc-1', 'ref-1'), deciding))];
  world.tick(MINUTE);
  late.push(await prepare(world, OPERATIONS['mcp.token'](byRefresh('ref-2', 'acc-3', 'ref-3'), deciding)));
  assert.ok(late.every((prepared) => !('refused' in prepared)));
  await sleep(120);
  assert.deepEqual([await commit(world, late[0] as never), await commit(world, late[1] as never)], [false, false]);
  world.tick(120);
  assert.deepEqual([await vault.change(byCode('code-1', 'acc-1', 'ref-1')), await vault.change(byRefresh('ref-2', 'acc-3', 'ref-3'))], [{ refused: 'expired' }, { refused: 'expired' }]);
  assert.equal(await who('acc-1'), 'unauthenticated');
  // Past its end, a connection's replaced token ends nothing: there is nothing left to end.
  world.tick(5000);
  assert.deepEqual(await vault.change(byCode('code-2', 'acc-4', 'ref-4')), { refused: 'unknown_grant' });
});

test('a step-up leaves a connection whose code still waits, and a connection written behind the vault still counts toward the twenty', async () => {
  await made(connect('ada-web', 'code-a', ['read']));
  const waiting = await made(connect('ada-web', 'code-w', ['read']));
  await made(connect('ada-web', 'code-b', ['read', 'write']));
  await redeemed(byCode('code-b', 'acc-b', 'ref-b'));
  assert.equal((await stored(waiting.connection)).revoked_at, null);
  await redeemed(byCode('code-w', 'acc-w', 'ref-w'));
  assert.equal(await who('acc-w'), `${ada} mcp`);

  for (let n = 3; n < MAX_CONNECTIONS; n += 1) await made(connect('ada-web', `code-${n}`));
  const [{ id }] = (await rowsOf<{ id: string }>(world.owner, sql`SELECT id::text FROM credentials WHERE token_hash = ${tokenOf('code-4')}`)) as [{ id: string }];
  await world.owner.execute(sql`UPDATE credentials SET label = 'Forged' WHERE id = ${id}::uuid`);
  assert.deepEqual(await vault.change(connect('ada-web', 'code-x')), { refused: 'too_many_connections' });
});

test('an access token stands only under its own connection: redeemed, live, of its person, generation and client, the one above it; it holds the scopes both hold', async () => {
  const { connection } = await made(connect('ada-web', 'code-1', ['read']));
  const first = await redeemed(byCode('code-1', 'acc-1', 'ref-1'));
  const client = (await stored(connection)).client;
  const scoped = (scopes: string, id = CLAUDE.id) => JSON.stringify({ ...JSON.parse(client), id, scopes });
  /** An access token as the vault would write one, sealed, under `above`. */
  const token = (label: string, above: string[], more: Parameters<typeof credential>[2] = {}) =>
    credential(label, ada, { kind: 'mcp', ancestors: JSON.stringify(above), client, label: 'Claude', expiresAt: new Date(world.now() + HOUR), ...more });
  /** A connection of Ada's, redeemed, then `more` put on it. */
  const live = async (code: string, more: Parameters<typeof amend>[3] = {}) => {
    const { connection: id } = await made(connect('ada-web', code, ['read']));
    await redeemed(byCode(code, `acc-${code}`, `ref-${code}`));
    await amend(world, 'credentials', sql`id = ${id}::uuid`, more);
    return id;
  };
  const waiting = (await made(connect('ada-web', 'code-w', ['read']))).connection;
  const older = await live('code-g', { generation: 1 });
  const lapsed = await live('code-e', { expiresAt: new Date(world.now() - MINUTE) });
  const frozen = await live('code-f', { frozenAt: new Date(world.now()) });
  await write(world, ...rows('credentials',
    token('as-made', [connection]),
    token('under-token', [first.credential]),
    token('under-code', [waiting]),
    credential('bo-under-ada', bo, { kind: 'mcp', ancestors: JSON.stringify([connection]), client, expiresAt: new Date(world.now() + HOUR) }),
    token('under-older', [older]),
    token('under-lapsed', [lapsed]),
    token('under-frozen', [frozen]),
    token('two-above', [connection, connection]),
    token('other-client', [connection], { client: scoped('read', OTHER.id) }),
    token('wider', [connection], { client: scoped('read reveal') }),
  ));
  assert.equal(await who('as-made'), `${ada} mcp`, 'as the vault writes one, it stands');
  for (const label of ['under-token', 'under-code', 'bo-under-ada', 'under-older', 'under-lapsed', 'under-frozen', 'two-above', 'other-client']) assert.equal(await who(label), 'unauthenticated', label);
  // Its own row says `reveal`, its connection does not: it holds `read`.
  world.memory.callers.clear();
  const wider = await vault.caller(shown('wider'));
  assert.ok(!('refused' in wider));
  assert.deepEqual(wider.credential.scopes, ['read']);
  assert.deepEqual(await reveal('wider'), { refused: 'mcp_no_reveal' });
  assert.deepEqual(await checked(), []);
});

test('a step-up leaves an earlier connection that lapsed as it was', async () => {
  const lapsed = await made(connect('ada-web', 'code-a', ['read']));
  await redeemed(byCode('code-a', 'acc-a', 'ref-a', { minutes: 10 }));
  world.tick(11 * MINUTE);
  await made(connect('ada-web', 'code-b', ['read', 'write']));
  await redeemed(byCode('code-b', 'acc-b', 'ref-b'));
  assert.equal((await stored(lapsed.connection)).revoked_at, null);
  const [, stepUp] = (await entries()).filter((one) => one.action === 'mcp.token');
  assert.deepEqual([stepUp!.kept, stepUp!.detail.superseded ?? null], [false, null]);
});
