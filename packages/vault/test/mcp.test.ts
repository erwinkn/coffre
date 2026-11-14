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
import { credentials, principals } from '@coffre/db/schema';
import { eq, sql } from 'drizzle-orm';

import { commit, prepare, WRITE_MS } from '../src/change.ts';
import { entryOf } from '../src/entry.ts';
import { openLocalVault } from '../src/local.ts';
import { OPERATIONS } from '../src/ops/index.ts';
import { through } from '../src/ops/via.ts';
import { Signer } from '../src/signer.ts';
import { emptyDatabase, memoryStore, openTestVault } from './database.ts';
import { amend, credential, environment, grant, identity, instance, oauthClient, principal, project, rewrite, role, rows, secret, tokenOf, user, value, write } from './world.ts';

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
  const bos = identity(bo, { provider: 'github', issuerHash: 'issuer-of-github', subject: 'gh-bo' });
  const database = await value(world, secret(prod, 'DATABASE_URL'), 'postgres://market');
  cursor = oauthClient('Cursor', { redirectUris: '["http://127.0.0.1/callback","https://cursor.example/cb"]' });
  await write(
    world,
    ...rows('policy', instance()),
    ...rows('roles', role(true, 'owner', ['secret.read']), role(true, 'member', []), role(false, 'viewer', ['secret.read'])),
    ...rows('principals', principal(root, { role: 'owner' }), principal(ada), principal(bo), principal(cy, { status: 'removed', generation: 1 }), principal(ci)),
    ...rows('identities', adas, bos),
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
      credential('bo-web', bo, { kind: 'browser', identityId: bos.id }),
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
/** The client gives back `token`, naming itself `client` or not. */
const revoke = (token: string, client: string | null = CLAUDE.id): Asked<'mcp.revoke'> => ({ ...from, op: 'mcp.revoke', token: hex(token), client });
const register = (name = 'Zed', redirectUris = ['http://127.0.0.1/callback']): Asked<'oauth.register'> => ({ ...from, ip: '198.51.100.9', op: 'oauth.register', name, redirectUris });

/** Who a token is, as the vault answers any request that shows it. */
const who = async (label: string) => {
  world.memory.callers.clear();
  const answer = await vault.caller(shown(label));
  return 'refused' in answer ? answer.refused : `${answer.principal} ${answer.credential.kind}`;
};
const entries = async () => (await rowsOf<{ kept: boolean; body: string; mac: Buffer }>(world.owner, sql`SELECT kept, body, mac FROM log_pending ORDER BY id`)).map((row) => ({ kept: row.kept, ...entryOf(world.keys, row)! }));
type Stored = { id: string; token_hash: string; previous_token_hash: string | null; code_hash: string | null; challenge: string | null; expires_at: number; revoked_at: number | null; revoked_by: string | null; ancestors: string | null; client: string; label: string; generation: number };
const stored = async (id: string) => (await rowsOf<Stored>(world.owner, sql`SELECT id::text, encode(token_hash, 'hex') AS token_hash, encode(previous_token_hash, 'hex') AS previous_token_hash, encode(code_hash, 'hex') AS code_hash, challenge, (extract(epoch FROM expires_at) * 1000)::float8 AS expires_at, (extract(epoch FROM revoked_at) * 1000)::float8 AS revoked_at, revoked_by, ancestors, client, label, generation FROM credentials WHERE id = ${id}::uuid`))[0]!;
/** Everything the vault told the signer of, signed, and the rows held to its mirror: what it found. */
async function checked() {
  for (const hash of world.woken.splice(0)) await signer.wake(hash);
  await signer.run(true);
  return (await signer.take()).map((finding) => finding.found);
}
/** A change's answer, which the test needs made. */
async function made<O extends 'mcp.connect' | 'mcp.token' | 'mcp.revoke' | 'oauth.register' | 'mcp.decide' | 'credential.end'>(input: Asked<O>) {
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
  assert.deepEqual([redeemedRow.token_hash, redeemedRow.previous_token_hash, redeemedRow.code_hash, redeemedRow.challenge, redeemedRow.expires_at], [hex('ref-1'), null, hex('code-1'), null, world.now() + MONTH * MINUTE]);
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
  // Of the client, how it is known and its host: never its name nor a URL, which its maker chose.
  assert.deepEqual(written[0]!.detail, { connection: connected.connection, registration: 'cimd', client: null, host: 'claude.ai', scopes: 'read reveal' });
  assert.deepEqual(written[3]!.detail, { connection: connected.connection, registration: 'cimd', client: null, host: 'claude.ai', grant: 'refresh_token', credential: second.credential, scopes: 'read' });
  assert.deepEqual(await checked(), []);
});

test('an entry keeps no text the client chose: a host that reads as no host is logged as none', async () => {
  const { connection } = await made(connect('ada-web', 'code-h', ['read'], { ...OTHER, host: 'Other <b>bold</b>' }));
  const [entry] = (await entries()).filter((one) => one.action === 'mcp.connect');
  assert.deepEqual(entry!.detail, { connection, registration: 'cimd', client: null, host: null, scopes: 'read' });
  assert.ok(!JSON.stringify(entry).includes('bold') && !JSON.stringify(entry).includes('Other'));
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

test("an MCP client's reveal is a person's own read: never remembered, so a write within the vault's memory is what the next one opens", async () => {
  await made(connect('ada-web', 'code-1', ['read', 'reveal']));
  await redeemed(byCode('code-1', 'acc-1', 'ref-1'));
  const opened = async () => {
    const answer = await reveal('acc-1');
    assert.ok(!('refused' in answer), JSON.stringify(answer));
    return answer.values.map((item) => ('refused' in item ? item.refused : item.value.toString()));
  };
  assert.deepEqual(await opened(), ['postgres://market']);
  const [held] = await rowsOf<{ id: string }>(world.owner, sql`SELECT id::text FROM secrets WHERE key = 'DATABASE_URL'`);
  await rewrite(world, held!, 'postgres://next');
  assert.deepEqual(await opened(), ['postgres://next']);
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
  assert.deepEqual([entry!.actor, entry!.kept, entry!.detail], [null, true, { connection, registration: 'cimd', client: null, host: 'claude.ai', principal: ada, reason: 'code_reused' }]);
  assert.deepEqual(await checked(), []);
});

test('its code stays known for as long as the connection lasts, and the refresh token it last replaced; an older one is unknown and ends nothing', async () => {
  const { connection } = await made(connect('ada-web', 'code-1'));
  await redeemed(byCode('code-1', 'acc-1', 'ref-1'));
  await redeemed(byRefresh('ref-1', 'acc-2', 'ref-2'));
  await redeemed(byRefresh('ref-2', 'acc-3', 'ref-3'));
  const row = await stored(connection);
  assert.deepEqual([row.token_hash, row.previous_token_hash, row.code_hash], [hex('ref-3'), hex('ref-2'), hex('code-1')]);
  // Two rotations back: whoever holds it got nothing with it, and the client is not told to connect again.
  assert.deepEqual(await vault.change(byRefresh('ref-1', 'acc-x', 'ref-x')), { refused: 'unknown_grant' });
  assert.equal(await who('acc-3'), `${ada} mcp`);
  // Refreshed twice, a day on, its code presented again still ends it.
  world.tick(DAY);
  await redeemed(byRefresh('ref-3', 'acc-4', 'ref-4'));
  assert.deepEqual(await vault.change(byCode('code-1', 'acc-y', 'ref-y')), { answer: { ended: true, connection } });
  assert.equal(await who('acc-4'), 'unauthenticated');

  const second = await made(connect('ada-web', 'code-2'));
  await redeemed(byCode('code-2', 'acc-b1', 'ref-b1'));
  await redeemed(byRefresh('ref-b1', 'acc-b2', 'ref-b2'));
  await redeemed(byRefresh('ref-b2', 'acc-b3', 'ref-b3'));
  assert.deepEqual(await vault.change(byRefresh('ref-b2', 'acc-b4', 'ref-b4')), { answer: { ended: true, connection: second.connection } });
  assert.equal(await who('acc-b3'), 'unauthenticated');
  assert.deepEqual((await entries()).filter((one) => one.action === 'mcp.disconnect').map((one) => one.detail.reason), ['code_reused', 'refresh_reused']);
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
  assert.deepEqual([entry!.action, entry!.actor, entry!.kept, entry!.objects, entry!.detail], ['oauth.register', null, false, [`oauth_client:${client}`], { client, redirects: 2 }]);
  // What a stranger wrote stays in its row: a redirect's query, or a name, never reaches the log.
  const quiet = await made(register('Leaky name', ['https://client.example/cb?token=confidential']));
  const [leak] = (await entries()).slice(before + 1);
  assert.deepEqual(leak!.detail, { client: quiet.client, redirects: 1 });
  assert.ok(!JSON.stringify(leak).includes('confidential') && !JSON.stringify(leak).includes('Leaky'));
  for (const bad of [register('Zed', []), register('Zed', ['cursor://cb']), register('Zed', ['https://a.example/cb', 'https://a.example/cb']), register('Ze‮d'), register('')]) {
    await assert.rejects(vault.change(bad), TypeError);
  }

  // Up to the last place, the vault's rows or not: Cursor, Zed and the leaky one are three.
  await world.owner.execute(sql`INSERT INTO oauth_clients (id, name, redirect_uris, created_at, mac) SELECT gen_random_uuid(), 'filler', '[]', now(), ''::bytea FROM generate_series(1, ${MAX_CLIENTS - 4})`);
  const raced = await Promise.all([1, 2].map((n) => vault.change(register(`Racer ${n}`))));
  assert.deepEqual(raced.map((answer) => ('refused' in answer ? answer.refused : 'made')).sort(), ['full', 'made']);
  assert.deepEqual(await vault.change(register()), { refused: 'full' });
  const [{ count }] = (await rowsOf<{ count: number }>(world.owner, sql`SELECT count(*)::int AS count FROM oauth_clients`)) as [{ count: number }];
  assert.equal(count, MAX_CLIENTS);
  // Refused, a stranger writes nothing at all.
  assert.equal((await entries()).length, before + 3);

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

test('a client gives back its refresh token or an access token: the connection ends, and every access token under it; anything else ends nothing', async () => {
  const { connection } = await made(connect('ada-web', 'code-1', ['read', 'reveal']));
  // A code waiting is no token to give back, nor another client's, nor one the vault never made.
  for (const [token, client] of [['code-1', CLAUDE.id], ['nobody', null]] as const) assert.deepEqual(await vault.change(revoke(token, client)), { refused: 'unknown_grant' });
  await redeemed(byCode('code-1', 'acc-1', 'ref-1'));
  const second = await redeemed(byRefresh('ref-1', 'acc-2', 'ref-2'));
  for (const [token, client] of [['ref-2', OTHER.id], ['acc-2', OTHER.id], ['ref-1', null], ['ada-cli', null]] as const) {
    assert.deepEqual(await vault.change(revoke(token, client)), { refused: 'unknown_grant' }, token);
  }
  assert.equal(await who('acc-2'), `${ada} mcp`);
  // An access token, its client named or not: its connection ends.
  assert.deepEqual(await made(revoke('acc-2', null)), { connection });
  for (const token of ['acc-1', 'acc-2']) assert.equal(await who(token), 'unauthenticated');
  assert.equal((await stored(second.credential)).revoked_at, null, 'its access tokens end with it, with no write of their own');
  assert.deepEqual(await vault.change(byRefresh('ref-2', 'acc-3', 'ref-3')), { refused: 'unknown_grant' });
  assert.deepEqual(await vault.change(revoke('ref-2')), { refused: 'unknown_grant' }, 'ended once');
  assert.deepEqual(await vault.change(revoke('acc-1')), { refused: 'unknown_grant' }, 'by any token under it');
  const ended = await stored(connection);
  assert.deepEqual([ended.revoked_by, ended.revoked_at], [ada, world.now()]);
  const [entry] = (await entries()).filter((one) => one.action === 'mcp.disconnect');
  assert.deepEqual([entry!.actor, entry!.credential, entry!.kept, entry!.detail], [ada, second.credential, true, { connection, registration: 'cimd', client: null, host: 'claude.ai', reason: 'revoked' }]);

  // Its refresh token: the connection itself.
  const other = await made(connect('ada-web', 'code-2'));
  await redeemed(byCode('code-2', 'acc-4', 'ref-4'));
  assert.deepEqual(await made(revoke('ref-4')), { connection: other.connection });
  assert.equal(await who('acc-4'), 'unauthenticated');
  // An access token that lapsed gives back nothing; its connection stands.
  const third = await made(connect('ada-web', 'code-3'));
  await redeemed(byCode('code-3', 'acc-5', 'ref-5'));
  world.tick(HOUR + 1);
  assert.deepEqual(await vault.change(revoke('acc-5')), { refused: 'unknown_grant' });
  assert.equal((await stored(third.connection)).revoked_at, null);
  assert.deepEqual(await checked(), []);
});

test('a token given back whose row, or whose connection\'s, was written behind the vault ends nothing', async () => {
  const { connection } = await made(connect('ada-web', 'code-1'));
  const tokens = await redeemed(byCode('code-1', 'acc-1', 'ref-1'));
  await world.owner.execute(sql`UPDATE credentials SET expires_at = expires_at + interval '1 day' WHERE id = ${tokens.credential}::uuid`);
  assert.deepEqual(await vault.change(revoke('acc-1')), { refused: 'tampered' });
  await world.owner.execute(sql`UPDATE credentials SET label = 'Claudia' WHERE id = ${connection}::uuid`);
  assert.deepEqual(await vault.change(revoke('ref-1')), { refused: 'tampered' });
  assert.equal((await stored(connection)).revoked_at, null);
});

const deciding = { workloads: world.workloads, owners: world.owners };
/** A connect Ada approves through her connection, as the vault makes it (`through`), to prepare and commit apart. */
const approving = (input: Asked<'mcp.connect'>) => through(OPERATIONS['mcp.connect'](input, deciding), input.via, tokenOf('ada-web'));
const ARGS = '{"secret":"market/prod/KEY"}';
const digestOf = (tool: string, args: string) => createHash('sha256').update(`[${JSON.stringify(tool)},${args}]`).digest('hex');
const ask = (label: string, args = ARGS, tool = 'request_secret_value', place: string | null = 'market/prod/KEY'): Asked<'mcp.ask'> => ({ ...shown(label), op: 'mcp.ask', tool, arguments: args, place });
const decide = (label: string, approval: string, approve: boolean, digest = digestOf('request_secret_value', ARGS)): Asked<'mcp.decide'> => ({ ...shown(label), op: 'mcp.decide', approval, approve, digest });
const approvalOf = async (id: string) => (await rowsOf<{ status: string; decided: boolean }>(world.owner, sql`SELECT status, decided_at IS NOT NULL AS decided FROM mcp_approvals WHERE id = ${id}::uuid`))[0];
/** Ada's connection, redeemed: its access token is `acc-1`. */
async function adaConnected() {
  const { connection } = await made(connect('ada-web', 'code-1', ['read', 'write']));
  const tokens = await redeemed(byCode('code-1', 'acc-1', 'ref-1'));
  return { connection, token: tokens.credential };
}
/** An approval asked on `acc-1`. */
async function asked(args = ARGS, tool = 'request_secret_value') {
  const answer = await vault.change(ask('acc-1', args, tool));
  assert.ok(!('refused' in answer), JSON.stringify(answer));
  return answer.answer.approval;
}

test('an MCP client asks for a change on its access token: one approval, pending five minutes, logged by its tool, place and digest, never its arguments', async () => {
  const { connection, token } = await adaConnected();
  const before = (await entries()).length;
  const args = '{"note":"the Stripe key, from Ada\'s dashboard","secret":"market/prod/KEY"}';
  const answer = await vault.change(ask('acc-1', args));
  assert.ok(!('refused' in answer));
  assert.equal(answer.answer.expiresAt, new Date(world.now() + 5 * MINUTE).toISOString());
  const [entry, ...more] = (await entries()).slice(before);
  assert.equal(more.length, 0);
  assert.deepEqual([entry!.kept, entry!.action, entry!.actor, entry!.credential], [true, 'mcp.ask', ada, token]);
  assert.deepEqual(entry!.detail, { approval: answer.answer.approval, connection, tool: 'request_secret_value', names: ['market/prod/KEY'], digest: digestOf('request_secret_value', args) });
  assert.ok(!JSON.stringify(entry).includes('Stripe'), 'the arguments are the client\'s text: only the row keeps them');
  assert.ok(!entry!.rows.some((row) => row.row.includes('mcp_approvals')), 'a row with no MAC is not among the entry\'s rows');
  const [row] = await rowsOf<{ connection_id: string; arguments: string; digest: string; status: string }>(world.owner, sql`SELECT connection_id::text, arguments, encode(digest, 'hex') AS digest, status FROM mcp_approvals`);
  assert.deepEqual(row, { connection_id: connection, arguments: args, digest: digestOf('request_secret_value', args), status: 'pending' });

  // Only an MCP access token that stands asks one: not a session, nor the connection's refresh token, nor one ended.
  for (const label of ['ada-web', 'ada-cli', 'ref-1', 'ada-pat']) assert.deepEqual(await vault.change(ask(label)), { refused: 'unauthenticated' }, label);
  // What it asks is a tool, a JSON object of its arguments, and a place, each plain.
  for (const bad of [ask('acc-1', '["market"]'), ask('acc-1', `{"note":"${'x'.repeat(4100)}"}`), ask('acc-1', ARGS, 'Rm -rf'), ask('acc-1', ARGS, 'x', 'market/prod/KEY with spaces')]) {
    await assert.rejects(vault.change(bad), TypeError);
  }
  await made({ ...shown('ada-web'), op: 'credential.end', credential: connection, of: null });
  assert.deepEqual(await vault.change(ask('acc-1')), { refused: 'unauthenticated' }, 'its connection ended');
  assert.deepEqual(await checked(), []);
});

test('a connection holds five approvals waiting: the same call waits on its own, and a client asking in a loop writes five entries an expiry, whatever it does between', async () => {
  await adaConnected();
  const first = await asked();
  const before = (await entries()).length;
  assert.deepEqual(await vault.change(ask('acc-1')), { refused: 'pending' }, 'the same call waits on its own: the app joins it');
  for (const key of ['B', 'C', 'D', 'E']) await asked(`{"secret":"market/prod/${key}"}`);
  assert.deepEqual(await vault.change(ask('acc-1', '{"secret":"market/prod/F"}')), { refused: 'full' });
  assert.deepEqual(await vault.change(ask('acc-1', '{"secret":"market/prod/G"}')), { refused: 'full' });
  // Four made, and the refusals wrote nothing, not even an entry.
  assert.equal((await entries()).length - before, 4);
  // Only the person's decision or the expiry frees a place.
  await made(decide('ada-web', first, false));
  await asked('{"secret":"market/prod/F"}');
  await world.owner.execute(sql`UPDATE mcp_approvals SET expires_at = ${new Date(world.now() - 1000).toISOString()}::timestamptz WHERE arguments = '{"secret":"market/prod/B"}'`);
  await asked('{"secret":"market/prod/G"}');
  assert.deepEqual(await vault.change(ask('acc-1', '{"secret":"market/prod/H"}')), { refused: 'full' });
  assert.equal((await entries()).filter((entry) => entry.action === 'mcp.ask').length, 7);
  assert.deepEqual(await checked(), []);
});

test("Ada denies an approval, or approves one that only shows her a value, on her browser session: decided once, while it waits, and only hers", async () => {
  const { connection } = await adaConnected();
  const change = await asked();
  const show = await asked(ARGS, 'show_secret_value');
  const showDigest = digestOf('show_secret_value', ARGS);
  const unknown = { refused: 'unknown_approval' };
  // A change is approved only by the change itself, through it.
  assert.deepEqual(await vault.change(decide('ada-web', change, true)), unknown);
  assert.deepEqual(await vault.change(decide('ada-web', change, false, showDigest)), unknown, 'not the digest the page rendered');
  assert.deepEqual(await vault.change(decide('bo-cli', change, false)), { refused: 'no_access' }, "Bo's CLI");
  assert.deepEqual(await vault.change(decide('bo-web', change, false)), unknown, "Bo's browser: Ada's approval is not his to see, let alone decide");
  assert.deepEqual(await vault.change(decide('ada-cli', change, false)), { refused: 'no_access' }, 'a CLI decides nothing of an app\'s');
  assert.deepEqual(await vault.change(decide('ada-web', '00000000-0000-4000-8000-000000000000', false)), unknown);
  const before = (await entries()).length;
  assert.deepEqual(await made(decide('ada-web', change, false)), { approval: change });
  assert.deepEqual(await approvalOf(change), { status: 'denied', decided: true });
  assert.deepEqual(await vault.change(decide('ada-web', change, false)), unknown, 'decided once');
  assert.deepEqual(await made(decide('ada-web', show, true, showDigest)), { approval: show });
  assert.deepEqual(await approvalOf(show), { status: 'approved', decided: true });
  const [denied, approved] = (await entries()).slice(before);
  assert.deepEqual([denied!.action, denied!.actor, denied!.detail], ['mcp.deny', ada, { approval: change, connection, tool: 'request_secret_value', digest: digestOf('request_secret_value', ARGS) }]);
  assert.equal(approved!.action, 'mcp.approve');
  assert.ok(approved!.objects.includes(`mcp_approval:${show}`) && approved!.objects.includes(`credential:${connection}`));

  // Expired by the time its write would start, a write's time before its end, it waits no more.
  const late = await asked('{"secret":"market/prod/LATE"}');
  await world.owner.execute(sql`UPDATE mcp_approvals SET expires_at = ${new Date(world.now() + WRITE_MS - 1000).toISOString()}::timestamptz WHERE id = ${late}::uuid`);
  assert.deepEqual(await vault.change(decide('ada-web', late, false, digestOf('request_secret_value', '{"secret":"market/prod/LATE"}'))), unknown);
  // Its connection ended, none is decided.
  const ended = await asked('{"secret":"market/prod/ENDED"}');
  await made({ ...shown('ada-web'), op: 'credential.end', credential: connection, of: null });
  assert.deepEqual(await vault.change(decide('ada-web', ended, false, digestOf('request_secret_value', '{"secret":"market/prod/ENDED"}'))), { refused: 'disconnected' });
  assert.deepEqual(await checked(), []);
});

test('two decisions of one approval at once: the second to write finds the approval changed under the change lock, starts over, and is refused', async () => {
  await adaConnected();
  const show = await asked(ARGS, 'show_secret_value');
  const showDigest = digestOf('show_secret_value', ARGS);
  const [approving, denying] = await Promise.all([prepare(world, OPERATIONS['mcp.decide'](decide('ada-web', show, true, showDigest), deciding)), prepare(world, OPERATIONS['mcp.decide'](decide('ada-web', show, false, showDigest), deciding))]);
  assert.ok(!('refused' in approving!) && !('refused' in denying!), 'each decided alone, the approval pending');
  assert.equal(await commit(world, denying), true);
  assert.equal(await commit(world, approving), false, 'read again by a hash of all of it: it is denied now');
  assert.deepEqual(await approvalOf(show), { status: 'denied', decided: true });
  assert.deepEqual(await vault.change(decide('ada-web', show, true, showDigest)), { refused: 'unknown_approval' });
});

test("an approval decided in its last moments is written only if its write starts a write's time before it expires, by the database's clock", async () => {
  const { connection } = await adaConnected();
  const approval = await asked();
  const digest = digestOf('request_secret_value', ARGS);
  // 50 ms before a write's time is left of its five minutes: decided, and its write waits longer than that.
  world.tick(5 * MINUTE - WRITE_MS - 50);
  const late = [
    await prepare(world, OPERATIONS['mcp.decide'](decide('ada-web', approval, false), deciding)),
    await prepare(world, approving({ ...connect('ada-web', 'code-late'), via: { connection, approval, digest } })),
  ];
  assert.ok(late.every((prepared) => !('refused' in prepared)));
  await sleep(120);
  assert.deepEqual([await commit(world, late[0] as never), await commit(world, late[1] as never)], [false, false]);
  world.tick(120);
  assert.deepEqual(await vault.change(decide('ada-web', approval, false)), { refused: 'unknown_approval' });
  assert.deepEqual(await approvalOf(approval), { status: 'pending', decided: false });
});

test("a decision is written only if its write starts a write's time before its connection ends too, which nothing in the connection's row says", async () => {
  const { connection } = await adaConnected();
  const approval = await asked();
  const show = await asked(ARGS, 'show_secret_value');
  const digest = digestOf('request_secret_value', ARGS);
  // The connection ends 50 ms after a write's time from now: decided, and the writes wait longer than that.
  await amend(world, 'credentials', sql`id = ${connection}::uuid`, { expiresAt: new Date(world.now() + WRITE_MS + 50) });
  const late = [
    await prepare(world, OPERATIONS['mcp.decide'](decide('ada-web', show, true, digestOf('show_secret_value', ARGS)), deciding)),
    await prepare(world, approving({ ...connect('ada-web', 'code-late'), via: { connection, approval, digest } })),
  ];
  assert.ok(late.every((prepared) => !('refused' in prepared)));
  await sleep(120);
  assert.deepEqual([await commit(world, late[0] as never), await commit(world, late[1] as never)], [false, false]);
  // Asked again, with less than a write's time left of it, the connection stands for none.
  world.tick(120);
  assert.deepEqual(await vault.change(decide('ada-web', approval, false)), { refused: 'disconnected' });
  assert.deepEqual(await vault.change({ ...connect('ada-web', 'code-later'), via: { connection, approval, digest } }), { refused: 'disconnected' });
  assert.deepEqual([await approvalOf(approval), await approvalOf(show)], [{ status: 'pending', decided: false }, { status: 'pending', decided: false }]);
});

test("a change Ada approves for her connection on coffre's page is hers, on her browser session: it marks the approval approved in its own write, once, and its entry names both", async () => {
  const { connection } = await adaConnected();
  const waiting = await made(connect('ada-web', 'code-2'));
  const bos = await made(connect('bo-cli', 'code-bo'));
  await redeemed(byCode('code-bo', 'acc-bo', 'ref-bo'));
  const approval = await asked();
  const digest = digestOf('request_secret_value', ARGS);
  const viaAda = (label: string, via: Record<string, string> = {}, code = 'code-x'): Asked<'mcp.connect'> => ({ ...connect(label, code), via: { connection, approval, digest, ...via } });

  // Weighed, it writes nothing; made, the approval is approved with it.
  assert.ok(!('refused' in (await vault.weigh(viaAda('ada-web')))));
  assert.deepEqual(await approvalOf(approval), { status: 'pending', decided: false });
  const before = (await entries()).length;
  // Not on a browser session, nor through another member's connection, nor anything but a connection that stands.
  const disconnected = { refused: 'disconnected' };
  assert.deepEqual(await vault.change(viaAda('ada-cli')), disconnected, "the CLI's session approves nothing");
  assert.deepEqual(await vault.change(viaAda('ada-web', { connection: bos.connection })), disconnected, "Bo's connection");
  assert.deepEqual(await vault.change(viaAda('ada-web', { connection: waiting.connection })), disconnected, 'a connection whose code still waits');
  // Nor an approval that is not this connection's, of this digest, and waiting.
  const unknown = { refused: 'unknown_approval' };
  assert.deepEqual(await vault.change(viaAda('ada-web', { digest: digestOf('request_secret_value', '{}') })), unknown, 'another digest');
  assert.deepEqual(await vault.change(viaAda('ada-web', { approval: '00000000-0000-4000-8000-000000000000' })), unknown, 'none');
  const denied = (await entries()).slice(before).filter((one) => one.detail.refused !== undefined);
  assert.ok(denied.length > 0 && denied.every((one) => one.action === 'mcp.connect' && one.detail.via === connection && one.detail.approval === approval), 'a refusal is logged as the change\'s, both named');

  const madeFor = await made(viaAda('ada-web'));
  const [entry] = (await entries()).slice(-1);
  assert.deepEqual([entry!.action, entry!.actor, entry!.detail.connection, entry!.detail.via, entry!.detail.approval], ['mcp.connect', ada, madeFor.connection, connection, approval]);
  assert.ok(entry!.objects.includes(`credential:${connection}`) && entry!.objects.includes(`mcp_approval:${approval}`));
  assert.ok(entry!.rows.some((row) => row.row === JSON.stringify(['credentials', connection]) && row.was === row.now), 'the connection is among the rows it read and left');
  assert.deepEqual(await approvalOf(approval), { status: 'approved', decided: true });
  assert.deepEqual(await vault.change(viaAda('ada-web', {}, 'code-y')), unknown, 'approved once: a second change under it is refused');

  // Two Approves at once, of two changes: the second to write finds the approval approved, starts over, and is refused.
  const second = await asked('{"secret":"market/prod/TWICE"}');
  const twice = (code: string) => approving(viaAda('ada-web', { approval: second, digest: digestOf('request_secret_value', '{"secret":"market/prod/TWICE"}') }, code));
  const [one, two] = await Promise.all([prepare(world, twice('code-a')), prepare(world, twice('code-b'))]);
  assert.ok(!('refused' in one!) && !('refused' in two!));
  assert.equal(await commit(world, one), true);
  assert.equal(await commit(world, two), false);

  // An approval and its connection are named by their ids, and only for a change someone asks.
  await assert.rejects(vault.change(viaAda('ada-web', { connection: 'not-an-id' })), TypeError);
  await assert.rejects(vault.change(viaAda('ada-web', { digest: 'nope' })), TypeError);
  await assert.rejects(vault.change({ ...revoke('acc-1'), via: { connection, approval, digest } } as never), TypeError);
  assert.deepEqual(await checked(), []);
});
