// 0.15's uses as the app routes them (docs/design/0.15-plan.md, PR 5b): with the vault answering them (`about().uses`),
// each value a request opens on a credential is one `use_credential` call, logged as its request and decided on the rows
// as they are then. Here every routed path, through the whole app as a deployment runs it: a reveal of one key, a run of
// a whole environment (a reference, a plain value, a fork's inherited keys), the credential proxy's use, sign and verify
// on a person's handle, and a CI run's sign-in then its read. Each runs with the switch off too, which logs 0.14's
// entries and no use. With it on, every live answer is the replay's (R53), and a checkpointer on the vault's seed seals
// every use (T128). On both engines.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac, generateKeyPairSync, randomBytes, sign as signWith } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { createClient, type CoffreClient } from '@coffre/client';
import { credential } from '@coffre/client/credential';
import { github, signin } from '@coffre/core/identity';
import { derivedSigningKey } from '@coffre/vault';
import { replayStored, runCheckpointer, type RunningCheckpointer } from '@coffre/vault/node';
import { and, eq, gt, sql } from 'drizzle-orm';

import { resolveConfig } from '../src/config.ts';
import { checkPlugins } from '../src/plugins.ts';
import { credentialProxy, header, hmac } from '../src/plugins/credential-proxy.ts';
import { createRuntime, type CoffreRuntime } from '../src/runtime.ts';
import { processLimits } from '../src/workloads/limits.ts';
import { FetchRefused, type WorkloadTransport } from '../src/workloads/transport.ts';
import { USES_AT_ONCE } from '../src/api/keys.ts';
import { clientFor, contextFor, openTestDatabase, resetDatabase, testDeps, testVault, type FixtureDeps } from './api-fixture.ts';
import { auditLog, environments, logBulk, logCheckpoints, logFence, logTiles, logUses } from './db/tables.ts';
import { openVaultDatabase } from './db/engine.ts';
import { answer, type Pages } from './start-fixture.ts';

const ORIGIN = 'https://secrets.acme.example';
const ROOT = 'admin@acme.example';
const DEV = 'dev@acme.example';
const CI = 'token:ci';
const DEPLOY = 'token:deploy';
const IP = '203.0.113.7';
const API_KEY = 'sk_live_real_0123456789abcdef';
const WEBHOOK = 'whsec_0123456789abcdef';
const ISSUER = 'https://token.actions.githubusercontent.com';
const JWKS = `${ISSUER}/.well-known/jwks`;
const CLAIMS = { repository_owner_id: '9919', repository_id: '41532', workflow_ref: 'acme/api/.github/workflows/deploy.yml@refs/heads/main', ref: 'refs/heads/main', event_name: 'push' };

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;
let runtime: CoffreRuntime;
let root: CoffreClient;
let signingKey: Uint8Array;
let checkpointer: RunningCheckpointer | null = null;
let scratch: string;
let upstream: Server;
let upstreamUrl: string;
let made = 0;

const issuerKey = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const transport: WorkloadTransport = {
  json: async (url) => {
    if (url.href === `${ISSUER}/.well-known/openid-configuration`) return { issuer: ISSUER, jwks_uri: JWKS };
    if (url.href === JWKS) return { keys: [{ ...issuerKey.publicKey.export({ format: 'jwk' }), kid: 'es-1', alg: 'ES256', use: 'sig' }] };
    throw new FetchRefused(url, 'answered 404');
  },
};

before(async () => {
  db = await openTestDatabase();
  scratch = mkdtempSync(join(tmpdir(), 'coffre-use-routes-'));
  // A fake API that says whether it got the real key.
  upstream = createServer((request, response) => {
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify({ real: request.headers['x-api-key'] === API_KEY }));
  });
  await new Promise<void>((resolve) => upstream.listen(0, '127.0.0.1', resolve));
  upstreamUrl = `http://127.0.0.1:${(upstream.address() as AddressInfo).port}`;
});

after(async () => {
  await checkpointer?.stop();
  await new Promise<void>((resolve) => upstream.close(() => resolve()));
  await db.close();
  rmSync(scratch, { recursive: true, force: true });
});

/**
 * The instance with 0.14's log alone, or 0.15's with its uses, its changes sealed by a checkpointer on the vault's
 * seed (each change waits for its tick, R51), and `inFlight`, the isolate's uses in flight at most.
 */
async function instance(log: '0.14' | '0.15', inFlight?: number): Promise<void> {
  await checkpointer?.stop();
  checkpointer = null;
  await resetDatabase(db.owner);
  for (const table of [logUses, logBulk, logCheckpoints, logTiles]) await db.owner.delete(table);
  // Uses go in at or past the floor of `at` (schema 0022), as a deployment's checkpointer keeps it.
  await db.owner.update(logFence).set({ atFloor: Date.now() - 60_000 });
  const kek = randomBytes(32);
  signingKey = derivedSigningKey(kek);
  if (log === '0.15') {
    checkpointer = await runCheckpointer({ database: await openVaultDatabase(), seed: signingKey, memory: join(scratch, `memory-${(made += 1)}`), intervalMs: 3_600_000 });
  }
  const vault = log === '0.15'
    ? testVault([ROOT], {}, { kek }, {}, { log: '0.15', sealThrough: checkpointer!.sealThrough, ...(inFlight === undefined ? {} : { uses: { inFlight } }) })
    : testVault([ROOT], {}, { kek }, {}, {});
  deps = testDeps(db.runtime, [ROOT], { vault });
  const config = resolveConfig({
    publicUrl: ORIGIN,
    vault: deps.vault,
    auth: signin({ providers: [github({ clientId: 'a', clientSecret: 'b' })], workloads: { limits: processLimits({ perSource: 1000, total: 1000 }) } }),
    auditChainKey: deps.chainKey.toString('base64'),
    plugins: [credentialProxy({
      credentials: { api: { upstream: `${upstreamUrl}/v1`, inject: header('x-api-key', '{API_KEY}') } },
      signers: { webhook: hmac('WEBHOOK', { encoding: 'hex' }) },
      verifiers: { incoming: hmac('WEBHOOK', { encoding: 'hex' }) },
      insecureUpstreams: true,
    })],
  });
  runtime = createRuntime(config, deps.db, deps.vault, transport);
  runtime.plugins = checkPlugins(config.plugins);
  // The fixture's clients issue tokens and bind CI runs through the same services.
  deps.signin = runtime.signin!;
  deps.workloads = runtime.workloads!;
  root = clientFor(deps, ROOT);
  await root.members.add(`user:${DEV}`);
  await root.members.add(CI);
  await root.members.add(DEPLOY);
  await root.projects.create('market');
  await root.environments.create('market/dev');
  await root.environments.create('market/prod');
  await root.secrets.set('market/prod', { SOURCE: 'from-prod' });
  await root.secrets.set('market/dev', { API_KEY, WEBHOOK, REGION: { value: 'eu-west-3', plain: true }, REF: { ref: 'market/prod/SOURCE' } });
  await root.environments.create('market/feature', { from: 'dev', inherit: true });
  for (const member of [CI, DEPLOY]) await root.access.set(member, { market: 'viewer' });
  await root.access.set(`user:${DEV}`, { market: 'developer' });
}

const ui = {} as Pages;

function send(request: Request): Promise<Response> {
  return answer(request, runtime, ui, IP);
}

/** The API as whoever `token` is, through the whole app. */
function bearer(token: string): CoffreClient {
  return createClient({ url: ORIGIN, headers: () => ({ authorization: `Bearer ${token}` }), transport: send });
}

/** A CLI session for a person, as the device flow leaves one. */
async function sessionFor(email: string): Promise<string> {
  const service = runtime.signin!;
  const started = await service.startDevice({ clientLabel: 'laptop', sourceIp: null });
  await service.decideDevice(await contextFor(deps, email), started.userCode, true);
  const polled = await service.pollDevice(started.deviceCode, { requestId: crypto.randomUUID(), sourceIp: null });
  if (polled.status !== 'approved') throw new Error('not approved');
  return polled.credential.token;
}

/** What `coffre run market/dev` hands a person's app: the handle, and `credential(name)` over coffre's own route. */
async function handleFor(email: string): Promise<{ handle: string; credential: (name: string) => ReturnType<typeof credential> }> {
  const { token: handle } = await bearer(await sessionFor(email)).handles.create({ label: 'run', paths: ['market/dev'] });
  const plan = (await (await send(new Request(`${ORIGIN}/use/market/dev`, { headers: { authorization: `Bearer ${handle}` } }))).json()) as { credentials: Record<string, string> };
  const env = { COFFRE_HANDLE: handle, COFFRE_CREDENTIALS: JSON.stringify(plan.credentials) };
  return { handle, credential: (name) => credential(name, env, (input, init) => send(new Request(input, init))) };
}

/** A CI run's sign-in: its binding, then its platform's ID token traded for a credential (`POST /api/auth/oidc`). */
async function ciSignIn(): Promise<string> {
  await runtime.workloads!.bind(await contextFor(deps, ROOT), 'deploy', { profile: 'github', issuer: null, claims: CLAIMS, label: 'deploys', replaces: [] }, { dryRun: false });
  const part = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
  const now = Math.floor(Date.now() / 1000);
  const input = `${part({ alg: 'ES256', kid: 'es-1', typ: 'JWT' })}.${part({
    iss: ISSUER, aud: ORIGIN, sub: 'repo:acme/api:ref:refs/heads/main', iat: now - 5, exp: now + 295, jti: crypto.randomUUID(), run_id: '7001', sha: 'f'.repeat(40), repository: 'acme/api', ...CLAIMS,
  })}`;
  const jwt = `${input}.${signWith('sha256', Buffer.from(input), { key: issuerKey.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url')}`;
  const traded = await send(new Request(`${ORIGIN}/api/auth/oidc`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ service: DEPLOY, token: jwt }) }));
  assert.equal(traded.status, 200, await traded.clone().text());
  return ((await traded.json()) as { token: string }).token;
}

async function usesLogged(): Promise<{ number: bigint | number | string; purpose: number; place: string | null }[]> {
  return db.owner.select({ number: logUses.number, purpose: logUses.purpose, place: logUses.place }).from(logUses).orderBy(logUses.number);
}

/** The vault's 0.14 reads and the proxy's `credential.use`: what 0.14's log holds of the reads. */
async function readEntries(): Promise<{ action: string; actor: string }[]> {
  return db.owner.select({ action: auditLog.action, actor: auditLog.actor }).from(auditLog)
    .where(and(eq(auditLog.decision, 'allow'), sql`${auditLog.action} IN ('secret.read', 'credential.use')`));
}

const hmacOf = (body: string) => createHmac('sha256', WEBHOOK).update(body).digest('hex');

for (const log of ['0.14', '0.15'] as const) {
  test(`${log}: a reveal, a run, the proxy's use, sign and verify, and a CI run's read each open their values${log === '0.15' ? ' by one use each, sealed, and live as replayed' : ' as 0.14 does'}`, async () => {
    await instance(log);
    const before = (await readEntries()).length;
    const issued = await root.tokens.issue(CI, { label: 'ci', expiresInDays: 30 });
    const ci = bearer(issued.token);
    // A reveal of one key, a run of a whole environment (a reference's source, and a plain value no use opens) and of a
    // fork that inherits each of its keys.
    assert.deepEqual((await ci.secrets.reveal('market/dev/API_KEY')).values, { API_KEY });
    const run = { API_KEY, WEBHOOK, REGION: 'eu-west-3', REF: 'from-prod' };
    assert.deepEqual({ ...(await ci.secrets.reveal('market/dev')).values }, run);
    assert.deepEqual({ ...(await ci.secrets.reveal('market/feature')).values }, run);
    // The credential proxy, on a person's handle: the real key injected, a signature made and one checked.
    const { handle, credential: named } = await handleFor(DEV);
    const used = await send(new Request(`${ORIGIN}/use/market/dev/api/thing`, { headers: { 'x-api-key': handle } }));
    assert.equal(used.status, 200);
    assert.deepEqual(await used.json(), { real: true });
    assert.equal(await named('webhook').sign('payload'), hmacOf('payload'));
    assert.equal(await named('incoming').verify('event', hmacOf('event')), true);
    assert.equal(await named('incoming').verify('event', hmacOf('other')), false);
    // A CI run: its sign-in, then its read on the credential it was issued.
    const exchanged = await ciSignIn();
    assert.deepEqual({ ...(await bearer(exchanged).secrets.reveal('market/dev', ['API_KEY', 'REF'])).values }, { API_KEY, REF: 'from-prod' });

    const uses = await usesLogged();
    const reads = (await readEntries()).length - before;
    if (log === '0.14') {
      assert.deepEqual(uses, [], 'with the switch off, no use');
      assert.ok(reads > 0, "0.14's reads, as before");
      return;
    }
    assert.equal(reads, 0, "with the switch on, nothing of the reads in 0.14's log: no head taken for them");
    // One use per sealed value, but for repeats an isolate's cover rides (they write none): every purpose here, and the
    // fork's reads through their place.
    const purposes = new Set(uses.map((row) => Number(row.purpose)));
    for (const [purpose, code] of [['reveal', 0], ['run', 1], ['use', 4]] as const) assert.ok(purposes.has(code), `a ${purpose} logged`);
    const [feature] = await db.owner.select({ id: environments.id }).from(environments).where(eq(environments.slug, 'feature'));
    assert.ok(uses.some((row) => row.place === feature!.id), "the fork's inherited keys, read through it");
    // The replay of the log allows each, as live did, and finds nothing out of place.
    const replayed = await replayStored(db.owner, [signingKey]);
    assert.deepEqual(replayed.faults, []);
    assert.deepEqual([...replayed.decided.entries()].filter(([, code]) => code !== null), [], 'every use allowed, as live');
    assert.equal(replayed.decided.size, uses.length);
    // The checkpointer seals them: each use's MAC is the log's, over the uses tree.
    const tick = await checkpointer!.checkpointer.tick();
    assert.ok(tick.signed, tick.failures.join('; '));
    assert.equal(Number(checkpointer!.checkpointer.pair.pair.uses.size), uses.length);
    assert.deepEqual(await checkpointer!.alarms(), []);
  });
}

test('0.15: a use the rows refuse refuses the request, logged as its request, and the replay refuses it too', async () => {
  await instance('0.15');
  const issued = await root.tokens.issue(CI, { label: 'ci', expiresInDays: 30 });
  const ci = bearer(issued.token);
  assert.deepEqual((await ci.secrets.reveal('market/dev/API_KEY')).values, { API_KEY });
  const newest = async () => (await db.owner.select({ seq: auditLog.seq }).from(auditLog)).reduce((max, row) => (row.seq > max ? row.seq : max), -1n);
  const denied = async (since: bigint) => (await db.owner.select({ decision: auditLog.decision }).from(auditLog).where(gt(auditLog.seq, since))).some((row) => row.decision === 'deny');
  /**
   * A refusal, recorded once: by the vault, its use refused on the rows as they are and replayed so (`code`), when the
   * key's row of the cap's is fresh; or, when the cap's period turned between the two requests (it is the wall clock's,
   * a minute at most) and the use would take the principal's lock, decided first and written nowhere by the vault, by
   * the app's own entry (T158), or for a credential ended, by none, as any 401. Which, the clock decides, never the key.
   */
  const recordedOnce = async (ask: () => Promise<unknown>, code: string, app: boolean) => {
    const [since, uses, decided] = [await newest(), (await usesLogged()).length, [...(await replayStored(db.owner, [signingKey])).decided.values()]];
    await ask();
    const replayed = await replayStored(db.owner, [signingKey]);
    assert.deepEqual(replayed.faults, []);
    const added = [...replayed.decided.values()].slice(decided.length);
    if ((await usesLogged()).length > uses) assert.deepEqual(added, [code], 'logged by the vault, and replayed so');
    else {
      assert.deepEqual(added, [], 'nothing in the vault\'s log');
      assert.equal(await denied(since), app, app ? "the app's entry records it" : 'a 401, as any');
    }
  };
  // Its grant gone: a key it has used is used and refused on the rows as they are. Nothing goes back, and it is
  // answered as every refusal of a key is (D153): no such key, or no access to it.
  await root.access.set(CI, { market: null });
  const notAvailable = (error: { status: number; code?: string }) => error.status === 404 && error.code === 'not_available';
  await recordedOnce(() => assert.rejects(ci.secrets.reveal('market/dev/API_KEY'), notAvailable), 'no_grant', true);
  // One it has not used in the window would take its principal's lock: its standing decides first, refuses it there,
  // and nothing is written, as for a key the place does not hold (T158); the app's own entry records the request.
  const [since, uses] = [await newest(), (await usesLogged()).length];
  await assert.rejects(ci.secrets.reveal('market/dev/WEBHOOK'), notAvailable);
  assert.equal((await usesLogged()).length, uses, 'no entry of its own');
  assert.ok(await denied(since), "the app's records it");
  // Revoked, the token reads nothing: its one key's use by name (T145) refuses it as the vault's rows have it, and the
  // app's own check answers it, 401, as ever.
  await root.tokens.revoke(CI, issued.id);
  await recordedOnce(() => assert.rejects(ci.secrets.reveal('market/dev/API_KEY'), (error: { status: number }) => error.status === 401), 'credential', false);
  const replayed = await replayStored(db.owner, [signingKey]);
  assert.equal([...replayed.decided.values()][0], null, 'the first allowed, live as replayed');
});

test(`0.15: a whole environment of more keys than a request has uses in flight (${USES_AT_ONCE}) opens each, by one use each`, async () => {
  await instance('0.15');
  const many = Object.fromEntries(Array.from({ length: USES_AT_ONCE * 2 + 1 }, (_, i) => [`KEY_${i}`, `value-${i}`]));
  await root.environments.create('market/many');
  await root.secrets.set('market/many', many);
  const ci = bearer((await root.tokens.issue(CI, { label: 'ci', expiresInDays: 30 })).token);
  assert.deepEqual({ ...(await ci.secrets.reveal('market/many')).values }, many);
  assert.equal((await usesLogged()).length, Object.keys(many).length);
});

test('0.15: past its uses in flight, the isolate refuses a read at once, by the API and the proxy, 503 with the vault\'s Retry-After, and logs nothing', async () => {
  await instance('0.15', 0);
  const { token } = await root.tokens.issue(CI, { label: 'ci', expiresInDays: 30 });
  const refused = await send(new Request(`${ORIGIN}/api/reveals`, { method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body: JSON.stringify({ path: 'market/dev/API_KEY' }) }));
  assert.equal(refused.status, 503, await refused.clone().text());
  assert.equal(refused.headers.get('retry-after'), '1', "the vault's own: an isolate's calls in flight free up in a moment");
  // The same through the credential proxy, coffre's own refusal, the vault's Retry-After with it.
  const { handle } = await handleFor(DEV);
  const used = await send(new Request(`${ORIGIN}/use/market/dev/api/thing`, { headers: { 'x-api-key': handle } }));
  assert.equal(used.status, 503, await used.clone().text());
  assert.deepEqual([used.headers.get('coffre-proxy'), used.headers.get('retry-after')], ['refused', '1']);
  assert.deepEqual(await usesLogged(), []);
});

test("0.15: a read through a fork vouches for no kept answer: its uses check where the values are held, and the app asks", async () => {
  await instance('0.15');
  await root.access.set(CI, { market: null, 'market/dev': 'viewer', 'market/feature': 'viewer' });
  const ci = bearer((await root.tokens.issue(CI, { label: 'ci', expiresInDays: 30 })).token);
  assert.equal((await ci.secrets.reveal('market/feature/API_KEY')).values.API_KEY, API_KEY);
  // Its grant on the fork gone, its parent's kept: each use is allowed where the value is held, and the kept answer,
  // which still holds the fork, is asked again rather than vouched for, and refuses it: a key's refusal, the one answer
  // for every one (D153), the fork's read the app's own path's.
  await root.access.set(CI, { 'market/feature': null });
  await assert.rejects(ci.secrets.reveal('market/feature/API_KEY'), (error: { status: number; code?: string }) => error.status === 404 && error.code === 'not_available');
  assert.equal((await ci.secrets.reveal('market/dev/API_KEY')).values.API_KEY, API_KEY, 'its parent it still reads');
});

test('0.15: a value written between the app\'s read and its use answers 409, to ask again: the answer is never of two versions', async () => {
  await instance('0.15');
  const ci = bearer((await root.tokens.issue(CI, { label: 'ci', expiresInDays: 30 })).token);
  const use = deps.vault.use!;
  deps.vault.use = async (input) => {
    deps.vault.use = use;
    await root.secrets.set('market/dev', { API_KEY: 'rotated' });
    return use(input);
  };
  // Two keys, which the app reads before their uses (a request of one key is the vault's use by name, which reads its rows
  // with the use: there is no read before it to differ from).
  const both = () => ci.secrets.reveal('market/dev', ['API_KEY', 'WEBHOOK']);
  await assert.rejects(both(), (error: { status: number; reason?: string }) => error.status === 409 && error.reason === 'changed');
  assert.equal((await both()).values.API_KEY, 'rotated', 'asked again, the new one');
});
