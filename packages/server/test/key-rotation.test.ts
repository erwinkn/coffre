// Rotating the app key (key-rotation.ts, docs/deploy.md "Rotating the app
// key"): an instance under key A, people signed in, a service's tokens and
// its binding, a session awaiting approval, an enrollment code and an OAuth
// client; then starts under key B, with A in previousAuditChainKeys.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';

import { generateToken, github, hashToken, signin, tokenHint } from '@coffre/core/identity';
import type { Database } from '@coffre/db';
import { appendEntries, KeyRetired, lockLogHead } from '@coffre/db/log';
import { SNAPSHOT } from '@coffre/db/dialect';
import { asc, desc, eq } from 'drizzle-orm';

import { coffreRoute, keyReady, respond, runScheduled, settleKey } from '../src/app.ts';
import { authMac, signedBy, type AuthTable } from '../src/auth-rows.ts';
import { resolveConfig } from '../src/config.ts';
import { appendAudit, appLogKey, CHAIN_START, walkChain } from '../src/db/audit.ts';
import { insertBinding, insertConnection, insertOauthClient, memberStanding } from '../src/db/queries.ts';
import { insertSession } from '../src/db/workloads.ts';
import { sealAnchor } from '../src/anchor.ts';
import { toErrorBody } from '../src/api/errors.ts';
import { finishRotation, keyState, keyStateNow, rotateStep, SIGNED_TABLES } from '../src/key-rotation.ts';
import { newestMove } from '../src/db/rotation.ts';
import { postgresOnly } from './db/engine.ts';
import { auditWatch, walkOn } from '../src/plugins/audit-watch.ts';
import { watchContext } from '../src/watch.ts';
import { createRuntime, type CoffreRuntime } from '../src/runtime.ts';
import type { WorkloadTransport } from '../src/workloads/transport.ts';
import { contextFor, holdSomething, openTestDatabase, resetDatabase, testAnchor, testDeps, type FixtureDeps } from './api-fixture.ts';
import {
  auditLog,
  credentials,
  deviceAuthorizations,
  enrollments,
  identities,
  mcpConnections,
  oauthClients,
  serviceBindings,
} from './db/tables.ts';

const ORIGIN = 'https://secrets.acme.example';
const ROOT = 'admin@acme.example';
const SERVICE = 'token:ci-deploy';
const AUTH = signin({ providers: [github({ clientId: 'gh-id', clientSecret: 'gh-secret' })] });
const [A, B, C] = [Buffer.alloc(32, 0xa1), Buffer.alloc(32, 0xb2), Buffer.alloc(32, 0xc3)];
const transport: WorkloadTransport = { json: async () => assert.fail('a rotation fetches nothing') };
const TABLES = { identities, credentials, device_authorizations: deviceAuthorizations, service_bindings: serviceBindings, oauth_clients: oauthClients, mcp_connections: mcpConnections, enrollments };

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;
/** What each person and the service hold under A, by what it is. */
let held: { browser: string; cli: string; service: string; personal: string };

before(async () => {
  db = await openTestDatabase();
});

after(async () => {
  await db.close();
});

/**
 * A start of the app under `chainKey`, with `previous` behind it: a
 * configuration of its own, as a new isolate or process has, which knows
 * nothing yet of where the log stands.
 */
function startUnder(chainKey: Buffer, previous: Buffer[] = [], plugins: CoffreRuntime['plugins'] = []): CoffreRuntime {
  const config = resolveConfig({
    publicUrl: ORIGIN, vault: deps.vault, auth: AUTH, plugins,
    auditChainKey: chainKey.toString('base64'), previousAuditChainKeys: previous.map((key) => key.toString('base64')),
  });
  return createRuntime(config, deps.db, deps.vault, transport);
}

const meta = () => ({ requestId: randomUUID(), sourceIp: '203.0.113.7', label: 'Firefox' });

beforeEach(async () => {
  await resetDatabase(db.owner);
  deps = testDeps(db.runtime, [ROOT], { chainKey: A });
  const old = startUnder(A);
  deps.signin = old.signin!;
  const service = old.signin!;
  const root = await contextFor(deps, ROOT);
  assert.equal((await deps.vault.admit({ actor: `user:${ROOT}`, principal: SERVICE })).ok, true);
  await holdSomething(db.owner, deps.vault, SERVICE, `user:${ROOT}`);
  const browser = await service.completeSignin({ provider: 'github', subject: '1', emails: [ROOT], name: null }, meta());
  assert.ok(browser.ok);
  const started = await service.startDevice({ clientLabel: 'laptop', sourceIp: null });
  await service.decideDevice(root, started.userCode, true);
  const cli = await service.pollDevice(started.deviceCode, { requestId: randomUUID(), sourceIp: null });
  assert.equal(cli.status, 'approved');
  const token = await service.issueServiceToken(root, SERVICE.slice('token:'.length), { label: 'deploy', expiresInDays: 30 });
  const personal = await service.issuePersonalToken(root, { label: 'scripts', expiresInMinutes: 60, scope: { 'ci-deploy-reads': 'viewer' } });
  // A binding, a session of it awaiting a person's approval, and an enrollment code of it.
  const { generation } = (await memberStanding(deps.db, SERVICE))!;
  const bindingId = randomUUID();
  await insertBinding(deps.db, A, {
    id: bindingId, principal: SERVICE, generation, profile: 'kubernetes', issuer: 'https://cluster.acme.example', jwksUri: 'https://cluster.acme.example/keys',
    jwks: null, claims: '{"sub":"x"}', scope: null, policy: '{"approve":true}', label: null, createdBy: ROOT,
  });
  const session = generateToken('workload');
  await insertSession(deps.db, A, {
    id: randomUUID(), kind: 'workload', tokenHash: hashToken(session), tokenHint: tokenHint(session), generation, principal: SERVICE, identityId: null,
    label: null, createdBy: `binding:${bindingId}`, expiresAt: new Date(Date.now() + 3_600_000), revokedAt: null, scope: null, places: null,
    jkt: 'jkt', notAfter: new Date(Date.now() + 86_400_000), ancestors: null, constraints: null, enrollmentId: null, approvedAt: null, approvedBy: null,
  });
  const code = { id: randomUUID(), bindingId, codeHash: randomBytes(32), codeHint: 'coffre_enr_x', scope: '{}', createdBy: ROOT, createdWith: null, expiresAt: new Date(Date.now() + 86_400_000) };
  await db.owner.insert(enrollments).values({ ...code, authMac: authMac(A, 'enrollments', code) });
  const clientId = randomUUID();
  await insertOauthClient(deps.db, A, { id: clientId, name: 'Claude', redirectUris: '["http://127.0.0.1/callback"]' });
  await insertConnection(deps.db, A, {
    id: randomUUID(), principal: `user:${ROOT}`, generation: 1, clientId, clientName: 'Claude', clientHost: null, registration: 'dcr',
    scopes: '["read"]', redirectUri: 'http://127.0.0.1/callback', codeHash: randomBytes(32), codeChallenge: 'challenge', codeExpiresAt: new Date(Date.now() + 60_000), expiresAt: new Date(Date.now() + 86_400_000),
  });
  held = { browser: browser.credential.token, cli: cli.credential.token, service: token.token, personal: personal.token };
});

/** Every signed row, by table: whether `key` signed it. */
async function signedUnder(key: Buffer): Promise<Record<AuthTable, boolean[]>> {
  const out = {} as Record<AuthTable, boolean[]>;
  for (const table of SIGNED_TABLES) {
    const rows = await db.owner.select().from(TABLES[table] as typeof credentials);
    out[table] = rows.map((row) => signedBy(key, table, row as never));
  }
  return out;
}

async function appEntries() {
  return db.owner.select().from(auditLog).where(eq(auditLog.author, 'app')).orderBy(asc(auditLog.seq));
}

async function verifies(token: string, runtime: CoffreRuntime): Promise<boolean> {
  return runtime.signin!.verify(token).then(() => true, () => false);
}

test('the first start under a new key signs every row again under it, signs people out, and writes key.rotate once', async () => {
  const before = await signedUnder(A);
  assert.ok(Object.values(before).every((rows) => rows.length > 0 && rows.every(Boolean)), JSON.stringify(before));
  const next = startUnder(B, [A]);
  assert.deepEqual(await keyState(deps.db, next), { kind: 'rotating', from: A, next: { table: 'identities', after: null }, others: [] });
  assert.equal(await keyReady(next), null);
  assert.deepEqual(next.appKey, { settled: true });

  const after = await signedUnder(B);
  assert.deepEqual(Object.fromEntries(Object.entries(after).map(([table, rows]) => [table, rows.every(Boolean)])), Object.fromEntries(SIGNED_TABLES.map((table) => [table, true])));
  // People sign in again; the service's token, the personal token and the pending session go on.
  assert.deepEqual(
    { browser: await verifies(held.browser, next), cli: await verifies(held.cli, next), service: await verifies(held.service, next), personal: await verifies(held.personal, next) },
    { browser: false, cli: false, service: true, personal: true },
  );
  const sessions = await db.owner.select({ kind: credentials.kind, revokedAt: credentials.revokedAt, revokedBy: credentials.revokedBy }).from(credentials);
  for (const row of sessions) assert.equal(row.revokedAt !== null, row.kind === 'browser' || row.kind === 'cli', JSON.stringify(row));
  const pending = await db.owner.select().from(credentials).where(eq(credentials.kind, 'workload'));
  assert.equal(pending[0]!.approvedAt, null);
  assert.ok(signedBy(B, 'credentials', pending[0]!));

  const moves = (await appEntries()).filter((entry) => entry.action === 'key.reseal' || entry.action === 'key.rotate');
  assert.deepEqual(moves.map((entry) => [entry.action, entry.keyId, entry.subjectPrincipal, entry.actor]), [
    ['key.reseal', appLogKey(B).keyId, appLogKey(A).keyId, 'system:coffre-key-rotation'],
    ['key.rotate', appLogKey(B).keyId, appLogKey(A).keyId, 'system:coffre-key-rotation'],
  ]);
  assert.deepEqual(JSON.parse(moves[0]!.metadata), { from: appLogKey(A).keyId, resealed: 9, signedOut: 2, later: 0, unsigned: [], unsignedCount: 0, next: null });
  // Another start is settled at once, and writes nothing.
  const again = startUnder(B, [A]);
  assert.equal(await keyReady(again), null);
  assert.equal((await appEntries()).filter((entry) => entry.action === 'key.rotate').length, 1);
  // The log verifies whole: A's entries before, B's after.
  assert.deepEqual(await walkChain(deps.db, next, CHAIN_START, { limit: Infinity }), { ok: true, at: (await walked(next)).at, done: true });
});

async function walked(runtime: CoffreRuntime) {
  const result = await walkChain(deps.db, runtime, CHAIN_START, { limit: Infinity });
  assert.ok(result.ok, JSON.stringify(result, (_, value: unknown) => (typeof value === 'bigint' ? String(value) : value)));
  return result;
}

test('from its first step, the old key writes no more; after it, it verifies only what came before', async () => {
  const old = startUnder(A);
  const next = startUnder(B, [A]);
  // One step, as a Worker takes it: the rotation is under way, and A is retired already.
  assert.equal((await rotateStep(deps.db, next, { rows: 2 })).kind, 'rotating');
  const late = await old.db.transaction((tx) => appendAudit(tx, A, [{ actorType: 'system', actorId: 'late', action: 'secret.read', decision: 'allow' }])).catch((error: unknown) => error);
  assert.ok(late instanceof KeyRetired);
  // Refused as an instance a newer deployment replaces, not a bug.
  assert.equal(toErrorBody(late).status, 503);
  assert.equal(toErrorBody(late).body.error, 'app_key');
  assert.equal(await keyReady(next), null);
  assert.equal(await verifies(held.service, old), false, 'A vouches for no row');
  // Someone who holds A and can write the database appends under it after the rotation, past the append's own check.
  await db.owner.transaction(async (tx) => {
    const head = await lockLogHead(tx);
    const [last] = await tx.select({ seq: auditLog.seq, hash: auditLog.hash }).from(auditLog).orderBy(desc(auditLog.seq)).limit(1);
    await appendEntries(tx, appLogKey(A), [{ actor: 'user:mallory@acme.example', action: 'secret.read', decision: 'allow' }], undefined, { head, last: last!, at: Date.now() });
  });
  const forged = (await appEntries()).at(-1)!;
  const rotated = (await appEntries()).find((entry) => entry.action === 'key.reseal')!;
  const result = await walkChain(deps.db, next, CHAIN_START, { limit: Infinity });
  assert.deepEqual(result, {
    ok: false,
    failedAtSeq: forged.seq,
    reason: `written under ${appLogKey(A).keyId} after the app moved on from it, at entry ${rotated.seq}: a key it replaced verifies only what came before`,
    through: forged.seq - 1n,
  });
  // A row A signs after the rotation is no credential.
  const token = generateToken('service');
  const row = {
    id: randomUUID(), kind: 'service', tokenHash: hashToken(token), tokenHint: tokenHint(token), principal: SERVICE, generation: 1, identityId: null,
    label: 'forged', createdBy: 'user:mallory@acme.example', expiresAt: new Date(Date.now() + 86_400_000), revokedAt: null, scope: null,
  };
  await db.owner.insert(credentials).values({ ...row, authMac: authMac(A, 'credentials', row as never) });
  assert.equal(await verifies(token, next), false);
  // Nor does a start that holds A move to anything again: the log is under B.
  assert.equal((await keyState(deps.db, startUnder(B, [A]))).kind, 'settled');
});

test('a rotation cut short goes on from its last step, and every row is signed once', async () => {
  const first = startUnder(B, [A]);
  assert.equal((await rotateStep(deps.db, first, { rows: 3 })).kind, 'rotating');
  assert.equal((await rotateStep(deps.db, first, { rows: 3 })).kind, 'rotating');
  // The process dies here. Another start, which knows nothing of it, goes on from where the log says.
  const second = startUnder(B, [A]);
  const standing = await keyState(deps.db, second);
  assert.equal(standing.kind, 'rotating');
  await settleKey(second);
  assert.equal(second.appKey.settled, true);
  const steps = (await appEntries()).filter((entry) => entry.action === 'key.reseal').map((entry) => JSON.parse(entry.metadata) as { resealed: number; signedOut: number });
  assert.equal(steps.reduce((sum, step) => sum + step.resealed + step.signedOut, 0), 11, JSON.stringify(steps));
  assert.ok(Object.values(await signedUnder(B)).every((rows) => rows.every(Boolean)));
  assert.equal((await appEntries()).filter((entry) => entry.action === 'key.rotate').length, 1);
  await walked(second);
});

test('starts that race each other rotate once, each step going on from the one before', async () => {
  const starts = Array.from({ length: 6 }, () => startUnder(B, [A]));
  await Promise.all(starts.map(async (start) => {
    for (let state = await keyState(deps.db, start); state.kind === 'rotating' || state.kind === 'sealing';) {
      state = state.kind === 'rotating' ? await rotateStep(deps.db, start, { rows: 2 }) : await finishRotation(deps.db, start);
    }
  }));
  const entries = await appEntries();
  assert.equal(entries.filter((entry) => entry.action === 'key.rotate').length, 1);
  const steps = entries.filter((entry) => entry.action === 'key.reseal').map((entry) => JSON.parse(entry.metadata) as { resealed: number; signedOut: number; next: unknown });
  assert.equal(steps.reduce((sum, step) => sum + step.resealed + step.signedOut, 0), 11);
  assert.equal(new Set(steps.map((step) => JSON.stringify(step.next))).size, steps.length, 'no step went on from where another had');
  assert.ok(Object.values(await signedUnder(B)).every((rows) => rows.every(Boolean)));
  // A start with a third key, racing too late, finds the log under B, a key it does not hold: it serves, as a key replaced without a rotation does.
  assert.equal((await keyState(deps.db, startUnder(C, [A]))).kind, 'settled');
  await walked(starts[0]!);
});

test('a row neither key signed is left as it is, failing as before, and named', async () => {
  const [row] = await db.owner.select().from(credentials).where(eq(credentials.kind, 'service'));
  await db.owner.update(credentials).set({ authMac: randomBytes(32) }).where(eq(credentials.id, row!.id));
  const next = startUnder(B, [A]);
  assert.equal(await keyReady(next), null);
  const step = (await appEntries()).find((entry) => entry.action === 'key.reseal')!;
  assert.deepEqual(JSON.parse(step.metadata).unsigned, [{ table: 'credentials', id: row!.id }]);
  assert.equal(await verifies(held.service, next), false);
});

test('the door answers rotating while the rotation steps, readiness steps it too, and the app serves once it is done', async () => {
  // Enough rows for several steps: a service's spent CI credentials, as each run leaves one.
  const spent = Array.from({ length: 1000 }, () => {
    const token = generateToken('service');
    return {
      id: randomUUID(), kind: 'service', tokenHash: hashToken(token), tokenHint: tokenHint(token), principal: SERVICE, generation: 1, identityId: null,
      label: null, createdBy: 'binding:x', expiresAt: new Date(Date.now() - 1000), revokedAt: null, scope: null,
    };
  });
  await db.owner.insert(credentials).values(spent.map((row) => ({ ...row, authMac: authMac(A, 'credentials', row as never) })));
  const next = startUnder(B, [A]);
  const ask = async (path: string, accept = 'application/json') => {
    const request = new Request(`${ORIGIN}${path}`, { headers: { accept } });
    const response = await respond(request, next, null, async () => (await coffreRoute(request, next, null)) ?? new Response('a page'));
    return { status: response.status, body: await response.text(), retry: response.headers.get('retry-after') };
  };
  const first = await ask('/api/me');
  assert.deepEqual([first.status, JSON.parse(first.body).error, first.retry], [503, 'rotating', '1']);
  assert.deepEqual(JSON.parse((await ask('/readyz')).body), { ok: false, rotating: true });
  assert.match((await ask('/', 'text/html')).body, /moving to its new app key/);
  await assert.rejects(runScheduled(next), /moving to its new app key/);
  for (let asks = 0; next.appKey.settled === false; asks++) {
    assert.ok(asks < 10, 'the rotation never ended');
    await ask('/readyz');
  }
  assert.equal((await ask('/api/me')).status, 401);
  assert.ok(Object.values(await signedUnder(B)).every((rows) => rows.every(Boolean)));
});

test('a key the log refuses: one the log moved on from, or not the one a rotation under way moves to; a key it does not know serves, as before rotations', async () => {
  const refusal = async (runtime: CoffreRuntime) => {
    const state = await keyState(deps.db, runtime);
    return state.kind === 'refused' ? state.reason : state.kind;
  };
  // A lost key, or the wrong one: the instance serves, everyone signed out, as before; the server's log says which key.
  assert.equal(await refusal(startUnder(C)), 'settled');
  assert.equal((await rotateStep(deps.db, startUnder(B, [A]), { rows: 2 })).kind, 'rotating');
  assert.equal(await refusal(startUnder(C, [A, B])), `a rotation to ${appLogKey(B).keyId} is under way, and this app's key is ${appLogKey(C).keyId}: deploy that one as auditChainKey to finish it`);
  assert.equal(await refusal(startUnder(B)), `the rotation under way moves from ${appLogKey(A).keyId}, a key missing from previousAuditChainKeys: put it back to finish it`);
  await settleKey(startUnder(B, [A]));
  // Rolled back to A, with or without B: the log moved on, and A writes no more.
  assert.equal(await refusal(startUnder(A)), `the log moved on from ${appLogKey(A).keyId}, this app's key: a key the app moved on from writes no more, and comes back only as a new key's rotation`);
  const rolledBack = startUnder(A, [B]);
  assert.equal(await refusal(rolledBack), `the log moved on from ${appLogKey(A).keyId}, this app's key: a key the app moved on from writes no more, and comes back only as a new key's rotation`);
  const before = (await appEntries()).length;
  const answered = await respond(new Request(`${ORIGIN}/api/me`), rolledBack, null, async () => new Response('served'));
  assert.deepEqual([answered.status, (await answered.json()).error], [503, 'app_key']);
  assert.equal((await appEntries()).length, before, 'a refused start writes nothing');
  // Once rotated, B no longer needs A to serve.
  assert.equal(await refusal(startUnder(B)), 'settled');
  // A key lost after the rotation, B's successor never given its predecessor: it serves.
  const lost = startUnder(C);
  const response = await respond(new Request(`${ORIGIN}/api/me`), lost, null, async () => new Response('served'));
  assert.equal(await response.text(), 'served');
  assert.equal(lost.appKey.settled, true);
});

test('a second rotation moves from the first one\'s key, and each old key verifies only its own stretch', async () => {
  await settleKey(startUnder(B, [A]));
  const second = startUnder(C, [B, A]);
  assert.deepEqual(await keyState(deps.db, second), { kind: 'rotating', from: B, next: { table: 'identities', after: null }, others: [] });
  await settleKey(second);
  assert.ok(Object.values(await signedUnder(C)).every((rows) => rows.every(Boolean)));
  assert.equal(await verifies(held.service, second), true);
  await walked(second);
  const rotations = (await appEntries()).filter((entry) => entry.action === 'key.rotate');
  assert.deepEqual(rotations.map((entry) => [entry.keyId, entry.subjectPrincipal]), [[appLogKey(B).keyId, appLogKey(A).keyId], [appLogKey(C).keyId, appLogKey(B).keyId]]);
});

test('the audit anchor is sealed again under the new key, and readiness is green after the rotation', async () => {
  const anchor = testAnchor();
  const old = startUnder(A, [], [auditWatch({ anchor })]);
  await runScheduled(old);
  const sealed = (await anchor.read())!;
  assert.equal(sealed.keyId, appLogKey(A).keyId);
  const ready = async (runtime: CoffreRuntime) => {
    const request = new Request(`${ORIGIN}/readyz`);
    return (await respond(request, runtime, null, async () => (await coffreRoute(request, runtime, null))!)).json();
  };
  assert.equal((await ready(old)).ok, true);

  const next = startUnder(B, [A], [auditWatch({ anchor })]);
  assert.equal(await keyReady(next), null);
  const resealed = (await anchor.read())!;
  assert.equal(resealed.keyId, appLogKey(B).keyId);
  const { keyId: _a, mac: _b, ...was } = sealed;
  const { keyId: _c, mac: _d, ...is } = resealed;
  assert.deepEqual(is, was, 'what the anchor says is what it said');
  assert.equal((await ready(next)).ok, true);
  await runScheduled(next);
  assert.deepEqual([(await ready(next)).ok, (await ready(next)).anchored], [true, true]);
});

test('a rotation cut short before its anchor was sealed again seals it at the next start; after key.rotate, nothing seals a record under the old key', async () => {
  const anchor = testAnchor();
  await runScheduled(startUnder(A, [], [auditWatch({ anchor })]));
  // Every row signed, and the process died before the anchor was sealed again: no key.rotate yet.
  const cut = startUnder(B, [A]);
  assert.equal((await rotateStep(deps.db, cut)).kind, 'sealing');
  assert.equal((await appEntries()).filter((entry) => entry.action === 'key.rotate').length, 0);
  assert.equal((await anchor.read())!.keyId, appLogKey(A).keyId);
  const next = startUnder(B, [A], [auditWatch({ anchor })]);
  assert.equal(await keyReady(next), null);
  const sealed = (await anchor.read())!;
  assert.equal(sealed.keyId, appLogKey(B).keyId);
  // Someone who holds A, and can write the store, writes a record of their own under it: it stays foreign, red.
  const { keyId: _k, mac: _m, ...fields } = sealed;
  const forged = sealAnchor(A, { ...fields, finding: null, at: Date.now() });
  assert.equal(await anchor.write(sealed, forged), true);
  await assert.rejects(runScheduled(next), /heartbeat failed/);
  assert.deepEqual(await anchor.read(), forged);
  const ready = await respond(new Request(`${ORIGIN}/readyz`), next, null, async () => (await coffreRoute(new Request(`${ORIGIN}/readyz`), next, null))!);
  assert.equal((await ready.json()).ok, false);
});

test('a start under the new key alone, before the old one is listed, loses nothing once it is: the old key is still rotated from', async () => {
  // As `wrangler secret put APP_KEY` alone would: B serves, everyone signed out meanwhile, and writes an entry or two.
  const alone = startUnder(B);
  assert.equal(await keyReady(alone), null);
  assert.equal(await verifies(held.service, alone), false);
  await alone.db.transaction((tx) => appendAudit(tx, B, [{ actorType: 'system', actorId: 'meanwhile', action: 'audit.heartbeat', decision: 'allow' }]));
  // The deploy that lists A rotates from it all the same.
  const next = startUnder(B, [A]);
  assert.deepEqual(await keyState(deps.db, next), { kind: 'rotating', from: A, next: { table: 'identities', after: null }, others: [] });
  await settleKey(next);
  assert.equal(next.appKey.settled, true);
  assert.equal(await verifies(held.service, next), true);
  assert.ok(Object.values(await signedUnder(B)).every((rows) => rows.every(Boolean)));
  await assert.rejects(startUnder(A).db.transaction((tx) => appendAudit(tx, A, [{ actorType: 'system', actorId: 'late', action: 'secret.read', decision: 'allow' }])), KeyRetired);
  await walked(next);
});

test('the order previous keys are listed in changes nothing: each that wrote is rotated from', async () => {
  // C wrote too, a key A replaced by hand before rotations: listed oldest first.
  await deps.db.transaction((tx) => appendAudit(tx, C, [{ actorType: 'system', actorId: 'older', action: 'audit.heartbeat', decision: 'allow' }]));
  const next = startUnder(B, [C, A]);
  await settleKey(next);
  assert.equal(next.appKey.settled, true);
  const rotations = (await appEntries()).filter((entry) => entry.action === 'key.rotate').map((entry) => entry.subjectPrincipal);
  assert.deepEqual(rotations.sort(), [appLogKey(A).keyId, appLogKey(C).keyId].sort());
  assert.equal(await verifies(held.service, next), true);
  assert.ok(Object.values(await signedUnder(B)).every((rows) => rows.every(Boolean)));
  // C's rotation found A's rows A's to sign, not lost.
  const steps = (await appEntries()).filter((entry) => entry.action === 'key.reseal').map((entry) => JSON.parse(entry.metadata) as { from: string; later: number; unsignedCount: number });
  assert.ok(steps.every((step) => step.unsignedCount === 0), JSON.stringify(steps));
  assert.ok(steps.some((step) => step.from === appLogKey(C).keyId && step.later > 0), JSON.stringify(steps));
  await walked(next);
});

test('the new key alone keeps the audit anchor as it was, and the rotation that lists the old key seals it again: readiness green', async () => {
  const anchor = testAnchor();
  await runScheduled(startUnder(A, [], [auditWatch({ anchor })]));
  const sealed = (await anchor.read())!;
  const alone = startUnder(B, [], [auditWatch({ anchor })]);
  await assert.rejects(runScheduled(alone), /heartbeat failed/);
  assert.deepEqual(await anchor.read(), sealed, 'left as it was');
  const next = startUnder(B, [A], [auditWatch({ anchor })]);
  await settleKey(next);
  assert.equal((await anchor.read())!.keyId, appLogKey(B).keyId);
  await runScheduled(next);
  const request = new Request(`${ORIGIN}/readyz`);
  const ready = await (await respond(request, next, null, async () => (await coffreRoute(request, next, null))!)).json();
  assert.deepEqual([ready.ok, ready.anchored], [true, true]);
  await walked(next);
});

test('a database that cannot be reached serves nothing before the key is settled', async () => {
  const next = startUnder(B, [A]);
  const lost = Object.assign(new Error('Network connection lost.'), { code: 'ECONNRESET' });
  const broken = new Proxy(next.db, { get: (target, key) => (key === 'select' || key === 'transaction' || key === 'selectDistinct' ? () => { throw lost; } : Reflect.get(target, key)) });
  const runtime = { ...next, db: broken as Database };
  const answered = await respond(new Request(`${ORIGIN}/api/me`), runtime, null, async () => new Response('served'));
  assert.deepEqual([answered.status, (await answered.json()).error], [503, 'unavailable']);
  assert.equal(runtime.appKey.settled, false);
  assert.equal((await keyState(deps.db, next)).kind, 'rotating');
});

test('a CLI login approved but not yet taken is used up: everyone signs in again', async () => {
  const old = startUnder(A);
  const started = await old.signin!.startDevice({ clientLabel: 'second laptop', sourceIp: null });
  await old.signin!.decideDevice(await contextFor(deps, ROOT), started.userCode, true);
  const next = startUnder(B, [A]);
  assert.equal(await keyReady(next), null);
  assert.deepEqual(await next.signin!.pollDevice(started.deviceCode, { requestId: randomUUID(), sourceIp: null }), { status: 'expired' });
});

test('the door reads where the key stands in one snapshot: a step committed between its reads changes nothing it decides', postgresOnly('SQLite runs one transaction at a time'), async () => {
  const keys = startUnder(B, [A]);
  // Its first read sees no step yet; another start's first step commits before the next.
  const seen = await deps.db.transaction(async (tx) => {
    const first = await newestMove(tx);
    assert.equal((await rotateStep(db.owner, keys, { rows: 2 })).kind, 'rotating');
    return { first, then: await keyState(tx, keys) };
  }, SNAPSHOT);
  assert.equal(seen.first, undefined);
  assert.deepEqual(seen.then, { kind: 'rotating', from: A, next: { table: 'identities', after: null }, others: [] }, 'the whole verdict is from before the step');
  // Read now, it is the step's: still rotating, never settled halfway.
  assert.equal((await keyStateNow(deps.db, keys)).kind, 'rotating');
});

test('a step the door takes while another start holds the head leaves it to that one, and answers rotating at once', postgresOnly('SQLite runs one transaction at a time'), async () => {
  const next = startUnder(B, [A]);
  let release = () => {};
  const released = new Promise<void>((resolve) => (release = resolve));
  let locked = () => {};
  const holding = new Promise<void>((resolve) => (locked = resolve));
  const held = db.owner.transaction(async (tx) => {
    await lockLogHead(tx);
    locked();
    await released;
  });
  await holding;
  try {
    assert.deepEqual(await rotateStep(deps.db, next, { wait: false }), { kind: 'busy' });
    assert.deepEqual(await keyReady(next), { kind: 'rotating' });
    assert.equal((await appEntries()).filter((entry) => entry.action === 'key.reseal').length, 0);
  } finally {
    release();
    await held;
  }
  assert.equal(await keyReady(next), null);
});

test('an anchor store that cannot be used holds the rotation back before key.rotate, and Node stops stepping until it can', async () => {
  const anchor = testAnchor();
  await runScheduled(startUnder(A, [], [auditWatch({ anchor })]));
  let broken = true;
  const flaky = { read: () => (broken ? Promise.reject(new Error('EACCES: the anchor file')) : anchor.read()), write: anchor.write };
  const next = startUnder(B, [A], [auditWatch({ anchor: flaky })]);
  // Returns rather than spinning: every row is signed, and the anchor waits.
  await settleKey(next);
  assert.equal(next.appKey.settled, false);
  assert.deepEqual(await keyReady(next), { kind: 'stalled' });
  const answered = await respond(new Request(`${ORIGIN}/api/me`), next, null, async () => new Response('served'));
  assert.deepEqual([answered.status, (await answered.json()).error], [503, 'rotating']);
  assert.equal((await appEntries()).filter((entry) => entry.action === 'key.rotate').length, 0);
  broken = false;
  assert.equal(await keyReady(next), null);
  assert.equal((await anchor.read())!.keyId, appLogKey(B).keyId);
});

test('a beat of an instance still under the old key, during the rotation, leaves the anchor as it was: no false finding carried over', async () => {
  const anchor = testAnchor();
  const old = startUnder(A, [], [auditWatch({ anchor })]);
  await runScheduled(old);
  const sealed = (await anchor.read())!;
  assert.equal(sealed.finding, null);
  // The old instance has served, its key known settled; the new one's first step retires A.
  const next = startUnder(B, [A], [auditWatch({ anchor })]);
  assert.equal((await rotateStep(deps.db, next, { rows: 2 })).kind, 'rotating');
  await assert.rejects(runScheduled(old), /heartbeat failed/);
  assert.deepEqual(await anchor.read(), sealed, 'the replaced instance wrote nothing');
  assert.equal(await keyReady(next), null);
  const resealed = (await anchor.read())!;
  assert.deepEqual([resealed.keyId, resealed.finding], [appLogKey(B).keyId, null]);
});

test('a step entry that does not say where the rotation goes on is refused, and readiness says the key is refused', async () => {
  // Written under B, with B's MAC, but saying nothing of where the next step goes on.
  await deps.db.transaction((tx) => appendAudit(tx, B, [{ actorType: 'system', actorId: 'coffre-key-rotation', action: 'key.reseal', decision: 'allow', subject: appLogKey(A).keyId, metadata: { from: appLogKey(A).keyId } }]));
  const next = startUnder(B, [A]);
  const state = await keyState(deps.db, next);
  assert.equal(state.kind, 'refused');
  assert.match((state as { reason: string }).reason, /does not say where it goes on/);
  const request = new Request(`${ORIGIN}/readyz`);
  const ready = await (await respond(request, next, null, async () => (await coffreRoute(request, next, null))!)).json();
  assert.deepEqual(ready, { ok: false, appKey: false });
});

test('an instance the log moved on from leaves the anchor as it is, whatever its walk found', async () => {
  const anchor = testAnchor();
  const old = startUnder(A, [], [auditWatch({ anchor })]);
  await runScheduled(old);
  // A backlog for the walks between beats: the checkpoint held, the app's walk from the start toward it.
  const caught = (await anchor.read())!;
  const { keyId: _k, mac: _m, ...fields } = caught;
  const backlog = sealAnchor(A, { ...fields, verified: null, epoch: caught.epoch + 1 });
  assert.equal(await anchor.write(caught, backlog), true);
  // The new key's first step, then a walk of the old instance, which meets B's entry where the checkpoint is: it writes nothing.
  assert.equal((await rotateStep(deps.db, startUnder(B, [A]), { rows: 2 })).kind, 'rotating');
  const context = watchContext({ db: deps.db, chainKey: A, vault: deps.vault, warn: () => {} });
  assert.equal(await context.log.movedOn(), true);
  assert.equal(await walkOn(context, anchor), false);
  assert.deepEqual(await anchor.read(), backlog);
});
