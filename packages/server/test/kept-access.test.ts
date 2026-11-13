// A read decides on the vault's answer about its caller kept from their
// last request, and makes one vault call, a use, which decides on the rows as
// they are and logs its request (`Accesses`, src/accesses.ts).
// Whatever changed since, it answers as a request that asked would have:
// a grant revoked or given, the reader removed, a vault too old to name its answer.
// And it logs only what that request would have: never a read or a refusal
// made on an answer that was no longer the vault's. A use refused on a stale
// answer is refused on its merits, and the request starts over, asking.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';

import { createClient, type CoffreClient } from '@coffre/client';
import { github, signin } from '@coffre/core/identity';
import type { Vault } from '@coffre/core/vault';

import { Accesses } from '../src/accesses.ts';
import { coffreRoute } from '../src/app.ts';
import { resolveConfig } from '../src/config.ts';
import { createRuntime, type CoffreRuntime } from '../src/runtime.ts';
import { clientFor, contextFor, entryOf, loggedSince, logMark, openTestDatabase, refusedIn, resetDatabase, testDeps, usesLogged, type FixtureDeps } from './api-fixture.ts';
import { auditLog } from '@coffre/db/schema';
import { inBulkPeriod } from './window-fixture.ts';

const ORIGIN = 'https://secrets.acme.example';
const ROOT = 'admin@acme.example';
const READER = 'reader@acme.example';
const SERVICE = 'token:ci';

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;
let root: CoffreClient;
/** The vault the runtime calls, counted. */
let calls: string[];
/**
 * Whether the vault serves a request's one key by name: then it keeps no answer. Off but where a test turns it
 * on, so that a read of one key here goes as a read of several does, on the answer kept.
 */
let named = false;
let runtime: CoffreRuntime;

before(async () => {
  db = await openTestDatabase();
});

after(async () => {
  await db.close();
});

beforeEach(async () => {
  await resetDatabase(db.owner);
  deps = testDeps(db.runtime, [ROOT]);
  calls = [];
  named = false;
  const counted = new Proxy(deps.vault as unknown as Vault, {
    get(target, key) {
      if (key === 'useNamed' && !named) return undefined;
      const value: unknown = Reflect.get(target, key, target);
      if (typeof value !== 'function') return value;
      return async (...args: unknown[]) => {
        calls.push(String(key));
        return (value as (...callArgs: unknown[]) => Promise<unknown>).apply(target, args);
      };
    },
  });
  const config = resolveConfig({
    publicUrl: ORIGIN,
    vault: entryOf(counted),
    auth: signin({ providers: [github({ clientId: 'a', clientSecret: 'b' })] }),
    auditChainKey: deps.chainKey.toString('base64'),
  });
  runtime = createRuntime(config, deps.db, counted, { json: async () => ({}) });
  deps.signin = runtime.signin!;
  root = clientFor(deps, ROOT);
  await root.projects.create('market');
  for (const path of ['market/dev', 'market/prod']) await root.environments.create(path);
  await root.secrets.set('market/dev', { API_KEY: 'fake-dev-key' });
  await root.secrets.set('market/prod', { API_KEY: 'fake-prod-key' });
  await root.members.add(`user:${READER}`);
  await root.access.set(`user:${READER}`, { 'market/dev': 'viewer' });
});

/** The reader's CLI session, from an approved device login: it carries everything they hold, now. */
async function readerSession(): Promise<CoffreClient> {
  return bearer(await readerToken());
}

async function readerToken(): Promise<string> {
  const signinService = runtime.signin!;
  const started = await signinService.startDevice({ clientLabel: 'laptop', sourceIp: null });
  await signinService.decideDevice(await contextFor(deps, READER), started.userCode, true);
  const polled = await signinService.pollDevice(started.deviceCode, { requestId: randomUUID(), sourceIp: null });
  if (polled.status !== 'approved') throw new Error('the device login was not approved');
  return polled.credential.token;
}

function bearer(token: string): CoffreClient {
  return createClient({ url: ORIGIN, headers: () => ({ authorization: `Bearer ${token}` }), transport: (request) => coffreRoute(request, runtime, '203.0.113.7').then((response) => response!) });
}

/** The reader's entries since `since`, of `action`: allowed and denied. */
async function entries(since: number, action: string): Promise<string[]> {
  const rows = (await loggedSince(db.owner, since, [action])).filter((entry) => entry.actor === `user:${READER}`);
  return rows.map((row) => `${row.decision} ${row.code ?? ''}`.trim());
}

function newestSeq(): Promise<number> {
  return logMark(db.owner);
}

/** A reveal's answer, or its refusal's status and reason. */
async function reveal(client: CoffreClient, path: string): Promise<string> {
  try {
    return Object.values((await client.secrets.reveal(path)).values).join();
  } catch (error) {
    const { status, code, reason } = error as { status: number; code?: string; reason?: string };
    // A key's one refusal says no reason: the app's entry of it does, the newest refusal of a read.
    return `${status} ${(code === 'not_available' ? await refusedIn(db.owner) : reason) ?? ''}`.trim();
  }
}

test('a read on a kept answer makes one vault call, which checks it', async () => {
  const reader = await readerSession();
  assert.equal(await reveal(reader, 'market/dev/API_KEY'), 'fake-dev-key');
  calls = [];
  assert.equal(await reveal(reader, 'market/dev/API_KEY'), 'fake-dev-key');
  assert.deepEqual(calls, ['use']);
});

test("a read of one key keeps and recalls nothing: the vault's one use by name decides on the reader as they are", async () => {
  named = true;
  const reader = await readerSession();
  // Both reads in one of the key's refresh periods (a minute, at the default window, from its phase), with time
  // to spare: a repeat rides its cover only while its key's bulk row is of the period it is in (CoverFresh), and two
  // reads either side of a period's turn write a use each (seen in CI).
  await inBulkPeriod(5_000, db.owner, [`user:${READER}`], 'market/dev');
  assert.equal(await reveal(reader, 'market/dev/API_KEY'), 'fake-dev-key');
  calls = [];
  assert.equal(await reveal(reader, 'market/dev/API_KEY'), 'fake-dev-key');
  assert.deepEqual(calls, ['useNamed']);
  // Revoked: refused at once as they are now, by the same one call; nothing asked first. A caller standing nowhere there
  // has no key read, so the vault logs no use of theirs: the app's entry records the request, a `note` of the
  // vault's after it (V1 has the refusing call write it).
  await root.access.set(`user:${READER}`, { 'market/dev': null, 'market/prod': 'viewer' });
  calls = [];
  assert.equal(await reveal(reader, 'market/dev/API_KEY'), '404 no_grant');
  assert.deepEqual(calls, ['useNamed', 'note']);
  assert.equal((await usesLogged(db.owner)).length, 1, 'the first read (the second rode its cover), and no use of the refusal');
  // Granted elsewhere: read there at once, with no answer kept to refuse it first.
  calls = [];
  assert.equal(await reveal(reader, 'market/prod/API_KEY'), 'fake-prod-key');
  assert.deepEqual(calls, ['useNamed']);
});

test('a grant revoked since: the vault refuses the kept answer, reading and logging no read, and the read is refused as the reader is now', async () => {
  const reader = await readerSession();
  assert.equal(await reveal(reader, 'market/dev/API_KEY'), 'fake-dev-key');
  await root.access.set(`user:${READER}`, { 'market/dev': null, 'market/prod': 'viewer' });
  const since = await newestSeq();
  calls = [];
  assert.equal(await reveal(reader, 'market/dev/API_KEY'), '404 missing_secret_read');
  // The use on the kept answer is refused on its merits, its refusal checked against the reader as they are (an
  // `access` that differs), and asked again; the app's entry of the refusal is a `note` (V1's refusing call
  // writes it).
  assert.deepEqual(calls, ['use', 'access', 'access', 'note']);
  // Its reason the event's code, as every refusal on the vault's chain carries it (`eventOf`).
  assert.deepEqual(await entries(since, 'secret.read'), ['deny missing_secret_read']);
});

test('a grant given since: the refusal the kept answer would make is checked first, and the read goes through', async () => {
  const reader = await readerSession();
  assert.equal(await reveal(reader, 'market/dev/API_KEY'), 'fake-dev-key');
  await root.access.set(`user:${READER}`, { 'market/prod': 'viewer' });
  const since = await newestSeq();
  calls = [];
  assert.equal(await reveal(reader, 'market/prod/API_KEY'), 'fake-prod-key');
  // Refused on the kept answer, which the vault no longer gives: nothing logged; asked again, it reads.
  assert.deepEqual(calls, ['access', 'access', 'use']);
  // The read, logged: a use (`usesLogged`).
  assert.deepEqual(await entries(since, 'secret.read'), []);
  assert.equal((await usesLogged(db.owner)).length, 2, 'the first read and this one');
});

test('removed since: the credential is refused, and nothing read', async () => {
  const reader = await readerSession();
  assert.equal(await reveal(reader, 'market/dev/API_KEY'), 'fake-dev-key');
  await root.members.remove(`user:${READER}`);
  const since = await newestSeq();
  calls = [];
  assert.equal(await reveal(reader, 'market/dev/API_KEY'), '401');
  // The removal revoked the session's row too: refused before anything is asked of the vault.
  assert.deepEqual(calls, []);
  assert.deepEqual(await entries(since, 'secret.read'), []);
});

test('admitted again, on a new credential: an answer kept from before is no answer about it', async () => {
  const before = await readerSession();
  assert.equal(await reveal(before, 'market/dev/API_KEY'), 'fake-dev-key');
  await root.members.remove(`user:${READER}`);
  await root.members.add(`user:${READER}`);
  await root.access.set(`user:${READER}`, { 'market/dev': 'viewer' });
  const after = await readerSession();
  calls = [];
  assert.equal(await reveal(after, 'market/dev/API_KEY'), 'fake-dev-key');
  assert.deepEqual(calls, ['access', 'use']);
  assert.equal(await reveal(before, 'market/dev/API_KEY'), '401');
});

test('a read of plain values alone, which opens nothing, asks before it answers', async () => {
  await root.secrets.set('market/dev', { REGION: { value: 'eu-west-3', sensitivity: 'plain' } });
  const reader = await readerSession();
  assert.equal(await reveal(reader, 'market/dev/API_KEY'), 'fake-dev-key');
  calls = [];
  assert.equal(await reveal(reader, 'market/dev/REGION'), 'eu-west-3');
  assert.deepEqual(calls, ['access']);
});

test("an answer from a vault older than 0.14.1, which names none, is never kept: beside one, every read asks", () => {
  const accesses = new Accesses();
  const answer = { principal: `user:${READER}`, status: 'active' as const, generation: 0, role: 'member' as const, scope: { kind: 'everywhere' } as never, grants: [], since: null, by: null };
  accesses.remember(answer);
  assert.equal(accesses.recall(answer.principal), undefined);
  accesses.remember({ ...answer, revision: 'r1' });
  assert.equal(accesses.recall(answer.principal)?.revision, 'r1');
  // Nor is a removed member's, nor one of another generation than the credential's.
  assert.equal(accesses.recall(answer.principal, 1), undefined);
  accesses.remember({ ...answer, status: 'removed', generation: 1, revision: 'r2' });
  assert.equal(accesses.recall(answer.principal), undefined);
});

test('a body past the bound, on a kept answer, is refused at once, its stream cancelled', async () => {
  const token = await readerToken();
  assert.equal(await reveal(bearer(token), 'market/dev/API_KEY'), 'fake-dev-key');
  let cancelled = false;
  const chunk = new Uint8Array(64 * 1024).fill(0x20);
  const body = new ReadableStream<Uint8Array>({ pull: (controller) => controller.enqueue(chunk), cancel: () => void (cancelled = true) });
  const request = new Request(`${ORIGIN}/api/reveals`, {
    method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body, duplex: 'half',
  } as RequestInit);
  const answered = await Promise.race([
    coffreRoute(request, runtime, '203.0.113.7'),
    new Promise<null>((resolve) => setTimeout(() => resolve(null), 5000)),
  ]);
  // Past the API's bound (`API_BODY_BYTES`): 413 `too_large`, .
  assert.equal(answered?.status, 413);
  assert.equal(((await answered!.json()) as { error: string }).error, 'too_large');
  assert.ok(cancelled, 'the body was cancelled');
});

/** A raw POST /api/reveals with this token and body: its status. */
async function post(token: string, body: BodyInit, init: Partial<RequestInit> = {}): Promise<number> {
  const request = new Request(`${ORIGIN}/api/reveals`, { method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body, ...init } as RequestInit);
  return (await coffreRoute(request, runtime, '203.0.113.7'))!.status;
}

test('a body is read as it would be on an answer asked for: decoded once, by the route', async () => {
  const token = await readerToken();
  const doubled = '\uFEFF\uFEFF{"path":"market/dev/API_KEY"}';
  const cold = await post(token, doubled);
  calls = [];
  assert.equal(await post(token, doubled), cold);
  assert.equal(await post(token, '{"path":"market/dev/API_KEY"}'), 200);
});

test('a body refused, on a kept answer the vault no longer gives, is answered as a request that asked: its caller first', async () => {
  const token = await readerToken();
  assert.equal(await reveal(bearer(token), 'market/dev/API_KEY'), 'fake-dev-key');
  // Removed in the vault, before the app's sweep reaches the session's row.
  assert.equal((await deps.vault.remove({ actor: `user:${ROOT}`, principal: `user:${READER}` })).ok, true);
  assert.equal(await post(token, new Uint8Array(1024 * 1024 + 1).fill(0x20)), 401);
});
