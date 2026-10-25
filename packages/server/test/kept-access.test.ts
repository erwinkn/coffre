// A read decides on the vault's answer about its caller kept from their
// last request, and makes one vault call, the unwrap, which checks that
// answer under the reader's row and the head (`Accesses`, src/accesses.ts).
// Whatever changed since, it answers as a request that asked would have:
// a grant revoked or given, the reader removed, a vault too old to check.
// And it logs only what that request would have: never a read or a refusal
// made on an answer that was no longer the vault's.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';

import { createClient, type CoffreClient } from '@coffre/client';
import { github, signin } from '@coffre/core/identity';
import type { Vault } from '@coffre/core/vault';
import { and, eq, gt } from 'drizzle-orm';

import { Accesses } from '../src/accesses.ts';
import { coffreRoute } from '../src/app.ts';
import { resolveConfig } from '../src/config.ts';
import { createRuntime, type CoffreRuntime } from '../src/runtime.ts';
import { clientFor, contextFor, openTestDatabase, resetDatabase, testDeps, type FixtureDeps } from './api-fixture.ts';
import { auditLog } from './db/tables.ts';

const ORIGIN = 'https://secrets.acme.example';
const ROOT = 'admin@acme.example';
const READER = 'reader@acme.example';
const SERVICE = 'token:ci';

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;
let root: CoffreClient;
/** The vault the runtime calls, counted; `unchecked` makes it answer as a vault older than 0.14.1, which names nothing back. */
let calls: string[];
let unchecked = false;
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
  unchecked = false;
  const counted = new Proxy(deps.vault as unknown as Vault, {
    get(target, key) {
      const value: unknown = Reflect.get(target, key, target);
      if (typeof value !== 'function') return value;
      return async (...args: unknown[]) => {
        calls.push(String(key));
        // An older vault reads no `accessRevision`, and names none back.
        if (key === 'unwrap' && unchecked) {
          const { accessRevision: _, ...input } = args[0] as Record<string, unknown>;
          args = [input];
        }
        const answer = await (value as (...callArgs: unknown[]) => Promise<unknown>).apply(target, args);
        if (key === 'unwrap' && unchecked && typeof answer === 'object' && answer !== null) {
          const { accessRevision: _, ...older } = answer as Record<string, unknown>;
          return older;
        }
        return answer;
      };
    },
  });
  const config = resolveConfig({
    publicUrl: ORIGIN,
    vault: counted,
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

/** The reader's entries since `seq`, of `action`: allowed and denied. */
async function entries(since: bigint, action: string): Promise<string[]> {
  const rows = await db.owner
    .select({ decision: auditLog.decision, code: auditLog.code })
    .from(auditLog)
    .where(and(gt(auditLog.seq, since), eq(auditLog.actor, `user:${READER}`), eq(auditLog.action, action)));
  return rows.map((row) => `${row.decision} ${row.code ?? ''}`.trim());
}

async function newestSeq(): Promise<bigint> {
  const rows = await db.owner.select({ seq: auditLog.seq }).from(auditLog);
  return rows.reduce((max, row) => (row.seq > max ? row.seq : max), -1n);
}

/** A reveal's answer, or its refusal's status and reason. */
async function reveal(client: CoffreClient, path: string): Promise<string> {
  try {
    return Object.values((await client.secrets.reveal(path)).values).join();
  } catch (error) {
    const { status, reason } = error as { status: number; reason?: string };
    return `${status} ${reason ?? ''}`.trim();
  }
}

test('a read on a kept answer makes one vault call, which checks it', async () => {
  const reader = await readerSession();
  assert.equal(await reveal(reader, 'market/dev/API_KEY'), 'fake-dev-key');
  calls = [];
  assert.equal(await reveal(reader, 'market/dev/API_KEY'), 'fake-dev-key');
  assert.deepEqual(calls, ['unwrap']);
});

test('a grant revoked since: the vault refuses the kept answer, reading and logging no read, and the read is refused as the reader is now', async () => {
  const reader = await readerSession();
  assert.equal(await reveal(reader, 'market/dev/API_KEY'), 'fake-dev-key');
  await root.access.set(`user:${READER}`, { 'market/dev': null, 'market/prod': 'viewer' });
  const since = await newestSeq();
  calls = [];
  assert.equal(await reveal(reader, 'market/dev/API_KEY'), '403 missing_secret_read');
  // The unwrap on the kept answer, refused; then the reader asked for, and refused by the app.
  assert.deepEqual(calls, ['unwrap', 'access']);
  assert.deepEqual(await entries(since, 'secret.read'), ['deny']);
});

test('a grant given since: the refusal the kept answer would make is checked first, and the read goes through', async () => {
  const reader = await readerSession();
  assert.equal(await reveal(reader, 'market/dev/API_KEY'), 'fake-dev-key');
  await root.access.set(`user:${READER}`, { 'market/prod': 'viewer' });
  const since = await newestSeq();
  calls = [];
  assert.equal(await reveal(reader, 'market/prod/API_KEY'), 'fake-prod-key');
  // Refused on the kept answer, which the vault no longer gives: nothing logged; asked again, it reads.
  assert.deepEqual(calls, ['access', 'access', 'unwrap']);
  assert.deepEqual(await entries(since, 'secret.read'), ['allow']);
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
  assert.deepEqual(calls, ['access', 'unwrap']);
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

test('a vault older than 0.14.1 checks nothing it is not told: the app asks before it answers', async () => {
  const reader = await readerSession();
  assert.equal(await reveal(reader, 'market/dev/API_KEY'), 'fake-dev-key');
  unchecked = true;
  calls = [];
  assert.equal(await reveal(reader, 'market/dev/API_KEY'), 'fake-dev-key');
  assert.deepEqual(calls, ['unwrap', 'access']);
  // Its answer changed meanwhile: nothing goes back on the kept one.
  await root.access.set(`user:${READER}`, { 'market/dev': null, 'market/prod': 'viewer' });
  calls = [];
  assert.equal(await reveal(reader, 'market/dev/API_KEY'), '403 missing_secret_read');
  // The vault decides the unwrap on its own rules and refuses it; the answer, asked for before anything goes back, has
  // changed, so the read goes again, asking, and is refused as the reader is now.
  assert.deepEqual(calls, ['unwrap', 'access', 'access']);
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
  assert.equal(answered?.status, 400);
  assert.ok(cancelled, 'the body was cancelled');
});
