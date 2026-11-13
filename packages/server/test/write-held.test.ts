// A key write in five round trips (T179 PR 3; docs/design/two-trips.md, "A key write"; formal/Writing.tla): the vault
// decides on one read of its own, and the app's transaction holds that read again under the fence before it commits.
// Each adversary of the model's scenarios is made here between the vault's read and the app's hold (`between`), and
// the write commits only as the log stands at its commit: asked again, a request of its own, decided on what moved.
// The tampering ones (a row put back, its newest change's seal forged, a token hash copied onto another's row) are
// made before the write.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';

import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { createClient } from '@coffre/client';
import { github, signin } from '@coffre/core/identity';
import type { Vault, VaultRefused, WriteKeysInput, WriteKeysOutcome } from '@coffre/core/vault';
import { type Queryable } from '@coffre/db';
import { rowsOf } from '@coffre/db/dialect';
import { derivedSigningKey } from '@coffre/vault';
import { replayStored, runCheckpointer, type RunningCheckpointer } from '@coffre/vault/node';
import { laterChanges, lockLogHead, logObject } from '@coffre/db/log';
import { eq, sql, type SQL } from 'drizzle-orm';

import { sessionCookieName } from '../src/auth.ts';
import { resolveConfig } from '../src/config.ts';
import { fetchApi } from '../src/fetch-api.ts';
import { listAudit } from '../src/api/audit.ts';
import { callerFrom } from '../src/api/caller.ts';
import type { ApiContext } from '../src/api/context.ts';
import { parsePath } from '../src/api/paths.ts';
import { acceptance } from '../src/named-use.ts';
import { createRuntime, type CoffreRuntime } from '../src/runtime.ts';
import { REFUSAL_UNSEALED_MESSAGE } from '../src/api/errors.ts';
import { clientFor, entryOf, nothingHeld, numbersFrom, openTestDatabase, resetDatabase, sealedNow, stallingSeal, testDeps, testVault, outcomes } from './api-fixture.ts';
import { openVaultDatabase } from './db/engine.ts';
import { credentials, grants, principals, secrets, secretVersions } from '@coffre/db/schema';

const ORIGIN = 'https://secrets.acme.example';
const ROOT = 'admin@acme.example';
const ADA = 'ada@acme.example';

const db = await openTestDatabase();
test.after(async () => {
  await resetDatabase(db.owner);
  await db.close();
});

const run = (on: Queryable, query: ReturnType<typeof sql>) => rowsOf(on, query);

/**
 * A fresh instance: market/dev holding API_KEY, Ada a developer there, and each one's browser session. `fast: false`:
 * a vault that serves no `writeKeys`, every write down today's path, to answer as the two-trip path's refusals must.
 */
async function world({ fast = true, past = 0n, sealer }: { fast?: boolean; past?: bigint; sealer?: (signingKey: Buffer) => Promise<Pick<RunningCheckpointer, 'sealThrough' | 'heldOutside'> | { sealThrough: typeof sealedNow; heldOutside: typeof nothingHeld }> } = {}) {
  await resetDatabase(db.owner);
  const kek = randomBytes(32);
  // Sealed at once, unless a checkpointer of the test's own seals each change (and refusal) before it answers.
  const sealing = sealer === undefined ? { sealThrough: sealedNow, heldOutside: nothingHeld } : await sealer(derivedSigningKey(kek));
  const vault = testVault([ROOT], {}, { kek }, {}, sealing);
  const deps = testDeps(db.runtime, [ROOT], { vault });
  const root = clientFor(deps, ROOT);
  await root.projects.create('market', { name: 'Market' });
  await root.environments.create('market/dev');
  await root.secrets.set('market/dev', { API_KEY: 'fake-old' });
  // From here on, numbers from `past`: the log's entries and 0.15's changes, bigints no JS number holds past 2^53.
  if (past > 0n) await numbersFrom(db.owner, past, deps.chainKey);
  await root.members.add(`user:${ADA}`);
  await root.access.set(`user:${ADA}`, { 'market/dev': 'developer' });
  // Each `writeKeys` answer, and what runs once, right after the next one, before the app's hold.
  const answers: WriteKeysOutcome[] = [];
  let next: (() => Promise<void>) | null = null;
  // What runs once, right after the vault's next `wrap` (today's path's decision), before the app's transaction.
  let wrapped: (() => Promise<void>) | null = null;
  const hooked = new Proxy(vault, {
    get(target, key) {
      const value: unknown = Reflect.get(target, key, target);
      if (key === 'writeKeys' && !fast) return undefined;
      if (typeof value !== 'function') return value;
      if (key === 'wrap') {
        return async (...args: unknown[]) => {
          const answer: unknown = await (value as (...args: unknown[]) => Promise<unknown>).apply(target, args);
          const adversary = wrapped;
          wrapped = null;
          if (adversary !== null) await adversary();
          return answer;
        };
      }
      if (key !== 'writeKeys') return (value as (...args: unknown[]) => unknown).bind(target);
      return async (input: WriteKeysInput) => {
        const answer = await (value as Vault['writeKeys'])!.call(target, input);
        answers.push(answer);
        const adversary = next;
        next = null;
        if (adversary !== null) await adversary();
        return answer;
      };
    },
  }) as Vault;
  const runtime: CoffreRuntime = createRuntime(
    resolveConfig({ publicUrl: ORIGIN, vault: entryOf(hooked), auth: signin({ providers: [github({ clientId: 'gh-id', clientSecret: 'gh-secret' })] }), auditChainKey: deps.chainKey.toString('base64') }),
    db.runtime,
    hooked,
    { json: async (url) => { throw new Error(`no fetch in this test: ${url.href}`); } },
  );
  const session = async (subject: string, email: string) => {
    const signed = await runtime.signin!.completeSignin({ provider: 'github', subject, emails: [email], name: null }, { requestId: randomUUID(), sourceIp: null, label: 'Firefox on macOS' });
    if (!('credential' in signed)) throw new Error(`${email} was not signed in`);
    return { token: signed.credential.token, id: signed.credential.id };
  };
  const ada = await session('ada', ADA);
  /** Ada's PATCH of market/dev (or `place`), as her browser sends it: its status and body. */
  const write = async (patch: Record<string, unknown>, token = ada.token, place = 'market/dev') => {
    const response = await fetchApi(new Request(`${ORIGIN}/api/secrets/${place}`, {
      method: 'PATCH',
      headers: { cookie: `${sessionCookieName(runtime.auth)}=${token}`, 'sec-fetch-site': 'same-origin', 'content-type': 'application/json' },
      body: JSON.stringify(patch),
    }), runtime, { sourceIp: null });
    return { status: response.status, body: await response.json() as Record<string, unknown>, retryAfter: response.headers.get('retry-after') };
  };
  /** Ada signs her session out, from it, as her browser does. */
  const signOut = async () => {
    const response = await fetchApi(new Request(`${ORIGIN}/api/sessions/${ada.id}`, {
      method: 'DELETE', headers: { cookie: `${sessionCookieName(runtime.auth)}=${ada.token}`, 'sec-fetch-site': 'same-origin' },
    }), runtime, { sourceIp: null });
    assert.ok(response.ok, await response.text());
  };
  /** A client of the API as a browser session's (Ada's by default) calls send it. */
  const client = (token = ada.token) => createClient({
    url: ORIGIN,
    headers: () => ({ cookie: `${sessionCookieName(runtime.auth)}=${token}`, 'sec-fetch-site': 'same-origin' }),
    transport: (request) => fetchApi(request, runtime, { sourceIp: null }),
  });
  return { deps, root, runtime, ada, session, write, signOut, client, answers, signingKey: derivedSigningKey(kek), between: (adversary: () => Promise<void>) => void (next = adversary), afterWrap: (adversary: () => Promise<void>) => void (wrapped = adversary) };
}


/** A key's row in market/dev, by name: its id and current version, or none. */
async function keyRow(name: string): Promise<{ id: string; currentVersion: number; currentVersionId: string | null } | undefined> {
  const [row] = await db.owner.select({ id: secrets.id, currentVersion: secrets.currentVersion, currentVersionId: secrets.currentVersionId }).from(secrets).where(eq(secrets.key, name));
  return row;
}

async function versionOf(id: string | null): Promise<{ sensitive: boolean; createdBy: string } | undefined> {
  if (id === null) return undefined;
  const [row] = await db.owner.select({ sensitive: secretVersions.sensitive, createdBy: secretVersions.createdBy }).from(secretVersions).where(eq(secretVersions.id, id));
  return row === undefined ? undefined : { sensitive: Boolean(row.sensitive), createdBy: row.createdBy };
}

/** A member's `access_seq`, exactly. */
async function accessSeq(principal: string): Promise<bigint> {
  const [row] = await run(db.owner, sql`SELECT CAST(access_seq AS TEXT) AS seq FROM principals WHERE principal = ${principal}`) as { seq: string }[];
  return BigInt(row!.seq);
}

/** Whether a JS number holds `value` exactly, as `JSON.parse` would read it. */
const exactAsNumber = (value: bigint) => BigInt(Number(value)) === value;

const served = (answers: readonly WriteKeysOutcome[]) => answers.map((answer) => (answer.served ? 'served' : answer.why));

test('a key write the vault decided on its read commits in one of the app\'s round trips, its change naming the request and the read it was decided on, and no 0.14 entry beside it (0.16.0)', async () => {
  const w = await world();
  const [{ seq }] = await run(db.owner, sql`SELECT coalesce(max(seq), 0)::text AS seq FROM audit_log`) as { seq: string }[];
  const wrote = await w.write({ NEW_KEY: 'fake-new', API_KEY: 'fake-again' });
  assert.equal(wrote.status, 200, JSON.stringify(wrote.body));
  assert.deepEqual(served(w.answers), ['served']);
  assert.deepEqual(outcomes(wrote.body.keys), { NEW_KEY: { version: 1, sensitivity: 'secret' }, API_KEY: { version: 2, sensitivity: 'secret' } });
  const answer = w.answers[0]!;
  assert.ok(answer.served);
  // Each change is the key's newest, its payload naming the request's number, its credential and the read's digest,
  // each under its own request id, derived from the request's number and its object.
  for (const name of ['NEW_KEY', 'API_KEY']) {
    const row = (await keyRow(name))!;
    assert.equal((wrote.body.keys as Record<string, { versionId?: string }>)[name]?.versionId, row.currentVersionId, 'its outcome names the version it made');
    assert.equal((await versionOf(row.currentVersionId))?.createdBy, `ada@acme.example`);
    const [change] = await run(db.owner, sql`SELECT request_id, payload FROM log_changes WHERE object = ${logObject('secret', row.id)} ORDER BY number DESC LIMIT 1`) as { request_id: string; payload: string }[];
    const payload = JSON.parse(change!.payload) as { request?: { number: string; credential: string; identity: string | null; operationId: string | null; requestId: string | null }; inputs?: string };
    const { identity, operationId, requestId, ...rest } = payload.request ?? {};
    assert.deepEqual(rest, { number: answer.number, credential: w.ada.id });
    assert.equal(typeof identity, 'string');
    // The app's ids of the request and its operation, which 0.14's entries carried: the write's one operation.
    assert.match(String(operationId), /^[0-9a-f-]{36}$/);
    assert.match(String(requestId), /^[0-9a-f-]{36}$/);
    assert.equal(payload.inputs, answer.digest);
  }
  // No 0.14 entry: neither the vault's `key.wrap` nor the app's `secret.write`. The changes are the write's record.
  const entries = await run(db.owner, sql`SELECT author, action FROM audit_log WHERE seq > ${seq} AND action IN ('key.wrap', 'secret.write')`) as { author: string; action: string }[];
  assert.deepEqual(entries, []);
});

test("numbers past 2^53 (Ada's newest access entry, every object's newest change): her write is served and commits, each read exactly, none through a JS number (Fable's review of #474)", async () => {
  // Past 2^53 a double holds only every other whole number: started one further on if Ada's access_seq lands on one.
  const past = 2n ** 53n + 1n;
  let w = await world({ past });
  if (exactAsNumber(await accessSeq(`user:${ADA}`))) w = await world({ past: past + 1n });
  const seq = await accessSeq(`user:${ADA}`);
  assert.ok(seq > past && !exactAsNumber(seq), `Ada's access_seq ${seq} is past 2^53, and no JS number holds it`);
  const wrote = await w.write({ NEW_KEY: 'fake-new', API_KEY: 'fake-again' });
  assert.equal(wrote.status, 200, JSON.stringify(wrote.body));
  assert.deepEqual(outcomes(wrote.body.keys), { NEW_KEY: { version: 1, sensitivity: 'secret' }, API_KEY: { version: 2, sensitivity: 'secret' } });
  // The two-trip path served it, its request numbered exactly.
  assert.deepEqual(served(w.answers), ['served']);
  const answer = w.answers[0]!;
  assert.ok(answer.served && BigInt(answer.number) > past, JSON.stringify(answer));
});

test("the head held and every place in the reads' line taken when Ada writes: the vault's wrap waits for the head, as today's does, and the write commits in one try (Fable's review of #474)", async () => {
  const w = await world();
  let release = () => {};
  let held = () => {};
  const taken = new Promise<void>((resolve) => (held = resolve));
  const holding = db.owner.transaction(async (tx) => {
    await lockLogHead(tx);
    // The reads' places in line (`READ_HEAD_WAITERS`, 16 of them, `lockLogHeadQueued`), and more.
    await run(tx, sql`SELECT pg_advisory_xact_lock(${0x636f6668}, place) FROM generate_series(1, 64) AS place`);
    held();
    await new Promise<void>((resolve) => (release = resolve));
  });
  await Promise.race([taken, holding]);
  const started = Date.now();
  setTimeout(() => release(), 400);
  const wrote = await w.write({ API_KEY: 'fake-again' });
  await holding;
  assert.equal(wrote.status, 200, JSON.stringify(wrote.body));
  assert.ok(Date.now() - started >= 400, `written after ${Date.now() - started} ms, before the head was free`);
  assert.deepEqual(served(w.answers), ['served']);
  assert.deepEqual(outcomes(wrote.body.keys), { API_KEY: { version: 2, sensitivity: 'secret' } });
});

test("Ada's grant taken between the vault's read and the hold: the hold fails, the write asks again, and the vault's refusal answers, nothing written (WritingRevoke, rev)", async () => {
  const w = await world();
  const before = (await keyRow('API_KEY'))!;
  w.between(async () => void (await w.root.access.set(`user:${ADA}`, { 'market/dev': null })));
  const wrote = await w.write({ API_KEY: 'fake-ada' });
  assert.equal(wrote.status, 403, JSON.stringify(wrote.body));
  // Served, held and failed; then refused, which today's path answers and logs.
  assert.deepEqual(served(w.answers), ['served', 'refused']);
  assert.deepEqual(await keyRow('API_KEY'), before);
});

test("a last use due, handed to a held write that then went down today's path: written there, not lost (Fable's review of #469)", async () => {
  const w = await world();
  const long = new Date(Date.now() - 60 * 60 * 1000);
  await db.owner.update(credentials).set({ lastUsedAt: long }).where(eq(credentials.id, w.ada.id));
  // The key made a reference between the read and the hold: the next try is one this path does not serve (a refusal
  // no longer goes down today's path: PR 6).
  await w.root.environments.create('market/prod');
  await w.root.secrets.set('market/prod', { SOURCE: 'fake-source' });
  w.between(async () => void (await w.root.secrets.set('market/dev', { API_KEY: { ref: 'market/prod/SOURCE' } })));
  const wrote = await w.write({ API_KEY: 'fake-ada' });
  assert.equal(wrote.status, 200, JSON.stringify(wrote.body));
  assert.deepEqual(served(w.answers), ['served', 'shape']);
  const [after] = await db.owner.select({ lastUsedAt: credentials.lastUsedAt }).from(credentials).where(eq(credentials.id, w.ada.id));
  assert.ok(after!.lastUsedAt !== null && after!.lastUsedAt.getTime() > long.getTime(), String(after!.lastUsedAt));
});

test("Ada's session revoked between the read and the hold: nothing commits on it (WritingRevoke, end)", async () => {
  const w = await world();
  const before = (await keyRow('API_KEY'))!;
  w.between(w.signOut);
  const wrote = await w.write({ API_KEY: 'fake-ada' });
  assert.equal(wrote.status, 401, JSON.stringify(wrote.body));
  assert.deepEqual(served(w.answers), ['served', 'ended']);
  assert.deepEqual(await keyRow('API_KEY'), before);
});

test("the key Ada writes renamed between the read and the hold: the write lands on the name she wrote, not on the renamed key (WritingNames, ren)", async () => {
  const w = await world();
  const before = (await keyRow('API_KEY'))!;
  w.between(async () => void (await w.root.secrets.rename('market/dev/API_KEY', 'OLD_KEY')));
  const wrote = await w.write({ API_KEY: 'fake-ada' });
  assert.equal(wrote.status, 200, JSON.stringify(wrote.body));
  assert.deepEqual(served(w.answers), ['served', 'served']);
  // OLD_KEY is the key she read, untouched; API_KEY a key of its own, made by the second try.
  assert.deepEqual(await keyRow('OLD_KEY'), before);
  const made = (await keyRow('API_KEY'))!;
  assert.notEqual(made.id, before.id);
  assert.equal(made.currentVersion, 1);
});

test('the key Ada makes made meanwhile by another, sensitive: her write asks again and keeps it sensitive (WritingNames, phn)', async () => {
  const w = await world();
  w.between(async () => void (await w.root.secrets.set('market/dev', { NEW_KEY: { value: 'fake-root', sensitivity: 'sensitive' } })));
  const wrote = await w.write({ NEW_KEY: 'fake-ada' });
  assert.equal(wrote.status, 200, JSON.stringify(wrote.body));
  assert.deepEqual(served(w.answers), ['served', 'served']);
  assert.deepEqual(outcomes(wrote.body.keys), { NEW_KEY: { version: 2, sensitivity: 'sensitive' } });
  const row = (await keyRow('NEW_KEY'))!;
  assert.equal((await versionOf(row.currentVersionId))?.sensitive, true);
});

test("market/dev renamed and a new market/dev made, Ada's grant moved to it, between the read and the hold: the second try's read is the new one's, and nothing commits at either (review r1 of #469)", async () => {
  const w = await world();
  w.between(async () => {
    await w.root.environments.update('market/dev', { slug: 'old' });
    await w.root.environments.create('market/dev');
    await w.root.access.set(`user:${ADA}`, { 'market/old': null, 'market/dev': 'developer' });
  });
  const wrote = await w.write({ NEW_KEY: 'fake-ada' });
  // The second try, by the slugs, read and decided the new market/dev; the route writes to the place it found, the old
  // one by its ids: that try commits nothing there, and today's path answers, as it does a rename after the router.
  assert.deepEqual(served(w.answers), ['served', 'served']);
  assert.ok([403, 404].includes(wrote.status), JSON.stringify(wrote));
  assert.equal(await keyRow('NEW_KEY'), undefined);
});

test("API_KEY sensitive when the vault first read it, written again as a secret before the hold: Ada's write, saying nothing, stays sensitive, as today's path keeps it (review r1 of #469)", async () => {
  const w = await world();
  await w.root.secrets.set('market/dev', { API_KEY: { value: 'fake-sensitive', sensitivity: 'sensitive' } });
  w.between(async () => void (await w.root.secrets.set('market/dev', { API_KEY: { value: 'fake-secret', sensitivity: 'secret' } })));
  const wrote = await w.write({ API_KEY: 'fake-ada' });
  assert.equal(wrote.status, 200, JSON.stringify(wrote.body));
  // The second try found it a secret: today's path writes it, sensitive, as the first try found it.
  assert.deepEqual(served(w.answers), ['served', 'served']);
  assert.deepEqual(outcomes(wrote.body.keys), { API_KEY: { version: 4, sensitivity: 'sensitive' } });
  const row = (await keyRow('API_KEY'))!;
  assert.equal((await versionOf(row.currentVersionId))?.sensitive, true);
});

test("a regenerate whose `replaces` names no version's id: 409 `stale`, as today's path answers it, the vault never asked (review r1 of #469)", async () => {
  const w = await world();
  const before = (await keyRow('API_KEY'))!;
  const wrote = await w.write({ API_KEY: { value: 'a'.repeat(64), generated: { recipe: 'bytes:32:hex' }, replaces: 'no-such-version' } });
  assert.equal(wrote.status, 409, JSON.stringify(wrote.body));
  assert.equal(wrote.body.reason ?? (wrote.body.error as { reason?: string } | undefined)?.reason, 'stale');
  assert.deepEqual(served(w.answers), []);
  assert.deepEqual(await keyRow('API_KEY'), before);
});

test('market/dev archived between the read and the hold: nothing commits there (WritingPlace, arc)', async () => {
  const w = await world();
  const before = (await keyRow('API_KEY'))!;
  w.between(async () => void (await w.root.environments.update('market/dev', { archived: true })));
  const wrote = await w.write({ API_KEY: 'fake-ada' });
  assert.notEqual(wrote.status, 200, JSON.stringify(wrote.body));
  assert.deepEqual(served(w.answers), ['served', 'place']);
  assert.deepEqual(await keyRow('API_KEY'), before);
});

test('the key written by another between the read and the hold: both commit, one version each, neither over the other (WritingRevoke, KeyChangesFlip)', async () => {
  const w = await world();
  w.between(async () => void (await w.root.secrets.set('market/dev', { API_KEY: 'fake-root' })));
  const wrote = await w.write({ API_KEY: 'fake-ada' });
  assert.equal(wrote.status, 200, JSON.stringify(wrote.body));
  assert.deepEqual(served(w.answers), ['served', 'served']);
  assert.deepEqual(outcomes(wrote.body.keys), { API_KEY: { version: 3, sensitivity: 'secret' } });
  const versions = await run(db.owner, sql`SELECT v.version, v.created_by FROM secret_versions v JOIN secrets s ON s.id = v.secret_id WHERE s.key = 'API_KEY' ORDER BY v.version`) as { version: number; created_by: string }[];
  assert.deepEqual(versions.map((row) => [Number(row.version), row.created_by]), [[1, ROOT], [2, ROOT], [3, ADA]]);
});

test("Ada's grant taken and given back between the read and the hold: the same rows, a newer change; the write asks again rather than commit on a read the log no longer shows (WritingABA)", async () => {
  const w = await world();
  w.between(async () => {
    await w.root.access.set(`user:${ADA}`, { 'market/dev': null });
    await w.root.access.set(`user:${ADA}`, { 'market/dev': 'developer' });
  });
  const wrote = await w.write({ API_KEY: 'fake-ada' });
  assert.equal(wrote.status, 200, JSON.stringify(wrote.body));
  assert.deepEqual(served(w.answers), ['served', 'served']);
});

test('a hold that keeps failing gives up after three tries: 409 `changed`, nothing written (EveryRequestEnds)', async () => {
  const w = await world();
  const before = (await keyRow('API_KEY'))!;
  // Every try's read moved before its hold: another write of the key each time.
  const churn = async () => {
    await w.root.secrets.set('market/dev', { OTHER: `fake-${randomUUID()}`, API_KEY: `fake-${randomUUID()}` });
    if (w.answers.length < 3) w.between(churn);
  };
  w.between(churn);
  const wrote = await w.write({ API_KEY: 'fake-ada' });
  assert.equal(wrote.status, 409, JSON.stringify(wrote.body));
  assert.equal(wrote.body.reason ?? (wrote.body.error as { reason?: string } | undefined)?.reason, 'changed');
  // Asked again in a second (two-trips.md, "Retries").
  assert.equal(wrote.retryAfter, '1');
  assert.deepEqual(served(w.answers), ['served', 'served', 'served']);
  const after = (await keyRow('API_KEY'))!;
  assert.equal(after.id, before.id);
  assert.equal((await versionOf(after.currentVersionId))?.createdBy, ROOT);
});

test("Ada's grant taken, then her member row and grants put back and the seal written into the revoke's change: the change's MAC fails, and nothing is written (WritingForge, T190)", async () => {
  const w = await world();
  const before = (await keyRow('API_KEY'))!;
  const [member] = await db.owner.select().from(principals).where(eq(principals.principal, `user:${ADA}`));
  const held = await db.owner.select().from(grants).where(eq(grants.principal, `user:${ADA}`));
  await w.root.access.set(`user:${ADA}`, { 'market/dev': null });
  // A database writer puts the rows back as they were, and the log's newest change of Ada, the revoke, edited to name
  // the row's seal: row and log agree; only that change's MAC, over its seal, says the vault never wrote it.
  await db.owner.delete(grants).where(eq(grants.principal, `user:${ADA}`));
  await db.owner.insert(grants).values(held);
  await db.owner.update(principals).set(member!).where(eq(principals.principal, `user:${ADA}`));
  await run(db.owner, sql`UPDATE log_changes SET seal = ${member!.seal} WHERE number = (SELECT max(number) FROM log_changes WHERE object = ${logObject('principal', `user:${ADA}`)})`);
  const wrote = await w.write({ API_KEY: 'fake-ada' });
  assert.notEqual(wrote.status, 200, JSON.stringify(wrote.body));
  assert.deepEqual(served(w.answers), ['tampered']);
  assert.deepEqual(await keyRow('API_KEY'), before);
});

// Today's path checks a credential's row by its MAC alone, which the row put back whole still carries; only 0.15's
// log says it was revoked (a gap of today's write path, not of this one's: reported with T179 PR 3).
test("Ada's session revoked and its row put back, live: the vault's read refuses it on the log's newest change, and the write answers 401, never down today's path (WritingTamper, dbw)", async () => {
  const w = await world();
  const before = (await keyRow('API_KEY'))!;
  const [row] = await db.owner.select().from(credentials).where(eq(credentials.id, w.ada.id));
  await w.signOut();
  await db.owner.update(credentials).set(row!).where(eq(credentials.id, w.ada.id));
  const wrote = await w.write({ API_KEY: 'fake-ada' });
  assert.equal(wrote.status, 401, JSON.stringify(wrote.body));
  // Refused on her credential's own log, and never asked down today's path, whose check of the row's MAC alone would take it.
  assert.deepEqual(served(w.answers), ['forged']);
  assert.deepEqual(await keyRow('API_KEY'), before);
});

test("Ada's session revoked and its row put back, writing to an environment that is not there: 401 on her credential's own log, not today's 404 (Fable's review of #469)", async () => {
  const w = await world();
  const [row] = await db.owner.select().from(credentials).where(eq(credentials.id, w.ada.id));
  await w.signOut();
  await db.owner.update(credentials).set(row!).where(eq(credentials.id, w.ada.id));
  const wrote = await w.write({ API_KEY: 'fake-ada' }, w.ada.token, 'market/nope');
  assert.equal(wrote.status, 401, JSON.stringify(wrote.body));
  assert.deepEqual(served(w.answers), ['forged']);
});

test("Ada's token hash copied onto the Owner's session: the vault reads the Owner, and the app's check of the row's MAC refuses it before anything commits (WritingTamper, sub; round 6)", async () => {
  const w = await world();
  const before = (await keyRow('API_KEY'))!;
  const owner = await w.session('root', ROOT);
  const [ada] = await db.owner.select({ tokenHash: credentials.tokenHash }).from(credentials).where(eq(credentials.id, w.ada.id));
  await db.owner.update(credentials).set({ tokenHash: randomBytes(32) }).where(eq(credentials.id, w.ada.id));
  await db.owner.update(credentials).set({ tokenHash: ada!.tokenHash }).where(eq(credentials.id, owner.id));
  const wrote = await w.write({ API_KEY: 'fake-ada' });
  assert.equal(wrote.status, 401, JSON.stringify(wrote.body));
  // The vault served it, on the Owner's rows: what refused it is the app's check (AuthChecked).
  assert.deepEqual(served(w.answers), ['served']);
  assert.deepEqual(await keyRow('API_KEY'), before);
});

test("Ada's token hash copied onto a Viewer's session: the vault reads the Viewer and refuses, and the app's check of the row's MAC answers 401 before the refusal is recorded: no record names the Viewer (WritingRefuse, RefusalAfterAuth; review r1 of PR 6)", async () => {
  const w = await world();
  const before = (await keyRow('API_KEY'))!;
  const carol = 'carol@acme.example';
  await w.root.members.add(`user:${carol}`);
  await w.root.access.set(`user:${carol}`, { 'market/dev': 'viewer' });
  const viewer = await w.session('carol', carol);
  const [ada] = await db.owner.select({ tokenHash: credentials.tokenHash }).from(credentials).where(eq(credentials.id, w.ada.id));
  await db.owner.update(credentials).set({ tokenHash: randomBytes(32) }).where(eq(credentials.id, w.ada.id));
  await db.owner.update(credentials).set({ tokenHash: ada!.tokenHash }).where(eq(credentials.id, viewer.id));
  const wrote = await w.write({ API_KEY: 'fake-ada' });
  assert.equal(wrote.status, 401, JSON.stringify(wrote.body));
  // The vault refused it, on the Viewer's rows, with a ticket: what kept it from the log is the app's check.
  assert.deepEqual(served(w.answers), ['refused']);
  assert.deepEqual(await run(db.owner, sql`SELECT number FROM log_changes WHERE payload LIKE '%"op":"write.refused"%'`), []);
  assert.deepEqual(await keyRow('API_KEY'), before);
});

test('a change that names a read goes only in a transaction that held it: `app_change_strict` refuses it otherwise', async () => {
  const w = await world();
  const answer = await w.runtime.vault.writeKeys!({
    tokenHash: createHash('sha256').update('nobody').digest('base64'), accepts: acceptance(w.runtime), project: 'market', environment: 'dev',
    keys: [{ name: 'API_KEY', id: randomUUID(), versionId: randomUUID(), key: randomBytes(32).toString('base64') }],
  });
  // No credential of that token: nothing served.
  assert.deepEqual(answer, { served: false, why: 'credential' });
  // The first answer of a write of Ada's, its hold left out: refused at its change.
  w.between(async () => {});
  await w.write({ HELD: 'fake-ada' });
  const decided = w.answers.at(-1)!;
  assert.ok(decided.served);
  await assert.rejects(
    db.runtime.transaction(async (tx) => {
      await laterChanges(tx, decided.changes);
      await tx.execute(sql`SELECT 1`);
    }),
    (error: unknown) => /names a read its transaction did not hold/.test(String((error as { message?: string }).message ?? error) + String((error as { cause?: unknown }).cause ?? '')),
  );
});

test("the read moves with every part a key write's decision weighs, its numbers too: what each adversary of Writing.tla changes changes its digest (ReadHeld, ReadByNumber)", async () => {
  const w = await world();
  const [ada] = await db.owner.select({ tokenHash: credentials.tokenHash }).from(credentials).where(eq(credentials.id, w.ada.id));
  const read = async (keys: readonly string[] = ['API_KEY', 'NEW_KEY']) => {
    const [row] = await run(db.owner, sql`SELECT encode(sha256(convert_to(write_inputs(${ada!.tokenHash}::bytea, 'market', 'dev', ${sql.param([...keys])}::text[]), 'UTF8')), 'hex') AS digest`) as { digest: string }[];
    return row!.digest;
  };
  const moves: [string, () => Promise<unknown>][] = [
    ['the key written', () => w.root.secrets.set('market/dev', { API_KEY: 'fake-1' })],
    ['a key appearing', () => w.root.secrets.set('market/dev', { NEW_KEY: 'fake-2' })],
    ['a grant taken and given back', async () => {
      await w.root.access.set(`user:${ADA}`, { 'market/dev': null });
      await w.root.access.set(`user:${ADA}`, { 'market/dev': 'developer' });
    }],
    ['the key renamed', () => w.root.secrets.rename('market/dev/API_KEY', 'RENAMED')],
    ['the environment protected', () => w.root.environments.protect('market/dev')],
    ['her session revoked', () => w.signOut()],
  ];
  let digest = await read();
  // Read again with nothing moved, the same bytes: the hold of a write nothing raced passes.
  assert.equal(await read(), digest);
  for (const [what, move] of moves) {
    await move();
    const now = await read();
    assert.notEqual(now, digest, what);
    digest = now;
  }
});

// Today's path, after the vault's call (T179 PR 3's fallback; formal/Writing.tla, WToday): what the vault's call left
// behind, and what the request then answers, against a vault that serves no `writeKeys` at all.

/** What a request added: the 0.14 entries (author, action, decision), oldest first, and the 0.15 changes, by object. */
async function since<T>(work: () => Promise<T>): Promise<{ result: T; entries: string[]; changes: number; wraps: { seq: string; operation: string | null }[] }> {
  const [{ seq }] = await run(db.owner, sql`SELECT coalesce(max(seq), 0)::text AS seq FROM audit_log`) as { seq: string }[];
  const [{ number }] = await run(db.owner, sql`SELECT coalesce(max(number), 0)::text AS number FROM log_changes`) as { number: string }[];
  const result = await work();
  const entries = await run(db.owner, sql`SELECT author, action, decision FROM audit_log WHERE seq > ${seq} ORDER BY seq`) as { author: string; action: string; decision: string }[];
  const [{ changes }] = await run(db.owner, sql`SELECT count(*)::int AS changes FROM log_changes WHERE number > ${number}`) as { changes: number }[];
  const wraps = await run(db.owner, sql`SELECT seq::text AS seq, operation_id AS operation FROM audit_log WHERE seq > ${seq} AND author = 'vault' AND action = 'key.wrap' ORDER BY audit_log.seq`) as { seq: string; operation: string | null }[];
  return { result, entries: entries.map((entry) => `${entry.author} ${entry.action} ${entry.decision}`), changes: Number(changes), wraps };
}

/** The same write, made once with the two-trip path and once without, on the same instance made the same way. */
async function bothWays(arrange: (w: Awaited<ReturnType<typeof world>>) => Promise<void>) {
  const attempt = async (fast: boolean) => {
    const w = await world({ fast });
    await arrange(w);
    const made = await since(() => w.write({ API_KEY: 'fake-ada' }));
    return { ...made, answers: served(w.answers), verified: (await w.root.audit.verify()).ok };
  };
  return { fast: await attempt(true), today: await attempt(false) };
}

test("a refusal the vault's read finds (a forged change's MAC, a row its newest change does not seal, a row its 0.4 MAC does not cover) is answered as today's path answers it, status and body, and the vault's call adds nothing to either log (T190; StaleFirst)", async () => {
  const cases: [string, string, (w: Awaited<ReturnType<typeof world>>) => Promise<void>][] = [
    ["Ada's grant taken, her rows put back and the revoke's seal forged (WritingForge)", 'tampered', async (w) => {
      const [member] = await db.owner.select().from(principals).where(eq(principals.principal, `user:${ADA}`));
      const held = await db.owner.select().from(grants).where(eq(grants.principal, `user:${ADA}`));
      await w.root.access.set(`user:${ADA}`, { 'market/dev': null });
      await db.owner.delete(grants).where(eq(grants.principal, `user:${ADA}`));
      await db.owner.insert(grants).values(held);
      await db.owner.update(principals).set(member!).where(eq(principals.principal, `user:${ADA}`));
      await run(db.owner, sql`UPDATE log_changes SET seal = ${member!.seal} WHERE number = (SELECT max(number) FROM log_changes WHERE object = ${logObject('principal', `user:${ADA}`)})`);
    }],
    ["Ada's grant taken and her rows put back, the log left as it is (StaleFirst)", 'stale', async (w) => {
      const [member] = await db.owner.select().from(principals).where(eq(principals.principal, `user:${ADA}`));
      const held = await db.owner.select().from(grants).where(eq(grants.principal, `user:${ADA}`));
      await w.root.access.set(`user:${ADA}`, { 'market/dev': null });
      await db.owner.delete(grants).where(eq(grants.principal, `user:${ADA}`));
      await db.owner.insert(grants).values(held);
      await db.owner.update(principals).set(member!).where(eq(principals.principal, `user:${ADA}`));
    }],
    // A column only the row's 0.4 MAC covers, which today's path checks first (`#integrity`; review r1 of #474).
    ["Ada's member row edited in its `created_by` alone", 'tampered', async () => {
      await db.owner.update(principals).set({ createdBy: 'user:someone@acme.example' }).where(eq(principals.principal, `user:${ADA}`));
    }],
    ['API_KEY written again, then its row put back to its first version (StaleFirst)', 'stale', async (w) => {
      const [first] = await db.owner.select().from(secrets).where(eq(secrets.key, 'API_KEY'));
      await w.root.secrets.set('market/dev', { API_KEY: 'fake-root' });
      await db.owner.update(secrets).set(first!).where(eq(secrets.id, first!.id));
    }],
  ];
  for (const [what, why, arrange] of cases) {
    const { fast, today } = await bothWays(arrange);
    assert.deepEqual(fast.answers, [why], what);
    assert.notEqual(fast.result.status, 200, what);
    // The same answer, the same entries, the same changes: the vault's unserved call wrote nothing (the number its
    // statement drew from `log_number` is a gap, which the checkpoints seal past, as a rolled-back change's).
    assert.deepEqual({ status: fast.result.status, body: fast.result.body }, { status: today.result.status, body: today.result.body }, what);
    assert.deepEqual(fast.entries, today.entries, what);
    assert.equal(fast.changes, today.changes, what);
    assert.equal(fast.verified, today.verified, what);
  }
});

test("Ada's session revoked before her write: 401, as today's path answers it, and never sent down that path (ended)", async () => {
  const { fast, today } = await bothWays(async (w) => w.signOut());
  assert.deepEqual(fast.answers, ['ended']);
  assert.deepEqual({ status: fast.result.status, body: fast.result.body }, { status: today.result.status, body: today.result.body });
  assert.equal(fast.result.status, 401);
  assert.deepEqual(fast.entries, today.entries);
});

test("a try the vault served, abandoned at its hold, then refused; Ada's grant given back and her session revoked after: the refusal is recorded and answered, and nothing goes down today's path to write (WritingCaller, TodayCallerStandsAtDecision, closed for refusals by PR 6; review r2 of #469)", async () => {
  // Before PR 6 the refusal went down today's path, which went on with the caller the first try checked and wrote,
  // her session revoked since. Now the refusal ends the request.
  const w = await world();
  const before = (await keyRow('API_KEY'))!;
  w.between(async () => {
    await w.root.access.set(`user:${ADA}`, { 'market/dev': null });
    w.between(async () => {
      await w.root.access.set(`user:${ADA}`, { 'market/dev': 'developer' });
      await w.signOut();
    });
  });
  const made = await since(() => w.write({ API_KEY: 'fake-ada' }));
  assert.deepEqual(served(w.answers), ['served', 'refused']);
  assert.equal(made.result.status, 403, JSON.stringify(made.result.body));
  assert.deepEqual(await keyRow('API_KEY'), before);
  // Its record, in place of today's deny entry: the grant's taking and giving back, and the sign-out, are the rest.
  assert.ok(!made.entries.some((entry) => entry.endsWith(' deny')), made.entries.join(', '));
});

test("a try the vault served, abandoned at its hold, then not served (the key made a reference), Ada's session revoked before today's path: it writes, for the caller the first try checked (WritingCallerShape, TodayCallerStandsAtDecision, an expected gap; review r2 of #469)", async () => {
  // Pinned as it is, not as it should be: today's path goes on with the caller the request authenticated, and its
  // wrap weighs her grant, not her session, as today's front door has always done between its check and its wrap.
  // Here the window spans the tries before it. What the two-trip path does not serve keeps it (PR 3b, PR 7).
  const w = await world();
  await w.root.environments.create('market/prod');
  await w.root.secrets.set('market/prod', { SOURCE: 'fake-source' });
  w.between(async () => {
    await w.root.secrets.set('market/dev', { API_KEY: { ref: 'market/prod/SOURCE' } });
    // After the next try's read, which finds the key a reference: before today's path.
    w.between(async () => w.signOut());
  });
  const wrote = await w.write({ API_KEY: 'fake-ada' });
  assert.deepEqual(served(w.answers), ['served', 'shape']);
  assert.equal(wrote.status, 200, JSON.stringify(wrote.body));
  const row = (await keyRow('API_KEY'))!;
  assert.equal(row.currentVersion, 2);
  assert.equal((await versionOf(row.currentVersionId))?.createdBy, ADA);
  const [session] = await db.owner.select({ revokedAt: credentials.revokedAt }).from(credentials).where(eq(credentials.id, w.ada.id));
  assert.notEqual(session?.revokedAt, null, 'her session was revoked before the write committed');
});

test("Developers' write taken away between today's wrap and its commit: 409 `policy_changed`, nothing written, as `audited` holds the commit to the policy the caller was loaded with (WritingFallBack, TodayPolicyHeld; review r3 of #469)", async () => {
  const w = await world({ fast: false });
  w.afterWrap(async () => {
    await w.root.roles.set('developer', { name: 'Developer', description: 'Read and use secrets.', permissions: ['secret.read', 'secret.use'], protected: ['secret.use'] });
  });
  const wrote = await w.write({ API_KEY: 'fake-ada' });
  assert.equal(wrote.status, 409, JSON.stringify(wrote.body));
  assert.equal(wrote.body.reason ?? (wrote.body.error as { reason?: string } | undefined)?.reason, 'policy_changed', JSON.stringify(wrote.body));
  assert.equal((await keyRow('API_KEY'))!.currentVersion, 1);
});

test("a try the vault served, abandoned at its hold, then refused StaleFirst: today's path refuses it as it would have alone, and the abandoned try leaves no entry in either log (WToday)", async () => {
  /** API_KEY written again, and a way to put its row back to its first version, as a database writer would. */
  const rewritten = async (w: Awaited<ReturnType<typeof world>>) => {
    const [first] = await db.owner.select().from(secrets).where(eq(secrets.key, 'API_KEY'));
    await w.root.secrets.set('market/dev', { API_KEY: 'fake-root' });
    return async () => void (await db.owner.update(secrets).set(first!).where(eq(secrets.id, first!.id)));
  };
  const w = await world();
  // Between the first try's read and its hold.
  w.between(await rewritten(w));
  const made = await since(() => w.write({ API_KEY: 'fake-ada' }));
  assert.deepEqual(served(w.answers), ['served', 'stale']);
  // Today's path alone, the row put back before the write.
  const t = await world({ fast: false });
  await (await rewritten(t))();
  const today = await since(() => t.write({ API_KEY: 'fake-ada' }));
  assert.notEqual(today.result.status, 200);
  assert.deepEqual({ status: made.result.status, body: made.result.body }, { status: today.result.status, body: today.result.body });
  // Exactly what today's path logs: the abandoned try appended nothing (0.16.0), and made no change in 0.15's log.
  assert.deepEqual(made.entries, today.entries);
  assert.equal(made.changes, today.changes);
  assert.ok(w.answers[0]!.served);
});

test("a try the vault served, abandoned at its hold, then not served (the key made a reference meanwhile): today's path writes it once, and its write names its own wrap, not the abandoned try's (WToday, OneWritePerRequest)", async () => {
  const w = await world();
  await w.root.environments.create('market/prod');
  await w.root.secrets.set('market/prod', { SOURCE: 'fake-source' });
  w.between(async () => void (await w.root.secrets.set('market/dev', { API_KEY: { ref: 'market/prod/SOURCE' } })));
  const made = await since(() => w.write({ API_KEY: 'fake-ada' }));
  assert.equal(made.result.status, 200, JSON.stringify(made.result.body));
  assert.deepEqual(served(w.answers), ['served', 'shape']);
  const answer = w.answers[0]!;
  assert.ok(answer.served);
  const row = (await keyRow('API_KEY'))!;
  assert.equal((await versionOf(row.currentVersionId))?.createdBy, ADA);
  // One write of Ada's, one change of hers for the key, its entry naming a wrap of its own operation.
  const writes = await run(db.owner, sql`SELECT related_seq::text AS related, operation_id AS operation FROM audit_log WHERE action = 'secret.write' AND decision = 'allow' AND actor = ${`user:${ADA}`}`) as { related: string; operation: string }[];
  assert.equal(writes.length, 1);
  const changes = async (id: string) => (await run(db.owner, sql`SELECT payload FROM log_changes WHERE object = ${logObject('secret', id)} AND actor = ${`user:${ADA}`} ORDER BY number`) as { payload: string }[])
    .map(({ payload }) => (JSON.parse(payload) as { op: string }).op);
  const mine = await changes(row.id);
  const verified = (await w.root.audit.verify()).ok;
  // As today's path alone writes over a reference: the same changes, none of the abandoned try's.
  const t = await world({ fast: false });
  await t.root.environments.create('market/prod');
  await t.root.secrets.set('market/prod', { SOURCE: 'fake-source' });
  await t.root.secrets.set('market/dev', { API_KEY: { ref: 'market/prod/SOURCE' } });
  const today = await since(() => t.write({ API_KEY: 'fake-ada' }));
  assert.equal(today.result.status, 200);
  assert.deepEqual(mine, await changes((await keyRow('API_KEY'))!.id));
  // The Owner's reference made between the first try and its hold, then exactly what today's path logs: the abandoned
  // try appended nothing (0.16.0), so the one wrap is today's path's own, which its write names.
  assert.deepEqual(made.entries, ['vault reference.create allow', 'app secret.reference allow', ...today.entries]);
  assert.equal(made.wraps.length, 1);
  assert.equal(made.wraps[0]!.seq, writes[0]!.related);
  assert.equal(made.wraps[0]!.operation, writes[0]!.operation);
  assert.equal(verified, true);
});

test("a key write down the two-trip path, recorded in 0.15's log alone, is listed where 0.14's `secret.write` stood: the whole log, its project's, environment's and key's pages, Ada's, a reader of its environment's; none of another place's, another member's or the refusals' (T179, 0.16.0)", async () => {
  const w = await world();
  await w.root.environments.create('market/prod');
  const wrote = await w.write({ API_KEY: 'fake-new' });
  assert.equal(wrote.status, 200, JSON.stringify(wrote.body));
  assert.deepEqual(served(w.answers), ['served']);
  type Client = ReturnType<typeof clientFor>;
  const written = async (client: Client, query: Record<string, string | undefined>) => (await client.audit.list({ limit: 50, ...query })).entries.filter((entry) => entry.action === 'secret.write');
  for (const query of [{}, { path: 'market' }, { path: 'market/dev' }, { path: 'market/dev/API_KEY' }, { actor: `user:${ADA}` }, { actor: ADA }, { path: 'market/dev', actor: ADA }]) {
    const shown = await written(w.root, query);
    const fast = shown.filter((entry) => entry.log === '0.15');
    assert.equal(fast.length, 1, JSON.stringify(query));
    const [entry] = fast;
    assert.deepEqual(
      { actor: entry!.actorId, project: entry!.project, environment: entry!.environment, key: entry!.key, version: entry!.version, author: entry!.author, forged: entry!.forged, detail: entry!.detail },
      { actor: ADA, project: 'market', environment: 'dev', key: 'API_KEY', version: 2, author: 'vault', forged: undefined, detail: false },
      JSON.stringify(query),
    );
    assert.match(String(entry!.operationId), /^[0-9a-f-]{36}$/);
    assert.match(String(entry!.requestId), /^[0-9a-f-]{36}$/);
    // Ada's session, which 0.14's entry never named (only a run's credential or a personal token's): nor does this.
    assert.deepEqual([entry!.metadata.credentialId, entry!.token, entry!.run], [undefined, null, null], JSON.stringify(query));
    // No 0.14 entry of it: of the key's two versions, 0.14's log holds the root's first alone, down today's path.
    assert.deepEqual(shown.filter((one) => one.log === '0.14').map((one) => one.version), 'actor' in query ? [] : [1], JSON.stringify(query));
  }
  for (const query of [{ path: 'market/prod' }, { actor: ROOT }, { decision: 'deny' }]) {
    assert.deepEqual((await written(w.root, query)).filter((entry) => entry.log === '0.15'), [], JSON.stringify(query));
  }
  // A reader of market/dev alone (an auditor there) reads it, on the whole log and the project's page; of prod alone, not.
  const bob = 'bob@acme.example';
  await w.root.members.add(`user:${bob}`);
  await w.root.access.set(`user:${bob}`, { 'market/dev': 'auditor' });
  const reader = clientFor(w.deps, bob);
  for (const query of [{}, { path: 'market' }, { path: 'market/dev' }]) assert.equal((await written(reader, query)).filter((entry) => entry.log === '0.15').length, 1, JSON.stringify(query));
  await w.root.access.set(`user:${bob}`, { 'market/dev': null, 'market/prod': 'auditor' });
  for (const query of [{}, { path: 'market' }]) assert.deepEqual((await written(reader, query)).filter((entry) => entry.log === '0.15'), [], JSON.stringify(query));
  // The offboarding report names the value she wrote, still current, as one to rotate.
  assert.deepEqual((await w.root.members.get(`user:${ADA}`)).exposed.map(({ key, version, how }) => `${key} v${version} ${how}`), ['API_KEY v2 wrote']);
  // Read again later: the report names when she last saw it, the read, though the write is listed after it (review r2 of #490).
  const [{ at: wroteAt }] = await rowsOf<{ at: string | number }>(db.owner, sql`SELECT at FROM log_changes WHERE payload LIKE ${'{"digest":%"inputs":"%'} AND actor = ${`user:${ADA}`}`);
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.equal((await clientFor(w.deps, ADA).secrets.reveal('market/dev/API_KEY')).values.API_KEY, 'fake-new');
  const [seen] = (await w.root.members.get(`user:${ADA}`)).exposed;
  assert.deepEqual([seen?.how, Date.parse(seen!.at) > Number(wroteAt)], ['wrote', true], JSON.stringify({ seen, wroteAt }));
  // Its row of the projection edited around coffre is listed marked: the vault does not vouch for it.
  await run(db.owner, sql`UPDATE audit_events SET actor = ${`user:${ROOT}`} WHERE log = 15 AND action = 'secret.write'`);
  const [edited] = (await written(w.root, { path: 'market/dev/API_KEY' })).filter((entry) => entry.log === '0.15');
  assert.deepEqual([edited?.actorId, edited?.forged], [ROOT, true]);
});

test("Ada a Viewer of market/dev, her write refused on the vault's read: answered as today's path answers it, status and body; the vault's record of it in place of today's deny entry, sealed, in two round trips, and nothing else in either log (PR 6)", async () => {
  const { fast, today } = await bothWays(async (w) => void (await w.root.access.set(`user:${ADA}`, { 'market/dev': 'viewer' })));
  assert.deepEqual(fast.answers, ['refused']);
  assert.equal(fast.result.status, 403, JSON.stringify(fast.result.body));
  assert.deepEqual({ status: fast.result.status, body: fast.result.body }, { status: today.result.status, body: today.result.body });
  // Today's path's one deny entry, the app's; the vault's record in its place.
  assert.deepEqual(today.entries.slice(-1), ['app secret.write deny']);
  assert.deepEqual(fast.entries, today.entries.slice(0, -1));
  assert.equal(fast.changes, today.changes + 1);
  assert.equal(fast.verified, true);
});

/** A refusal's record, as the vault wrote it: its row, its payload parsed. */
async function refusalRecords(): Promise<{ number: string; requestId: string; object: string; actor: string; payload: Record<string, unknown>; mac: Buffer }[]> {
  const rows = await run(db.owner, sql`SELECT number::text AS number, request_id, object::text AS object, actor, payload, mac FROM log_changes WHERE strpos(payload, '"op":"write.refused"') > 0 ORDER BY log_changes.number`) as
    { number: string; request_id: string; object: string; actor: string; payload: string; mac: Uint8Array }[];
  return rows.map((row) => ({ number: row.number, requestId: row.request_id, object: row.object, actor: row.actor, payload: JSON.parse(row.payload) as Record<string, unknown>, mac: Buffer.from(row.mac) }));
}

test("a refused write leaves every reader of the log as it was (the lead's condition on PR 6): Ada's use and the Owner's, the key's history, the member pages, the list of everyone, the log's verification; only the audit pages list it, where 0.14's deny entry stood (PR 6)", async () => {
  const w = await world();
  await w.root.access.set(`user:${ADA}`, { 'market/dev': 'viewer' });
  await w.root.environments.create('market/prod');
  const ada = w.client();
  // Everything a reader of 0.15's log answers, by the same calls before and after the refusal.
  // A use's answer but its operation's id, each its own.
  const used = ({ operationId: _, ...answer }: { operationId?: string }) => answer;
  // Ada's report but how far the log is listed, which the projector moves on with every read listed, and when she last
  // read each key: her reveal in `readers` is logged anew, at its own time, once the key's bulk period has turned.
  const report = (member: Awaited<ReturnType<typeof w.root.members.get>>) => ({ ...member, reads: undefined, exposed: member.exposed.map(({ at: _, ...read }) => read) });
  const readers = async () => ({
    adaUse: used(await ada.secrets.reveal('market/dev', ['API_KEY'])),
    rootUse: used(await w.root.secrets.reveal('market/dev', ['API_KEY'])),
    list: await ada.secrets.list('market/dev'),
    history: await w.root.secrets.history('market/dev/API_KEY'),
    member: report(await w.root.members.get(`user:${ADA}`)),
    access: await w.root.members.access(`user:${ADA}`),
    everyone: await w.root.members.list(),
    verified: (await w.root.audit.verify()).ok,
  });
  const audit = async (query: Parameters<typeof w.root.audit.list>[0] = {}) => (await w.root.audit.list({ ...query })).entries
    .map((entry) => `${entry.action} ${entry.decision} ${entry.actorId} ${entry.project ?? '-'}/${entry.environment ?? '-'} ${entry.reason ?? '-'}`);
  const before = await readers();
  const pages = { all: await audit(), dev: await audit({ path: 'market/dev' }), prod: await audit({ path: 'market/prod' }), ada: await audit({ actor: ADA }), deny: await audit({ decision: 'deny' }), allow: await audit({ decision: 'allow' }) };
  const uses = async () => (await run(db.owner, sql`SELECT count(*)::int AS n FROM log_uses`))[0];
  const usesBefore = await uses();
  const wrote = await w.write({ API_KEY: 'fake-ada' });
  // A refused write logs no use, for anyone.
  assert.deepEqual(await uses(), usesBefore);
  assert.equal(wrote.status, 403, JSON.stringify(wrote.body));
  assert.deepEqual(served(w.answers), ['refused']);
  // Listed where 0.14's deny entry would be, and nowhere else: the whole log, market/dev's page, Ada's, the deny ones.
  const record = `secret.write deny ${ADA} market/dev no_grant`;
  assert.deepEqual(await audit(), [record, ...pages.all]);
  assert.deepEqual(await audit({ path: 'market/dev' }), [record, ...pages.dev]);
  assert.deepEqual(await audit({ actor: ADA }), [record, ...pages.ada]);
  assert.deepEqual(await audit({ decision: 'deny' }), [record, ...pages.deny]);
  assert.deepEqual(await audit({ path: 'market/prod' }), pages.prod);
  assert.deepEqual(await audit({ decision: 'allow' }), pages.allow);
  // Every other reader as it was (the Owner's reveal above logs a read of its own: after the pages).
  assert.deepEqual(await readers(), before);
  // A reader of market/dev alone (an auditor there) reads it, on the whole log and the place's page; of prod alone, not.
  const bob = 'bob@acme.example';
  await w.root.members.add(`user:${bob}`);
  await w.root.access.set(`user:${bob}`, { 'market/dev': 'auditor' });
  const reader = clientFor(w.deps, bob);
  const refusals = async (query: Parameters<typeof reader.audit.list>[0]) => (await reader.audit.list({ decision: 'deny', ...query })).entries.filter((entry) => entry.log === '0.15');
  for (const query of [{}, { path: 'market' }, { path: 'market/dev' }]) assert.equal((await refusals(query)).length, 1, JSON.stringify(query));
  await w.root.access.set(`user:${bob}`, { 'market/dev': null, 'market/prod': 'auditor' });
  for (const query of [{}, { path: 'market' }]) assert.deepEqual(await refusals(query), [], JSON.stringify(query));
  // The record: a change of nothing, its object its request's own, MAC'd by the vault, sealed.
  const [only, ...others] = await refusalRecords();
  assert.equal(others.length, 0);
  assert.equal(only!.object, logObject('request', only!.requestId));
  assert.deepEqual((only!.payload.ref as Record<string, unknown>), { id: only!.requestId, kind: 'request' });
  assert.equal(only!.actor, `user:${ADA}`);
  assert.equal(only!.payload.credential, w.ada.id);
  assert.deepEqual(only!.payload.keys, ['API_KEY']);
  // Its credential's id, as a two-trip change's, not shown for a session (Fable's review of #490).
  const [shown] = (await w.root.audit.list({ decision: 'deny' })).entries;
  assert.equal(shown!.metadata.credentialId, undefined);
  // (Sealed into the trees by a checkpointer and replayed: the test of that, below.)
});

test("a refused key write whose record committed but whose seal did not come in time: 503, in words that say no change was made, never a change's; the key as it was, and no 0.14 entry (review r2 of PR 6)", async () => {
  const sealing = stallingSeal();
  const w = await world({ sealer: async () => ({ sealThrough: sealing.sealThrough, heldOutside: nothingHeld }) });
  await w.root.access.set(`user:${ADA}`, { 'market/dev': 'viewer' });
  const before = await keyRow('API_KEY');
  sealing.stalled = true;
  const made = await since(() => w.write({ API_KEY: 'fake-ada' }));
  assert.equal(made.result.status, 503, JSON.stringify(made.result.body));
  assert.deepEqual(made.result.body, { error: 'unavailable', message: REFUSAL_UNSEALED_MESSAGE });
  assert.deepEqual(served(w.answers), ['refused']);
  assert.deepEqual(await keyRow('API_KEY'), before);
  // The record written, which the next checkpointer seals; no deny entry beside it.
  assert.deepEqual(made.entries, []);
  assert.deepEqual((await refusalRecords()).map((each) => each.payload.op), ['write.refused']);
  // Sealing again, the same write is refused as before, 403.
  sealing.stalled = false;
  assert.equal((await w.write({ API_KEY: 'fake-ada' })).status, 403);
});

test("a key write the router let through, refused on a later try's read, its ticket expired before its record: today's 0.14 deny entry, naming the write's operation as today's wrap refusal does, and no record (Fable's review of PR 6)", async () => {
  // The router's check passes on the first try's answer; the grant taken at its hold, the second try's read refuses.
  const w = await world();
  w.between(async () => void (await w.root.access.set(`user:${ADA}`, { 'market/dev': null })));
  const { seq } = (await run(db.owner, sql`SELECT coalesce(max(seq), 0)::text AS seq FROM audit_log`) as { seq: string }[])[0]!;
  // The vault finds the ticket expired: nothing recorded, and the app appends the entry it stands for.
  w.deps.vault.recordRefusal = async () => ({ recorded: false, why: 'expired' });
  assert.equal((await w.write({ API_KEY: 'fake-ada' })).status, 403);
  assert.deepEqual(served(w.answers), ['served', 'refused']);
  const denies = await run(db.owner, sql`SELECT operation_id AS operation FROM audit_log WHERE seq > ${seq} AND action = 'secret.write' AND decision = 'deny'`) as { operation: string | null }[];
  assert.equal(denies.length, 1);
  assert.match(String(denies[0]!.operation), /^[0-9a-f-]{36}$/);
  assert.deepEqual(await refusalRecords(), []);
});

test("two retries of one refusal's ticket at once, both finding no record: the second's insert waits for the first's, and both answer its number, one record written, never a duplicate key (review r1 of PR 6)", async () => {
  const w = await world();
  await w.root.access.set(`user:${ADA}`, { 'market/dev': 'viewer' });
  assert.equal((await w.write({ API_KEY: 'fake-ada' })).status, 403);
  const answer = w.answers.at(-1)!;
  assert.ok(!answer.served && answer.why === 'refused' && 'ticket' in answer, JSON.stringify(answer));
  const { ticket } = answer as VaultRefused;
  const [record] = await refusalRecords();
  // The record taken out, then put back by a transaction left open: both retries look, find none, and meet it at their
  // insert, which waits for that transaction. Committed, it is the record both find (the first, as their race leaves it).
  const [row] = await run(db.owner, sql`DELETE FROM log_changes WHERE number = ${record!.number}::bigint RETURNING number, at, request_id, object, actor, payload, seal, mac`) as Record<string, unknown>[];
  let release!: () => void;
  const released = new Promise<void>((resolve) => { release = resolve; });
  let inserted!: () => void;
  const putBack = new Promise<void>((resolve) => { inserted = resolve; });
  const holding = db.owner.transaction(async (tx) => {
    await run(tx, sql`INSERT INTO log_changes (number, at, request_id, object, actor, payload, seal, mac)
      VALUES (${row!.number}, ${row!.at}, ${row!.request_id}, ${row!.object}, ${row!.actor}, ${row!.payload}, ${row!.seal}, ${row!.mac})`);
    inserted();
    await released;
  });
  await putBack;
  const recordRefusal = w.deps.vault.recordRefusal!.bind(w.deps.vault);
  const retries = Promise.all([recordRefusal({ ticket }), recordRefusal({ ticket })]);
  const waiting = async () => Number((await run(db.owner, sql`SELECT count(*)::int AS n FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid
    WHERE NOT l.granted AND l.locktype = 'transactionid' AND a.datname = current_database()`) as { n: number }[])[0]!.n);
  // Released however the wait ends, and both settled: a failed wait must not leave the row's transaction open (review r2).
  try {
    for (let tries = 0; (await waiting()) < 2; tries += 1) {
      assert.ok(tries < 500, 'both retries wait at their insert');
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
  } finally {
    release();
    await Promise.allSettled([holding, retries]);
  }
  await holding;
  assert.deepEqual(await retries, [{ recorded: true, number: record!.number }, { recorded: true, number: record!.number }]);
  // And once committed, a retry after them finds it first.
  assert.deepEqual(await recordRefusal({ ticket }), { recorded: true, number: record!.number });
  assert.deepEqual((await refusalRecords()).map((each) => each.number), [record!.number]);
});

test("a refusal's record copied to another object, by a database writer, Ada's row put back to match: its MAC is over its own object, so the vault refuses the member it now stands for, and nothing is written; copied whole under another request id, no audit page lists it (WritingRefuse)", async () => {
  const w = await world();
  // Ada refused once (no grant at market/dev): the record to copy.
  const [member] = await db.owner.select().from(principals).where(eq(principals.principal, `user:${ADA}`));
  const held = await db.owner.select().from(grants).where(eq(grants.principal, `user:${ADA}`));
  await w.root.access.set(`user:${ADA}`, { 'market/dev': null });
  assert.equal((await w.write({ API_KEY: 'fake-ada' })).status, 403);
  const [record] = await refusalRecords();
  const denied = async () => (await w.root.audit.list({ decision: 'deny' })).entries.filter((entry) => entry.log === '0.15').map((entry) => entry.forged === true);
  assert.deepEqual(await denied(), [false]);
  // The writer puts her grant back, her row as it was, and copies the record as her member's newest change, its seal
  // column her row's: row and log agree, and only the record's MAC, over the request's object, says otherwise.
  await db.owner.delete(grants).where(eq(grants.principal, `user:${ADA}`));
  await db.owner.insert(grants).values(held);
  await db.owner.update(principals).set(member!).where(eq(principals.principal, `user:${ADA}`));
  await run(db.owner, sql`INSERT INTO log_changes (number, at, request_id, object, actor, payload, seal, mac)
    SELECT nextval('log_number'), c.at, ${randomUUID()}, ${logObject('principal', `user:${ADA}`)}::uuid, c.actor, c.payload, ${member!.seal}, c.mac
      FROM log_changes c WHERE c.number = ${record!.number}::bigint`);
  const before = (await keyRow('API_KEY'))!;
  const wrote = await w.write({ API_KEY: 'fake-ada-2' });
  assert.notEqual(wrote.status, 200, JSON.stringify(wrote.body));
  assert.deepEqual(served(w.answers).slice(-1), ['tampered']);
  assert.deepEqual(await keyRow('API_KEY'), before);
  // Copied whole under a request id of its own (its own object then names another request): its MAC covers both.
  await run(db.owner, sql`INSERT INTO log_changes (number, at, request_id, object, actor, payload, seal, mac)
    SELECT nextval('log_number'), c.at, ${randomUUID()}, c.object, c.actor, c.payload, c.seal, c.mac FROM log_changes c WHERE c.number = ${record!.number}::bigint`);
  // Neither copy is listed: the projector lists what the vault signed, and it signs no change its MAC refuses.
  assert.deepEqual(await denied(), [false]);
});

test("a refusal's record sealed by the checkpointer before it answers, as a change is (D165): the trees verify with it among them, and the log replays with no fault, every use decided as before (PR 6)", async () => {
  const scratch = mkdtempSync(join(tmpdir(), 'coffre-refusals-'));
  const running: RunningCheckpointer[] = [];
  try {
    const w = await world({
      sealer: async (signingKey) => {
        const checkpointer = await runCheckpointer({ database: await openVaultDatabase(), signingKeys: [signingKey], memory: join(scratch, 'memory'), intervalMs: 60_000 });
        running.push(checkpointer);
        return checkpointer;
      },
    });
    await w.root.access.set(`user:${ADA}`, { 'market/dev': 'viewer' });
    await w.client().secrets.reveal('market/dev', ['API_KEY']);
    const replayed = await replayStored(db.owner, [w.signingKey]);
    const wrote = await w.write({ API_KEY: 'fake-ada' });
    assert.equal(wrote.status, 403, JSON.stringify(wrote.body));
    assert.deepEqual(served(w.answers), ['refused']);
    // Answered once sealed: the newest checkpoint is at or past the record.
    const [record] = await refusalRecords();
    const [{ upto }] = await run(db.owner, sql`SELECT max(upto)::text AS upto FROM log_checkpoints`) as { upto: string }[];
    assert.ok(BigInt(upto) >= BigInt(record!.number), `the record ${record!.number}, the newest checkpoint ${upto}`);
    const trees = await w.root.audit.verifyTrees();
    assert.ok(trees.kept && trees.ok, JSON.stringify(trees));
    // The replay passes over it, as over the log's own changes: no fault, and the use before it decided as it was.
    const again = await replayStored(db.owner, [w.signingKey]);
    assert.deepEqual(again.faults, []);
    assert.deepEqual(again.decided, replayed.decided);
  } finally {
    for (const checkpointer of running) await checkpointer.stop();
    rmSync(scratch, { recursive: true, force: true });
  }
});
