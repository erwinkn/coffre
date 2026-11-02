// A key write in five round trips (T179 PR 3; docs/design/two-trips.md, "A key write"; formal/Writing.tla): the vault
// decides on one read of its own, and the app's transaction holds that read again under the fence before it commits.
// Each adversary of the model's scenarios is made here between the vault's read and the app's hold (`between`), and
// the write commits only as the log stands at its commit: asked again, a request of its own, decided on what moved.
// The tampering ones (a row put back, its newest change's seal forged, a token hash copied onto another's row) are
// made before the write, on both engines: SQLite's writes take today's path, one transaction, and refuse them as well.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';

import { github, signin } from '@coffre/core/identity';
import type { Vault, WriteKeysInput, WriteKeysOutcome } from '@coffre/core/vault';
import { tablesOf, type Queryable } from '@coffre/db';
import { rowsOf } from '@coffre/db/dialect';
import { laterChanges, logObject } from '@coffre/db/log';
import { eq, sql } from 'drizzle-orm';

import { sessionCookieName } from '../src/auth.ts';
import { resolveConfig } from '../src/config.ts';
import { fetchApi } from '../src/fetch-api.ts';
import { acceptance } from '../src/named-use.ts';
import { createRuntime, type CoffreRuntime } from '../src/runtime.ts';
import { clientFor, entryOf, LOG, nothingHeld, openTestDatabase, resetDatabase, sealedNow, testDeps, testVault } from './api-fixture.ts';
import { TEST_ENGINE } from './db/engine.ts';

const ORIGIN = 'https://secrets.acme.example';
const ROOT = 'admin@acme.example';
const ADA = 'ada@acme.example';
const POSTGRES = TEST_ENGINE === 'postgres' && LOG === '0.15' ? false : "the two-trip write is Postgres's, under 0.15's log";
const ANY = LOG === '0.15' ? false : "0.15's log only";

const db = await openTestDatabase();
test.after(async () => {
  await resetDatabase(db.owner);
  await db.close();
});

const run = (on: Queryable, query: ReturnType<typeof sql>) => rowsOf(on, query);

/** A fresh instance: market/dev holding API_KEY, Ada a developer there, and each one's browser session. */
async function world() {
  await resetDatabase(db.owner);
  const kek = randomBytes(32);
  const vault = testVault([ROOT], {}, { kek }, {}, { log: '0.15', sealThrough: sealedNow, heldOutside: nothingHeld });
  const deps = testDeps(db.runtime, [ROOT], { vault });
  const root = clientFor(deps, ROOT);
  await root.projects.create('market', { name: 'Market' });
  await root.environments.create('market/dev');
  await root.secrets.set('market/dev', { API_KEY: 'fake-old' });
  await root.members.add(`user:${ADA}`);
  await root.access.set(`user:${ADA}`, { 'market/dev': 'developer' });
  // Each `writeKeys` answer, and what runs once, right after the next one, before the app's hold.
  const answers: WriteKeysOutcome[] = [];
  let next: (() => Promise<void>) | null = null;
  const hooked = new Proxy(vault, {
    get(target, key) {
      const value: unknown = Reflect.get(target, key, target);
      if (typeof value !== 'function') return value;
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
  /** Ada's PATCH of market/dev, as her browser sends it: its status and body. */
  const write = async (patch: Record<string, unknown>, token = ada.token) => {
    const response = await fetchApi(new Request(`${ORIGIN}/api/secrets/market/dev`, {
      method: 'PATCH',
      headers: { cookie: `${sessionCookieName(runtime.auth)}=${token}`, 'sec-fetch-site': 'same-origin', 'content-type': 'application/json' },
      body: JSON.stringify(patch),
    }), runtime, { sourceIp: null });
    return { status: response.status, body: await response.json() as Record<string, unknown> };
  };
  /** Ada signs her session out, from it, as her browser does. */
  const signOut = async () => {
    const response = await fetchApi(new Request(`${ORIGIN}/api/sessions/${ada.id}`, {
      method: 'DELETE', headers: { cookie: `${sessionCookieName(runtime.auth)}=${ada.token}`, 'sec-fetch-site': 'same-origin' },
    }), runtime, { sourceIp: null });
    assert.ok(response.ok, await response.text());
  };
  return { deps, root, runtime, ada, session, write, signOut, answers, between: (adversary: () => Promise<void>) => void (next = adversary) };
}

const { secrets, secretVersions, vaultMembers, vaultGrants, credentials } = tablesOf(db.owner);

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

const served = (answers: readonly WriteKeysOutcome[]) => answers.map((answer) => (answer.served ? 'served' : answer.why));

test('a key write the vault decided on its read commits in two of the app\'s round trips, its change naming the request and the read it was decided on', { skip: POSTGRES }, async () => {
  const w = await world();
  const wrote = await w.write({ NEW_KEY: 'fake-new', API_KEY: 'fake-again' });
  assert.equal(wrote.status, 200, JSON.stringify(wrote.body));
  assert.deepEqual(served(w.answers), ['served']);
  assert.deepEqual(wrote.body.keys, { NEW_KEY: { version: 1, sensitivity: 'secret' }, API_KEY: { version: 2, sensitivity: 'secret' } });
  const answer = w.answers[0]!;
  assert.ok(answer.served);
  // Each change is the key's newest, its payload naming the request's number, its credential and the read's digest,
  // each under its own request id, derived from the request's number and its object.
  for (const name of ['NEW_KEY', 'API_KEY']) {
    const row = (await keyRow(name))!;
    assert.equal((await versionOf(row.currentVersionId))?.createdBy, `ada@acme.example`);
    const [change] = await run(db.owner, sql`SELECT request_id, payload FROM log_changes WHERE object = ${logObject('secret', row.id)} ORDER BY number DESC LIMIT 1`) as { request_id: string; payload: string }[];
    const payload = JSON.parse(change!.payload) as { request?: { number: string; credential: string; identity: string | null }; inputs?: string };
    assert.deepEqual({ ...payload.request, identity: undefined }, { number: answer.number, credential: w.ada.id, identity: undefined });
    assert.equal(typeof payload.request?.identity, 'string');
    assert.equal(payload.inputs, answer.digest);
  }
  // 0.14's entries, as today's path writes them: the app's `secret.write`, each naming the vault's `key.wrap`.
  const entries = await run(db.owner, sql`SELECT seq, author, action, related_seq FROM audit_log WHERE action IN ('key.wrap', 'secret.write') AND decision = 'allow' ORDER BY seq`) as { seq: string; author: string; action: string; related_seq: string | null }[];
  const wraps = entries.filter((entry) => entry.action === 'key.wrap').slice(-2).map((entry) => String(entry.seq));
  const writes = entries.filter((entry) => entry.action === 'secret.write').slice(-2).map((entry) => String(entry.related_seq));
  assert.deepEqual(writes.sort(), wraps.sort());
});

test("Ada's grant taken between the vault's read and the hold: the hold fails, the write asks again, and the vault's refusal answers, nothing written (WritingRevoke, rev)", { skip: POSTGRES }, async () => {
  const w = await world();
  const before = (await keyRow('API_KEY'))!;
  w.between(async () => void (await w.root.access.set(`user:${ADA}`, { 'market/dev': null })));
  const wrote = await w.write({ API_KEY: 'fake-ada' });
  assert.equal(wrote.status, 403, JSON.stringify(wrote.body));
  // Served, held and failed; then refused, which today's path answers and logs.
  assert.deepEqual(served(w.answers), ['served', 'refused']);
  assert.deepEqual(await keyRow('API_KEY'), before);
});

test("Ada's session revoked between the read and the hold: nothing commits on it (WritingRevoke, end)", { skip: POSTGRES }, async () => {
  const w = await world();
  const before = (await keyRow('API_KEY'))!;
  w.between(w.signOut);
  const wrote = await w.write({ API_KEY: 'fake-ada' });
  assert.equal(wrote.status, 401, JSON.stringify(wrote.body));
  assert.deepEqual(served(w.answers), ['served', 'credential']);
  assert.deepEqual(await keyRow('API_KEY'), before);
});

test("the key Ada writes renamed between the read and the hold: the write lands on the name she wrote, not on the renamed key (WritingNames, ren)", { skip: POSTGRES }, async () => {
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

test('the key Ada makes made meanwhile by another, sensitive: her write asks again and keeps it sensitive (WritingNames, phn)', { skip: POSTGRES }, async () => {
  const w = await world();
  w.between(async () => void (await w.root.secrets.set('market/dev', { NEW_KEY: { value: 'fake-root', sensitivity: 'sensitive' } })));
  const wrote = await w.write({ NEW_KEY: 'fake-ada' });
  assert.equal(wrote.status, 200, JSON.stringify(wrote.body));
  assert.deepEqual(served(w.answers), ['served', 'served']);
  assert.deepEqual(wrote.body.keys, { NEW_KEY: { version: 2, sensitivity: 'sensitive' } });
  const row = (await keyRow('NEW_KEY'))!;
  assert.equal((await versionOf(row.currentVersionId))?.sensitive, true);
});

test('market/dev archived between the read and the hold: nothing commits there (WritingPlace, arc)', { skip: POSTGRES }, async () => {
  const w = await world();
  const before = (await keyRow('API_KEY'))!;
  w.between(async () => void (await w.root.environments.update('market/dev', { archived: true })));
  const wrote = await w.write({ API_KEY: 'fake-ada' });
  assert.notEqual(wrote.status, 200, JSON.stringify(wrote.body));
  assert.deepEqual(served(w.answers), ['served', 'place']);
  assert.deepEqual(await keyRow('API_KEY'), before);
});

test('the key written by another between the read and the hold: both commit, one version each, neither over the other (WritingRevoke, KeyChangesFlip)', { skip: POSTGRES }, async () => {
  const w = await world();
  w.between(async () => void (await w.root.secrets.set('market/dev', { API_KEY: 'fake-root' })));
  const wrote = await w.write({ API_KEY: 'fake-ada' });
  assert.equal(wrote.status, 200, JSON.stringify(wrote.body));
  assert.deepEqual(served(w.answers), ['served', 'served']);
  assert.deepEqual(wrote.body.keys, { API_KEY: { version: 3, sensitivity: 'secret' } });
  const versions = await run(db.owner, sql`SELECT v.version, v.created_by FROM secret_versions v JOIN secrets s ON s.id = v.secret_id WHERE s.key = 'API_KEY' ORDER BY v.version`) as { version: number; created_by: string }[];
  assert.deepEqual(versions.map((row) => [Number(row.version), row.created_by]), [[1, ROOT], [2, ROOT], [3, ADA]]);
});

test("Ada's grant taken and given back between the read and the hold: the same rows, a newer change; the write asks again rather than commit on a read the log no longer shows (WritingABA)", { skip: POSTGRES }, async () => {
  const w = await world();
  w.between(async () => {
    await w.root.access.set(`user:${ADA}`, { 'market/dev': null });
    await w.root.access.set(`user:${ADA}`, { 'market/dev': 'developer' });
  });
  const wrote = await w.write({ API_KEY: 'fake-ada' });
  assert.equal(wrote.status, 200, JSON.stringify(wrote.body));
  assert.deepEqual(served(w.answers), ['served', 'served']);
});

test('a hold that keeps failing gives up after three tries: 409 `changed`, nothing written (EveryRequestEnds)', { skip: POSTGRES }, async () => {
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
  assert.deepEqual(served(w.answers), ['served', 'served', 'served']);
  const after = (await keyRow('API_KEY'))!;
  assert.equal(after.id, before.id);
  assert.equal((await versionOf(after.currentVersionId))?.createdBy, ROOT);
});

test("Ada's grant taken, then her member row and grants put back and the seal written into the revoke's change: the change's MAC fails, and nothing is written (WritingForge, T190)", { skip: ANY }, async () => {
  const w = await world();
  const before = (await keyRow('API_KEY'))!;
  const [member] = await db.owner.select().from(vaultMembers).where(eq(vaultMembers.principal, `user:${ADA}`));
  const grants = await db.owner.select().from(vaultGrants).where(eq(vaultGrants.principal, `user:${ADA}`));
  await w.root.access.set(`user:${ADA}`, { 'market/dev': null });
  // A database writer puts the rows back as they were, and the log's newest change of Ada, the revoke, edited to name
  // the row's seal: row and log agree; only that change's MAC, over its seal, says the vault never wrote it.
  await db.owner.delete(vaultGrants).where(eq(vaultGrants.principal, `user:${ADA}`));
  await db.owner.insert(vaultGrants).values(grants);
  await db.owner.update(vaultMembers).set(member!).where(eq(vaultMembers.principal, `user:${ADA}`));
  await run(db.owner, sql`UPDATE log_changes SET seal = ${member!.seal} WHERE number = (SELECT max(number) FROM log_changes WHERE object = ${logObject('principal', `user:${ADA}`)})`);
  const wrote = await w.write({ API_KEY: 'fake-ada' });
  assert.notEqual(wrote.status, 200, JSON.stringify(wrote.body));
  if (TEST_ENGINE === 'postgres') assert.deepEqual(served(w.answers), ['tampered']);
  assert.deepEqual(await keyRow('API_KEY'), before);
});

// Postgres's: today's path, SQLite's, checks a credential's row by its MAC alone, which the row put back whole still
// carries; only 0.15's log says it was revoked (a gap of today's write path, not of this one's: reported with T179 PR 3).
test("Ada's session revoked and its row put back, live: the vault's read refuses it on the log's newest change, and the write answers 401, never down today's path (WritingTamper, dbw)", { skip: POSTGRES }, async () => {
  const w = await world();
  const before = (await keyRow('API_KEY'))!;
  const [row] = await db.owner.select().from(credentials).where(eq(credentials.id, w.ada.id));
  await w.signOut();
  await db.owner.update(credentials).set(row!).where(eq(credentials.id, w.ada.id));
  const wrote = await w.write({ API_KEY: 'fake-ada' });
  assert.equal(wrote.status, 401, JSON.stringify(wrote.body));
  // Refused on her credential's own log, and never asked down today's path, whose check of the row's MAC alone would take it.
  if (TEST_ENGINE === 'postgres') assert.deepEqual(served(w.answers), ['forged']);
  assert.deepEqual(await keyRow('API_KEY'), before);
});

test("Ada's token hash copied onto the Owner's session: the vault reads the Owner, and the app's check of the row's MAC refuses it before anything commits (WritingTamper, sub; round 6)", { skip: ANY }, async () => {
  const w = await world();
  const before = (await keyRow('API_KEY'))!;
  const owner = await w.session('root', ROOT);
  const [ada] = await db.owner.select({ tokenHash: credentials.tokenHash }).from(credentials).where(eq(credentials.id, w.ada.id));
  await db.owner.update(credentials).set({ tokenHash: randomBytes(32) }).where(eq(credentials.id, w.ada.id));
  await db.owner.update(credentials).set({ tokenHash: ada!.tokenHash }).where(eq(credentials.id, owner.id));
  const wrote = await w.write({ API_KEY: 'fake-ada' });
  assert.equal(wrote.status, 401, JSON.stringify(wrote.body));
  // On Postgres the vault served it, on the Owner's rows: what refused it is the app's check (AuthChecked).
  if (TEST_ENGINE === 'postgres') assert.deepEqual(served(w.answers), ['served']);
  assert.deepEqual(await keyRow('API_KEY'), before);
});

test('a change that names a read goes only in a transaction that held it: `app_change_strict` refuses it otherwise', { skip: POSTGRES }, async () => {
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

test("the read moves with every part a key write's decision weighs, its numbers too: what each adversary of Writing.tla changes changes its digest (ReadHeld, ReadByNumber)", { skip: POSTGRES }, async () => {
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
