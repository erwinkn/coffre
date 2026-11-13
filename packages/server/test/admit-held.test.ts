// A member add in three round trips (docs/design/two-trips.md, "A member add"; formal/Writing.tla, the add):
// the vault decides a first add on one read of its own, the app checks the caller's rows it answered, and the vault's
// write holds that read again under the fence before it commits. Each adversary of the model's add scenarios is made
// here between the vault's read and its write (`between`), and the add commits only as the log stands at its commit:
// asked again, a read of its own, decided on what moved. The tampering ones (a row put back, its newest change's seal
// forged, a token hash copied onto another's row) are made before the add.
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';

import { github, signin } from '@coffre/core/identity';
import type { AdmitReadInput, AdmitReadOutcome, Vault } from '@coffre/core/vault';
import { type Queryable } from '@coffre/db';
import { rowsOf } from '@coffre/db/dialect';
import { lockLogHead, logObject } from '@coffre/db/log';
import { eq, sql } from 'drizzle-orm';

import { sessionCookieName } from '../src/auth.ts';
import { resolveConfig } from '../src/config.ts';
import { missingMembers } from '../src/db/queries.ts';
import { fetchApi } from '../src/fetch-api.ts';
import { createRuntime, type CoffreRuntime } from '../src/runtime.ts';
import { localVault, spoken } from '@coffre/vault/node';

import { REFUSAL_UNSEALED_MESSAGE } from '../src/api/errors.ts';
import { clientFor, entryOf, hotDatabaseUrl, nothingHeld, numbersFrom, openTestDatabase, resetDatabase, sealedNow, stallingSeal, testDeps, testVault } from './api-fixture.ts';
import { openVaultDatabase } from './db/engine.ts';
import { steppedUp } from './passkey-rows.ts';
import { credentials, principals } from '@coffre/db/schema';

const ORIGIN = 'https://secrets.acme.example';
const ROOT = 'admin@acme.example';
const BOB = 'bob@acme.example';
const NEW = 'user:new@acme.example';

const db = await openTestDatabase();
test.after(async () => {
  await resetDatabase(db.owner);
  await db.close();
});

const run = (on: Queryable, query: ReturnType<typeof sql>) => rowsOf(on, query);

/**
 * A fresh instance: projects market and billing, Bob an admin of the whole instance, and his browser session. `fast:
 * false`: a vault that serves no `admitRead`, every add down today's path, to answer as the two-trip path's refusals must.
 */
async function world({ fast = true, past = 0n, sealThrough = sealedNow }: { fast?: boolean; past?: bigint; sealThrough?: typeof sealedNow } = {}) {
  await resetDatabase(db.owner);
  const kek = randomBytes(32);
  const vault = testVault([ROOT], {}, { kek }, {}, { sealThrough, heldOutside: nothingHeld });
  const deps = testDeps(db.runtime, [ROOT], { vault });
  const root = clientFor(deps, ROOT);
  await root.projects.create('market', { name: 'Market' });
  await root.projects.create('billing', { name: 'Billing' });
  // From here on, numbers from `past`: the log's entries and 0.15's changes, bigints no JS number holds past 2^53.
  if (past > 0n) await numbersFrom(db.owner, past, deps.chainKey);
  await root.members.add(`user:${BOB}`, { role: 'admin' });
  // Each `admitRead` answer, and what runs once, right after the next one, before the app hands the add back.
  const answers: AdmitReadOutcome[] = [];
  let next: (() => Promise<void>) | null = null;
  const hooked = new Proxy(vault, {
    get(target, key) {
      const value: unknown = Reflect.get(target, key, target);
      if ((key === 'admitRead' || key === 'admitWrite') && !fast) return undefined;
      if (typeof value !== 'function') return value;
      if (key !== 'admitRead') return (value as (...args: unknown[]) => unknown).bind(target);
      return async (input: AdmitReadInput) => {
        const answer = await (value as Vault['admitRead'])!.call(target, input);
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
  // A browser session as a member who adds others holds one: a passkey of theirs touched a moment ago, which a member's
  // add takes (a fresh check, passkeys.md, section 4.1).
  const session = async (subject: string, email: string) => {
    const signed = await runtime.signin!.completeSignin({ provider: 'github', subject, emails: [email], name: null }, { requestId: randomUUID(), sourceIp: null, label: 'Firefox on macOS' });
    if (!('credential' in signed)) throw new Error(`${email} was not signed in`);
    return steppedUp(runtime.signin!, db.owner, deps.chainKey, email, signed.credential.token);
  };
  const bob = await session('bob', BOB);
  /** Bob's PUT of a member, as his browser sends it: its status, body and Retry-After. */
  const add = async (body: Record<string, unknown> = { role: 'developer', scope: { projects: { only: ['market'] } } }, member = NEW, token = bob.token) => {
    const response = await fetchApi(new Request(`${ORIGIN}/api/members/${encodeURIComponent(member)}`, {
      method: 'PUT',
      headers: { cookie: `${sessionCookieName(runtime.auth)}=${token}`, 'sec-fetch-site': 'same-origin', 'content-type': 'application/json' },
      body: JSON.stringify(body),
    }), runtime, { sourceIp: null });
    return { status: response.status, body: await response.json() as Record<string, unknown>, retryAfter: response.headers.get('retry-after') };
  };
  /** Bob signs his session out, from it, as his browser does. */
  const signOut = async () => {
    const response = await fetchApi(new Request(`${ORIGIN}/api/sessions/${bob.id}`, {
      method: 'DELETE', headers: { cookie: `${sessionCookieName(runtime.auth)}=${bob.token}`, 'sec-fetch-site': 'same-origin' },
    }), runtime, { sourceIp: null });
    assert.ok(response.ok, await response.text());
  };
  return { kek, deps, root, runtime, bob, session, add, signOut, answers, between: (adversary: () => Promise<void>) => void (next = adversary) };
}

/** A member's row, by principal: its role and scope columns, or none. */
async function memberRow(principal: string): Promise<{ role: string | null; createdBy: string } | undefined> {
  const [row] = await db.owner.select({ role: principals.role, createdBy: principals.createdBy }).from(principals).where(eq(principals.principal, principal));
  return row;
}

/** A member's `access_seq`, exactly. */
async function accessSeq(principal: string): Promise<bigint> {
  const [row] = await run(db.owner, sql`SELECT CAST(access_seq AS TEXT) AS seq FROM principals WHERE principal = ${principal}`) as { seq: string }[];
  return BigInt(row!.seq);
}

/** Whether a JS number holds `value` exactly, as `JSON.parse` would read it. */
const exactAsNumber = (value: bigint) => BigInt(Number(value)) === value;

const served = (answers: readonly AdmitReadOutcome[]) => answers.map((answer) => (answer.served ? 'served' : answer.why));
const reason = (body: Record<string, unknown>) => body.reason ?? (body.error as { reason?: string } | undefined)?.reason;

/** What a request added: the 0.14 entries (author, action, decision, actor), oldest first, and the 0.15 changes. */
async function since<T>(work: () => Promise<T>): Promise<{ result: T; entries: string[]; changes: { actor: string; payload: Record<string, unknown> }[] }> {
  const [{ seq }] = await run(db.owner, sql`SELECT coalesce(max(seq), 0)::text AS seq FROM audit_log`) as { seq: string }[];
  const [{ number }] = await run(db.owner, sql`SELECT coalesce(max(number), 0)::text AS number FROM log_changes`) as { number: string }[];
  const result = await work();
  const entries = await run(db.owner, sql`SELECT author, action, decision, actor FROM audit_log WHERE seq > ${seq} ORDER BY seq`) as { author: string; action: string; decision: string; actor: string }[];
  const changes = await run(db.owner, sql`SELECT actor, payload FROM log_changes WHERE number > ${number} ORDER BY number`) as { actor: string; payload: string }[];
  return { result, entries: entries.map((entry) => `${entry.author} ${entry.action} ${entry.decision} ${entry.actor}`), changes: changes.map((change) => ({ actor: change.actor, payload: JSON.parse(change.payload) as Record<string, unknown> })) };
}

test("a first add the vault decided on its read commits in its write, no app statement, its change naming the caller and the read it was decided on, and no 0.14 entry (0.16.0), answered as today's path answers it", async () => {
  const fast = await world();
  const made = await since(() => fast.add());
  assert.equal(made.result.status, 200, JSON.stringify(made.result.body));
  assert.deepEqual(served(fast.answers), ['served']);
  // The change is the add's record: no `member.add` entry of 0.14's.
  assert.deepEqual(made.entries, []);
  assert.equal(made.changes.length, 1);
  const [change] = made.changes;
  assert.equal(change!.actor, `user:${BOB}`);
  assert.equal(change!.payload.op, 'member.add');
  assert.equal(change!.payload.old, undefined);
  const request = change!.payload.request as { credential: string; operationId: unknown; requestId: unknown };
  assert.deepEqual(request.credential, fast.bob.id);
  assert.match(String(request.operationId), /^[0-9a-f-]{36}$/);
  assert.match(String(request.requestId), /^[0-9a-f-]{36}$/);
  assert.match(String(change!.payload.inputs), /^[0-9a-f]{64}$/);
  assert.deepEqual(await memberRow(NEW), { role: 'developer', createdBy: `user:${BOB}` });
  assert.ok((await fast.root.audit.verify()).ok);
  // As a vault that serves no `admitRead` answers the same add: status and body. Its record differs: today's path
  // appends `member.add`, beside its change; the two-trip path's change stands alone.
  const today = await world({ fast: false });
  const was = await since(() => today.add());
  assert.deepEqual({ status: made.result.status, body: made.result.body }, { status: was.result.status, body: was.result.body });
  assert.deepEqual(was.entries, [`vault member.add allow user:${BOB}`]);
  assert.deepEqual(await memberRow(NEW), { role: 'developer', createdBy: `user:${BOB}` });
});


test("numbers past 2^53 (Bob's newest access entry, his rows' newest changes): his add is served and commits, each read exactly, none through a JS number", async () => {
  // Past 2^53 a double holds only every other whole number: started one further on if Bob's access_seq lands on one.
  const past = 2n ** 53n + 1n;
  let w = await world({ past });
  if (exactAsNumber(await accessSeq(`user:${BOB}`))) w = await world({ past: past + 1n });
  const seq = await accessSeq(`user:${BOB}`);
  assert.ok(seq > past && !exactAsNumber(seq), `Bob's access_seq ${seq} is past 2^53, and no JS number holds it`);
  const added = await w.add();
  assert.equal(added.status, 200, JSON.stringify(added.body));
  // The two-trip path served it.
  assert.deepEqual(served(w.answers), ['served']);
  assert.deepEqual(await memberRow(NEW), { role: 'developer', createdBy: `user:${BOB}` });
});
test('a service account and a person with no role are added the same way, each in one try', async () => {
  const w = await world();
  for (const [member, body] of [['token:ci', {}], ['user:plain@acme.example', {}], ['user:everywhere@acme.example', { role: 'auditor' }]] as const) {
    const added = await w.add(body, member);
    assert.equal(added.status, 200, JSON.stringify(added.body));
    assert.equal(added.body.created, true);
  }
  assert.deepEqual(served(w.answers), ['served', 'served', 'served']);
  assert.ok((await w.root.audit.verify()).ok);
});

test('Bob demoted between the read and the write: the hold fails, the read again refuses him, and today\'s path answers 403, nothing added (WritingAdd, dem)', async () => {
  const w = await world();
  w.between(async () => void (await w.root.members.add(`user:${BOB}`, { role: 'member' })));
  const added = await w.add();
  assert.equal(added.status, 403, JSON.stringify(added.body));
  assert.deepEqual(served(w.answers), ['served', 'refused']);
  assert.equal(await memberRow(NEW), undefined);
});

test("Bob's session revoked between the read and the write: the hold fails, and the read again answers 401, nothing added (PR 5: the add's read holds the adder's session)", async () => {
  const w = await world();
  w.between(() => w.signOut());
  const added = await w.add();
  assert.equal(added.status, 401, JSON.stringify(added.body));
  assert.deepEqual(served(w.answers), ['served', 'ended']);
  assert.equal(await memberRow(NEW), undefined);
});

test("the head held and every place in the reads' line taken when the write comes: it waits for the head, as today's add does, and adds in one try (Fable's review of #474)", async () => {
  const w = await world();
  let release = () => {};
  let holding: Promise<void> = Promise.resolve();
  w.between(async () => {
    let held = () => {};
    const taken = new Promise<void>((resolve) => (held = resolve));
    holding = db.owner.transaction(async (tx) => {
      await lockLogHead(tx);
      // The reads' places in line (`READ_HEAD_WAITERS`, 16 of them, `lockLogHeadQueued`), and more.
      await run(tx, sql`SELECT pg_advisory_xact_lock(${0x636f6668}, place) FROM generate_series(1, 64) AS place`);
      held();
      await new Promise<void>((resolve) => (release = resolve));
    });
    await Promise.race([taken, holding]);
    setTimeout(() => release(), 400);
  });
  const started = Date.now();
  const added = await w.add();
  await holding;
  assert.equal(added.status, 200, JSON.stringify(added.body));
  assert.ok(Date.now() - started >= 400, `added after ${Date.now() - started} ms, before the head was free`);
  assert.deepEqual(served(w.answers), ['served']);
  assert.deepEqual(await memberRow(NEW), { role: 'developer', createdBy: `user:${BOB}` });
});

test('the roles redefined between the read and the write: the hold fails, and the add goes again on the roles as they are (WritingAdd, pol)', async () => {
  const w = await world();
  w.between(async () => void (await w.root.roles.set('auditor', { name: 'Auditor', description: '', permissions: ['secret.read', 'secret.use'], protected: [] })));
  const added = await w.add();
  assert.equal(added.status, 200, JSON.stringify(added.body));
  assert.deepEqual(served(w.answers), ['served', 'served']);
  assert.deepEqual(await memberRow(NEW), { role: 'developer', createdBy: `user:${BOB}` });
});

test('another add of the same member between the read and the write: the hold fails, and the add finds a member, today\'s path answering as for one (AddsFlip)', async () => {
  const w = await world();
  w.between(async () => void (await w.root.members.add(NEW, { role: 'auditor' })));
  const added = await w.add();
  assert.equal(added.status, 200, JSON.stringify(added.body));
  assert.equal(added.body.created, false);
  assert.deepEqual(served(w.answers), ['served', 'shape']);
  // Once: the root's, down today's path, whose role Bob's then changes, as today's path does a member's. No add of
  // Bob's recorded in 0.15's log alone (a two-trip add's change starts with its `inputs`).
  const [{ count }] = await run(db.owner, sql`SELECT count(*)::int AS count FROM audit_log WHERE action = 'member.add' AND subject_principal = ${NEW} AND decision = 'allow'`) as { count: number }[];
  const [{ adds }] = await run(db.owner, sql`SELECT count(*)::int AS adds FROM log_changes WHERE object = ${logObject('principal', NEW)} AND payload LIKE ${'{"inputs":"%'}`) as { adds: number }[];
  assert.deepEqual([Number(count), Number(adds)], [1, 0]);
});

test('a hold that keeps failing gives up after three tries: 409 `changed`, asked again in a second, nothing added (EveryRequestEnds)', async () => {
  const w = await world();
  const churn = async () => {
    await w.root.roles.set(`role-${w.answers.length}`, { name: `Role ${w.answers.length}`, description: '', permissions: ['secret.read', 'secret.use'], protected: [] });
    if (w.answers.length < 3) w.between(churn);
  };
  w.between(churn);
  const added = await w.add();
  assert.equal(added.status, 409, JSON.stringify(added.body));
  assert.equal(reason(added.body), 'changed');
  assert.equal(added.retryAfter, '1');
  assert.deepEqual(served(w.answers), ['served', 'served', 'served']);
  assert.equal(await memberRow(NEW), undefined);
});

test("Bob removed and restored as an admin between the read and the write, his session's row not yet revoked: the read again finds it of his earlier membership, 401, nothing added (WritingRejoin; review r1 of #474)", async () => {
  const w = await world();
  // The vault's removal alone: the app's sweep, which revokes the session's row, has not run yet.
  w.between(async () => {
    assert.equal((await w.deps.vault.remove({ actor: `user:${ROOT}`, principal: `user:${BOB}` })).ok, true);
    assert.equal((await w.deps.vault.admit({ actor: `user:${ROOT}`, principal: `user:${BOB}`, role: 'admin' })).ok, true);
    const [row] = await db.owner.select({ revokedAt: credentials.revokedAt }).from(credentials).where(eq(credentials.id, w.bob.id));
    assert.equal(row!.revokedAt, null);
  });
  const added = await w.add();
  assert.equal(added.status, 401, JSON.stringify(added.body));
  assert.deepEqual(served(w.answers), ['served', 'ended']);
  assert.equal(await memberRow(NEW), undefined);
  // And on a first try: the session of the earlier membership is ended there too, never down today's path.
  const again = await w.add();
  assert.equal(again.status, 401, JSON.stringify(again.body));
  assert.deepEqual(served(w.answers), ['served', 'ended', 'ended']);
  assert.equal(await memberRow(NEW), undefined);
});

test("Bob's member row edited in a column only its 0.4 MAC covers (`created_by`): the read refuses it, and today's path answers it as ever, 401, nothing added (review r1 of #474)", async () => {
  const attempt = async (fast: boolean) => {
    const w = await world({ fast });
    await db.owner.update(principals).set({ createdBy: 'user:someone@acme.example' }).where(eq(principals.principal, `user:${BOB}`));
    const made = await since(() => w.add());
    return { served: served(w.answers), status: made.result.status, body: made.result.body, entries: made.entries, row: await memberRow(NEW) };
  };
  const fast = await attempt(true);
  const today = await attempt(false);
  assert.deepEqual(fast.served, ['tampered']);
  assert.equal(fast.status, 401, JSON.stringify(fast.body));
  assert.equal(fast.row, undefined);
  assert.deepEqual({ ...fast, served: [] }, { ...today, served: [] });
});

test("a member added down the two-trip path and changed no further, then the vault's key rotated: the rotation seals their row again under the new key, as it does everyone's, and they are served (review r1 of #490)", async () => {
  const w = await world();
  const added = await w.add();
  assert.equal(added.status, 200, JSON.stringify(added.body));
  assert.deepEqual(served(w.answers), ['served']);
  assert.equal(await accessSeq(NEW), 0n);
  // A cold isolate of the deployment given a new KEK, the old one among its previous: its first call rotates.
  const rotated = spoken(await localVault(
    {
      database: await openVaultDatabase(), hotDatabase: hotDatabaseUrl(), owners: [ROOT],
      kek: { id: 'test-kek-2', key: randomBytes(32).toString('base64') }, previousKeks: [{ id: 'test-kek-1', key: w.kek.toString('base64') }],
    },
    { sealThrough: sealedNow, heldOutside: nothingHeld },
  ));
  const access = await rotated.access(NEW);
  assert.deepEqual([access.status, access.role], ['active', 'developer'], JSON.stringify(access));
  assert.deepEqual(await run(db.owner, sql`SELECT count(*)::int AS n FROM audit_log WHERE action = 'key.rotate'`), [{ n: 1 }]);
  const verified = await rotated.verifyLog({});
  assert.ok(verified.ok, JSON.stringify(verified));
});

test("a ticket another vault read, written by one whose config names the member an Owner: that vault leaves the add to today's path, nothing written (review r1 of #474)", async () => {
  const w = await world();
  // A cold isolate of the deployment after a rollout that names new@ an Owner: its own config, the same keys.
  const rolled = spoken(await localVault(
    { database: await openVaultDatabase(), hotDatabase: hotDatabaseUrl(), kek: { id: 'test-kek-1', key: w.kek.toString('base64') }, owners: ['new@acme.example'] },
    { sealThrough: sealedNow, heldOutside: nothingHeld },
  ));
  // Asserted outside the callback: inside it, a failed assertion would be the route's 500, which nothing checks.
  let written: unknown;
  let after: Awaited<ReturnType<typeof memberRow>> | 'unset' = 'unset';
  w.between(async () => {
    const ticket = (w.answers.at(-1) as Extract<AdmitReadOutcome, { served: true }>).ticket;
    written = await rolled.admitWrite!({ ticket });
    after = await memberRow(NEW);
  });
  const added = await w.add();
  assert.deepEqual(written, { written: false, why: 'unserved' });
  // Settling its config, the rolled-out vault declares new@ an Owner itself: that row is the vault's, never Bob's add.
  assert.deepEqual(after, { role: 'owner', createdBy: 'system:vault' });
  // Bob's own try then finds that change: its hold fails, the read again finds a member, and today's path refuses an admin's change to an Owner.
  assert.deepEqual(served(w.answers), ['served', 'shape']);
  assert.equal(added.status, 403, JSON.stringify(added.body));
  assert.equal(reason(added.body), 'not_allowed');
  assert.deepEqual(await memberRow(NEW), { role: 'owner', createdBy: 'system:vault' });
});

test("Bob's token hash copied onto the Owner's session: the vault reads the Owner, and the app's check of the row's MAC refuses it before anything is written (WritingAdd, sub; round 6)", async () => {
  const w = await world();
  const owner = await w.session('root', ROOT);
  const [bob] = await db.owner.select({ tokenHash: credentials.tokenHash }).from(credentials).where(eq(credentials.id, w.bob.id));
  await db.owner.update(credentials).set({ tokenHash: randomBytes(32) }).where(eq(credentials.id, w.bob.id));
  await db.owner.update(credentials).set({ tokenHash: bob!.tokenHash }).where(eq(credentials.id, owner.id));
  const added = await w.add({ role: 'owner' });
  assert.equal(added.status, 401, JSON.stringify(added.body));
  // The vault served it, on the Owner's rows: what refused it is the app's check (AuthChecked).
  assert.deepEqual(served(w.answers), ['served']);
  assert.equal(await memberRow(NEW), undefined);
});

test("Bob's token hash copied onto a Developer's session: the vault reads the Developer and refuses, and the app's check of the row's MAC answers 401 before the refusal is recorded: no record names the Developer (WritingRefuse, RefusalAfterAuth; review r1 of PR 6)", async () => {
  const w = await world();
  const carol = 'carol@acme.example';
  await w.root.members.add(`user:${carol}`, { role: 'developer' });
  const developer = await w.session('carol', carol);
  const [bob] = await db.owner.select({ tokenHash: credentials.tokenHash }).from(credentials).where(eq(credentials.id, w.bob.id));
  await db.owner.update(credentials).set({ tokenHash: randomBytes(32) }).where(eq(credentials.id, w.bob.id));
  await db.owner.update(credentials).set({ tokenHash: bob!.tokenHash }).where(eq(credentials.id, developer.id));
  const added = await w.add();
  assert.equal(added.status, 401, JSON.stringify(added.body));
  // The vault refused it, on the Developer's rows, with a ticket: what kept it from the log is the app's check.
  assert.deepEqual(served(w.answers), ['refused']);
  assert.deepEqual(await run(db.owner, sql`SELECT number FROM log_changes WHERE payload LIKE '%"op":"add.refused"%'`), []);
  assert.equal(await memberRow(NEW), undefined);
});

test("a refused first add whose record committed but whose seal did not come in time: 503, in words that say no change was made, never a change's; the member not added, and no 0.14 entry (review r2 of PR 6)", async () => {
  const sealing = stallingSeal();
  const w = await world({ sealThrough: sealing.sealThrough });
  sealing.stalled = true;
  const made = await since(() => w.add({ role: 'owner' }));
  assert.equal(made.result.status, 503, JSON.stringify(made.result.body));
  assert.deepEqual(made.result.body, { error: 'unavailable', message: REFUSAL_UNSEALED_MESSAGE });
  assert.deepEqual(served(w.answers), ['refused']);
  assert.equal(await memberRow(NEW), undefined);
  // The record written, which the next checkpointer seals; no deny entry beside it.
  assert.deepEqual(made.entries, []);
  assert.deepEqual(made.changes.map((change) => change.payload.op), ['add.refused']);
  // Sealing again, the same add is refused as before, 403.
  sealing.stalled = false;
  assert.equal((await w.add({ role: 'owner' })).status, 403);
});

test("Bob's session revoked and its row put back, live: the vault's read refuses it on the log's newest change, 401, never down today's path (dbw)", async () => {
  const w = await world();
  const [row] = await db.owner.select().from(credentials).where(eq(credentials.id, w.bob.id));
  await w.signOut();
  await db.owner.update(credentials).set(row!).where(eq(credentials.id, w.bob.id));
  const added = await w.add();
  assert.equal(added.status, 401, JSON.stringify(added.body));
  assert.deepEqual(served(w.answers), ['forged']);
  assert.equal(await memberRow(NEW), undefined);
});

test("Bob demoted, then his row put back and its seal written into the demotion's change: the change's MAC fails, the add goes down today's path, which refuses it too (WritingForge, T190)", async () => {
  const w = await world();
  const [member] = await db.owner.select().from(principals).where(eq(principals.principal, `user:${BOB}`));
  await w.root.members.add(`user:${BOB}`, { role: 'member' });
  await db.owner.update(principals).set(member!).where(eq(principals.principal, `user:${BOB}`));
  await run(db.owner, sql`UPDATE log_changes SET seal = ${member!.seal} WHERE number = (SELECT max(number) FROM log_changes WHERE object = ${logObject('principal', `user:${BOB}`)})`);
  const added = await w.add();
  assert.notEqual(added.status, 200, JSON.stringify(added.body));
  assert.deepEqual(served(w.answers), ['tampered']);
  assert.equal(await memberRow(NEW), undefined);
});

test("a refusal is answered as today's path answers it, status and body: one who runs no instance, an Owner asked by an admin, refused on the vault's read and recorded by it in place of 0.14's deny entry (PR 6); a project no slug names, today's path's still", async () => {
  // What the fast attempt answers by: the vault's refusal and its record, or today's path.
  const cases: [string, (w: Awaited<ReturnType<typeof world>>) => Promise<void>, Record<string, unknown>, string | null][] = [
    ['Bob no admin', async (w) => void (await w.root.members.add(`user:${BOB}`, { role: 'developer' })), { role: 'developer' }, 'app member.add deny'],
    ['an Owner, by an admin', async () => {}, { role: 'owner' }, 'vault member.add deny'],
    ['a project no slug names', async () => {}, { role: 'developer', scope: { projects: { only: ['nowhere'] } } }, null],
  ];
  for (const [what, arrange, body, entry] of cases) {
    const attempt = async (fast: boolean) => {
      const w = await world({ fast });
      await arrange(w);
      const everyone = await w.root.members.list();
      const made = await since(() => w.add(body));
      // The list of everyone as it was: the record names the member asked for, whom no scan of the missing takes for one.
      assert.deepEqual(await w.root.members.list(), everyone, what);
      await assert.rejects(w.root.members.get(NEW), (error: { status?: number }) => error.status === 404, what);
      return { answer: { status: made.result.status, body: made.result.body, row: await memberRow(NEW) }, entries: made.entries, changes: made.changes, answers: served(w.answers) };
    };
    const fast = await attempt(true);
    const today = await attempt(false);
    assert.notEqual(fast.answer.status, 200, what);
    assert.deepEqual(fast.answer, today.answer, what);
    if (entry === null) {
      assert.deepEqual(fast.answers, ['shape'], what);
      assert.deepEqual({ entries: fast.entries, changes: fast.changes }, { entries: today.entries, changes: today.changes }, what);
      continue;
    }
    // Today's deny entry, Bob's; the vault's record in its place, and nothing else of either log's.
    assert.deepEqual(fast.answers, ['refused'], what);
    assert.deepEqual(today.entries, [`${entry} user:${BOB}`], what);
    assert.deepEqual(fast.entries, [], what);
    assert.equal(fast.changes.length, 1, what);
    const [record] = fast.changes;
    assert.equal(record!.actor, `user:${BOB}`, what);
    assert.equal(record!.payload.op, 'add.refused', what);
    assert.equal(record!.payload.code, 'not_allowed', what);
    assert.equal(record!.payload.principal, NEW, what);
    assert.deepEqual((record!.payload.ref as { kind: string }).kind, 'request', what);
  }
});

test('a change that names a read goes only in a transaction that held it: `change_input_strict` refuses it otherwise', async () => {
  await world();
  await assert.rejects(
    db.owner.transaction(async (tx) => {
      await tx.execute(sql`SELECT change_input_strict('principal', ${NEW}, ${randomUUID()}, 0, ${`user:${BOB}`}, ${JSON.stringify({ op: 'member.add', inputs: '00'.repeat(32) })}, NULL, NULL, NULL, ${randomBytes(32)})`);
    }),
    (error: unknown) => /names a read its transaction did not hold/.test(String((error as { message?: string }).message ?? error) + String((error as { cause?: unknown }).cause ?? '')),
  );
});

test("a ticket is the vault's own: one edited, its role or its time, is refused and writes nothing; the one the vault made writes", async () => {
  const w = await world();
  const answer = await w.runtime.vault.admitRead!({
    tokenHash: (await db.owner.select({ tokenHash: credentials.tokenHash }).from(credentials).where(eq(credentials.id, w.bob.id)))[0]!.tokenHash.toString('base64'),
    accepts: { signin: true, issuers: [], passkeys: 'off' as const }, principal: NEW,
  });
  // A browser session's issuer is the app's to accept: none named, none served.
  assert.deepEqual(answer, { served: false, why: 'credential' });
  w.between(async () => {
    const ticket = (w.answers.at(-1) as Extract<AdmitReadOutcome, { served: true }>).ticket;
    const [body, mac] = ticket.split('.');
    const edited = Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(body!, 'base64url').toString('utf8')), role: 'owner' }), 'utf8').toString('base64url');
    await assert.rejects(w.runtime.vault.admitWrite!({ ticket: `${edited}.${mac}` }), /not/);
    assert.equal(await memberRow(NEW), undefined);
    const stale = Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(body!, 'base64url').toString('utf8')), until: 0 }), 'utf8').toString('base64url');
    await assert.rejects(w.runtime.vault.admitWrite!({ ticket: `${stale}.${mac}` }), /not/);
  });
  const added = await w.add();
  assert.equal(added.status, 200, JSON.stringify(added.body));
  assert.deepEqual(await memberRow(NEW), { role: 'developer', createdBy: `user:${BOB}` });
});

test("the read moves with every part an add's decision weighs, its numbers too: what each adversary of Writing.tla's add changes changes its digest (ReadHeld, ReadByNumber)", async () => {
  const w = await world();
  const [bob] = await db.owner.select({ tokenHash: credentials.tokenHash }).from(credentials).where(eq(credentials.id, w.bob.id));
  const read = async () => {
    const [row] = await run(db.owner, sql`SELECT encode(sha256(convert_to(admit_inputs(${bob!.tokenHash}::bytea, ${NEW}, ARRAY['market']::text[]), 'UTF8')), 'hex') AS digest`) as { digest: string }[];
    return row!.digest;
  };
  const moves: [string, () => Promise<unknown>][] = [
    ['the roles redefined', () => w.root.roles.set('auditor', { name: 'Auditor', description: '', permissions: ['secret.read', 'secret.use'], protected: [] })],
    ['Bob demoted and made an admin again', async () => {
      await w.root.members.add(`user:${BOB}`, { role: 'member' });
      await w.root.members.add(`user:${BOB}`, { role: 'admin' });
    }],
    ['the scope\'s project renamed, another made under its slug', async () => {
      await w.root.projects.update('market', { slug: 'market-old' });
      await w.root.projects.create('market', { name: 'Market again' });
    }],
    ['the member added', () => w.root.members.add(NEW)],
    ['his session revoked', () => w.signOut()],
  ];
  let digest = await read();
  assert.equal(await read(), digest);
  for (const [what, move] of moves) {
    await move();
    const now = await read();
    assert.notEqual(now, digest, what);
    digest = now;
  }
});

test("a first add down the two-trip path, recorded in 0.15's log alone, is listed on the instance's page where 0.14's `member.add` stood; the log verifies through a later change down today's path, and not with the row forged; its row deleted, the member is missing (T179, 0.16.0)", async () => {
  const w = await world();
  const added = await w.add();
  assert.equal(added.status, 200, JSON.stringify(added.body));
  assert.deepEqual(served(w.answers), ['served']);
  const adds = async (query: Record<string, string | undefined>) => (await w.root.audit.list({ sealed: '1', limit: 50, ...query })).entries.filter((entry) => entry.action === 'member.add' && entry.log === '0.15');
  for (const query of [{}, { actor: `user:${BOB}` }, { actor: BOB }]) {
    const [entry, ...more] = await adds(query);
    assert.deepEqual(more, [], JSON.stringify(query));
    assert.deepEqual(
      { actor: entry?.actorId, subject: entry?.subject, role: entry?.metadata.role, author: entry?.author, forged: entry?.forged },
      { actor: BOB, subject: NEW, role: 'developer', author: 'vault', forged: undefined },
      JSON.stringify(query),
    );
    assert.match(String(entry?.operationId), /^[0-9a-f-]{36}$/);
  }
  // An add is the instance's, of no place; and no other member's.
  for (const query of [{ path: 'market' }, { actor: ROOT }, { decision: 'deny' }]) assert.deepEqual(await adds(query), [], JSON.stringify(query));
  // 0.14's replay of the vault's access entries never saw the add: a role change down today's path after it is one it
  // cannot follow, and 0.15's log holds the rows instead.
  await w.root.members.add(NEW, { role: 'auditor' });
  assert.ok((await w.root.audit.verify()).ok);
  const [row] = await run(db.owner, sql`SELECT * FROM principals WHERE principal = ${NEW}`) as Record<string, unknown>[];
  await run(db.owner, sql`UPDATE principals SET role = 'owner' WHERE principal = ${NEW}`);
  const forged = await w.root.audit.verify();
  assert.deepEqual([forged.ok, forged.ok ? null : forged.author], [false, 'vault']);
  await run(db.owner, sql`UPDATE principals SET role = ${row!.role as string} WHERE principal = ${NEW}`);
  assert.ok((await w.root.audit.verify()).ok);
  // Its row deleted around the vault: the list of everyone finds the member missing.
  await run(db.owner, sql`DELETE FROM principals WHERE principal = ${NEW}`);
  assert.deepEqual(await missingMembers(db.runtime), [NEW]);
});

test("a member added down the two-trip path, then removed down today's path: 0.14's replay stops at a removal of someone it never saw added, and the log still verifies, every row held to 0.15's log instead; a row deleted around the vault after it is found (T179, 0.16.0)", async () => {
  const w = await world();
  const added = await w.add();
  assert.equal(added.status, 200, JSON.stringify(added.body));
  assert.deepEqual(served(w.answers), ['served']);
  const CAROL = 'user:carol@acme.example';
  assert.equal((await w.deps.vault.admit({ actor: `user:${ROOT}`, principal: CAROL, role: 'developer' })).ok, true);
  assert.equal((await w.deps.vault.remove({ actor: `user:${ROOT}`, principal: NEW })).ok, true);
  const [removal] = await run(db.owner, sql`SELECT action FROM audit_log WHERE author = 'vault' AND subject_principal = ${NEW}`) as { action: string }[];
  assert.equal(removal?.action, 'member.remove');
  const verified = await w.root.audit.verify();
  assert.ok(verified.ok, JSON.stringify(verified));
  // Carol, added down today's path before the removal, her row deleted: no replay says she is missing now, 0.15's log does.
  await run(db.owner, sql`DELETE FROM principals WHERE principal = ${CAROL}`);
  const missing = await w.root.audit.verify();
  assert.deepEqual([missing.ok, missing.ok ? null : missing.author, missing.ok ? null : missing.reason], [false, 'vault', "the store's carol@acme.example is older than the log's last change to them: it was put back"], JSON.stringify(missing));
});

test("a member added down the two-trip path alone, with no 0.14 entry of them, whose row is deleted around the vault is missing by their add's change in 0.15's log (T179, 0.16.0)", async () => {
  const w = await world();
  const added = await w.add();
  assert.equal(added.status, 200, JSON.stringify(added.body));
  assert.deepEqual(served(w.answers), ['served']);
  assert.deepEqual(await run(db.owner, sql`SELECT count(*)::int AS n FROM audit_log WHERE subject_principal = ${NEW}`), [{ n: 0 }]);
  assert.deepEqual(await missingMembers(db.runtime), []);
  assert.ok((await w.root.audit.verify()).ok);
  await run(db.owner, sql`DELETE FROM principals WHERE principal = ${NEW}`);
  assert.deepEqual(await missingMembers(db.runtime), [NEW]);
  // And the vault's verification, which no 0.14 entry of theirs tells either.
  const verified = await w.root.audit.verify();
  assert.deepEqual([verified.ok, verified.ok ? null : verified.reason], [false, "the store's new@acme.example is older than the log's last change to them: it was put back"], JSON.stringify(verified));
});
