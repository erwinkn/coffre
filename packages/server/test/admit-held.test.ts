// A member add in three round trips (T179 PR 5; docs/design/two-trips.md, "A member add"; formal/Writing.tla, the add):
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
import { tablesOf, type Queryable } from '@coffre/db';
import { rowsOf } from '@coffre/db/dialect';
import { logObject } from '@coffre/db/log';
import { eq, sql } from 'drizzle-orm';

import { sessionCookieName } from '../src/auth.ts';
import { resolveConfig } from '../src/config.ts';
import { fetchApi } from '../src/fetch-api.ts';
import { createRuntime, type CoffreRuntime } from '../src/runtime.ts';
import { clientFor, entryOf, LOG, nothingHeld, openTestDatabase, resetDatabase, sealedNow, testDeps, testVault } from './api-fixture.ts';
import { TEST_ENGINE } from './db/engine.ts';

const ORIGIN = 'https://secrets.acme.example';
const ROOT = 'admin@acme.example';
const BOB = 'bob@acme.example';
const NEW = 'user:new@acme.example';
const POSTGRES = TEST_ENGINE === 'postgres' && LOG === '0.15' ? false : "the two-trip add is Postgres's, under 0.15's log";
const ANY = LOG === '0.15' ? false : "0.15's log only";

const db = await openTestDatabase();
test.after(async () => {
  await resetDatabase(db.owner);
  await db.close();
});

const run = (on: Queryable, query: ReturnType<typeof sql>) => rowsOf(on, query);
const { vaultMembers, credentials } = tablesOf(db.owner);

/**
 * A fresh instance: projects market and billing, Bob an admin of the whole instance, and his browser session. `fast:
 * false`: a vault that serves no `admitRead`, every add down today's path, to answer as the two-trip path's refusals must.
 */
async function world({ fast = true }: { fast?: boolean } = {}) {
  await resetDatabase(db.owner);
  const vault = testVault([ROOT], {}, { kek: randomBytes(32) }, {}, { log: '0.15', sealThrough: sealedNow, heldOutside: nothingHeld });
  const deps = testDeps(db.runtime, [ROOT], { vault });
  const root = clientFor(deps, ROOT);
  await root.projects.create('market', { name: 'Market' });
  await root.projects.create('billing', { name: 'Billing' });
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
  const session = async (subject: string, email: string) => {
    const signed = await runtime.signin!.completeSignin({ provider: 'github', subject, emails: [email], name: null }, { requestId: randomUUID(), sourceIp: null, label: 'Firefox on macOS' });
    if (!('credential' in signed)) throw new Error(`${email} was not signed in`);
    return { token: signed.credential.token, id: signed.credential.id };
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
  return { deps, root, runtime, bob, session, add, signOut, answers, between: (adversary: () => Promise<void>) => void (next = adversary) };
}

/** A member's row, by principal: its role and scope columns, or none. */
async function memberRow(principal: string): Promise<{ role: string | null; createdBy: string } | undefined> {
  const [row] = await db.owner.select({ role: vaultMembers.role, createdBy: vaultMembers.createdBy }).from(vaultMembers).where(eq(vaultMembers.principal, principal));
  return row;
}

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

test("a first add the vault decided on its read commits in its write, no app statement, its change naming the caller and the read it was decided on, answered as today's path answers it", { skip: POSTGRES }, async () => {
  const fast = await world();
  const made = await since(() => fast.add());
  assert.equal(made.result.status, 200, JSON.stringify(made.result.body));
  assert.deepEqual(served(fast.answers), ['served']);
  assert.deepEqual(made.entries, [`vault member.add allow user:${BOB}`]);
  assert.equal(made.changes.length, 1);
  const [change] = made.changes;
  assert.equal(change!.actor, `user:${BOB}`);
  assert.equal(change!.payload.op, 'member.add');
  assert.deepEqual((change!.payload.request as { credential: string }).credential, fast.bob.id);
  assert.match(String(change!.payload.inputs), /^[0-9a-f]{64}$/);
  assert.deepEqual(await memberRow(NEW), { role: 'developer', createdBy: `user:${BOB}` });
  assert.ok((await fast.root.audit.verify()).ok);
  // As a vault that serves no `admitRead` answers the same add: status, body, entries.
  const today = await world({ fast: false });
  const was = await since(() => today.add());
  assert.deepEqual({ status: made.result.status, body: made.result.body, entries: made.entries }, { status: was.result.status, body: was.result.body, entries: was.entries });
  assert.deepEqual(await memberRow(NEW), { role: 'developer', createdBy: `user:${BOB}` });
});

test('a service account and a person with no role are added the same way, each in one try', { skip: POSTGRES }, async () => {
  const w = await world();
  for (const [member, body] of [['token:ci', {}], ['user:plain@acme.example', {}], ['user:everywhere@acme.example', { role: 'auditor' }]] as const) {
    const added = await w.add(body, member);
    assert.equal(added.status, 200, JSON.stringify(added.body));
    assert.equal(added.body.created, true);
  }
  assert.deepEqual(served(w.answers), ['served', 'served', 'served']);
  assert.ok((await w.root.audit.verify()).ok);
});

test('Bob demoted between the read and the write: the hold fails, the read again refuses him, and today\'s path answers 403, nothing added (WritingAdd, dem)', { skip: POSTGRES }, async () => {
  const w = await world();
  w.between(async () => void (await w.root.members.add(`user:${BOB}`, { role: 'member' })));
  const added = await w.add();
  assert.equal(added.status, 403, JSON.stringify(added.body));
  assert.deepEqual(served(w.answers), ['served', 'refused']);
  assert.equal(await memberRow(NEW), undefined);
});

test("Bob's session revoked between the read and the write: the hold fails, and the read again answers 401, nothing added (PR 5: the add's read holds the adder's session)", { skip: POSTGRES }, async () => {
  const w = await world();
  w.between(() => w.signOut());
  const added = await w.add();
  assert.equal(added.status, 401, JSON.stringify(added.body));
  assert.deepEqual(served(w.answers), ['served', 'ended']);
  assert.equal(await memberRow(NEW), undefined);
});

test('the roles redefined between the read and the write: the hold fails, and the add goes again on the roles as they are (WritingAdd, pol)', { skip: POSTGRES }, async () => {
  const w = await world();
  w.between(async () => void (await w.root.roles.set('auditor', { name: 'Auditor', description: '', permissions: ['secret.read', 'secret.use'], protected: [] })));
  const added = await w.add();
  assert.equal(added.status, 200, JSON.stringify(added.body));
  assert.deepEqual(served(w.answers), ['served', 'served']);
  assert.deepEqual(await memberRow(NEW), { role: 'developer', createdBy: `user:${BOB}` });
});

test('another add of the same member between the read and the write: the hold fails, and the add finds a member, today\'s path answering as for one (AddsFlip)', { skip: POSTGRES }, async () => {
  const w = await world();
  w.between(async () => void (await w.root.members.add(NEW, { role: 'auditor' })));
  const added = await w.add();
  assert.equal(added.status, 200, JSON.stringify(added.body));
  assert.equal(added.body.created, false);
  assert.deepEqual(served(w.answers), ['served', 'shape']);
  // Once: the root's, whose role Bob's then changes, as today's path does a member's.
  const [{ count }] = await run(db.owner, sql`SELECT count(*)::int AS count FROM audit_log WHERE action = 'member.add' AND subject_principal = ${NEW} AND decision = 'allow'`) as { count: number }[];
  assert.equal(count, 1);
});

test('a hold that keeps failing gives up after three tries: 409 `changed`, asked again in a second, nothing added (EveryRequestEnds)', { skip: POSTGRES }, async () => {
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

test("Bob's token hash copied onto the Owner's session: the vault reads the Owner, and the app's check of the row's MAC refuses it before anything is written (WritingAdd, sub; round 6)", { skip: ANY }, async () => {
  const w = await world();
  const owner = await w.session('root', ROOT);
  const [bob] = await db.owner.select({ tokenHash: credentials.tokenHash }).from(credentials).where(eq(credentials.id, w.bob.id));
  await db.owner.update(credentials).set({ tokenHash: randomBytes(32) }).where(eq(credentials.id, w.bob.id));
  await db.owner.update(credentials).set({ tokenHash: bob!.tokenHash }).where(eq(credentials.id, owner.id));
  const added = await w.add({ role: 'owner' });
  assert.equal(added.status, 401, JSON.stringify(added.body));
  // On Postgres the vault served it, on the Owner's rows: what refused it is the app's check (AuthChecked).
  if (TEST_ENGINE === 'postgres') assert.deepEqual(served(w.answers), ['served']);
  assert.equal(await memberRow(NEW), undefined);
});

test("Bob's session revoked and its row put back, live: the vault's read refuses it on the log's newest change, 401, never down today's path (dbw)", { skip: POSTGRES }, async () => {
  const w = await world();
  const [row] = await db.owner.select().from(credentials).where(eq(credentials.id, w.bob.id));
  await w.signOut();
  await db.owner.update(credentials).set(row!).where(eq(credentials.id, w.bob.id));
  const added = await w.add();
  assert.equal(added.status, 401, JSON.stringify(added.body));
  assert.deepEqual(served(w.answers), ['forged']);
  assert.equal(await memberRow(NEW), undefined);
});

test("Bob demoted, then his row put back and its seal written into the demotion's change: the change's MAC fails, the add goes down today's path, which refuses it too (WritingForge, T190)", { skip: ANY }, async () => {
  const w = await world();
  const [member] = await db.owner.select().from(vaultMembers).where(eq(vaultMembers.principal, `user:${BOB}`));
  await w.root.members.add(`user:${BOB}`, { role: 'member' });
  await db.owner.update(vaultMembers).set(member!).where(eq(vaultMembers.principal, `user:${BOB}`));
  await run(db.owner, sql`UPDATE log_changes SET seal = ${member!.seal} WHERE number = (SELECT max(number) FROM log_changes WHERE object = ${logObject('principal', `user:${BOB}`)})`);
  const added = await w.add();
  assert.notEqual(added.status, 200, JSON.stringify(added.body));
  if (TEST_ENGINE === 'postgres') assert.deepEqual(served(w.answers), ['tampered']);
  assert.equal(await memberRow(NEW), undefined);
});

test('a refusal is answered as today\'s path answers it, status and body: one who runs no instance, a project no slug names, a role no instance has', { skip: POSTGRES }, async () => {
  const cases: [string, (w: Awaited<ReturnType<typeof world>>) => Promise<void>, Record<string, unknown>][] = [
    ['Bob no admin', async (w) => void (await w.root.members.add(`user:${BOB}`, { role: 'developer' })), { role: 'developer' }],
    ['a project no slug names', async () => {}, { role: 'developer', scope: { projects: { only: ['nowhere'] } } }],
    ['an Owner, by an admin', async () => {}, { role: 'owner' }],
  ];
  for (const [what, arrange, body] of cases) {
    const attempt = async (fast: boolean) => {
      const w = await world({ fast });
      await arrange(w);
      const made = await since(() => w.add(body));
      return { status: made.result.status, body: made.result.body, entries: made.entries, row: await memberRow(NEW) };
    };
    const fast = await attempt(true);
    const today = await attempt(false);
    assert.notEqual(fast.status, 200, what);
    assert.deepEqual(fast, today, what);
  }
});

test('a change that names a read goes only in a transaction that held it: `change_input_strict` refuses it otherwise', { skip: POSTGRES }, async () => {
  await world();
  await assert.rejects(
    db.owner.transaction(async (tx) => {
      await tx.execute(sql`SELECT change_input_strict('principal', ${NEW}, ${randomUUID()}, 0, ${`user:${BOB}`}, ${JSON.stringify({ op: 'member.add', inputs: '00'.repeat(32) })}, NULL, NULL, NULL, ${randomBytes(32)})`);
    }),
    (error: unknown) => /names a read its transaction did not hold/.test(String((error as { message?: string }).message ?? error) + String((error as { cause?: unknown }).cause ?? '')),
  );
});

test("a ticket is the vault's own: one edited, its role or its time, is refused and writes nothing; the one the vault made writes", { skip: POSTGRES }, async () => {
  const w = await world();
  const answer = await w.runtime.vault.admitRead!({
    tokenHash: (await db.owner.select({ tokenHash: credentials.tokenHash }).from(credentials).where(eq(credentials.id, w.bob.id)))[0]!.tokenHash.toString('base64'),
    accepts: { signin: true, issuers: [] }, principal: NEW,
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

test("the read moves with every part an add's decision weighs, its numbers too: what each adversary of Writing.tla's add changes changes its digest (ReadHeld, ReadByNumber)", { skip: POSTGRES }, async () => {
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
