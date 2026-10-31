// B2 (T167): a request's several keys as one vault call, `useMany`, one
// statement (`use_batch`, migration 0048) where each key had a call of its own,
// on both engines. Each case is named for what formal/Batching.tla holds of it;
// every key's use is `use_credential`'s, whose own guarantees use.test.ts holds.
// Every run's live answers are held to the replay of the log (R53).
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';

import { decrypt } from '@coffre/core/envelope';
import type { UseManyInput, UseManyOutcome, UseOutcome } from '@coffre/core/vault';
import { createDatabase, tablesOf, type Database } from '@coffre/db';
import { postgresClient } from '@coffre/db/connect';
import { sql } from 'drizzle-orm';

import type { Input } from '../src/inputs.ts';
import { newRequestId } from '../src/use.ts';
import { openVault, prepareVault } from '../src/vault.ts';
import { HOT_URL, openTestDatabase, postgresOnly, rows, run, type TestDatabase } from './database.ts';
import { ask, change, CONFIG, emptyLog, isolate, LOG_015, replayed, seal, useDatabases, world } from './use-world.ts';

let db: TestDatabase;
before(async () => {
  db = await openTestDatabase();
  await useDatabases(db);
});
after(() => db.close());
beforeEach(emptyLog);

/** Every live answer, by entry number: what the replay must say. */
const answered = new Map<string, UseOutcome>();
beforeEach(() => answered.clear());

/** A batch's answer, each value it handed back kept for the replay. */
function heard(outcome: UseManyOutcome): UseManyOutcome {
  if (outcome.ok) {
    for (const value of outcome.values) if (!value.covered) answered.set(value.number, { ok: true, ...value });
  } else if ('code' in outcome && outcome.number !== null) {
    answered.set(outcome.number, { ok: false, code: outcome.code, number: outcome.number });
  }
  return outcome;
}

/** A batch of `ids` as one request. */
function many(w: { credentialId: string }, ids: readonly string[], extra: Partial<UseManyInput> = {}): UseManyInput {
  const { secretId: _, place: __, requestId: ___, ...one } = ask(w, ids[0]!);
  return { ...one, items: ids.map((secretId) => ({ secretId, place: null, requestId: newRequestId() })), ...extra };
}

/** An isolate whose hot pool counts the statements it sends, and the vault over it (Postgres). */
async function counted(options: { batch?: number; before?: (n: number) => Promise<void> } = {}) {
  let statements = 0;
  let batches = 0;
  const client = postgresClient(HOT_URL, { max: 2 });
  const pool = new Proxy(client, {
    get(target, key) {
      const value: unknown = Reflect.get(target, key, target);
      if (key !== 'unsafe') return value;
      return (...args: unknown[]) => {
        statements += 1;
        const send = () => (value as (...a: unknown[]) => unknown).apply(target, args);
        // A hook before a batch's nth statement: what lands between its rounds.
        if (options.before === undefined || !String(args[0]).includes('use_batch(')) return send();
        return options.before(++batches).then(send);
      };
    },
  });
  const hot: Database = createDatabase(pool);
  const prepared = await prepareVault(CONFIG, { ...LOG_015, ...(options.batch === undefined ? {} : { uses: { batch: options.batch } }) });
  const vault = openVault(db.vault, prepared, hot);
  // The isolate's first call waits for the cutover's seal: made here, before anything is counted.
  await vault.about();
  return { useMany: (input: UseManyInput) => vault.useMany!(input), statements: () => statements, cache: prepared.uses, close: () => client.end() };
}

const opened = (outcome: UseManyOutcome) => {
  assert.ok(outcome.ok, JSON.stringify(outcome));
  return outcome.values.map(({ value }) => decrypt(
    { envelopeVersion: value.envelope.version, ciphertext: Buffer.from(value.envelope.ciphertext, 'base64'), iv: Buffer.from(value.envelope.iv, 'base64'), authTag: Buffer.from(value.envelope.authTag, 'base64') },
    value.context, Buffer.from(value.key, 'base64'),
  ).toString());
};

const count = async (table: string) => (await rows(db.owner, sql.raw(`SELECT 1 FROM ${table}`))).length;

test('a batch is one entry a key, every value opened, in the order asked; a first batch two calls, its keys entering the cap\'s set; the next one call', async () => {
  const w = await world();
  const ids = [await w.key('a'), await w.key('b'), await w.key('c')];
  const { vault } = await isolate();
  assert.deepEqual(opened(heard(await vault.useMany!(many(w, ids)))), ['a', 'b', 'c']);
  assert.equal(await count('log_uses'), 3);
  assert.equal(await count('log_bulk'), 3);
  // In the set now: each key's use takes no lock, and the batch is one call.
  assert.deepEqual(opened(heard(await vault.useMany!(many(w, [ids[2]!, ids[0]!], { purpose: 'reveal' })))), ['c', 'a']);
  assert.equal(await count('log_uses'), 5);
  assert.equal(await replayed(answered), 5);
});

test('one statement for every key, up to `limits.batch` (100): two with keys entering the set, one once they are in', postgresOnly('the hot pool counted'), async () => {
  const w = await world();
  const ids: string[] = [];
  for (let i = 0; i < 30; i += 1) ids.push(await w.key(`v${i}`));
  const isolate = await counted();
  try {
    const before = isolate.statements();
    assert.equal(opened(heard(await isolate.useMany(many(w, ids)))).length, 30);
    assert.equal(isolate.statements() - before, 2, 'round 1 decides, round 2 enters the 30 keys under the lock');
    const warm = isolate.statements();
    assert.equal(opened(heard(await isolate.useMany(many(w, ids)))).length, 30);
    assert.equal(isolate.statements() - warm, 1, 'every key fresh in the set: one statement');
    const two = isolate.statements();
    assert.equal(opened(heard(await isolate.useMany(many(w, ids.slice(0, 2))))).length, 2);
    assert.equal(isolate.statements() - two, 1);
  } finally {
    await isolate.close();
  }
  // The repeats, in the same isolate within a minute, ride the first batch's entries (covers): no entry of their own.
  assert.equal(await count('log_uses'), 30);
  assert.equal(await replayed(answered), 30);
});

test('CountsOwnBatch: each key counts the keys before it in its batch; past the cap, the batch is refused at the first key over it', async () => {
  const w = await world({ count: 3, windowMs: 15 * 60_000 });
  const ids = [await w.key(), await w.key(), await w.key(), await w.key(), await w.key()];
  const { vault, use } = await isolate();
  // One key in the set already: of the batch of four, two more fit.
  assert.ok((await use(ask(w, ids[0]!))).ok);
  const outcome = heard(await vault.useMany!(many(w, ids.slice(1))));
  assert.ok(!outcome.ok && 'code' in outcome, JSON.stringify(outcome));
  assert.deepEqual([outcome.index, outcome.code], [2, 'bulk_limit']);
  assert.notEqual(outcome.number, null, 'the request over the cap is logged, as a lone use over it is');
  // The cap holds: three keys in the set, never the batch's four on top of the one.
  assert.equal(await count('log_bulk'), 3);
  assert.equal(await count('log_uses'), 1 + 4, 'every request of the batch logged, the one past the cap and the one after it included');
  // The replay counts each of the batch's keys as it is numbered: the refusal it answered is the replay's too.
  assert.equal(await replayed(answered), 1);
});

test('AllDecidedFirst: a batch the vault refuses on its first call\'s rows enters no key in the set, takes no lock, and is answered at its first key refused', async () => {
  const w = await world();
  const fresh = await w.key();
  const ids = [fresh, await w.key(), await w.key()];
  const { vault, use } = await isolate();
  const first = await use(ask(w, fresh));
  assert.ok(first.ok);
  answered.set(first.number, first);
  // Her grant revoked: a change to the principal.
  const revoked = { ...(w.objects.principal as Extract<Input, { kind: 'principal' }>), grants: [] };
  await change({ kind: 'principal', id: w.principal }, { op: 'access.revoke', place: { projectId: w.project, environmentId: w.dev, environmentSlug: null } }, revoked, async (tx, value) => {
    await run(tx, sql`DELETE FROM vault_grants WHERE principal = ${w.principal}`);
    await seal('vault_members', 'principal', w.principal)(tx, value);
  });
  const outcome = heard(await vault.useMany!(many(w, ids)));
  // Its first key, in the set, is used and logged in the first call, refused; the others answered `decide`, written nothing.
  assert.ok(!outcome.ok && 'code' in outcome, JSON.stringify(outcome));
  assert.equal(outcome.index, 0);
  assert.equal(outcome.code, 'no_grant');
  assert.notEqual(outcome.number, null);
  assert.equal(await count('log_bulk'), 1, 'no key entered the set');
  assert.equal(await count('log_uses'), 2);
  // The same batch, its fresh key last: refused at its first key, which answered `decide`, logged nothing (the app logs
  // it); its fresh key's request is logged all the same, as every request of a first call that takes no lock is.
  const unlogged = heard(await vault.useMany!(many(w, [ids[1]!, ids[2]!, fresh])));
  assert.deepEqual(unlogged, { ok: false, index: 0, code: 'no_grant', number: null });
  assert.equal(await count('log_bulk'), 1);
  assert.equal(await count('log_uses'), 3);
  assert.equal(await replayed(answered), 2);
});

test('AnswerWhole: one key the rules refuse (another environment, no grant there) refuses the batch: no value of it goes back', async () => {
  const w = await world();
  const env = await environmentOf(w, 'staging');
  const ids = [await w.key('here'), await w.key('there', false, env)];
  const { vault } = await isolate();
  const outcome = heard(await vault.useMany!(many(w, ids)));
  assert.ok(!outcome.ok && 'code' in outcome, JSON.stringify(outcome));
  assert.equal(outcome.index, 1);
  assert.equal(outcome.code, 'no_grant');
  assert.equal(await count('log_bulk'), 0, 'refused on the first call\'s rows: nothing entered');
});

test('StrongestFirst: two batches of one principal\'s, each moving one key on and entering another, both answered, neither waiting on the other', postgresOnly('advisory locks'), async () => {
  const w = await world();
  const [moved, entered1, entered2] = [await w.key(), await w.key(), await w.key()];
  const { use } = await isolate();
  assert.ok((await use(ask(w, moved))).ok);
  // Its row from two periods back, still in the window: the next use moves it on, under the principal's lock shared.
  await run(db.owner, sql`UPDATE log_bulk SET last = last - 120000`);
  // The principal's lock held exclusive elsewhere, so that both batches' second calls queue on it, then go together.
  const holder = await db.connect(1);
  let release!: () => void;
  const released = new Promise<void>((resolve) => { release = resolve; });
  let locked!: () => void;
  const holding = new Promise<void>((resolve) => { locked = resolve; });
  const held = holder.transaction(async (tx) => {
    await run(tx, sql`SELECT pg_advisory_xact_lock(1668244066, hashtext(${w.principal}))`);
    locked();
    await released;
  });
  await holding;
  try {
    const [a, b] = [await isolate(), await isolate()];
    const first = a.vault.useMany!(many(w, [moved, entered1]));
    const second = b.vault.useMany!(many(w, [moved, entered2]));
    await waitForPrincipalLock(2);
    release();
    await held;
    const started = Date.now();
    const answers = await Promise.all([first, second]);
    // Shared for the move, then exclusive to enter: each would wait for the other until Postgres ended one (40P01),
    // after its deadlock_timeout, answered `late`.
    for (const answer of answers) assert.ok(heard(answer).ok, JSON.stringify(answer));
    assert.ok(Date.now() - started < 900, 'no deadlock waited out');
  } finally {
    release();
    await held.catch(() => {});
  }
  assert.equal(await count('log_bulk'), 3);
  assert.equal(await replayed(answered), 4);
});

test('one admission and one deadline for the batch: past it, busy, nothing written', async () => {
  const w = await world();
  const ids = [await w.key(), await w.key()];
  const { vault } = await isolate();
  const at = Date.now() - 4000;
  assert.deepEqual(await vault.useMany!(many(w, ids, { at, deadline: at + 3000 })), { ok: false, busy: 'late', retryAfter: 1 });
  assert.equal(await count('log_uses'), 0);
});

test('a batch names each key with a request id of its own, by ids alone', async () => {
  const w = await world();
  const id = await w.key();
  const { vault } = await isolate();
  const asked = many(w, [id, id]);
  await assert.rejects(vault.useMany!({ ...asked, items: [asked.items[0]!, asked.items[0]!] }), /request id of their own/);
  await assert.rejects(vault.useMany!({ ...asked, items: [] }), /a key at least/);
  await assert.rejects(vault.useMany!({ ...asked, items: [{ ...asked.items[0]!, secretId: 'KEY' }] }), /lowercase UUID/);
});

test('a replayed batch (its request ids again) writes nothing more: busy, its first answer\'s entries stand', postgresOnly('the request ids\' unique index'), async () => {
  const w = await world();
  const ids = [await w.key(), await w.key()];
  const { vault } = await isolate();
  const asked = many(w, ids);
  assert.ok(heard(await vault.useMany!(asked)).ok);
  // Another isolate, with no cover of these: the same requests again.
  const other = await isolate();
  assert.deepEqual(await other.vault.useMany!(asked), { ok: false, busy: 'replayed', retryAfter: 1 });
  assert.equal(await count('log_uses'), 2);
  assert.equal(await replayed(answered), 2);
});

test('a batch past `limits.batch` keys is made in statements of that many, in turn: each round so, every value', postgresOnly('the hot pool counted'), async () => {
  const w = await world();
  const ids: string[] = [];
  for (let i = 0; i < 5; i += 1) ids.push(await w.key(`v${i}`));
  const isolate = await counted({ batch: 2 });
  try {
    const before = isolate.statements();
    assert.deepEqual(opened(heard(await isolate.useMany(many(w, ids)))), ['v0', 'v1', 'v2', 'v3', 'v4']);
    assert.equal(isolate.statements() - before, 6, 'three statements a round, two rounds, the keys entering the set');
  } finally {
    await isolate.close();
  }
  assert.equal(await count('log_bulk'), 5);
  assert.equal(await replayed(answered), 5);
});

test('past its deadline, a batch sends none of its statements left, and lets go of its admission (review r3 of #433)', postgresOnly('the hot pool counted'), async () => {
  const w = await world();
  const ids: string[] = [];
  for (let i = 0; i < 5; i += 1) ids.push(await w.key());
  // Its first statement held until the deadline has passed: the request is answered `late` meanwhile.
  const isolate = await counted({ batch: 1, before: async (n) => { if (n === 1) await sleep(250); } });
  try {
    const at = Date.now() - 2900;
    const before = isolate.statements();
    assert.deepEqual(await isolate.useMany(many(w, ids, { at, deadline: at + 3000 })), { ok: false, busy: 'late', retryAfter: 1 });
    await sleep(400);
    assert.equal(isolate.statements() - before, 1, 'the statement in flight, and none after it');
    assert.equal(isolate.cache.inFlight, 0);
  } finally {
    await isolate.close();
  }
  assert.equal(await count('log_uses'), 0, 'its one statement, past the deadline by Postgres\'s clock, wrote nothing');
});

test('a batch answered `late` by its timer while the clock is still short of its deadline sends no statement after the one in flight (T170)', postgresOnly('the hot pool counted'), async (t) => {
  const w = await world();
  const ids: string[] = [];
  for (let i = 0; i < 3; i += 1) ids.push(await w.key());
  // Its first statement held until the race's timer, under the test's hand, has fired: seconds before the clock
  // reaches the deadline, as Node's may a ms or two before. The clock alone would let the next statements go.
  let sending = () => {};
  const sent = new Promise<void>((resolve) => (sending = resolve));
  let go = () => {};
  const held = new Promise<void>((resolve) => (go = resolve));
  const isolate = await counted({ batch: 1, before: async (n) => {
    if (n !== 1) return;
    sending();
    await held;
  } });
  try {
    const before = isolate.statements();
    t.mock.timers.enable({ apis: ['setTimeout'] });
    const at = Date.now();
    const answer = isolate.useMany(many(w, ids, { at, deadline: at + 3_000 }));
    await sent;
    t.mock.timers.tick(3_000);
    t.mock.timers.reset();
    assert.deepEqual(await answer, { ok: false, busy: 'late', retryAfter: 1 });
    go();
    await sleep(200);
    assert.ok(Date.now() < at + 3_000);
    assert.equal(isolate.statements() - before, 1, 'the statement in flight, and none after it');
    assert.equal(isolate.cache.inFlight, 0);
  } finally {
    await isolate.close();
  }
});

test('a batch refused on its second call\'s rows (her grant revoked between the calls) is refused there, each key\'s request logged and counted in the set, as lone uses would be', postgresOnly('the hot pool counted'), async () => {
  const w = await world();
  const ids = [await w.key(), await w.key()];
  const revoked = { ...(w.objects.principal as Extract<Input, { kind: 'principal' }>), grants: [] };
  // Between the first call, which decides both keys allowed, and the second, which takes the lock: the revoke.
  const isolate = await counted({
    before: async (n) => {
      if (n !== 2) return;
      await change({ kind: 'principal', id: w.principal }, { op: 'access.revoke', place: { projectId: w.project, environmentId: w.dev, environmentSlug: null } }, revoked, async (tx, value) => {
        await run(tx, sql`DELETE FROM vault_grants WHERE principal = ${w.principal}`);
        await seal('vault_members', 'principal', w.principal)(tx, value);
      });
    },
  });
  try {
    const outcome = heard(await isolate.useMany(many(w, ids)));
    assert.ok(!outcome.ok && 'code' in outcome, JSON.stringify(outcome));
    assert.deepEqual([outcome.index, outcome.code], [0, 'no_grant']);
    assert.notEqual(outcome.number, null, 'decided under the lock, on the rows of the call that wrote its entry');
  } finally {
    await isolate.close();
  }
  // Each key's request logged, refused, under the lock; and each counted in the set, as every request the cap does not
  // refuse is, whatever the rules decide (HotPathOne's bulk rows, which the replay recomputes alike).
  assert.equal(await count('log_uses'), 2);
  assert.equal(await count('log_bulk'), 2);
  assert.equal(await replayed(answered), 1);
});

/** Waits until `n` calls wait for the principal's lock (1668244066 and its hash). */
async function waitForPrincipalLock(n: number): Promise<void> {
  for (let i = 0; i < 200; i += 1) {
    const [row] = await rows<{ n: string }>(db.owner, sql`SELECT count(*) AS n FROM pg_locks l JOIN pg_database d ON d.oid = l.database
      WHERE d.datname = current_database() AND l.locktype = 'advisory' AND NOT l.granted AND l.objsubid = 2 AND l.classid = 1668244066`);
    if (Number(row!.n) >= n) return;
    await sleep(20);
  }
  throw new Error(`fewer than ${n} calls waited for the principal's lock`);
}

/** Another environment of the world's project, sealed, where it has no grant. */
async function environmentOf(w: { project: string }, slug: string): Promise<ReturnType<typeof randomUUID>> {
  const id = randomUUID();
  await db.owner.insert(tablesOf(db.owner).environments).values({ id, projectId: w.project, slug, name: slug, protected: false, owner: null, parentId: null });
  const object: Input = { kind: 'environment', id, projectId: w.project, slug, owner: null, parentId: null, protected: false, deleted: false, archived: false, projectArchived: false };
  await change({ kind: 'environment', id }, { op: 'genesis', value: object }, object, seal('environments', 'id', id));
  return id;
}
