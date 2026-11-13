// `log_events` (migration 0086): the one function that writes events' rows, as the vault (`note`) and as the
// app (the events `prepare` signed, committed in the app's transaction, all of a request's in one call). The same event
// again answers its number; another under a written id, or a payload no event's of its id, is refused, and the call
// writes nothing.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';

import type { EventAuthor } from '@coffre/core/vault';
import { createDatabase, type Database, type Queryable } from '@coffre/db';
import { postgresClient } from '@coffre/db/connect';
import { sql, type SQL } from 'drizzle-orm';

import { logMacKey } from '../src/log-entry.ts';
import { eventRow } from '../src/note.ts';
import { APP_URL, openTestDatabase, rows, type TestDatabase } from './database.ts';

const KEY = logMacKey(Buffer.alloc(32, 0x11));

let db: TestDatabase;
let app: Database;
let closeApp: () => Promise<void>;
before(async () => {
  db = await openTestDatabase();
  const client = postgresClient(APP_URL, { max: 1 });
  closeApp = () => client.end();
  app = createDatabase(client);
});
after(async () => {
  await closeApp();
  await db.close();
});

const event = (id: string, action = 'project.create', actor = 'user:ada@acme.example') => ({
  id, requestId: randomUUID(), action, allowed: true, code: null, actor, subject: null,
  places: { projectId: null, environmentId: null, secretId: null, versionId: null }, credential: null, operationId: null, sourceIp: null, detail: {},
});
const signed = (input: ReturnType<typeof event>, author: EventAuthor = 'app') => eventRow(KEY, Date.now(), input, author);

/** Postgres's error code, under the query error the driver wraps it in. */
const failsWith = (code: string) => (error: Error) => (error.cause as { code?: string } | undefined)?.code === code;

/** One column's values as a Postgres array of `type`, one parameter each. */
const array = (values: readonly unknown[], type: string): SQL => sql`ARRAY[${sql.join(values.map((v) => sql`${v}`), sql`, `)}]::${sql.raw(type)}[]`;

/** The events written in one call, as the app's transaction's last statement writes them: their numbers, in order. */
async function write(login: Queryable, events: readonly ReturnType<typeof eventRow>[]): Promise<string[]> {
  const call = sql`SELECT CAST(log_events(${array(events.map((e) => e.requestId), 'text')}, ${array(events.map((e) => e.at), 'bigint')},
    ${array(events.map((e) => e.actor), 'text')}, ${array(events.map((e) => e.payload), 'text')}, ${array(events.map((e) => e.mac), 'bytea')}) AS text[]) AS numbers`;
  const [written] = await rows<{ numbers: string[] }>(login, call);
  return written!.numbers;
}

const count = async (ids: readonly string[]) => (await rows<{ n: number }>(db.owner, sql`SELECT count(*)::int AS n FROM log_changes WHERE request_id IN (${sql.join(ids.map((id) => sql`${id}`), sql`, `)})`))[0]!.n;

test('the vault and the app each write an event; the same event again answers its number', async () => {
  for (const [login, author] of [[db.vault, 'vault'], [app, 'app']] as const) {
    const row = signed(event(randomUUID()), author);
    const [number] = await write(login, [row]);
    assert.deepEqual(await write(login, [row]), [number]);
    // Signed again, at another time: the same event, its first row's number.
    assert.deepEqual(await write(login, [{ ...signed(event(row.requestId), author), payload: row.payload }]), [number]);
    const [stored] = await rows<{ object: string; seal: Buffer | null; payload: string }>(db.owner, sql`SELECT object::text AS object, seal, payload FROM log_changes WHERE number = ${number}`);
    assert.deepEqual(stored, { object: row.object, seal: null, payload: row.payload });
  }
});

// That the fence is taken once for the call is the function's code (one lock before its loop): `pg_locks` shows a lock held
// several times as one row, so this shows only that it is held, and shared.
test("a request's events are one call: numbered ascending in the order asked, under the fence held shared", async () => {
  const events = [signed(event(randomUUID(), 'project.create')), signed(event(randomUUID(), 'passkey.add')), signed(event(randomUUID(), 'identity.link'))];
  const numbers = await app.transaction(async (tx) => {
    const written = await write(tx, events);
    const locks = await rows<{ mode: string }>(tx, sql`SELECT mode FROM pg_locks
      WHERE locktype = 'advisory' AND classid = 1668244070 AND objid = 0 AND objsubid = 2 AND pid = pg_backend_pid()`);
    assert.deepEqual(locks.map((l) => l.mode), ['ShareLock']);
    return written;
  });
  assert.equal(numbers.length, 3);
  assert.ok(BigInt(numbers[0]!) < BigInt(numbers[1]!) && BigInt(numbers[1]!) < BigInt(numbers[2]!), numbers.join());
  const stored = await rows<{ request_id: string }>(db.owner, sql`SELECT request_id FROM log_changes WHERE number IN (${sql.join(numbers.map((n) => sql`${n}`), sql`, `)}) ORDER BY number`);
  assert.deepEqual(stored.map((r) => r.request_id), events.map((e) => e.requestId));
});

test('another event under a written id is refused, by its payload or its actor, and so is a payload filed under another id; the call writes nothing', async () => {
  const id = randomUUID();
  const first = signed(event(id));
  await write(app, [first]);
  const fresh = randomUUID();
  // The second event of the call is the refused one: the first, written before it, goes with it.
  await assert.rejects(write(app, [signed(event(fresh)), signed(event(id, 'project.rename'))]), failsWith('23505'));
  // The very row written, its payload and MAC unchanged, under another actor.
  await assert.rejects(write(app, [{ ...first, actor: 'user:bob@acme.example' }]), failsWith('23505'));
  const other = signed(event(randomUUID()));
  await assert.rejects(write(app, [{ ...other, requestId: randomUUID() }]), failsWith('22023'));
  assert.equal(await count([id, fresh]), 1);
});

test('the columns come as arrays of one length, at least one event', async () => {
  const row = signed(event(randomUUID()));
  const call = sql`SELECT log_events(${array([row.requestId], 'text')}, ${array([row.at, row.at], 'bigint')}, ${array([row.actor], 'text')}, ${array([row.payload], 'text')}, ${array([row.mac], 'bytea')})`;
  await assert.rejects(rows(app, call), failsWith('22023'));
  await assert.rejects(write(app, []), failsWith('22023'));
  assert.equal(await count([row.requestId]), 0);
});

test("a retry or a repeated id within one call answers its written number; a new event's ascend in the order asked", async () => {
  const old = signed(event(randomUUID()));
  const [written] = await write(app, [old]);
  const [a, retried, b] = await write(app, [signed(event(randomUUID())), old, signed(event(randomUUID()))]);
  assert.equal(retried, written);
  assert.ok(BigInt(written!) < BigInt(a!) && BigInt(a!) < BigInt(b!), [written, a, b].join());

  // The same event twice in one call: the second is a retry of the first.
  const twice = signed(event(randomUUID()));
  const [one, two] = await write(app, [twice, twice]);
  assert.equal(one, two);
  assert.equal(await count([twice.requestId]), 1);

  // The same id with another payload in one call: refused, and the call writes nothing.
  const id = randomUUID();
  await assert.rejects(write(app, [signed(event(id)), signed(event(id, 'project.rename'))]), failsWith('23505'));
  assert.equal(await count([id]), 0);
});

test('the same event written by two transactions at once: the second waits for the first and answers its number', async () => {
  const row = signed(event(randomUUID()));
  let release!: () => void;
  const held = new Promise<void>((resolve) => (release = resolve));
  let wrote!: (n: string) => void;
  const written = new Promise<string>((resolve) => (wrote = resolve));
  const first = db.vault.transaction(async (tx) => {
    const [n] = await write(tx, [row]);
    wrote(n!);
    await held;
    return n!;
  });
  const number = await written;
  const second = write(app, [row]);
  // The second's insert waits on the first's uncommitted row, under its unique request id.
  try {
    for (let waited = 0; ; waited += 20) {
      const [waiting] = await rows<{ n: number }>(db.owner, sql`SELECT count(*)::int AS n FROM pg_stat_activity
      WHERE datname = current_database() AND wait_event_type = 'Lock' AND query LIKE '%log_events%' AND usename = 'coffre_runtime'`);
      if (waiting!.n > 0) break;
      assert.ok(waited < 5_000, 'the second call never waited on the first');
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
  } finally {
    release();
  }
  assert.equal(await first, number);
  assert.deepEqual(await second, [number]);
  assert.equal(await count([row.requestId]), 1);
});
