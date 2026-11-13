import assert from 'node:assert/strict';
import { after, beforeEach, test } from 'node:test';

import { rowsOf } from '@coffre/db/dialect';
import { principals } from '@coffre/db/schema';
import { sql } from 'drizzle-orm';

import { change, drop, part, put } from '../src/change.ts';
import { pending, type Pending } from '../src/entry.ts';
import { CHECK_MS, KEEP, SignerHost, STOPPED_MS, storeOf, TICK_MS, type SignerAlert } from '../src/signer-host.ts';
import { emptyDatabase, objectStorage, openTestVault } from './database.ts';
import { principal, user } from './world.ts';

/**
 * What runs the signer, over a Durable Object's storage and alarm played
 * in memory, and Postgres: when it runs, what it sends of what a run
 * found, and what it does when its database, its storage or its alert
 * fails. The signer's own steps are signer.test.ts's.
 */
const vault = await openTestVault();
after(() => vault.close());

const [ada, bo, cy] = [user('ada'), user('bo'), user('cy')];
const named = (id: string) => JSON.stringify(['principals', id]);

let storage: ReturnType<typeof objectStorage>;
let host: SignerHost;
let alerts: SignerAlert[];
/** The database is out of reach, and the deployment's alert fails. */
const down = { database: false, alert: false };

/** A host over the storage, as the one a Durable Object makes each time it starts. */
const start = () =>
  new SignerHost({
    storage,
    alone: (run) => run(),
    keys: vault.keys,
    db: new Proxy(vault.db, {
      get(db, key) {
        if (down.database) throw new Error('the database is out of reach');
        return Reflect.get(db, key) as unknown;
      },
    }),
    now: vault.now,
    alert: (alert) => {
      if (down.alert) throw new Error('the alert could not be sent');
      alerts.push(alert);
    },
  });

beforeEach(async () => {
  await emptyDatabase(vault.owner);
  vault.woken.length = 0;
  storage = objectStorage();
  alerts = [];
  down.database = down.alert = false;
  host = start();
});

/** The vault tells the signer of what it committed, as it does after each commit. */
async function told(): Promise<void> {
  for (const hash of vault.woken.splice(0)) await host.wake(hash);
}
/** The alarm, as the runtime fires it: once it is due, and again while it is set for now. How often. */
async function fire(): Promise<number> {
  let fired = 0;
  while (storage.alarm !== null && storage.alarm <= vault.now()) {
    storage.alarm = null;
    await host.alarm();
    fired += 1;
  }
  return fired;
}
/** Told of everything, then a minute on: the check comes round. */
async function minute(): Promise<void> {
  await told();
  vault.tick(CHECK_MS);
  await fire();
}

async function member(id: string, role: string | null): Promise<void> {
  const result = await change(vault, {
    read: { found: part(principals, sql`id = ${id}`) },
    decide: ({ found: [was] }) => ({
      writes: [role === null ? drop(principals, was!) : put(principals, principal(id, { role }), was ?? null)],
      entry: { kept: true, action: 'member.role', actor: null, credential: null, request: null, ip: null, objects: [`principal:${id}`], detail: {} },
      answer: null,
    }),
  });
  assert.ok('answer' in result);
}
const reading = (key: string): Pending => pending(vault.keys[0]!, { kept: false, action: 'secret.read', actor: ada, credential: null, request: null, ip: null, objects: [`secret:${key}`], detail: {} }, vault.now(), []);
/** Entries committed as a use commits one, and the vault's word of each. */
async function wait(...entries: Pending[]): Promise<void> {
  const rows = JSON.stringify(entries.map(({ kept, body, mac }) => ({ kept, body, mac: mac.toString('hex') })));
  await vault.db.execute(sql`INSERT INTO log_pending (kept, body, mac) SELECT kept, body, decode(mac, 'hex') FROM jsonb_to_recordset(${rows}::jsonb) AS t(kept boolean, body text, mac text)`);
  for (const { hash } of entries) vault.wake(hash);
}
/** Entries that wait under no MAC of the vault's, as a writer plants them. */
const forge = (count: number) => vault.owner.execute(sql`INSERT INTO log_pending (kept, body, mac) SELECT false, '{}', decode(repeat('00', 36), 'hex') FROM generate_series(1, ${count})`);

const count = async (table: 'log' | 'log_pending') => (await rowsOf<{ n: number }>(vault.owner, sql`SELECT count(*)::int AS n FROM ${sql.identifier(table)}`))[0]!.n;

test('an entry is signed a second after the vault tells of it, and the check comes round each minute, told of anything or not', async () => {
  const opened = vault.now();
  await member(ada, 'owner');
  await member(bo, 'member');
  await told();
  // One alarm for the two, a second on, and nothing before it.
  assert.deepEqual([storage.alarm, storage.sets], [opened + TICK_MS, 1]);
  vault.tick(TICK_MS - 1);
  assert.equal(await fire(), 0);
  vault.tick(1);
  assert.equal(await fire(), 1);
  assert.deepEqual([await count('log'), await count('log_pending')], [2, 0]);

  // Then the check, a minute after the signer was first opened: no check has completed yet.
  assert.equal(storage.alarm, opened + CHECK_MS);
  vault.tick(CHECK_MS);
  assert.equal(await fire(), 1);
  assert.deepEqual(await host.status(), { checked: vault.now(), standing: [] });
  // And a minute after that one, with nothing told: the alarm is always set.
  assert.equal(storage.alarm, vault.now() + CHECK_MS);
  vault.tick(CHECK_MS);
  assert.equal(await fire(), 1);
  assert.equal(storage.alarm, vault.now() + CHECK_MS);
  assert.equal(alerts.length, 0);

  // An entry told of meanwhile brings the alarm forward, and the check keeps its minute.
  const checked = vault.now();
  vault.tick(10_000);
  await member(cy, 'member');
  await told();
  assert.equal(storage.alarm, vault.now() + TICK_MS);
  vault.tick(TICK_MS);
  assert.equal(await fire(), 1);
  assert.deepEqual([await count('log'), storage.alarm], [3, checked + CHECK_MS]);

  // An object that starts again keeps the alarm it finds: one set for sooner is not put off.
  await member(cy, 'owner');
  await told();
  host = start();
  await host.status();
  assert.equal(storage.alarm, vault.now() + TICK_MS);
});

test('a signer nobody told of anything checks once it is asked how it stands', async () => {
  assert.equal(storage.alarm, null);
  assert.deepEqual(await host.status(), { checked: vault.now(), standing: [] });
  assert.equal(storage.alarm, vault.now() + CHECK_MS);
  // A row written behind the vault, in a database no entry was ever written to.
  await vault.owner.insert(principals).values({ ...principal(ada, { role: 'owner' }), mac: Buffer.alloc(36) });
  vault.tick(CHECK_MS);
  await fire();
  assert.deepEqual(alerts.map((alert) => alert.findings), [[{ found: 'row', of: named(ada) }]]);
});

test('a row that is wrong is said when a check first finds it, and again only once a check has found it right in between', async () => {
  await member(ada, 'owner');
  await member(bo, 'member');
  await minute();
  assert.equal(alerts.length, 0);

  const [row] = await vault.owner.select().from(principals).where(sql`id = ${bo}`);
  await vault.owner.execute(sql`DELETE FROM principals WHERE id = ${bo}`);
  await minute();
  const finding = { found: 'row', of: named(bo) };
  assert.deepEqual(alerts.map((alert) => alert.findings), [[finding]]);
  assert.match(alerts[0]!.text, /^coffre's signer found what the vault did not write \(1\):\n- row \["principals","user:bo@acme\.example"\]: this row is not what the log says/);
  // Found again each minute, said once, by this host or the next one the object starts, with runs that check nothing in between.
  await minute();
  host = start();
  await wait(reading('a'));
  await told();
  vault.tick(TICK_MS);
  await fire();
  await minute();
  assert.equal(alerts.length, 1);
  assert.deepEqual((await host.status()).standing, [finding]);

  // Put back: nothing stands. Gone again: said again.
  await vault.owner.insert(principals).values(row!);
  await minute();
  assert.deepEqual([alerts.length, (await host.status()).standing], [1, []]);
  await vault.owner.execute(sql`DELETE FROM principals WHERE id = ${bo}`);
  await minute();
  assert.deepEqual(alerts.map((alert) => alert.findings), [[finding], [finding]]);
});

test('an alert that could not be sent is sent again after the next run, and what it says is let go only then', async (t) => {
  t.mock.method(console, 'error', () => {});
  await wait(reading('a'));
  await forge(1);
  down.alert = true;
  await told();
  vault.tick(TICK_MS);
  await fire();
  assert.deepEqual([await count('log'), await count('log_pending'), alerts.length], [1, 0, 0]);
  // A host that starts meanwhile finds them in the signer's storage.
  host = start();
  down.alert = false;
  await minute();
  assert.deepEqual(alerts.map((alert) => alert.findings), [[{ found: 'forged', of: 'pending:2' }]]);
  // Let go, in its storage too: the next host does not send it again.
  host = start();
  await minute();
  assert.equal(alerts.length, 1);
});

test('findings that pile up behind an alert that cannot be sent go to the log, and the signer keeps signing', async (t) => {
  const logged = t.mock.method(console, 'error', () => {});
  await host.status();
  // Four runs' worth and some: past what is kept by the fourth.
  await forge(4 * 256 + 76);
  down.alert = true;
  vault.tick(CHECK_MS);
  // A run a tile, one after the other at once, then the check that waited for them.
  assert.equal(await fire(), 6);
  assert.ok(4 * 256 > KEEP && 3 * 256 <= KEEP);
  const let_go = logged.mock.calls.filter(({ arguments: [text] }) => /They are let go/.test(String(text)));
  assert.equal(let_go.length, 1);
  assert.equal((let_go[0]!.arguments[1] as unknown[]).length, 4 * 256);
  assert.equal(await count('log_pending'), 0);
  down.alert = false;
  await minute();
  assert.deepEqual(alerts.map((alert) => alert.findings.length), [76]);
  assert.match(alerts[0]!.text, /\(76\):\n(- forged pending:\d+: .*\n){10}and 66 more$/);
});

test('a signer whose runs fail is said to be stopped, once, and again if it stops again', async (t) => {
  t.mock.method(console, 'error', () => {});
  await member(ada, 'owner');
  await minute();
  const checked = vault.now();
  assert.equal((await host.status()).checked, checked);

  /** A second at a time, as the alarm comes round when a run failed. */
  const seconds = async (count: number) => {
    for (let second = 0; second < count; second += 1) {
      vault.tick(TICK_MS);
      assert.equal(await fire(), 1);
    }
  };
  // The check comes round and fails, and a run is tried each second from then.
  down.database = true;
  vault.tick(CHECK_MS - TICK_MS);
  await seconds(1 + (STOPPED_MS - CHECK_MS) / TICK_MS);
  assert.equal(alerts.length, 0);
  await seconds(1);
  const stopped = { found: 'stopped', of: new Date(checked).toISOString() };
  assert.deepEqual(alerts.map((alert) => alert.findings), [[stopped]]);
  await seconds(120);
  assert.equal(alerts.length, 1);
  assert.deepEqual((await host.status()).standing, [stopped]);

  // Its database back, the check completes and nothing stands.
  down.database = false;
  await minute();
  assert.deepEqual([alerts.length, (await host.status()).standing], [1, []]);
  down.database = true;
  vault.tick(CHECK_MS - TICK_MS);
  await seconds(2 + (STOPPED_MS - CHECK_MS) / TICK_MS);
  assert.deepEqual(alerts.map((alert) => alert.findings.map((each) => each.found)), [['stopped'], ['stopped']]);
});

test('a check that fails is tried again a minute on, and what waits is signed meanwhile', async (t) => {
  const logged = t.mock.method(console, 'error', () => {});
  await member(ada, 'owner');
  await minute();
  const checked = vault.now();
  // The writer holds a table the check reads: the check gives up on its lock, 2 seconds on.
  let release!: () => void;
  const locked = vault.owner.transaction(async (tx) => {
    await tx.execute(sql`LOCK TABLE principals IN ACCESS EXCLUSIVE MODE`);
    await new Promise<void>((resolve) => (release = resolve));
  });
  try {
    await new Promise((resolve) => setTimeout(resolve, 100));
    await wait(reading('a'));
    await told();
    vault.tick(CHECK_MS);
    await fire();
    // What waited is signed all the same, and a run is tried again a second on.
    assert.equal(logged.mock.calls.length, 1);
    assert.deepEqual([await count('log'), (await host.status()).checked, storage.alarm], [2, checked, vault.now() + TICK_MS]);
    // The runs until the next minute do not try the check again: they wait for no lock.
    await wait(reading('b'));
    await told();
    vault.tick(TICK_MS);
    const from = Date.now();
    await fire();
    assert.ok(Date.now() - from < 1500, 'a run that checks nothing');
    assert.deepEqual([await count('log'), logged.mock.calls.length, storage.alarm], [3, 1, vault.now() - TICK_MS + CHECK_MS]);
  } finally {
    release();
    await locked;
  }
  vault.tick(CHECK_MS);
  await fire();
  assert.equal((await host.status()).checked, vault.now());
  assert.equal(alerts.length, 0);
});

test('a signer whose storage failed a step is opened again from its storage, and signs each entry once', async (t) => {
  const logged = t.mock.method(console, 'error', () => {});
  await member(ada, 'owner');
  await told();
  // A wake-up the storage refuses: the vault's call fails, and the signer in memory does nothing more.
  storage.down = true;
  await member(bo, 'member');
  await assert.rejects(told(), /storage is down/);
  // Nor does a run: it fails, and the alarm is set for the next.
  vault.tick(TICK_MS);
  assert.equal(await fire(), 1);
  assert.deepEqual([await count('log'), storage.alarm], [0, vault.now() + TICK_MS]);
  // Said once, as the run that failed: one that did nothing is not asked what it found.
  assert.deepEqual(logged.mock.calls.map(({ arguments: [text] }) => text), ['coffre: a run of the signer failed, and the next tries again']);

  storage.down = false;
  await member(cy, 'member');
  await told();
  vault.tick(TICK_MS);
  await fire();
  assert.deepEqual([await count('log'), await count('log_pending')], [3, 0]);

  // Storage that fails in the middle of a run: what it decided was not kept, so nothing moved, and the next run decides again.
  await member(cy, 'owner');
  await told();
  storage.refuses = 'moving';
  vault.tick(TICK_MS);
  await fire();
  assert.deepEqual([await count('log'), await count('log_pending')], [3, 1]);
  storage.refuses = null;
  vault.tick(TICK_MS);
  await fire();
  assert.deepEqual([await count('log'), await count('log_pending')], [4, 0]);
  await minute();
  assert.equal(alerts.length, 0);
});

test('more entries than a run takes are signed by runs one after the other, at once', async () => {
  await wait(...Array.from({ length: 300 }, (_, index) => reading(`key-${index}`)));
  await told();
  vault.tick(TICK_MS);
  storage.alarm = null;
  await host.alarm();
  assert.deepEqual([await count('log'), storage.alarm], [256, vault.now()]);
  assert.equal(await fire(), 1);
  assert.deepEqual([await count('log'), await count('log_pending')], [300, 0]);
  assert.equal(alerts.length, 0);
});

test('a step\'s changes are stored all of them or none', async () => {
  const store = storeOf(storage);
  await store.write(new Map<string, unknown>([['a', 1], ['b', 2]]));
  // And on disk before the step is done.
  assert.equal(storage.syncs, 1);
  storage.refuses = 'd';
  await assert.rejects(store.write(new Map<string, unknown>([['a', undefined], ['c', 3], ['d', 4]])), /refuses d/);
  assert.deepEqual([...(await store.read())], [['a', 1], ['b', 2]]);
  storage.refuses = null;
  await store.write(new Map<string, unknown>([['a', undefined], ['c', 3]]));
  assert.deepEqual([...(await store.read())], [['b', 2], ['c', 3]]);
});
