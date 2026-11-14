import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { after, beforeEach, test } from 'node:test';

import { rowsOf } from '@coffre/db/dialect';
import { auditArchive, principals } from '@coffre/db/schema';
import { sql } from 'drizzle-orm';

import { change, drop, part, put } from '../src/change.ts';
import { pending, type Pending } from '../src/entry.ts';
import { keyOf } from '../src/rows.ts';
import { ADOPT_AGAIN_MS, ALERT_MS, CHECK_MS, KEEP, SignerHost, storeOf, STOPPED_MS, TICK_MS, type Hosting, type SignerAlert } from '../src/signer-host.ts';
import { adopt, adopted } from '../src/adopt.ts';
import { openLocalVault } from '../src/local.ts';
import { Signer } from '../src/signer.ts';
import { emptyDatabase, memoryStore, objectStorage, openTestVault } from './database.ts';
import { principal, tokenOf, user } from './world.ts';

/**
 * What runs the signer, over a Durable Object's storage and alarm played
 * in memory, and Postgres: when it runs, what it sends of what a run
 * found, and what it does when its database, its storage or its alert
 * fails. The signer's own steps are signer.test.ts's.
 */
const seed = randomBytes(32);
const vault = await openTestVault({ keys: [keyOf(seed)] });
after(() => vault.close());
const adopting = { keks: vault.keks, owners: ['root@acme.example'], signingKeys: [seed] };

const [ada, bo, cy] = [user('ada'), user('bo'), user('cy')];
const named = (id: string) => JSON.stringify(['principals', id]);

let storage: ReturnType<typeof objectStorage>;
let host: SignerHost;
let alerts: SignerAlert[];
/** The database is out of reach, and the deployment's alert fails. */
const down = { database: false, alert: false };
/** What the deployment's alert does before it returns, if anything. */
let sending: (() => void | Promise<void>) | null;

/** A host over the storage, as the one a Durable Object makes each time it starts. */
const start = (alone: Hosting['alone'] = (run) => run()) =>
  new SignerHost({
    storage,
    alone,
    keys: vault.keys,
    db: new Proxy(vault.db, {
      get(db, key) {
        if (down.database) throw new Error('the database is out of reach');
        return Reflect.get(db, key) as unknown;
      },
    }),
    now: vault.now,
    keepUsesDays: 90,
    adopting,
    alert: async (alert) => {
      if (down.alert) throw new Error('the alert could not be sent');
      await sending?.();
      alerts.push(alert);
    },
  });

beforeEach(async () => {
  await emptyDatabase(vault.owner);
  vault.woken.length = 0;
  storage = objectStorage();
  alerts = [];
  down.database = down.alert = false;
  sending = null;
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

const count = async (table: string) => (await rowsOf<{ n: number }>(vault.owner, sql`SELECT count(*)::int AS n FROM ${sql.identifier(table)}`))[0]!.n;

test('an entry is signed a second after the vault tells of it, and the check comes round each minute, told of anything or not', async () => {
  const opened = vault.now();
  await member(ada, 'owner');
  await member(bo, 'member');
  await told();
  // One alarm for the two, a second on, and nothing before it. Each step on disk before it is done: the opening, and the two wake-ups.
  assert.deepEqual([storage.alarm, storage.sets, storage.syncs], [opened + TICK_MS, 1, 3]);
  vault.tick(TICK_MS - 1);
  assert.equal(await fire(), 0);
  vault.tick(1);
  assert.equal(await fire(), 1);
  assert.deepEqual([await count('log'), await count('log_pending')], [2, 0]);

  // Then the check, a minute after the signer was first opened: no check has completed yet.
  assert.equal(storage.alarm, opened + CHECK_MS);
  vault.tick(CHECK_MS);
  assert.equal(await fire(), 1);
  assert.deepEqual(await host.status(), { checked: vault.now(), standing: [], adopted: true, adoption: null });
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

test('before the adoption, a signer asked how it stands checks nothing and says nothing, however long; adopted, it checks', async () => {
  assert.equal(storage.alarm, null);
  assert.deepEqual(await host.status(), { checked: vault.now(), standing: [], adopted: false, adoption: null });
  assert.equal(storage.alarm, vault.now() + CHECK_MS);
  // A row as the migration from 0.14 leaves it, with no MAC: a check would find it, and every other.
  await vault.owner.insert(principals).values({ ...principal(ada, { role: 'owner' }), mac: Buffer.alloc(0) });
  for (let minutes = 0; minutes < 10; minutes += 1) {
    vault.tick(CHECK_MS);
    assert.equal(await fire(), 1);
  }
  assert.deepEqual([alerts, await host.status()], [[], { checked: vault.now() - 10 * CHECK_MS, standing: [], adopted: false, adoption: null }]);
  assert.equal(storage.alarm, vault.now() + CHECK_MS);
  // Adopted, the row is the vault's; one written behind it after is found by the next check.
  assert.equal(await host.adopt(), true);
  await vault.owner.insert(principals).values({ ...principal(bo), mac: Buffer.alloc(36) });
  vault.tick(CHECK_MS);
  await fire();
  assert.deepEqual(alerts.map((alert) => alert.findings), [[{ found: 'row', of: named(bo) }]]);
});

test('a host whose storage could not give its alarm as it started asks again: the alarm set for sooner stays', async () => {
  await member(ada, 'owner');
  await told();
  const set = storage.alarm;
  assert.equal(set, vault.now() + TICK_MS);
  // The object starts again, and its storage fails once.
  host = start();
  const { getAlarm } = storage;
  storage.getAlarm = () => Promise.reject(new Error('the alarm cannot be read'));
  await assert.rejects(host.status(), /the alarm cannot be read/);
  storage.getAlarm = getAlarm;
  await host.status();
  assert.equal(storage.alarm, set);
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
  assert.match(alerts[0]!.text, /^coffre's signer reports \(1\):\n- row \["principals","user:bo@acme\.example"\]: this row is not what the log says/);
  // Wrong at each check since, said once, by this host or the next one the object starts, with runs that check nothing in between.
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

test('a row found wrong while the alert failed, and right by the next check, is said once and does not stand; wrong again, it is said again', async (t) => {
  t.mock.method(console, 'error', () => {});
  await member(ada, 'owner');
  await member(bo, 'member');
  await minute();
  const [row] = await vault.owner.select().from(principals).where(sql`id = ${bo}`);
  const finding = { found: 'row', of: named(bo) };

  await vault.owner.execute(sql`DELETE FROM principals WHERE id = ${bo}`);
  down.alert = true;
  await minute();
  // It stands, sent or not.
  assert.deepEqual([alerts.length, (await host.status()).standing], [0, [finding]]);
  await vault.owner.insert(principals).values(row!);
  down.alert = false;
  await minute();
  assert.deepEqual([alerts.map((alert) => alert.findings), (await host.status()).standing], [[[finding]], []]);
  await vault.owner.execute(sql`DELETE FROM principals WHERE id = ${bo}`);
  await minute();
  assert.deepEqual([alerts.map((alert) => alert.findings), (await host.status()).standing], [[[finding], [finding]], [finding]]);

  // Put right and wrong again, twice over while alerts fail: it waits as one finding.
  down.alert = true;
  for (let times = 0; times < 2; times += 1) {
    await vault.owner.insert(principals).values(row!);
    await minute();
    await vault.owner.execute(sql`DELETE FROM principals WHERE id = ${bo}`);
    await minute();
  }
  down.alert = false;
  await minute();
  assert.deepEqual(alerts.map((alert) => alert.findings), [[finding], [finding], [finding]]);
});

test('a row said, then found right by a check whose alert failed, is said again when it is wrong again', async (t) => {
  t.mock.method(console, 'error', () => {});
  await member(ada, 'owner');
  await member(bo, 'member');
  await minute();
  const [row] = await vault.owner.select().from(principals).where(sql`id = ${bo}`);
  const finding = { found: 'row', of: named(bo) };
  await vault.owner.execute(sql`DELETE FROM principals WHERE id = ${bo}`);
  await minute();
  assert.deepEqual(alerts.map((alert) => alert.findings), [[finding]]);

  // Put right, in a minute that finds something else, with the alert down.
  await vault.owner.insert(principals).values(row!);
  await forge(1);
  down.alert = true;
  await minute();
  assert.deepEqual([alerts.length, (await host.status()).standing], [1, []]);
  await vault.owner.execute(sql`DELETE FROM principals WHERE id = ${bo}`);
  down.alert = false;
  await minute();
  assert.deepEqual(alerts.at(-1)!.findings.map((each) => each.found), ['forged', 'row']);
});

test('rows that stay wrong while alerts fail wait once each, however long: they are sent, and not let go to the log', async (t) => {
  const logged = t.mock.method(console, 'error', () => {});
  await member(ada, 'owner');
  await minute();
  const planted = ['p', 'q', 'r', 's', 't'].map(user);
  await vault.owner.insert(principals).values(planted.map((id) => ({ ...principal(id, { role: 'member' }), mac: Buffer.alloc(36) })));
  down.alert = true;
  // Enough checks for five rows a minute to pass what is kept.
  for (let checks = 0; checks < KEEP / planted.length + 2; checks += 1) await minute();
  assert.equal((storage.kv.get('found') as unknown[]).length, planted.length);
  assert.equal(logged.mock.calls.filter(({ arguments: [text] }) => /They are let go/.test(String(text))).length, 0);
  down.alert = false;
  await minute();
  assert.deepEqual(alerts.map((alert) => alert.findings.map((each) => each.of).sort()), [planted.map(named).sort()]);
});

test('the alarm for the next run is set before an alert is sent, and an alert that does not return has failed', { timeout: 30_000 }, async (t) => {
  t.mock.method(console, 'error', () => {});
  await wait(reading('a'));
  await forge(1);
  await told();
  vault.tick(TICK_MS);
  // The vault tells of another entry while the alert is on its way: the alarm, set for the next check, is brought forward.
  const seen: (number | null)[] = [];
  sending = async () => {
    seen.push(storage.alarm);
    await wait(reading('b'));
    await told();
    seen.push(storage.alarm);
  };
  const opened = vault.now() - TICK_MS;
  await fire();
  assert.deepEqual(seen, [opened + CHECK_MS, vault.now() + TICK_MS]);
  assert.equal(alerts.length, 1);

  // One that hangs: the run is done with, and the finding waits for the next.
  await forge(1);
  sending = () => new Promise(() => {});
  vault.tick(TICK_MS);
  const from = Date.now();
  await fire();
  assert.ok(Date.now() - from >= ALERT_MS - 100 && Date.now() - from < ALERT_MS + 2000);
  assert.deepEqual([await count('log'), await count('log_pending'), alerts.length], [2, 0, 1]);
  sending = null;
  await minute();
  assert.deepEqual(alerts.map((alert) => alert.findings), [[{ found: 'forged', of: 'pending:2' }], [{ found: 'forged', of: 'pending:4' }]]);
});

test('with no alert configured, what is found goes to the log, once', async (t) => {
  const logged = t.mock.method(console, 'error', () => {});
  host = new SignerHost({ storage, alone: (run) => run(), keys: vault.keys, db: vault.db, now: vault.now, keepUsesDays: 90, adopting });
  await host.status();
  await forge(1);
  vault.tick(CHECK_MS);
  await fire();
  vault.tick(CHECK_MS);
  await fire();
  assert.deepEqual(logged.mock.calls.map(({ arguments: [text] }) => text), ["coffre's signer reports (1):\n- forged pending:1: an entry that waited to be signed was not the vault's. Removed\n(no alert is configured: the vault's `alert`)"]);
});

test('an alarm that cannot be set is thrown, for the runtime to fire this one again', async () => {
  await member(ada, 'owner');
  await told();
  vault.tick(TICK_MS);
  storage.alarm = null;
  storage.noAlarm = true;
  await assert.rejects(host.alarm(), /cannot be set/);
  // The run was done; the runtime's next try does another, and sets it.
  assert.equal(await count('log'), 1);
  storage.noAlarm = false;
  await host.alarm();
  assert.equal(storage.alarm, vault.now() - TICK_MS + CHECK_MS);
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

test('findings that pile up behind an alert that cannot be sent go to the log, and the signer keeps signing; what stands is said once alerts go again', async (t) => {
  const logged = t.mock.method(console, 'error', () => {});
  // Adopted, empty: its checks run from then on.
  assert.equal(await host.adopt(), true);
  // A row written behind the vault, which every check finds, and four runs' worth of forged entries and some.
  await vault.owner.insert(principals).values({ ...principal(ada, { role: 'owner' }), mac: Buffer.alloc(36) });
  await forge(4 * 256 + 76);
  down.alert = true;
  vault.tick(CHECK_MS);
  // A run a tile, one after the other at once, then the check that waited for them.
  assert.equal(await fire(), 6);
  // Past what is kept by the fourth: to the log, all of them, and let go.
  assert.ok(4 * 256 > KEEP && 3 * 256 <= KEEP);
  const letGo = logged.mock.calls.filter(({ arguments: [text] }) => /They are let go/.test(String(text)));
  assert.equal(letGo.length, 1);
  assert.equal((letGo[0]!.arguments[1] as unknown[]).length, 4 * 256);
  assert.equal(await count('log_pending'), 0);

  // The check found the row, and its alert failed: not let go.
  const finding = { found: 'row', of: named(ada) };
  assert.deepEqual((await host.status()).standing, [finding]);
  down.alert = false;
  await minute();
  assert.deepEqual(alerts.map((alert) => [alert.findings.length, alert.findings.at(-1)]), [[77, finding]]);
  assert.match(alerts[0]!.text, /\(77\):\n(- forged pending:\d+: .*\n){10}and 67 more$/);
  assert.deepEqual((await host.status()).standing, [finding]);
});

test('a row that went to the log with the findings piled up before it is not marked as said: the next check says it, once alerts go again', async (t) => {
  const logged = t.mock.method(console, 'error', () => {});
  // Adopted, empty: its checks run from then on.
  assert.equal(await host.adopt(), true);
  // As many forged entries as are kept, which wait for the alert, then the check's row: one more than is kept.
  await vault.owner.insert(principals).values({ ...principal(ada, { role: 'owner' }), mac: Buffer.alloc(36) });
  await forge(KEEP);
  down.alert = true;
  vault.tick(CHECK_MS);
  await fire();
  const finding = { found: 'row', of: named(ada) };
  const letGo = logged.mock.calls.filter(({ arguments: [text] }) => /They are let go/.test(String(text)));
  assert.equal(letGo.length, 1);
  const inLog = letGo[0]!.arguments[1] as unknown[];
  assert.deepEqual([inLog.length, inLog.at(-1)], [KEEP + 1, finding]);

  down.alert = false;
  await minute();
  assert.deepEqual(alerts.map((alert) => alert.findings), [[finding]]);
  assert.deepEqual((await host.status()).standing, [finding]);
  await minute();
  assert.equal(alerts.length, 1);
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
  // Said once, by this host or the next the object starts.
  await seconds(60);
  host = start();
  await seconds(60);
  assert.equal(alerts.length, 1);
  assert.deepEqual((await host.status()).standing, [stopped]);
  assert.match(alerts[0]!.text, /^coffre's signer reports \(1\):\n- stopped \d{4}-.*Z: the signer has completed no check/);

  // Its database back, the check completes and nothing stands.
  down.database = false;
  await minute();
  assert.deepEqual([alerts.length, (await host.status()).standing], [1, []]);
  down.database = true;
  vault.tick(CHECK_MS - TICK_MS);
  await seconds(2 + (STOPPED_MS - CHECK_MS) / TICK_MS);
  assert.deepEqual(alerts.map((alert) => alert.findings.map((each) => each.found)), [['stopped'], ['stopped']]);

  // Its database back while alerts fail: the check completes, what it found waits, and the next stop is news all the same.
  down.database = false;
  down.alert = true;
  await forge(1);
  await minute();
  down.database = true;
  vault.tick(CHECK_MS - TICK_MS);
  await seconds(2 + (STOPPED_MS - CHECK_MS) / TICK_MS);
  down.alert = false;
  await seconds(1);
  assert.deepEqual(alerts.map((alert) => alert.findings.map((each) => each.found)), [['stopped'], ['stopped'], ['forged', 'stopped']]);
  await seconds(60);
  assert.equal(alerts.length, 3);
});

test('that it is stopped, gone to the log with findings piled up behind an alert that cannot be sent, is not marked as said: it is said once alerts go again', async (t) => {
  const logged = t.mock.method(console, 'error', () => {});
  await member(ada, 'owner');
  await minute();
  // As many findings as are kept wait for the alert.
  down.alert = true;
  await forge(KEEP);
  vault.tick(CHECK_MS);
  await fire();
  const checked = vault.now();
  assert.equal((await host.status()).checked, checked);

  // The writer holds a table the check reads: the check that comes round fails, and none has completed for as long as one may take.
  let release!: () => void;
  const locked = vault.owner.transaction(async (tx) => {
    await tx.execute(sql`LOCK TABLE principals IN ACCESS EXCLUSIVE MODE`);
    await new Promise<void>((resolve) => (release = resolve));
  });
  try {
    await new Promise((resolve) => setTimeout(resolve, 100));
    vault.tick(STOPPED_MS);
    assert.equal(await fire(), 1);
    // A second on, a run that checks nothing signs: one finding more than is kept, and the signer is stopped.
    await forge(1);
    vault.tick(TICK_MS);
    assert.equal(await fire(), 1);
    const stopped = { found: 'stopped', of: new Date(checked).toISOString() };
    const letGo = logged.mock.calls.filter(({ arguments: [text] }) => /They are let go/.test(String(text)));
    assert.equal(letGo.length, 1);
    const inLog = letGo[0]!.arguments[1] as unknown[];
    assert.deepEqual([inLog.length, inLog.at(-1)], [KEEP + 2, stopped]);

    // Alerts go again, and the next run says it, before any check completes; the one after does not.
    down.alert = false;
    for (const key of ['a', 'b']) {
      await wait(reading(key));
      await told();
      vault.tick(TICK_MS);
      assert.equal(await fire(), 1);
      assert.deepEqual(alerts.map((alert) => alert.findings), [[stopped]]);
    }
  } finally {
    release();
    await locked;
  }
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

// The adoption (adopt.ts), as the vault's first call has the signer's object make it.

/** The vault in process over the suite's database, of a deployment that names Root an Owner: what the vault Worker serves. */
const served = () => openLocalVault(vault.db, { ...vault, owners: adopting.owners }, { wake: vault.wake, now: vault.now });
const signin = (email: string) =>
  served().change({ op: 'signin', request: null, ip: null, account: { provider: 'github', issuer: 'github', subject: email, emails: [email] }, session: { token: tokenOf(email).toString('hex'), minutes: 60, label: null }, replaces: null });
const actions = async (table: 'log' | 'log_pending') => (await rowsOf<{ action: string }>(vault.owner, sql`SELECT body::jsonb ->> 'action' AS action FROM ${sql.identifier(table)} ORDER BY 1`)).map(({ action }) => action);
/** The object's `blockConcurrencyWhile`: one at a time, in the order asked. */
function serially(): <T>(run: () => Promise<T>) => Promise<T> {
  let last: Promise<unknown> = Promise.resolve();
  return (run) => {
    const next = last.then(run);
    last = next.catch(() => {});
    return next;
  };
}

test('the first call adopts an empty database for the signer, which has signed its entry when it answers; after, it answers from memory', async () => {
  assert.deepEqual(await signin('root@acme.example'), { refused: 'adopting' });
  assert.equal(await host.adopt(), true);
  // The Owners the configuration names, the log's first entry signed, and the head that says so.
  assert.deepEqual(await rowsOf(vault.owner, sql`SELECT id, role FROM principals`), [{ id: user('root'), role: 'owner' }]);
  assert.deepEqual([await actions('log'), await actions('log_pending'), await adopted(vault.db)], [['vault.adopt'], [], true]);
  assert.deepEqual(await host.status(), { checked: vault.now(), standing: [], adopted: true, adoption: null });
  assert.ok('answer' in (await signin('root@acme.example')));
  // Nothing more is read: the database could be gone.
  down.database = true;
  assert.equal(await host.adopt(), true);
  down.database = false;
  // A change after it is held to the mirror the adoption filled: no `rewritten`, and the check finds every row right.
  await member(ada, 'member');
  await minute();
  await minute();
  assert.deepEqual(alerts, []);
});

test('first calls at once adopt once, one after the other: each after the first finds the database adopted', async (t) => {
  const logged = t.mock.method(console, 'error', () => {});
  host = start(serially());
  assert.deepEqual(await Promise.all([host.adopt(), host.adopt(), host.adopt()]), [true, true, true]);
  assert.deepEqual([await actions('log'), await actions('log_pending'), (await host.status()).adoption, logged.mock.callCount()], [['vault.adopt'], [], null, 0]);
  // One signer signed it, once: its next changes and checks find nothing.
  await member(ada, 'member');
  await minute();
  await minute();
  assert.deepEqual(alerts, []);
});

test('a database whose adoption fails is left as it was, answered `adopting`, said in the log and the status, and tried again a while on', async (t) => {
  const logged = t.mock.method(console, 'error', () => {});
  // 0.14's newest policy.change, in the vault's name and under no MAC of its own.
  const fields = { seq: 1n, author: 'vault', keyId: 'vault:0000000000000000', occurredAt: Date.UTC(2026, 9, 1), actor: ada, action: 'policy.change', decision: 'allow', code: null, subjectPrincipal: null, projectId: null, environmentId: null, secretId: null, secretVersionId: null, operationId: null, requestId: null, sourceIp: null, relatedSeq: null, metadata: '{"policy":{"roles":{},"instanceRoles":{},"protected":[]}}' };
  await vault.owner.insert(auditArchive).values({ ...fields, prevHash: Buffer.alloc(32), mac: Buffer.alloc(32), hash: Buffer.alloc(32) });
  assert.equal(await host.adopt(), false);
  assert.deepEqual([await count('log'), await count('log_pending'), await rowsOf(vault.owner, sql`SELECT count(*)::int AS n FROM policy UNION ALL SELECT count(*)::int FROM principals`)], [0, 0, [{ n: 0 }, { n: 0 }]]);
  const { adoption } = await host.status();
  assert.match(adoption!.error, /policy\.change, entry 1 of audit_archive, does not carry its vault's MAC/);
  assert.equal(adoption!.at, vault.now());
  assert.match(String(logged.mock.calls[0]!.arguments[0]), /did not adopt its database/);
  assert.deepEqual(await signin('root@acme.example'), { refused: 'adopting' });
  // It returned: a host that starts over the same storage tries again, and does not take it for one a reset cut off.
  const again = start();
  assert.equal(await again.adopt(), false);
  assert.match((await again.status()).adoption!.error, /does not carry its vault's MAC/);
  assert.equal(logged.mock.callCount(), 2);

  // Fixed: tried again by the first call a while on, not before.
  await vault.owner.execute(sql`DELETE FROM audit_archive`);
  vault.tick(ADOPT_AGAIN_MS - 1);
  assert.equal(await host.adopt(), false);
  assert.equal(logged.mock.callCount(), 2);
  vault.tick(1);
  assert.equal(await host.adopt(), true);
  assert.deepEqual([await actions('log'), (await host.status()).adoption], [['vault.adopt'], null]);
});

test('a log emptied under a signer that has signed is not adopted again: the planted Owner is no member, nobody signs in, and the check finds the log cut', async () => {
  assert.equal(await host.adopt(), true);
  await member(ada, 'member');
  await minute();
  // The writer empties the log, the policy and the roles, and plants an Owner. The object starts again.
  await vault.owner.execute(sql`TRUNCATE log, log_index, log_tiles, log_head, log_pending, policy, roles`);
  await vault.owner.insert(principals).values({ ...principal(user('mallory'), { role: 'owner' }), mac: Buffer.alloc(0) });
  host = start();
  assert.equal(await host.adopt(), true);
  assert.deepEqual([await actions('log_pending'), await count('policy')], [[], 0]);
  assert.deepEqual(await signin('mallory@acme.example'), { refused: 'adopting' });
  vault.tick(CHECK_MS);
  await fire();
  assert.deepEqual(new Set(alerts.flatMap((alert) => alert.findings.map(({ found }) => found))), new Set(['row', 'cut']));
});

test('a log emptied under a signer told of the adoption, before it signed: refused, loudly, at every try', async (t) => {
  const logged = t.mock.method(console, 'error', () => {});
  // The adoption commits and tells the signer, and the object stops before it signs.
  assert.equal(await adopt(await Signer.open({ db: vault.db, keys: vault.keys, now: vault.now, store: storeOf(storage), keepUsesDays: 90 }), vault, adopting), true);
  // The writer deletes the entry, and what the adoption wrote, and plants an Owner.
  await vault.owner.execute(sql`TRUNCATE log_pending, policy, roles, principals CASCADE`);
  await vault.owner.insert(principals).values({ ...principal(user('mallory'), { role: 'owner' }), mac: Buffer.alloc(0) });
  host = start();
  assert.equal(await host.adopt(), false);
  assert.match((await host.status()).adoption!.error, /the database shows no log, and its signer has signed one or is told of one: someone emptied it/);
  // And a head that counts an entry, which the signer did not sign: no word of the database's says it is adopted.
  await vault.owner.execute(sql`INSERT INTO log_head (only_row, size, kept_size, kept_root, aging_size, aging_root, aging_from, signed_at, mac) VALUES (true, 1, 1, decode(repeat('00', 32), 'hex'), 0, decode(repeat('00', 32), 'hex'), 0, now(), decode(repeat('00', 36), 'hex'))`);
  vault.tick(ADOPT_AGAIN_MS);
  assert.equal(await host.adopt(), false);
  assert.match((await host.status()).adoption!.error, /the database's log is begun, and its signer has signed none of it/);
  assert.equal(logged.mock.calls.filter(({ arguments: [text] }) => String(text).includes('did not adopt')).length, 2);
  // What the signer was told of is gone: said by its next alarm.
  vault.tick(CHECK_MS);
  await fire();
  assert.deepEqual(alerts.flatMap((alert) => alert.findings.map(({ found }) => found)), ['missing']);
  assert.deepEqual([await count('log_pending'), await count('policy'), await rowsOf(vault.owner, sql`SELECT octet_length(mac) AS n FROM principals`)], [0, 0, [{ n: 0 }]]);
  assert.deepEqual(await signin('mallory@acme.example'), { refused: 'adopting' });
});

test('an object that stopped between the adoption\'s commit and its first signature has it signed by the next call, with no finding', async () => {
  assert.equal(await adopt(await Signer.open({ db: vault.db, keys: vault.keys, now: vault.now, store: storeOf(storage), keepUsesDays: 90 }), vault, adopting), true);
  // Between the two, its first entry waits: the vault Worker serves nothing until the signer says it is signed.
  assert.equal(await adopted(vault.db), false);
  host = start();
  assert.equal(await host.adopt(), true);
  assert.deepEqual([await actions('log'), await actions('log_pending')], [['vault.adopt'], []]);
  await member(ada, 'member');
  await minute();
  await minute();
  assert.deepEqual(alerts, []);
});

test('or by its alarm, though its word of the entry was lost; and an adoption whose signature fails answers no until the alarm signs it', async (t) => {
  t.mock.method(console, 'error', () => {});
  // Told no signer: its storage is blank, and the entry waits.
  assert.equal(await adopt(await Signer.open({ db: vault.db, keys: vault.keys, now: vault.now, store: memoryStore(), keepUsesDays: 90 }), vault, adopting), true);
  storage.alarm = vault.now();
  await fire();
  assert.deepEqual([await actions('log'), (await host.status()).adopted], [['vault.adopt'], true]);
  await member(ada, 'member');
  await minute();
  await minute();
  assert.deepEqual(alerts, []);

  // Again, from nothing: the signature's step cannot be stored. The call is answered no, and the alarm, set before the adoption, signs it.
  await emptyDatabase(vault.owner);
  storage = objectStorage();
  host = start();
  storage.refuses = 'moving';
  assert.equal(await host.adopt(), false);
  assert.deepEqual([await actions('log'), await actions('log_pending'), (await host.status()).adopted], [[], ['vault.adopt'], false]);
  storage.refuses = null;
  vault.tick(TICK_MS);
  await fire();
  assert.deepEqual([await actions('log'), await host.adopt()], [['vault.adopt'], true]);
  await minute();
  assert.deepEqual(alerts, []);
});
