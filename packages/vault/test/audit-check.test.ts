// The audit page's check, flat (T277; audit-check.ts; state-rows.md, section 4, "What a visit's check catches"): one
// test per row of that table a visit catches, for a database writer with no key, and its cost, one statement at two
// sizes of the log.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';

import { deriveLogKey, GENESIS_HASH, sealEntry, type LogFields } from '@coffre/core/audit';
import { decodePair } from '@coffre/core/merkle';
import type { AuditCursorRow, AuditEventRow, CheckInput } from '@coffre/core/vault';
import { defineDeployment } from '@coffre/core/deployment';
import { KekRegistry, LocalKekProvider } from '@coffre/core/kek';
import { createDatabase, type Database, type Queryable } from '@coffre/db';
import { postgresClient } from '@coffre/db/connect';
import { sql } from 'drizzle-orm';

import { CHECK_TAIL_ENTRIES, checkAudit } from '../src/audit-check.ts';
import { cursorMac, eventMac, type AuditEvent } from '../src/audit-rows.ts';
import { openLogCheckpointer } from '../src/log-checkpointer.ts';
import { entryMac, logMacKey, type LogMacKey } from '../src/log-entry.ts';
import { logStore } from '../src/log-store.ts';
import { ANCHOR_OBJECT, anchorPayload, UPGRADE_ACTOR, UPGRADE_REQUESTS } from '../src/upgrade.ts';
import { verifierKeys } from '../src/verifier.ts';
import { variableMemory } from './audit-tree.ts';
import { logWriter } from './log-entries.ts';
import { emptyDatabase, openLocalVault, openTestDatabase, rows, run, sealed, VAULT_URL, withTriggersLifted, type TestDatabase } from './database.ts';

let db: TestDatabase;
before(async () => {
  db = await openTestDatabase();
});
after(() => db.close());
beforeEach(async () => {
  for (const table of ['log_uses', 'bulk_cap', 'log_checkpoints', 'log_tiles', 'log_changes']) await run(db.owner, sql.raw(`DELETE FROM ${table}`));
  await run(db.owner, sql`UPDATE checkpoint_fence SET at_floor = ${Date.now() - 60_000}, retired = '{}'`);
  const today = new Date().toISOString().slice(0, 10);
  await run(db.owner, sql`SELECT make_day(${today}::date - 1), make_day(${today}::date), make_day(${today}::date + 1)`);
});

/** A log under a key of its own, its checkpointer, and the check of it, held to the pair its signer remembers. */
async function logged() {
  const seed = randomBytes(32);
  const mac = logMacKey(seed);
  const memory = variableMemory();
  const cp = await openLogCheckpointer({ store: logStore(db.vault), signingKeys: [seed], memory });
  const keys = await verifierKeys([seed]);
  const tick = async () => assert.ok((await cp.tick()).signed);
  const upto = () => cp.pair.pair.upto;
  const check = (input: CheckInput, { upgraded = false, on = db.vault }: { upgraded?: boolean; on?: Database } = {}) =>
    checkAudit(on, keys, input, { anchors: [decodePair(memory.record!)!], upgraded });
  return { mac, log: logWriter(db.owner, mac), cp, tick, upto, check };
}

/** A row of `audit_events` as the projector signs it, as the page hands it in. */
function shown(mac: LogMacKey, number: bigint, change: Partial<Omit<AuditEvent, 'mac'>> = {}): AuditEventRow {
  const row: Omit<AuditEvent, 'mac'> = {
    at: Date.now(), number, log: 15, author: 'vault', action: 'secret.write', shown: true, allowed: true, code: null, actor: 'user:ada@acme.example',
    subject: null, credential: null, project: randomUUID(), environment: null, secret: null, version: null, places: [], requestId: randomUUID(),
    operationId: null, related: null, sourceIp: null, detail: '{}', ...change,
  };
  return asRow({ ...row, mac: eventMac(mac, row) });
}
const asRow = (e: AuditEvent): AuditEventRow => ({ ...e, number: String(e.number), related: e.related === null ? null : String(e.related), mac: e.mac.toString('base64') });

/** The cursor as the projector signs it, listed through `through`, at `at`. */
function cursor(mac: LogMacKey, through: bigint, at: number): AuditCursorRow {
  const c = { through, pair: through, at, oldFrom: 0n, oldHash: Buffer.alloc(32) };
  return { through: String(through), pair: String(through), at, oldFrom: '0', oldHash: c.oldHash.toString('hex'), mac: cursorMac(mac, c).toString('base64') };
}

/** A log with history sealed, a few entries above its newest checkpoint, three rows shown and the cursor at that checkpoint. */
async function visited() {
  const l = await logged();
  await l.log.uses(50);
  await l.log.change();
  await l.tick();
  await l.log.uses(5);
  const at = Number(l.cp.pair.pair.at);
  const input: CheckInput = { events: [shown(l.mac, 3n), shown(l.mac, 9n, { log: 16 }), shown(l.mac, 2n, { log: 14, author: 'app' })], cursor: cursor(l.mac, l.upto(), at) };
  return { ...l, input, at };
}

test('a visit with nothing wrong: ok, the newest checkpoint, the cursor listed through it, no row forged', async () => {
  const v = await visited();
  const checked = await v.check(v.input);
  assert.deepEqual(checked, { state: 'ok', reason: null, checkpoint: { number: String(v.upto()), at: v.at }, listedThrough: { number: String(v.upto()), at: v.at }, forged: [], behind: false });
});

test('an entry forged or altered above the newest checkpoint: broken, by its MAC', async () => {
  const v = await visited();
  const forged = await v.log.use(Date.now(), true);
  const checked = await v.check(v.input);
  assert.equal(checked.state, 'broken');
  assert.match(checked.reason!, new RegExp(`${forged}: its MAC does not hold`));

  await run(db.owner, sql`DELETE FROM log_uses WHERE number = ${forged}`);
  assert.equal((await v.check(v.input)).state, 'ok');
  const [above] = await rows<{ number: string }>(db.owner, sql`SELECT min(number)::text AS number FROM log_uses WHERE number > ${v.upto()}`);
  await run(db.owner, sql`UPDATE log_uses SET secret = ${randomUUID()} WHERE number = ${BigInt(above!.number)}`);
  const altered = await v.check(v.input);
  assert.equal(altered.state, 'broken');
  assert.match(altered.reason!, new RegExp(`${above!.number}: its MAC does not hold`));
});

test('the newest row\'s floor of `at` raised by a writer: the entries above are read from the floor its pair signed, a forged one still found', async () => {
  const v = await visited();
  const forged = await v.log.use(Date.now(), true);
  await run(db.owner, sql`UPDATE log_checkpoints SET at_floor = ${Date.now() + 3_600_000} WHERE upto = ${v.upto()}`);
  const checked = await v.check(v.input);
  assert.equal(checked.state, 'broken');
  assert.match(checked.reason!, new RegExp(`${forged}: its MAC does not hold`));
});

test('a checkpoint deleted, or an older one served: behind, below the pair its signer holds', async () => {
  const v = await visited();
  await v.tick();
  const newest = v.upto();
  await run(db.owner, sql`DELETE FROM log_checkpoints WHERE upto = ${newest}`);
  const checked = await v.check(v.input);
  assert.equal(checked.state, 'behind');
  assert.ok(checked.behind);
  // The database's own newest, which the beat's finding is named for: the older one, still a signed pair.
  assert.ok(checked.checkpoint !== null && BigInt(checked.checkpoint.number) < newest, JSON.stringify(checked));
  // The cursor the projector signed at the deleted one is past what the database still holds.
  assert.match(checked.reason!, /below the checkpoint its signer holds/);
});

test('a row the page shows, altered: broken, its place in `forged`', async () => {
  const v = await visited();
  const rows_ = [...v.input.events];
  rows_[1] = { ...rows_[1]!, action: 'secret.read' };
  rows_[2] = { ...rows_[2]!, mac: Buffer.alloc(16).toString('base64') };
  const checked = await v.check({ ...v.input, events: rows_ });
  assert.equal(checked.state, 'broken');
  assert.deepEqual(checked.forged, [1, 2]);
  // A row no projector writes at all (a field of another type) is forged too, never a crash.
  const odd = await v.check({ ...v.input, events: [{ ...rows_[0]!, number: 'seven' }] });
  assert.deepEqual([odd.state, odd.forged], ['broken', [0]]);
});

test('the cursor put back: shown, listed through less than the checkpoint; the cursor altered: broken', async () => {
  const v = await visited();
  const old = { through: v.upto(), at: v.at };
  await v.log.uses(3);
  await v.tick();
  // An older cursor, signed by the projector when it stood there: the page says how far it lists, the check passes.
  const back = await v.check({ ...v.input, cursor: cursor(v.mac, old.through, old.at) });
  assert.equal(back.state, 'ok');
  assert.deepEqual(back.listedThrough, { number: String(old.through), at: old.at });
  assert.ok(BigInt(back.checkpoint!.number) > old.through);
  // Moved by hand: its MAC no longer holds.
  const moved = await v.check({ ...v.input, cursor: { ...cursor(v.mac, old.through, old.at), through: String(v.upto()) } });
  assert.equal(moved.state, 'broken');
  assert.match(moved.reason!, /audit cursor is not the projector's/);
  // Retention's `reads_from` and P1's interim `old_floor`, `old_top` carry no MAC, and nothing reads them.
  const extra = { ...cursor(v.mac, old.through, old.at), readsFrom: '999', oldFloor: '5', oldTop: '7' } as AuditCursorRow;
  assert.equal((await v.check({ ...v.input, cursor: extra })).state, 'ok');
});

/** `n` entries of the frozen log, chained from its start, written past its triggers; the last one's seq and hash. */
async function frozenLog(n: number): Promise<{ seq: bigint; hash: Buffer }> {
  const key = deriveLogKey('app', randomBytes(32));
  let prev = GENESIS_HASH;
  let last = { seq: 0n, hash: GENESIS_HASH };
  await withTriggersLifted(db.owner, 'audit_log', async (tx) => {
    await run(tx, sql`DELETE FROM audit_log`);
    for (let seq = 1n; seq <= BigInt(n); seq += 1n) {
      const fields: LogFields = {
        seq, author: 'app', keyId: key.keyId, occurredAt: Date.now(), actor: 'user:ada@acme.example', action: 'secret.read', decision: 'allow', code: null,
        subjectPrincipal: null, projectId: null, environmentId: null, secretId: null, secretVersionId: null, operationId: null, requestId: null, sourceIp: null,
        relatedSeq: null, metadata: '{}',
      };
      const { mac, hash } = sealEntry(key, prev, fields);
      await insertEntry(tx, fields, prev, mac, hash);
      prev = hash;
      last = { seq, hash };
    }
  });
  return last;
}

async function insertEntry(tx: Queryable, f: LogFields, prev: Buffer, mac: Buffer, hash: Buffer): Promise<void> {
  await run(tx, sql`INSERT INTO audit_log (seq, author, key_id, occurred_at, actor, action, decision, metadata, prev_hash, mac, hash)
    VALUES (${f.seq}, ${f.author}, ${f.keyId}, ${f.occurredAt}, ${f.actor}, ${f.action}, ${f.decision}, ${f.metadata}, ${prev}, ${mac}, ${hash})`);
}

/** The upgrade's anchor change, naming `anchor`, as V1's step writes it (upgrade.ts), under `mac`. */
async function anchored(mac: LogMacKey, anchor: { seq: bigint; hash: Buffer }): Promise<void> {
  const row = { at: Date.now(), requestId: UPGRADE_REQUESTS.anchor, object: ANCHOR_OBJECT, actor: UPGRADE_ACTOR, payload: anchorPayload(anchor, anchor), seal: null };
  await db.owner.transaction(async (tx) => {
    await run(tx, sql`SELECT pg_advisory_xact_lock_shared(1668244070, 0)`);
    await run(tx, sql`INSERT INTO log_changes (number, at, request_id, object, actor, payload, seal, mac)
      VALUES (nextval('log_number'), ${row.at}, ${row.requestId}, ${row.object}::uuid, ${row.actor}, ${row.payload}, NULL, ${entryMac(mac, { tree: 'changes', row })})`);
  });
}

test('the frozen log cut, extended or its last entry altered: broken, its last entry is not the anchor', async () => {
  const v = await visited();
  const last = await frozenLog(4);
  await anchored(v.mac, last);
  await v.tick();
  assert.equal((await v.check(v.input, { upgraded: true })).state, 'ok');

  await withTriggersLifted(db.owner, 'audit_log', (tx) => run(tx, sql`UPDATE audit_log SET action = 'secret.write' WHERE seq = ${last.seq}`));
  const altered = await v.check(v.input, { upgraded: true });
  assert.equal(altered.state, 'broken');
  assert.match(altered.reason!, /it was altered/);
  await withTriggersLifted(db.owner, 'audit_log', (tx) => run(tx, sql`UPDATE audit_log SET action = 'secret.read' WHERE seq = ${last.seq}`));
  assert.equal((await v.check(v.input, { upgraded: true })).state, 'ok');

  const [kept] = await rows<{ seq: string; author: 'app'; key_id: string; occurred_at: string; prev_hash: Buffer; mac: Buffer; hash: Buffer }>(db.owner, sql`SELECT * FROM audit_log WHERE seq = ${last.seq}`);
  await withTriggersLifted(db.owner, 'audit_log', (tx) => run(tx, sql`DELETE FROM audit_log WHERE seq = ${last.seq}`));
  const cut = await v.check(v.input, { upgraded: true });
  assert.equal(cut.state, 'broken');
  assert.match(cut.reason!, /it was cut/);

  await withTriggersLifted(db.owner, 'audit_log', async (tx) => {
    await run(tx, sql`INSERT INTO audit_log (seq, author, key_id, occurred_at, actor, action, decision, metadata, prev_hash, mac, hash)
      VALUES (${last.seq}, ${kept!.author}, ${kept!.key_id}, ${BigInt(kept!.occurred_at)}, 'user:ada@acme.example', 'secret.read', 'allow', '{}', ${kept!.prev_hash}, ${kept!.mac}, ${kept!.hash})`);
    await run(tx, sql`INSERT INTO audit_log (seq, author, key_id, occurred_at, actor, action, decision, metadata, prev_hash, mac, hash)
      VALUES (${last.seq + 1n}, 'app', ${kept!.key_id}, ${Date.now()}, 'user:ada@acme.example', 'secret.read', 'allow', '{}', ${last.hash}, ${randomBytes(32)}, ${randomBytes(32)})`);
  });
  const extended = await v.check(v.input, { upgraded: true });
  assert.equal(extended.state, 'broken');
  assert.match(extended.reason!, /it was extended/);
});

test('the anchor deleted after the upgrade, or one not the vault\'s: broken; before the upgrade there is none to hold', async () => {
  const v = await visited();
  const last = await frozenLog(2);
  assert.equal((await v.check(v.input)).state, 'ok', 'before the upgrade: no anchor, nothing to hold');
  const gone = await v.check(v.input, { upgraded: true });
  assert.equal(gone.state, 'broken');
  assert.match(gone.reason!, /no anchor/);
  // An anchor under a key the vault does not hold: a writer's.
  await anchored(logMacKey(randomBytes(32)), last);
  const planted = await v.check(v.input, { upgraded: true });
  assert.equal(planted.state, 'broken');
  assert.match(planted.reason!, /anchor is not the vault's/);
});

test.todo('V1: the vault says it is upgraded once its step wrote the anchor (`#upgraded`), and a visit then holds the frozen log to it');

test('more entries above the newest checkpoint than `CHECK_TAIL_ENTRIES`: late, not verified past it, no problem', async () => {
  const v = await visited();
  await v.log.uses(CHECK_TAIL_ENTRIES);
  const checked = await v.check(v.input);
  assert.equal(checked.state, 'late');
  assert.match(checked.reason!, /checkpointer is late/);
});

test('the vault answers `check` over its own log, held to the pair its signer remembers: ok, then a row shown altered', async () => {
  await emptyDatabase(db.owner);
  const seed = randomBytes(32);
  const memory = variableMemory();
  const config = {
    keks: new KekRegistry(LocalKekProvider.generate('test-kek-1')), owners: ['root@acme.example'], signingKeys: [seed],
    bulkLimit: { count: 1000, windowMs: 15 * 60_000 }, deployment: defineDeployment(),
  };
  const vault = await openLocalVault(db.vault, config, { log: '0.15', sealThrough: sealed, heldOutside: async () => (memory.record === null ? [] : [decodePair(memory.record)!]) });
  // Its first call starts its log: the cutover's change, then the root's.
  assert.equal((await vault.access('user:root@acme.example')).role, 'owner');
  const cp = await openLogCheckpointer({ store: logStore(db.vault), signingKeys: [seed], memory });
  assert.ok((await cp.tick()).signed);
  const mac = logMacKey(seed);
  const at = Number(cp.pair.pair.at);
  const input: CheckInput = { events: [shown(mac, 1n), shown(mac, 2n)], cursor: cursor(mac, cp.pair.pair.upto, at) };
  const checked = await vault.check!(input);
  assert.deepEqual(checked, { ok: true, state: 'ok', reason: null, checkpoint: { number: String(cp.pair.pair.upto), at }, listedThrough: { number: String(cp.pair.pair.upto), at }, forged: [] });
  const altered = await vault.check!({ ...input, events: [input.events[0]!, { ...input.events[1]!, allowed: false }] });
  assert.ok(altered.ok && altered.state === 'broken' && altered.forged.join() === '1', JSON.stringify(altered));
});

/** The vault's database, each statement and each transaction counted as it is sent. */
function counting(): { db: Database; statements: () => number; transactions: () => number; close: () => Promise<void> } {
  let [statements, transactions] = [0, 0];
  const pool = postgresClient(VAULT_URL, { max: 1 });
  const counted = <C extends object>(client: C): C => new Proxy(client, {
    get(target, key) {
      const value: unknown = Reflect.get(target, key, target);
      if (typeof value !== 'function') return value;
      if (key === 'unsafe') {
        return (...args: unknown[]) => {
          statements += 1;
          return (value as (...a: unknown[]) => unknown).apply(target, args);
        };
      }
      if (key === 'begin') {
        return (...args: unknown[]) => {
          transactions += 1;
          const work = args.pop() as (tx: object) => unknown;
          return (value as (...a: unknown[]) => unknown).apply(target, [...args, (tx: object) => work(counted(tx))]);
        };
      }
      return (value as (...a: unknown[]) => unknown).bind(target);
    },
  });
  return { db: createDatabase(counted(pool)), statements: () => statements, transactions: () => transactions, close: () => pool.end() };
}

test('D200: a visit\'s check is one statement, no transaction, at 2,000 and at 20,000 entries', { timeout: 300_000 }, async () => {
  const v = await logged();
  const counter = counting();
  const measured: Record<number, { statements: number; transactions: number }> = {};
  try {
    for (const size of [2_000, 20_000]) {
      for (let at = (await rows<{ n: string }>(db.owner, sql`SELECT count(*)::text AS n FROM log_uses`))[0]!.n; Number(at) < size; at = String(Number(at) + 2_000)) {
        await v.log.uses(2_000);
        await v.tick();
      }
      await v.log.uses(10);
      const input: CheckInput = { events: Array.from({ length: 200 }, (_, i) => shown(v.mac, BigInt(i + 1))), cursor: cursor(v.mac, v.upto(), Number(v.cp.pair.pair.at)) };
      const [statements, transactions] = [counter.statements(), counter.transactions()];
      const checked = await v.check(input, { on: counter.db });
      assert.equal(checked.state, 'ok', checked.reason ?? '');
      measured[size] = { statements: counter.statements() - statements, transactions: counter.transactions() - transactions };
    }
  } finally {
    await counter.close();
  }
  assert.deepEqual(measured, { 2000: { statements: 1, transactions: 0 }, 20000: { statements: 1, transactions: 0 } });
});
