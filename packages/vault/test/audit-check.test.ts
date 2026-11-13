// The audit page's check, flat (T277; audit-check.ts; state-rows.md, section 4, "What a visit's check catches"): one
// test per row of that table a visit catches, for a database writer with no key, and its cost, one statement at two
// sizes of the log.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';

import { deriveLogKey, GENESIS_HASH, sealEntry, type LogFields } from '@coffre/core/audit';
import { decodePair } from '@coffre/core/merkle';
import type { AuditCursorRow, AuditEventRow, CheckInput, Sealing } from '@coffre/core/vault';
import { defineDeployment } from '@coffre/core/deployment';
import { KekRegistry, LocalKekProvider } from '@coffre/core/kek';
import { createDatabase, type Database, type Queryable } from '@coffre/db';
import { postgresClient } from '@coffre/db/connect';
import { sql } from 'drizzle-orm';

import { CHECK_TAIL_ENTRIES, checkAudit, projectorStopped } from '../src/audit-check.ts';
import { reachedOf, type Checkpointer, type Reached } from '../src/checkpointer.ts';
import { cursorMac, eventMac, type AuditEvent } from '../src/audit-rows.ts';
import { openLogCheckpointer } from '../src/log-checkpointer.ts';
import { entryMac, logMacKey, type LogMacKey } from '../src/log-entry.ts';
import { logStore, type LogStore } from '../src/log-store.ts';
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

/**
 * A log under a key of its own, its checkpointer, and the check of it, held to what its signer answers when asked
 * (`reached`, its own by default: the pair it wrote, the one it is writing, sealing). `store` stands in for the
 * checkpointer's, to hold its write open.
 */
async function logged(store: LogStore = logStore(db.vault)) {
  const seed = randomBytes(32);
  const mac = logMacKey(seed);
  const memory = variableMemory();
  const cp = await openLogCheckpointer({ store, signingKeys: [seed], memory });
  const keys = await verifierKeys([seed]);
  const tick = async () => assert.ok((await cp.tick()).signed);
  const upto = () => cp.pair.pair.upto;
  const check = (input: CheckInput, { upgraded = false, on = db.vault, reached = reachedOf(cp, { ok: true }) }: { upgraded?: boolean; on?: Database; reached?: Reached } = {}) =>
    checkAudit(on, keys, input, { reached, upgraded });
  return { mac, log: logWriter(db.owner, mac), cp, memory, tick, upto, check };
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
  // P1's interim `oldFloor` and `oldTop` are outside the MAC: any value signs the same.
  const c = { through, pair: through, at, oldFloor: 0n, oldFrom: 0n, oldTop: 0n, oldHash: Buffer.alloc(32) };
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
  assert.deepEqual(checked, {
    state: 'ok', reason: null, checkpoint: { number: String(v.upto()), at: v.at }, listedThrough: { number: String(v.upto()), at: v.at }, forged: [],
    listed: { through: v.upto(), at: v.at }, unlisted: null,
  });
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
  // The database's own newest, which the beat's finding is named for: the older one, still a signed pair.
  assert.ok(checked.checkpoint !== null && BigInt(checked.checkpoint.number) < newest, checked.reason ?? '');
  // The cursor the projector signed at the deleted one is past what the database still holds.
  assert.match(checked.reason!, /below the checkpoint its signer wrote/);
  // A row forged as well: broken comes first.
  const forged = await v.check({ ...v.input, events: [{ ...v.input.events[0]!, action: 'secret.read' }] });
  assert.equal(forged.state, 'broken');
  assert.match(forged.reason!, /not the projector's/);
});

test('the cursor past the newest checkpoint: behind, a database rolled back below what the projector listed', async () => {
  const v = await visited();
  const signed = cursor(v.mac, v.upto() + 3n, v.at);
  const past = await v.check({ ...v.input, cursor: signed });
  assert.equal(past.state, 'behind');
  assert.match(past.reason!, new RegExp(`lists through ${v.upto() + 3n}, past the newest checkpoint \\(${v.upto()}\\)`));
});

test('the cursor past genesis, the only checkpoint (every other deleted, the signer\'s memory lost with them): no checkpoint shown, behind', async () => {
  const fresh = await logged();
  await fresh.log.uses(5);
  const genesis = await fresh.check({ events: [], cursor: cursor(fresh.mac, 4n, Date.now()) });
  assert.deepEqual([genesis.state, genesis.checkpoint], ['behind', null]);
  assert.match(genesis.reason!, /past the newest checkpoint \(0\)/);
});

test('the signer asked before the read: a visit while its write is in flight is ok, before the row lands and after', async () => {
  // The checkpointer's store, its write held open: first before the row is written, then after, before the signer
  // knows it landed.
  const real = logStore(db.vault);
  let hold: 'before' | 'after' | null = null;
  let held: () => void = () => {};
  let release: () => void = () => {};
  const store: LogStore = {
    ...real,
    async write(row, tiles) {
      const gate = hold === null ? null : new Promise<void>((resolve) => (release = resolve));
      if (hold === 'before') {
        held();
        await gate;
      }
      await real.write(row, tiles);
      if (hold === 'after') {
        held();
        await gate;
      }
    },
  };
  const v = await logged(store);
  await v.log.uses(20);
  await v.tick();
  const at = Number(v.cp.pair.pair.at);
  const input: CheckInput = { events: [], cursor: cursor(v.mac, v.upto(), at) };
  const wrote = v.upto();

  for (const when of ['before', 'after'] as const) {
    await v.log.uses(5);
    hold = when;
    const holding = new Promise<void>((resolve) => (held = resolve));
    let done = false;
    const ticking = v.cp.tick().finally(() => (done = true));
    await holding;
    assert.ok(!done);
    // The signer remembers the next pair before its row lands: read from its memory after the database, as the beat
    // read it, the database is one pair below, and the visit says behind for nothing.
    const remembered = decodePair(v.memory.record!)!;
    const said = v.cp.reached;
    assert.ok(said.writing !== null && said.writing.changes === remembered.changes);
    if (when === 'before') assert.equal((await v.check(input, { reached: { pair: remembered, writing: null, sealing: { ok: true } } })).state, 'behind');
    const counter = counting();
    try {
      const checked = await v.check(input, { on: counter.db });
      assert.equal(checked.state, 'ok', checked.reason ?? '');
      // One statement whether the row has landed or not: the pair at the database's newest place is held note for note.
      assert.equal(counter.statements(), 1);
    } finally {
      await counter.close();
    }
    hold = null;
    release();
    await ticking;
    assert.ok(v.upto() > wrote);
  }
});

test('a signer that does not seal, or holds no pair: late, its reason; broken still comes first', async () => {
  const v = await visited();
  const stalled = await v.check(v.input, { reached: { ...reachedOf(v.cp, { ok: false, reason: 'its last tick ended 9000 ms ago' }) } });
  assert.equal(stalled.state, 'late');
  assert.match(stalled.reason!, /does not seal: its last tick ended 9000 ms ago/);
  // Not open: no pair to hold the database to, and its host says why.
  const closed = await v.check(v.input, { reached: reachedOf(null, { ok: false, reason: 'the checkpointer is not open' }) });
  assert.deepEqual([closed.state, closed.reason], ['late', 'the signer holds no pair to check the database against: the checkpointer is not open']);
  const forged = await v.check({ ...v.input, events: [{ ...v.input.events[0]!, allowed: false }] }, { reached: reachedOf(null, { ok: false, reason: 'down' }) });
  assert.equal(forged.state, 'broken');
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
  const row = { at: Date.now(), requestId: UPGRADE_REQUESTS.anchor, object: ANCHOR_OBJECT, actor: UPGRADE_ACTOR, payload: anchorPayload(anchor, anchor, 'outside'), seal: null };
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
  // No anchor and no old row (a database born on 0.16): nothing to hold, upgraded or not.
  await run(db.owner, sql`DELETE FROM log_changes WHERE object = ${ANCHOR_OBJECT}::uuid`);
  await withTriggersLifted(db.owner, 'audit_log', (tx) => run(tx, sql`DELETE FROM audit_log`));
  assert.equal((await v.check(v.input, { upgraded: true })).state, 'ok');
});

test.todo('V1: the vault says it is upgraded once its step wrote the anchor (`#upgraded`), and a visit then holds the frozen log to it');

test('more entries above the newest checkpoint than `CHECK_TAIL_ENTRIES`: late, not verified past it, no problem', async () => {
  const v = await visited();
  await v.log.uses(CHECK_TAIL_ENTRIES);
  const checked = await v.check(v.input);
  assert.equal(checked.state, 'late');
  assert.match(checked.reason!, /checkpointer is late/);
});

/**
 * A vault over its own log and its checkpointer, which answers `check` and `beat` with what `sealing` says: the
 * checkpointer's own pairs.
 */
async function vaulted() {
  await emptyDatabase(db.owner);
  const seed = randomBytes(32);
  const memory = variableMemory();
  const config = {
    keks: new KekRegistry(LocalKekProvider.generate('test-kek-1')), owners: ['root@acme.example'], signingKeys: [seed],
    bulkLimit: { count: 1000, windowMs: 15 * 60_000 }, deployment: defineDeployment(),
  };
  const signer: { cp: Checkpointer | null; sealing: Sealing } = { cp: null, sealing: { ok: true } };
  const vault = await openLocalVault(db.vault, config, {
    log: '0.15', sealThrough: sealed, heldOutside: async () => (memory.record === null ? [] : [decodePair(memory.record)!]),
    reached: () => reachedOf(signer.cp, signer.sealing),
  });
  // Its first call starts its log: the cutover's change, then the root's.
  assert.equal((await vault.access('user:root@acme.example')).role, 'owner');
  const cp = (signer.cp = await openLogCheckpointer({ store: logStore(db.vault), signingKeys: [seed], memory }));
  assert.ok((await cp.tick()).signed);
  return { vault, cp, signer, mac: logMacKey(seed) };
}

test('the vault answers `check` over its own log, held to what its signer answers: ok, then a row shown altered', async () => {
  const { vault, cp, mac } = await vaulted();
  const at = Number(cp.pair.pair.at);
  const input: CheckInput = { events: [shown(mac, 1n), shown(mac, 2n)], cursor: cursor(mac, cp.pair.pair.upto, at) };
  const checked = await vault.check!(input);
  assert.deepEqual(checked, { ok: true, state: 'ok', reason: null, checkpoint: { number: String(cp.pair.pair.upto), at }, listedThrough: { number: String(cp.pair.pair.upto), at }, forged: [] });
  const altered = await vault.check!({ ...input, events: [input.events[0]!, { ...input.events[1]!, allowed: false }] });
  assert.ok(altered.ok && altered.state === 'broken' && altered.forged.join() === '1', JSON.stringify(altered));
});

/** The events the vault wrote under `id`: its payload and actor. */
const events = (id: string) => rows<{ actor: string; payload: string; mac: Buffer }>(db.owner, sql`SELECT actor, payload, mac FROM log_changes WHERE request_id = ${id}`);

test('`beat`: ok writes nothing; not ok, the finding, an event of the vault\'s under `findingEventId`, written once over beats', async () => {
  const { vault, cp, signer, mac } = await vaulted();
  const at = Number(cp.pair.pair.at);
  const input = { cursor: cursor(mac, cp.pair.pair.upto, at), everyMs: 300_000 };
  const ok = await vault.beat!(input);
  assert.deepEqual(ok, { ok: true, state: 'ok', reason: null, checkpoint: { number: String(cp.pair.pair.upto), at }, listedThrough: { number: String(cp.pair.pair.upto), at }, finding: null, projector: null });

  signer.sealing = { ok: false, reason: 'its last tick ended 9000 ms ago' };
  const late = await vault.beat!(input);
  const id = `system:vault/finding:${cp.pair.pair.upto}:late`;
  assert.ok(late.ok && late.state === 'late' && late.finding === id, JSON.stringify(late));
  const [written] = await events(id);
  assert.equal(written!.actor, 'system:vault');
  const payload = JSON.parse(written!.payload) as Record<string, unknown>;
  assert.deepEqual([payload.action, payload.author, payload.allowed], ['audit.finding', 'vault', true]);
  assert.deepEqual(payload.detail, { state: 'late', reason: 'the checkpointer does not seal: its last tick ended 9000 ms ago', checkpoint: String(cp.pair.pair.upto) });
  // Seen again, for the same reason and for another: the same finding, written once.
  assert.equal((await vault.beat!(input)).ok && (await events(id)).length, 1);
  signer.sealing = { ok: false, reason: 'its last tick was refused: a forged entry' };
  const again = await vault.beat!(input);
  assert.ok(again.ok && again.finding === id);
  assert.equal((await events(id)).length, 1);

  // A writer's row planted under the id of the finding it causes (its MAC fails, so `broken`): never counted as it.
  const broken = `system:vault/finding:${cp.pair.pair.upto}:broken`;
  await run(db.owner, sql`UPDATE log_changes SET request_id = ${broken}, mac = ${Buffer.alloc(written!.mac.length, 7)} WHERE request_id = ${id}`);
  await assert.rejects(vault.beat!(input), /the row under the finding's id .* is not the vault's/);
});

test('`beat`: a projector that stopped, a checkpoint above its cursor signed two beats ago, fails the run with no finding', async () => {
  const { vault, cp, mac } = await vaulted();
  const below = cp.pair.pair.upto;
  // After an hour's quiet, one use and its tick: the cursor's pair an hour old, the checkpoint above it just signed, the
  // projector a moment from listing it. Not stopped, and neither is a first projection, its cursor at the start.
  await logWriter(db.owner, mac).uses(3);
  assert.ok((await cp.tick()).signed);
  const above = cp.pair.pair.upto;
  const quiet = await vault.beat!({ cursor: cursor(mac, below, Date.now() - 3_600_000), everyMs: 300_000 });
  assert.ok(quiet.ok && quiet.state === 'ok' && quiet.projector === null, JSON.stringify(quiet));
  const first = await vault.beat!({ cursor: { ...cursor(mac, 0n, 0), mac: null }, everyMs: 300_000 });
  assert.ok(first.ok && first.projector === null, JSON.stringify(first));
  // The same checkpoint, two beats on (a beat of 50 ms): stopped, and the run fails with no finding.
  const everyMs = 50;
  await new Promise((done) => setTimeout(done, 3 * everyMs));
  const stopped = await vault.beat!({ cursor: cursor(mac, below, Date.now()), everyMs });
  assert.ok(stopped.ok && stopped.state === 'ok' && stopped.finding === null, JSON.stringify(stopped));
  assert.match(stopped.projector!, new RegExp(`lists through ${below}, and the checkpoint above it \\(up to ${above}\\) was signed \\d+ ms ago`));
  // At the checkpoint, however old: nothing above it to list.
  const level = await vault.beat!({ cursor: cursor(mac, above, 0), everyMs });
  assert.ok(level.ok && level.projector === null, JSON.stringify(level));
  // A checkpoint above it that does not open under the vault's keys: said, not taken as a time.
  assert.match(projectorStopped({ through: below, at: 0 }, { upto: above, at: null }, everyMs)!, /does not open under the vault's keys/);
  await assert.rejects(vault.beat!({ cursor: cursor(mac, below, Date.now()), everyMs: 0 }), /positive integer/);
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
