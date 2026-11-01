// The reads' projection across a rotation of the vault's signing key (T168; keyring.ts; formal/Rotation.tla's
// BoundaryChecked; docs/design/audit-tree.md, "A rotation"): the projector, the whole log's check of it (`coffre verify
// log`) and the vault's `vouch` hold to one rule, R41's: the key the log moved on from vouches for a pair, an entry, a
// read or the cursor only below its rotation's number; the current key for any.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

import type { VouchedEntry } from '@coffre/core/vault';
import { sql } from 'drizzle-orm';

import { entryVouched, keyringOf } from '../src/keyring.ts';
import { openLogCheckpointer } from '../src/log-checkpointer.ts';
import { entryMac, KEY_OBJECT, logMacKey, useEntry } from '../src/log-entry.ts';
import { logStore } from '../src/log-store.ts';
import { checkReads, cursorMac, projectReads, Projector, readMac, type ReadRow, type ReadsCursor } from '../src/reads.ts';
import { verifierKeys } from '../src/verifier.ts';
import { variableMemory } from './audit-tree.ts';
import { ENGINE, openTestDatabase, rows, run, type TestDatabase } from './database.ts';
import { ask, CONFIG, emptyLog, isolate, SIGNING_KEY, useDatabases, world } from './use-world.ts';

let db: TestDatabase;
before(async () => {
  db = await openTestDatabase();
  await useDatabases(db);
});
after(() => db.close());
beforeEach(async () => {
  await emptyLog();
  for (const table of ['log_checkpoints', 'log_tiles']) await run(db.owner, sql.raw(`DELETE FROM ${table}`));
  // No key retired: each test's log starts under A.
  await run(db.owner, ENGINE === 'postgres' ? sql`UPDATE log_fence SET retired = '{}'` : sql`UPDATE log_fence SET retired = '[]'`);
});

/** The key the deploy moves to; the old one, A, is the fixture's `SIGNING_KEY`. */
const B = randomBytes(32);
const [A_MAC, B_MAC] = [logMacKey(SIGNING_KEY), logMacKey(B)];
const before_ = () => verifierKeys([SIGNING_KEY]);
const after_ = () => verifierKeys([B, SIGNING_KEY]);
/** The vault's configuration after the deploy: B signs, A verifies what came before. */
const ROTATED = { ...CONFIG, signingKeys: [B, SIGNING_KEY] };

/** A checkpointer under `signingKeys` over `memory`, each tick asserted clean. */
async function signer(signingKeys: readonly Buffer[], memory: ReturnType<typeof variableMemory>) {
  const cp = await openLogCheckpointer({ store: logStore(db.vault), signingKeys, memory, record: () => {} });
  return {
    cp,
    async tick() {
      const tick = await cp.tick();
      assert.deepEqual(tick.failures, []);
    },
  };
}

/** A read of each key through an isolate under `config`'s keys. */
async function reads(w: Awaited<ReturnType<typeof world>>, keys: readonly string[], config = CONFIG) {
  const { use } = await isolate({}, config);
  for (const key of keys) {
    const outcome = await use(ask(w, key));
    assert.ok(outcome.ok, JSON.stringify(outcome));
  }
}

/** The log moved on from A to B, A's reads in pairs under A the projector has partly listed: where the rotation is, and the world. */
async function rotatedOverReads() {
  const memory = variableMemory();
  const old = await signer([SIGNING_KEY], memory);
  const w = await world();
  // Every key made under A, before the deploy: past the rotation, the database refuses A's changes.
  const keys: string[] = [];
  for (let i = 0; i < 7; i += 1) keys.push(await w.key());
  await reads(w, keys.slice(0, 2));
  await old.tick();
  await projectReads(logStore(db.vault), await before_());
  // A's reads the projector has not listed yet, sealed under A.
  await reads(w, keys.slice(2, 5));
  await old.tick();
  await old.cp.close();
  // The deploy: the checkpointer under B over the same memory writes the rotation; B's reads follow.
  const now = await signer([B, SIGNING_KEY], memory);
  const [rotation] = await rows<{ number: string | number }>(db.owner, sql`SELECT number FROM log_changes WHERE object = ${KEY_OBJECT}`);
  assert.ok(rotation !== undefined, 'the rotation is written');
  await reads(w, keys.slice(5), ROTATED);
  await now.tick();
  return { now, w, rotation: BigInt(rotation.number) };
}

const store = () => logStore(db.vault);
const listed = async () => (await store().listing({ after: 0n, upto: (1n << 62n), from: 0, to: Number.MAX_SAFE_INTEGER })).sort((a, b) => (a.number < b.number ? -1 : 1));
const projectedAll = async () => {
  for (let run = 0; run < 20; run += 1) {
    const { through, sealed } = await projectReads(store(), await after_());
    if (through >= sealed) return;
  }
  assert.fail('the projection did not catch up');
};
/** Every stretch of the whole log's check of the reads, from the first, its problems together. */
async function checked() {
  const problems: string[] = [];
  for (let from: bigint | null = 0n; from !== null;) {
    const stretch = await checkReads(store(), await after_(), from);
    problems.push(...stretch.problems);
    from = stretch.next;
  }
  return problems;
}

const asVouched = (row: ReadRow): VouchedEntry => ({
  tree: 'reads', number: String(row.number), at: row.at, credential: row.credential, purpose: row.purpose, principal: row.principal, secret: row.secret,
  environment: row.environment, project: row.project, place: row.place, source: row.source, sourceEnvironment: row.sourceEnvironment,
  sourceProject: row.sourceProject, version: row.version, mac: row.mac.toString('hex'),
});
const cursorVouchedAs = (cursor: ReadsCursor): VouchedEntry => ({ tree: 'cursor', number: 'cursor', through: String(cursor.through), pair: String(cursor.pair), at: cursor.at, mac: cursor.mac === null ? null : cursor.mac.toString('hex') });

test('rotated with A\'s pairs not yet projected: the projector goes on from them, lists them under A\'s MACs as they hold, then B\'s, and moves the cursor under B', async () => {
  const { rotation } = await rotatedOverReads();
  assert.equal((await listed()).length, 2, 'the projector stood among A\'s pairs at the rotation');
  await projectedAll();
  const rows_ = await listed();
  assert.equal(rows_.length, 7);
  // What it listed before the rotation keeps A's MAC; what it listed since, B's, whatever key the use was under.
  for (const row of rows_.slice(0, 2)) assert.ok(row.mac.equals(readMac(A_MAC, row)), `read ${row.number} kept under A`);
  for (const row of rows_.slice(2)) assert.ok(row.mac.equals(readMac(B_MAC, row)), `read ${row.number} listed under B`);
  assert.ok(rows_.slice(0, 5).every((row) => row.number < rotation) && rows_.slice(5).every((row) => row.number > rotation));
  const cursor = await store().readsCursor();
  assert.ok(cursor.through > rotation && cursor.mac!.equals(cursorMac(B_MAC, cursor)), 'the cursor moved on under B');
});

test('the whole log\'s check (`coffre verify log`) holds the reads listed before the rotation, under A, and those since, under B: nothing found', async () => {
  await rotatedOverReads();
  await projectedAll();
  assert.deepEqual(await checked(), []);
});

test('A\'s MAC at or past the rotation counts for nothing: on a read, on the cursor and on an entry, for the projector, the check and vouch', async () => {
  const { rotation } = await rotatedOverReads();
  await projectedAll();
  const rows_ = await listed();
  const past = rows_.find((row) => row.number > rotation)!;
  const below = rows_.find((row) => row.number < rotation)!;
  // A read past the rotation re-MAC'd under A, by someone who holds it and writes the database.
  await run(db.owner, sql`UPDATE log_reads SET mac = ${readMac(A_MAC, past)} WHERE number = ${past.number}`);
  assert.ok((await checked()).includes(`read ${past.number} is listed otherwise than the log sealed it`));
  const { vault } = await isolate({}, ROTATED);
  const forged = await vault.vouch({ entries: [asVouched({ ...past, mac: readMac(A_MAC, past) }), asVouched(below)] });
  assert.deepEqual(forged.forged, [String(past.number)]);
  // The cursor, where it stands past the rotation, MAC'd under A: the projector and the check refuse it, and vouch.
  const cursor = await store().readsCursor();
  const underA = { ...cursor, mac: cursorMac(A_MAC, cursor) };
  await run(db.owner, sql`UPDATE log_reads_cursor SET mac = ${underA.mac}`);
  await assert.rejects(projectReads(store(), await after_()), /the reads' cursor, at \d+, is not the vault's/);
  assert.match((await checked()).join('\n'), /the reads' cursor, at \d+, is not the vault's/);
  assert.deepEqual((await vault.vouch({ entries: [cursorVouchedAs(underA)] })).forged, ['cursor']);
  // An entry under A: below the rotation it holds, at or past it it is refused, by the keyring every reader uses and by vouch.
  const ring = await keyringOf(await after_(), store());
  const use = (number: bigint) => {
    const row = { at: Date.now(), requestId: 7n, credential: past.credential, secret: past.secret, purpose: 1, place: null };
    return useEntry({ number, ...row, mac: entryMac(A_MAC, { tree: 'uses', row }) });
  };
  assert.equal(entryVouched(ring, use(rotation - 1n)), 'held');
  assert.equal(entryVouched(ring, use(rotation)), 'past');
  assert.equal(entryVouched(ring, use(rotation + 1n)), 'past');
  const asEntry = (number: bigint): VouchedEntry => {
    const e = use(number);
    const [at, requestId, credential, secret, purpose, place, mac] = e.columns as [bigint, bigint, string, string, number, null, Buffer];
    return { tree: 'uses', number: String(number), at: Number(at), requestId: String(requestId), credential, secret, purpose, place, mac: mac.toString('hex') };
  };
  assert.deepEqual((await vault.vouch({ entries: [asEntry(rotation - 1n), asEntry(rotation), asEntry(rotation + 1n)] })).forged, [String(rotation), String(rotation + 1n)]);
});

test('vouch holds a replaced key to its rotation (R41): never any key the vault holds, and its rotation\'s row deleted leaves the key vouching for nothing', async () => {
  const { rotation } = await rotatedOverReads();
  await projectedAll();
  const below = (await listed()).find((row) => row.number < rotation)!;
  // A read under A at a number past the rotation: forged, though A is a key this vault holds.
  const planted = { ...below, number: rotation + 100n };
  const { vault } = await isolate({}, ROTATED);
  assert.deepEqual((await vault.vouch({ entries: [asVouched(below), asVouched({ ...planted, mac: readMac(A_MAC, planted) })] })).forged, [String(planted.number)]);
  // The rotation's row gone, with the newest pair under B: A vouches for nothing, its reads from before included (fail closed).
  await run(db.owner, sql`DELETE FROM log_changes WHERE object = ${KEY_OBJECT}`);
  const { vault: fresh } = await isolate({}, ROTATED);
  assert.deepEqual((await fresh.vouch({ entries: [asVouched(below)] })).forged, [String(below.number)]);
});

test('a restart mid-projection after the rotation: a new projector goes on from the cursor the last one left, under either key, and the check finds nothing', async () => {
  await rotatedOverReads();
  // One step of one read, then the host stops: the cursor stands inside A's range, still under A's MAC or B's.
  await projectReads(store(), await after_(), { steps: 1, atOnce: 1 });
  const stopped = await store().readsCursor();
  assert.equal((await listed()).length, 3);
  // The host starts again, its projector new.
  const alarms: string[] = [];
  const projector = new Projector(store(), await after_(), (message) => alarms.push(message));
  for (let run = 0; run < 20 && (await projector.run()); run += 1);
  await projector.stop();
  assert.deepEqual(alarms, []);
  assert.ok((await store().readsCursor()).through > stopped.through);
  assert.equal((await listed()).length, 7);
  assert.deepEqual(await checked(), []);
});
