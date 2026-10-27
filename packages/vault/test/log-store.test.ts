// The checkpointer over 0.15's log as migration 0022 (Postgres) and 0018
// (SQLite) lay it out, through the vault's own login: the barrier and the
// window, write_checkpoint and its tiles, and the reads proofs and the
// verifier make (docs/design/audit-tree.md). The owner plays the change and
// use paths (plans PR 4 and 5), which write the entries, and a database
// writer where a case says so.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { after, before, beforeEach, test } from 'node:test';

import { leafHash, pairSigners, pairVerifiers, verifyInclusion, verifyLog, type PairSigners, type PairVerifiers } from '@coffre/core/merkle';
import { sql } from 'drizzle-orm';

import { Checkpointer } from '../src/checkpointer.ts';
import { authentic, logMacKey } from '../src/log-entry.ts';
import { logWriter } from './log-entries.ts';
import { logStore } from '../src/log-store.ts';
import { variableMemory } from './audit-tree.ts';
import { ENGINE, openTestDatabase, rows, run, type TestDatabase } from './database.ts';

let db: TestDatabase;
let signers: PairSigners;
let verifiers: PairVerifiers;
let macKey: Buffer;
let log: ReturnType<typeof logWriter>;
const use = (at?: number, forged?: boolean) => log.use(at, forged);
const change = () => log.change();

before(async () => {
  db = await openTestDatabase();
  const seed = randomBytes(32);
  signers = await pairSigners('coffre.test/audit', seed);
  verifiers = await pairVerifiers({ changes: signers.changes.verifierKey, uses: signers.uses.verifierKey });
  macKey = logMacKey(seed);
  // One connection on SQLite, as a deployment has: two to one file would wait on each other's writes.
  log = logWriter(ENGINE === 'sqlite' ? db.vault : db.owner, macKey);
  // Today's and tomorrow's uses, as the checkpointer will make them ahead (plan PR 7).
  await log.days();
});
after(() => db?.close());
beforeEach(() => log.empty());

/** Ranges of 512 leaves, so that a test crosses some; one size for the file, whose database keeps the ranges made. */
const RANGE = 512;

async function open(memory = variableMemory()) {
  const alerts: string[] = [];
  const store = logStore(db.vault, { tileRange: RANGE });
  const cp = await Checkpointer.open(store, signers, { memory, authentic: authentic(macKey), alert: (m) => alerts.push(m) });
  return { cp, store, memory, alerts };
}

test('ticks seal both trees through the vault login, and the log verifies, every entry provable', async () => {
  const { cp, store, memory, alerts } = await open();
  const numbers: bigint[] = [];
  for (let t = 0; t < 4; t += 1) {
    for (let i = 0; i < 30; i += 1) numbers.push(await use());
    numbers.push(await change());
    const tick = await cp.tick();
    assert.ok(tick.signed, tick.failures.join('; '));
  }
  assert.deepEqual([cp.pair.pair.changes.size, cp.pair.pair.uses.size], [4, 120]);
  const [row] = await rows<{ n: number }>(db.owner, sql`SELECT count(*) AS n FROM log_checkpoints`);
  assert.equal(Number(row!.n), 5, 'genesis and four pairs, one row each');
  const v = await verifyLog(store, { verifiers, anchors: [JSON.parse(memory.record!)], check: (e) => (authentic(macKey)(e) ? null : 'mac') });
  assert.ok(v.ok && v.sealed === 124, v.problems.join('\n'));
  for (const number of [numbers[0]!, numbers[30]!, numbers[45]!, numbers.at(-1)!]) {
    const p = (await cp.prove(number))!;
    assert.ok(verifyInclusion(leafHash(p.leaf), p.index, p.size, p.proof, cp.pair.pair[p.tree].root), `${number}`);
  }
  // A change as the change path will ask: sealed, proved in the changes tree.
  const pending = await change();
  const sealed = await cp.sealThrough(pending);
  assert.equal(sealed.proof.tree, 'changes');
  assert.equal(sealed.witnessed, null);
  assert.deepEqual(alerts, []);
});

test('the uses tree\'s leaf tiles land in ranges made ahead; a restart from the database seals on', async () => {
  const memory = variableMemory();
  const { cp } = await open(memory);
  for (let t = 0; t < 3; t += 1) {
    for (let i = 0; i < 300; i += 1) await use();
    assert.ok((await cp.tick()).signed);
  }
  if (ENGINE === 'postgres') {
    const ranges = await rows<{ name: string }>(db.owner, sql`
      SELECT c.relname AS name FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
       WHERE i.inhparent = 'log_tiles_uses_leaves'::regclass ORDER BY 1`);
    for (const name of ['log_tiles_uses_0', 'log_tiles_uses_512', 'log_tiles_uses_1024']) assert.ok(ranges.some((r) => r.name === name), `${name} in ${ranges.map((r) => r.name)}`);
  }
  const [tiles] = await rows<{ n: number }>(db.owner, sql`SELECT count(*) AS n FROM log_tiles WHERE tree = 'uses' AND level = 0`);
  assert.equal(Number(tiles!.n), 4, '900 leaves: three full tiles and the partial one');
  const again = await open(memory);
  for (let i = 0; i < 10; i += 1) await use();
  assert.ok((await again.cp.tick()).signed);
  assert.equal(again.cp.pair.pair.uses.size, 910);
  const v = await verifyLog(again.store, { verifiers });
  assert.ok(v.ok, v.problems.join('\n'));
});

test('a forged entry, a floor lowered by a writer, and a tile changed under the signer are each refused', async () => {
  {
    const { cp } = await open();
    await use();
    assert.ok((await cp.tick()).signed);
    await use(Date.now(), true);
    const t = await cp.tick();
    assert.ok(!t.signed && /MAC does not hold/.test(t.failures.join()), t.failures.join());
  }
  {
    await run(db.owner, sql`DELETE FROM log_uses`);
    const { cp } = await open();
    await use();
    assert.ok((await cp.tick()).signed);
    // BarrierChecksFloor: a writer lowers the unsigned floor row.
    await run(db.owner, sql`UPDATE log_fence SET at_floor = at_floor - 60000`);
    await use();
    const t = await cp.tick();
    assert.ok(!t.signed && /floor of at is .* lowered by a writer/.test(t.failures.join()), t.failures.join());
  }
  {
    await log.empty();
    const { cp } = await open();
    for (let i = 0; i < 3; i += 1) await use();
    assert.ok((await cp.tick()).signed);
    // The partial leaf tile, cut short by a writer: the next write, which grows it, is refused whole.
    await run(db.owner, sql`UPDATE log_tiles SET hashes = substr(hashes, 1, 32) WHERE tree = 'uses' AND level = 0`);
    await run(db.owner, sql`UPDATE log_tiles SET hashes = ${randomBytes(64)} WHERE tree = 'uses' AND level = 0`);
    await use();
    await assert.rejects(cp.tick(), (e: Error) => /shrink or change/.test(`${e.message} ${(e.cause as Error | undefined)?.message}`));
    const [count] = await rows<{ n: number }>(db.owner, sql`SELECT count(*) AS n FROM log_checkpoints`);
    assert.equal(Number(count!.n), 2, 'no pair written over the tiles that disagree');
  }
});

test('reads are bounded by their windows: locate finds a use in an old window by its floor, not by scanning', async () => {
  const { cp, store } = await open();
  const first = await use();
  assert.ok((await cp.tick()).signed);
  for (let t = 0; t < 3; t += 1) {
    await use();
    await change();
    assert.ok((await cp.tick()).signed);
  }
  const found = (await store.locate(first))!;
  assert.deepEqual([found.entry.tree, found.index], ['uses', 0]);
  const p = (await cp.prove(first))!;
  assert.ok(verifyInclusion(leafHash(p.leaf), p.index, p.size, p.proof, cp.pair.pair.uses.root));
  if (ENGINE === 'postgres') {
    // The window read and the locate each scan the uses' one index from a floor, never the table.
    const plan = await rows<{ 'QUERY PLAN': string }>(db.vault, sql`EXPLAIN SELECT 1 FROM log_uses u WHERE u.at >= ${Date.now() - 10_000} AND u.number > 0 AND u.number <= 10`);
    assert.ok(plan.some((r) => /Index|Bitmap/.test(r['QUERY PLAN'])), plan.map((r) => r['QUERY PLAN']).join('\n'));
  }
  // A change, as stored: the leaf the checkpointer sealed.
  const [raw] = await rows<{ number: string }>(db.owner, sql`SELECT number FROM log_changes ORDER BY number LIMIT 1`);
  const c = (await store.locate(BigInt(raw!.number)))!;
  assert.equal(c.entry.tree, 'changes');
});

test('review r3: entries and locate read one window\'s bounds, at any index, an empty window between', async () => {
  const { cp, store } = await open();
  const windows: bigint[][] = [];
  for (let t = 0; t < 4; t += 1) {
    const numbers: bigint[] = [];
    if (t !== 2) for (let i = 0; i < 5; i += 1) numbers.push(await use());
    if (t === 1) numbers.push(await change());
    windows.push(numbers);
    // A tick of nothing new signs nothing: an empty window is a pair at the same place, so the third window comes from
    // a skipped number alone.
    if (t === 2) await log.change().then(async (n) => (numbers.push(n), undefined));
    assert.ok((await cp.tick()).signed);
  }
  const pairs = await store.pairs(-1n, 10);
  // The middle windows' entries, exactly, read by the verifier's `entries`.
  const middle = await store.entries(pairs[1]!.upto, pairs[3]!.upto);
  assert.deepEqual(middle.map((e) => e.number), [...windows[1]!, ...windows[2]!]);
  // A use in the last window, not its first: its index counts every use before it in the tree.
  const last = windows[3]!;
  const found = (await store.locate(last[3]!))!;
  assert.deepEqual([found.entry.tree, found.index], ['uses', 5 + 5 + 3]);
  const p = (await cp.prove(last[3]!))!;
  assert.ok(verifyInclusion(leafHash(p.leaf), p.index, p.size, p.proof, cp.pair.pair.uses.root));
  // The change of the second window, by its key: the first in its tree.
  assert.deepEqual([(await store.locate(windows[1]!.at(-1)!))!.index], [0]);
});
