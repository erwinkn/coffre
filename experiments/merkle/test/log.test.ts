// The log against a real Postgres: appends, checkpoints, proofs, restarts and
// day changes. W209_URL names a scratch database it may wipe.
//
//   W209_URL=postgresql://… node --test experiments/merkle/test/log.test.ts
import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';

import pg from 'pg';

import { append, Checkpointer, createLog, keysFrom, leafOf, proveConsistency, proveNumber, type Keys } from '../src/log.ts';
import { openNote, parseCheckpoint, verifierFrom } from '../src/note.ts';
import { verifyConsistency, verifyInclusion } from '../src/tree.ts';

const url = process.env.W209_URL;
if (url === undefined) throw new Error('W209_URL names a scratch database');
const pool = new pg.Pool({ connectionString: url, max: 20 });
let keys: Keys;

const use = (i: number) => append(pool, keys, {
  at: Date.now(), principal: `svc-${i % 7}`, credential: `cred-${i % 7}`, kind: 'use', requestId: `r${i}`, payload: JSON.stringify({ secret: 'DFNS_KEY' }),
});

before(async () => {
  keys = await keysFrom('w209-synthetic');
  await createLog(pool);
  await pool.query('SELECT new_day(1)');
});
after(() => pool.end());

test('checkpoints seal every committed entry, in number order, and proofs verify', async () => {
  const cp = await Checkpointer.open(pool, keys);
  const verifier = await verifierFrom(keys.signer.verifierKey);
  const heads: { size: number; root: Buffer }[] = [];
  let i = 0;
  for (let round = 0; round < 6; round += 1) {
    // Appends race the tick: whatever has not committed when it seals waits for the next one.
    const appends = Array.from({ length: 300 }, () => use(i++));
    const tick = await cp.tick();
    assert.deepEqual(tick.failures, []);
    await Promise.all(appends);
    if (tick.signed) heads.push({ size: tick.size, root: parseCheckpoint((await openNote((await pool.query('SELECT note FROM checkpoints ORDER BY upto DESC LIMIT 1')).rows[0].note, verifier))!).root });
  }
  const last = await cp.tick();
  assert.equal(last.size, i, 'every entry is in the tree');
  const { rows } = await pool.query('SELECT number::text FROM audit ORDER BY random() LIMIT 25');
  for (const { number } of rows) {
    const p = (await proveNumber(pool, number))!;
    const head = parseCheckpoint((await openNote(p.checkpoint, verifier))!);
    assert.ok(verifyInclusion(leafOf(p.entry), p.index, head.size, p.proof, head.root), `inclusion of ${number}`);
  }
  for (const h of heads) {
    const top = parseCheckpoint((await openNote((await pool.query('SELECT note FROM checkpoints ORDER BY upto DESC LIMIT 1')).rows[0].note, verifier))!);
    assert.ok(verifyConsistency(h.size, top.size, h.root, top.root, await proveConsistency(pool, h.size, top.size)), `consistency from ${h.size}`);
  }
});

test('a checkpointer that restarts carries on from the tiles', async () => {
  for (let j = 0; j < 100; j += 1) await use(10_000 + j);
  const cp = await Checkpointer.open(pool, keys);
  const before = cp.size;
  const tick = await cp.tick();
  assert.equal(tick.size, before + 100);
});

test('a day ends at a checkpoint, its extent in a signed entry, and the next day numbers on from its own range', async () => {
  const cp = await Checkpointer.open(pool, keys);
  await use(20_000);
  const end = await cp.tick({ nextDay: 1 });
  // The day's entry is the new day's first number; the next use, the one after.
  const n = await use(20_001);
  assert.equal(BigInt(n), 1_000_000_000_001n);
  const next = await cp.tick();
  assert.equal(next.size, end.size + 2);
  const { rows: [d] } = await pool.query("SELECT a.payload FROM audit_changes a WHERE a.payload LIKE '{\"action\":\"audit.day\"%'");
  const day = JSON.parse(d.payload);
  assert.equal(day.last, end.upto);
  assert.equal(day.lastLeaf, end.size - 1);
  const p = (await proveNumber(pool, n))!;
  assert.equal(p.index, end.size + 1);
  // A second close of the same day, or a clock stepped back: the sequence does not move back.
  await cp.tick({ nextDay: 1 });
  assert.ok(BigInt(await use(20_002)) > BigInt(n));
});
