// Retention, both ways (W209): days of uses dropped once sealed, changes kept,
// and the log still verifying from the cut; what stays below it tampered with
// fails. W209_URL names a scratch database it may wipe.
//
//   W209_URL=postgresql://… node --test experiments/merkle/test/retention.test.ts
import assert from 'node:assert/strict';
import { after, test } from 'node:test';

import pg from 'pg';

import { append, Checkpointer, createLog, keysFrom, leafOf, proveNumber } from '../src/log.ts';
import { openNote, parseCheckpoint, verifierFrom } from '../src/note.ts';
import { retainDay, retentions } from '../src/retention.ts';
import { verifyInclusion } from '../src/tree.ts';
import { verifyLog } from '../src/verify.ts';

const url = process.env.W209_URL;
if (url === undefined) throw new Error('W209_URL names a scratch database');
const pool = new pg.Pool({ connectionString: url, max: 10 });
after(() => pool.end());
const keys = await keysFrom('w209-synthetic');
const verify = () => verifyLog(pool, { verifierKey: keys.signer.verifierKey, macKey: keys.mac });

let i = 0;
const entry = (kind: 'use' | 'change', at = Date.now()) => append(pool, keys, {
  at, principal: `svc-${i % 3}`, credential: `cred-${i % 3}`, kind, requestId: `r${i++}`, payload: '{}', seal: kind === 'change' ? Buffer.alloc(32, i % 256) : null,
});

for (const mode of ['number', 'at'] as const) {
  test(`${mode} days: a sealed day dropped, the changes kept, the log verifying from the cut`, async () => {
    const dayMs = 60_000;
    await createLog(pool, mode, dayMs);
    const cp = await Checkpointer.open(pool, keys);
    // Day "d0": uses and a few changes. With `at` days, the day is the Worker's clock: the uses carry at in day d0.
    const d0 = mode === 'number' ? 0 : Math.floor(Date.now() / dayMs);
    const atOf = (d: number) => (mode === 'number' ? Date.now() : d * dayMs + 1000);
    for (let r = 0; r < 4; r += 1) {
      for (let e = 0; e < 40; e += 1) await entry(e % 13 === 0 ? 'change' : 'use', atOf(d0));
      await cp.tick();
    }
    if (mode === 'number') {
      await pool.query('SELECT new_day(1)');
      await cp.tick({ nextDay: 1 });
    }
    // Day d0 + 1, and, with `at` days, a straggler: a use of day d0 numbered after day d0 + 1 began.
    for (let e = 0; e < 30; e += 1) await entry(e % 10 === 0 ? 'change' : 'use', atOf(d0 + 1));
    if (mode === 'at') await entry('use', atOf(d0));
    await cp.tick();
    assert.ok((await verify()).ok);

    const r = await retainDay(pool, keys, d0);
    await cp.tick();
    const v = await verify();
    assert.deepEqual(v.problems, []);
    assert.ok(r.dropped > 100 && r.retention.kept >= 12, `dropped ${r.dropped}, kept ${r.retention.kept}`);
    // Proofs of what came after the cut still verify: the tiles they read are kept.
    const verifier = await verifierFrom(keys.signer.verifierKey);
    const { rows } = await pool.query('SELECT a.number::text FROM audit a WHERE a.number > $1 AND a.number <= $2', [r.retention.cutUpto, cp.upto]);
    for (const { number } of rows) {
      const p = (await proveNumber(pool, number))!;
      const head = parseCheckpoint((await openNote(p.checkpoint, verifier))!);
      assert.ok(verifyInclusion(leafOf(p.entry), p.index, head.size, p.proof, head.root), `after the cut: ${number}`);
    }

    // A kept change below the cut deleted: caught by the retention entry's head.
    const { rows: [kept] } = await pool.query("SELECT a.number::text FROM audit_changes a WHERE a.number <= $1 AND a.payload = '{}' LIMIT 1", [r.retention.cutUpto]);
    await pool.query('DROP TABLE IF EXISTS saved; CREATE TABLE saved AS SELECT * FROM audit WHERE false');
    await pool.query('WITH d AS (DELETE FROM audit WHERE number = $1 RETURNING *) INSERT INTO saved SELECT * FROM d', [kept.number]);
    assert.match((await verify()).problems.join(';'), /retention of day/);
    await pool.query('INSERT INTO audit SELECT * FROM saved');
    assert.ok((await verify()).ok);
    // The retention entry itself deleted: the walk then starts below the cut, where leaves are gone.
    const [ret] = await retentions(pool);
    await pool.query('DELETE FROM audit WHERE number = $1', [ret!.number]);
    assert.ok(!(await verify()).ok);
  });
}
