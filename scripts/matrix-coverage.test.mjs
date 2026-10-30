import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { coverage, readReports } from './matrix-coverage.mjs';
import { shardSpec, sliceOf } from './matrix-shard.ts';

const root = new URL('..', import.meta.url).pathname;

test('a shard is <k>/<n>, 1 <= k <= n; unset, the whole matrix', () => {
  assert.deepEqual(shardSpec(undefined), { shard: 1, of: 1 });
  assert.deepEqual(shardSpec(''), { shard: 1, of: 1 });
  assert.deepEqual(shardSpec('3/4'), { shard: 3, of: 4 });
  for (const value of ['0/4', '5/4', '1/0', '4', '1/4/2', ' 1/4', '01/4', '-1/4', 'a/b']) assert.throws(() => shardSpec(value), /COFFRE_TEST_SHARD/, value);
});

test('the slices of n shards partition the cases, in order, their sizes within one of each other', () => {
  const cases = Array.from({ length: 867 }, (_, i) => i);
  for (const of of [1, 2, 3, 4, 5, 7, 900]) {
    const slices = Array.from({ length: of }, (_, k) => sliceOf(cases, { shard: k + 1, of }));
    assert.deepEqual(slices.flat().sort((a, b) => a - b), cases, `${of}`);
    for (const slice of slices) {
      assert.deepEqual(slice, [...slice].sort((a, b) => a - b));
      assert.ok(Math.abs(slice.length - cases.length / of) < 1, `${of}: ${slice.length}`);
    }
  }
});

const files = ['packages/a/test/one.matrix.ts', 'packages/b/test/two.matrix.ts'];
const cases = ['a', 'b', 'c', 'd', 'e'];
function shards(engine, file, of, all = cases) {
  return Array.from({ length: of }, (_, k) => ({ engine, file, shard: k + 1, of, cases: all, ran: sliceOf(all, { shard: k + 1, of }) }));
}
const complete = () => [...shards('postgres', files[0], 3), ...shards('postgres', files[1], 2), ...shards('sqlite', files[0], 2), ...shards('sqlite', files[1], 1)];

test('shards that ran every case once, each matrix its own count of them, pass', () => {
  assert.deepEqual(coverage(complete(), files, ['postgres', 'sqlite']), []);
});

test('a case run twice, in no shard, or of no matrix fails, by name', () => {
  const twice = complete();
  twice[0].ran = [...twice[0].ran, 'b'];
  assert.deepEqual(coverage(twice, files, ['postgres', 'sqlite']), [`postgres ${files[0]}: b ran in shards 1, 2`]);
  const none = complete();
  none[1].ran = [];
  assert.deepEqual(coverage(none, files, ['postgres', 'sqlite']), [`postgres ${files[0]}: b ran in no shard`, `postgres ${files[0]}: e ran in no shard`]);
  const stray = complete();
  stray[0].ran = [...stray[0].ran, 'z'];
  assert.deepEqual(coverage(stray, files, ['postgres', 'sqlite']), [`postgres ${files[0]}: shard 1 ran z, no case of the matrix`]);
});

test('a matrix that does not shard runs every case in each shard, and fails', () => {
  const unsharded = complete().map((report) => ({ ...report, ran: report.cases }));
  const problems = coverage(unsharded, files, ['postgres', 'sqlite']);
  assert.ok(problems.includes(`postgres ${files[0]}: a ran in shards 1, 2, 3`), problems.join('\n'));
  // Every shard writing the one shard of one, its slice never learnt, reports shard 1 n times.
  const unlearnt = complete().map((report) => ({ ...report, shard: 1, of: 1, ran: report.cases }));
  assert.ok(coverage(unlearnt, files, ['postgres', 'sqlite']).includes(`postgres ${files[0]}: shards 1, 1, 1 reported, of 1`));
});

test('a shard missing, shards of another count, other cases, or a label twice fails', () => {
  assert.deepEqual(coverage(complete().filter((r) => !(r.engine === 'postgres' && r.file === files[0] && r.shard === 2)), files, ['postgres', 'sqlite']), [`postgres ${files[0]}: shards 1, 3 reported, of 3`]);
  const counts = complete();
  counts[0].of = 4;
  assert.deepEqual(coverage(counts, files, ['postgres', 'sqlite']), [`postgres ${files[0]}: shards of 3 and 4`]);
  const other = complete();
  other[0].cases = [...cases, 'f'];
  assert.deepEqual(coverage(other, files, ['postgres', 'sqlite']), [`postgres ${files[0]}: its shards generated other cases`]);
  const dup = [...shards('postgres', files[0], 2, ['a', 'a', 'b']), ...shards('postgres', files[1], 1)];
  assert.deepEqual(coverage(dup, files, ['postgres']), [`postgres ${files[0]}: two cases of one label`]);
});

test('a matrix or an engine that never reported, or a report of neither asked for, fails', () => {
  assert.deepEqual(coverage(complete().filter((r) => r.file !== files[1] || r.engine !== 'sqlite'), files, ['postgres', 'sqlite']), [`sqlite ${files[1]}: no shard reported`]);
  assert.deepEqual(coverage(complete(), [...files, 'packages/c/test/three.matrix.ts'], ['postgres']).slice(-1), ['postgres packages/c/test/three.matrix.ts: no shard reported']);
  assert.deepEqual(coverage(complete(), [files[0]], ['postgres']), [
    `postgres ${files[1]}: a report of no matrix asked for (shard 1 of 2)`,
    `postgres ${files[1]}: a report of no matrix asked for (shard 2 of 2)`,
    `sqlite ${files[0]}: a report of no matrix asked for (shard 1 of 2)`,
    `sqlite ${files[0]}: a report of no matrix asked for (shard 2 of 2)`,
    `sqlite ${files[1]}: a report of no matrix asked for (shard 1 of 1)`,
  ]);
});

test('shardOf reports what it ran, which the check reads back from shards in directories of their own', () => {
  const dir = mkdtempSync(join(tmpdir(), 'coffre-matrix-shards-'));
  try {
    const script = `import { shardOf } from './scripts/matrix-shard.ts';
      console.log(JSON.stringify(shardOf(new URL('./packages/x/test/x.matrix.ts', import.meta.url).href, ['a', 'b', 'c', 'd', 'e'], (c) => c)));`;
    for (const shard of ['1/2', '2/2']) {
      const run = spawnSync(process.execPath, ['--input-type=module', '-e', script], {
        cwd: root, encoding: 'utf8', env: { ...process.env, COFFRE_TEST_ENGINE: 'sqlite', COFFRE_TEST_SHARD: shard, COFFRE_TEST_SHARD_REPORT: join(dir, shard.replace('/', '-of-')) },
      });
      assert.equal(run.status, 0, run.stderr);
      assert.deepEqual(JSON.parse(run.stdout), shard === '1/2' ? ['a', 'c', 'e'] : ['b', 'd']);
    }
    const reports = readReports(dir);
    assert.equal(reports.length, 2);
    assert.deepEqual(reports.map((r) => [r.engine, r.file, r.shard, r.of]).sort(), [['sqlite', 'packages/x/test/x.matrix.ts', 1, 2], ['sqlite', 'packages/x/test/x.matrix.ts', 2, 2]]);
    assert.deepEqual(coverage(reports, ['packages/x/test/x.matrix.ts'], ['sqlite']), []);
    const check = spawnSync(process.execPath, ['scripts/matrix-coverage.mjs', dir, 'sqlite'], { cwd: root, encoding: 'utf8' });
    // The checkout's own matrices never reported here: the check names each.
    assert.equal(check.status, 1);
    assert.match(check.stderr, /sqlite packages\/vault\/test\/use\.matrix\.ts: no shard reported/);
    assert.match(check.stderr, /sqlite packages\/x\/test\/x\.matrix\.ts: a report of no matrix asked for/);
    assert.ok(readFileSync(join(root, 'package.json'), 'utf8').includes("--files 'packages/*/test/*.matrix.ts'"), 'test:matrices runs every matrix of the checkout');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
