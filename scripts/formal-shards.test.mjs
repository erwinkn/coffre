import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const root = new URL('..', import.meta.url).pathname;

// What `scripts/formal.sh --list` prints, without TLC or its jar: a line per scenario and per run without a protection.
const list = (...args) => {
  const run = spawnSync('scripts/formal.sh', [...args, '--list'], { cwd: root, encoding: 'utf8' });
  assert.equal(run.status, 0, run.stderr);
  return run.stdout.split('\n').filter(Boolean);
};

const shards = readFileSync(`${root}scripts/formal.sh`, 'utf8').match(/^SHARDS="([^"]+)"$/m)?.[1].split(' ');
const matrix = readFileSync(`${root}.github/workflows/validate.yml`, 'utf8').match(/^ +shard: \[([a-z, -]+)\]$/m)?.[1].split(', ');

test("CI's matrix runs the shards formal.sh names", () => {
  assert.ok(shards?.length && matrix?.length, 'both lists found');
  assert.deepEqual(matrix, shards);
});

test('every scenario and every run without a protection is in exactly one shard', () => {
  const all = list();
  assert.ok(all.some((line) => line.startsWith('holds ')) && all.some((line) => line.startsWith('without ')));
  const sharded = [];
  for (const shard of shards) {
    const lines = list('--shard', shard);
    assert.ok(lines.some((line) => line.startsWith('holds ')), `${shard} runs no scenario`);
    sharded.push(...lines);
  }
  // A scenario is in one shard. The runs without a protection are not unique lines (one protection is removed once
  // per invariant it keeps, and --list names the protection only): as a whole they must match the unsharded list,
  // so no run is lost or doubled.
  const scenarios = sharded.filter((line) => line.startsWith('holds '));
  assert.equal(new Set(scenarios).size, scenarios.length, 'a scenario in two shards');
  assert.deepEqual([...sharded].sort(), [...all].sort());
});
