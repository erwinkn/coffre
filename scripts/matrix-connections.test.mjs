import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { connectionShare, withinShare } from './matrix-connections.ts';

/** `work` with the run's files, at once, and the directory where they end, as `test-suite.sh --files` sets them. */
function inRun(files, atOnce, work) {
  const ended = mkdtempSync(join(tmpdir(), 'coffre-ended-test-'));
  const before = { ...process.env };
  Object.assign(process.env, { COFFRE_TEST_FILES: String(files), COFFRE_TEST_CONCURRENCY: String(atOnce), COFFRE_TEST_FILES_ENDED: ended });
  try {
    return work((pid) => writeFileSync(join(ended, String(pid)), ''));
  } finally {
    for (const name of ['COFFRE_TEST_FILES', 'COFFRE_TEST_CONCURRENCY', 'COFFRE_TEST_FILES_ENDED']) {
      if (before[name] === undefined) delete process.env[name];
      else process.env[name] = before[name];
    }
    rmSync(ended, { recursive: true, force: true });
  }
}

test("a matrix's share is what Postgres lets open, split evenly among the files still running", () => {
  inRun(4, 4, (end) => {
    assert.equal(connectionShare(97), 24);
    end(101);
    assert.equal(connectionShare(97), 32);
    end(102);
    assert.equal(connectionShare(97), 48);
    end(103);
    // The last file running: every connection is its own.
    assert.equal(connectionShare(97), 97);
  });
});

test('more files than run at once: a file that ends lets the next start, and the share holds until fewer remain than run at once', () => {
  inRun(6, 4, (end) => {
    assert.equal(connectionShare(97), 24);
    end(101);
    end(102);
    assert.equal(connectionShare(97), 24);
    end(103);
    assert.equal(connectionShare(97), 32);
  });
});

test('a file past its share fails before any cell, saying so; within it, nothing', () => {
  inRun(4, 4, () => {
    withinShare('forks.matrix.ts', 21, 97);
    assert.throws(() => withinShare('forks.matrix.ts', 25, 97), /forks\.matrix\.ts holds up to 25 connections at once, past its share of Postgres's 97, 24/);
  });
});

test('outside a run of test-suite.sh --files, no share: a matrix cannot know what runs beside it', () => {
  const before = process.env.COFFRE_TEST_FILES;
  delete process.env.COFFRE_TEST_FILES;
  try {
    assert.throws(() => connectionShare(97), /scripts\/test-suite\.sh --files/);
  } finally {
    if (before !== undefined) process.env.COFFRE_TEST_FILES = before;
  }
});
