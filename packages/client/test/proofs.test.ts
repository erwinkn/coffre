// The judgment of a page of `GET /audit` on what the real server cannot be
// made to answer: an entry proven past the head. The real pages, edited,
// deleted and past the head, are the server's audit tests.
import test from 'node:test';
import assert from 'node:assert/strict';

import { judgeProofs, type AuditEntryView } from '../src/index.ts';

const entry = (seq: number, proof: AuditEntryView['proof']) => ({ seq, proof }) as AuditEntryView;
type Hole = { above: number | null; below: number | null; kept: number; aging: number };
const page = (entries: AuditEntryView[], head: { size: number; signedAt: string } | null = { size: 2, signedAt: '2026-11-14T00:00:00Z' }, holes: Hole[] = []) =>
  ({ entries, more: false, next: null, head, holes: head === null ? null : holes });

test('the head numbers the log\'s first entries: those proven, the rest unproven, and anything else misplaced or failed', () => {
  assert.deepEqual(judgeProofs(page([entry(2, 'unproven'), entry(1, 'proven'), entry(0, 'proven')])), {
    head: { size: 2, signedAt: '2026-11-14T00:00:00Z' }, numbered: 2, proven: 2, failed: [], misplaced: [], missing: [], racing: false,
  });
  const wrong = judgeProofs(page([entry(3, 'proven'), entry(2, 'unproven'), entry(1, 'unproven'), entry(0, 'failed')]));
  assert.deepEqual([wrong.misplaced.map(({ seq }) => seq), wrong.failed.map(({ seq }) => seq)], [[3, 1], [0]]);
  // With no head, nothing is numbered, and what the page lacks cannot be said.
  const none = judgeProofs(page([entry(0, 'unproven')], null));
  assert.deepEqual([none.numbered, none.misplaced, none.missing, none.racing], [0, [], null, true]);
});

test('a page races its head when the head numbers none of it, or its stretch lacks aging entries alone, which a pruning in between removes', () => {
  const listed = [entry(1, 'proven'), entry(0, 'proven')];
  // Every entry past the head: a batch signed between the two reads.
  assert.equal(judgeProofs(page([entry(3, 'unproven'), entry(2, 'unproven')])).racing, true);
  // Aging uses the older head still counts: a pruning committed between the two reads.
  assert.equal(judgeProofs(page(listed, undefined, [{ above: 1, below: 0, kept: 0, aging: 2 }])).racing, true);
  // A kept entry missing is no race, mixed with aging ones or not: no pruning removes it.
  assert.equal(judgeProofs(page(listed, undefined, [{ above: 1, below: 0, kept: 1, aging: 0 }])).racing, false);
  assert.equal(judgeProofs(page(listed, undefined, [{ above: 1, below: 0, kept: 0, aging: 1 }, { above: 0, below: null, kept: 1, aging: 0 }])).racing, false);
});
