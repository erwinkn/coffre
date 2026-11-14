import test from 'node:test';
import assert from 'node:assert/strict';

import type { AuditEntryView } from '@coffre/client';

import { proofOf, remember, shownProofs, type Proof, type Proved } from '../src/lib/audit-proofs.ts';

const entry = (seq: number, proof: Proof) => ({ seq, proof }) as AuditEntryView;
const head = { size: 769, signedAt: '2026-11-14T12:00:00.000Z' };

test("a batch shows its worst entry's proof", () => {
  assert.equal(proofOf(['proven', 'proven']), 'proven');
  assert.equal(proofOf(['proven', 'unproven']), 'unproven');
  assert.equal(proofOf(['unproven', 'failed', 'proven']), 'failed');
});

test('an entry proven under a head and then not under the same head shows as failed; another head is another answer', () => {
  const proved: Proved = new Map();
  const first = [entry(768, 'proven'), entry(769, 'unproven')];
  assert.deepEqual([...shownProofs(proved, head, first)], [[768, 'proven'], [769, 'unproven']]);
  remember(proved, head, first);

  // The same head, and 768 moved past it: a writer's edit, not a signing.
  assert.deepEqual([...shownProofs(proved, head, [entry(768, 'unproven'), entry(769, 'unproven')])], [[768, 'failed'], [769, 'unproven']]);

  // A newer head proves 769; an older one put back covers less, and says so.
  const newer = { size: 773, signedAt: '2026-11-14T12:00:05.000Z' };
  assert.equal(shownProofs(proved, newer, [entry(769, 'proven')]).get(769), 'proven');
  const older = { size: 700, signedAt: '2026-11-14T11:55:00.000Z' };
  assert.equal(shownProofs(proved, older, [entry(768, 'unproven')]).get(768), 'unproven');
  // No head: nothing proven, nothing remembered.
  assert.equal(shownProofs(proved, null, [entry(768, 'unproven')]).get(768), 'unproven');
  remember(proved, null, [entry(1, 'proven')]);
  assert.equal(proved.size, 1);
});
