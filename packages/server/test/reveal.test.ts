import test from 'node:test';
import assert from 'node:assert/strict';

import { revealIsCurrent, type Reveal } from '../../ui/src/lib/reveal.ts';

const revealed: Reveal = { value: 'postgres://old', version: 3, at: 0 };

test('a reveal is shown only while its version is current', () => {
  assert.equal(revealIsCurrent(revealed, 3), true);
});

test('a new version retires the old plaintext', () => {
  // Saving through the edit row, or anyone else writing, moves the version on.
  assert.equal(revealIsCurrent(revealed, 4), false);
});

test('a rollback retires it too', () => {
  assert.equal(revealIsCurrent(revealed, 2), false);
});

test('nothing revealed is never current', () => {
  assert.equal(revealIsCurrent(null, 3), false);
});
