import test from 'node:test';
import assert from 'node:assert/strict';

import { revealIsCurrent, type Reveal } from '../src/lib/reveal.ts';
import {
  noReads,
  revealToggleDisabled,
  rowReads,
  type RowReads,
  type RowReadsAction,
} from '../src/lib/row-reads.ts';

const value: Reveal = { value: 'hunter2', version: 1, at: 0 };

function run(...actions: RowReadsAction[]): RowReads {
  return actions.reduce(rowReads, noReads);
}

/** What the row passes the eye button: the reveal, while it is the current version. */
function shownOf(state: RowReads): Reveal | null {
  return revealIsCurrent(state.reveal, 1) ? state.reveal : null;
}

test('Copy finishing before Reveal leaves the value shown and Hide enabled', () => {
  const state = run(
    { type: 'read-started' }, // Reveal asked
    { type: 'copy-started' }, // Copy asked, a moment later
    { type: 'copy-succeeded' }, // Copy came back first
    { type: 'read-succeeded', reveal: value }, // then Reveal
  );
  assert.deepEqual(shownOf(state), value);
  assert.equal(revealToggleDisabled(state, shownOf(state)), false);
  assert.equal(state.revealing, false);
  assert.equal(state.copyError, null);
});

test('Reveal finishing before Copy leaves the value shown and Hide enabled, while Copy is out', () => {
  let state = run(
    { type: 'read-started' }, // Reveal asked
    { type: 'copy-started' }, // Copy asked
    { type: 'read-succeeded', reveal: value }, // Reveal came back first
  );
  assert.deepEqual(shownOf(state), value);
  assert.equal(revealToggleDisabled(state, shownOf(state)), false, 'Hide while Copy is still reading');
  state = rowReads(state, { type: 'copy-succeeded' });
  assert.deepEqual(shownOf(state), value);
  assert.equal(revealToggleDisabled(state, shownOf(state)), false);
});

test('a Copy that fails, in either order, neither shows nor hides anything', () => {
  const copyFirst = run(
    { type: 'read-started' },
    { type: 'copy-started' },
    { type: 'copy-failed', message: 'refused' },
    { type: 'read-succeeded', reveal: value },
  );
  const revealFirst = run(
    { type: 'read-started' },
    { type: 'copy-started' },
    { type: 'read-succeeded', reveal: value },
    { type: 'copy-failed', message: 'refused' },
  );
  for (const state of [copyFirst, revealFirst]) {
    assert.deepEqual(shownOf(state), value);
    assert.equal(revealToggleDisabled(state, shownOf(state)), false);
    assert.equal(state.copyError, 'refused');
    assert.equal(state.error, null);
  }
});

test('a Reveal that fails does not touch Copy, and a failed Copy does not touch Reveal', () => {
  const state = run(
    { type: 'copy-started' },
    { type: 'copy-failed', message: 'clipboard said no' },
    { type: 'read-started' },
    { type: 'read-failed', message: 'not allowed' },
  );
  assert.equal(state.copyError, 'clipboard said no');
  assert.equal(state.error, 'not allowed');
  assert.equal(state.reveal, null);
  assert.equal(state.revealing, false);
});

test('Copy never starts or ends a Reveal read', () => {
  const state = run({ type: 'copy-started' });
  assert.equal(state.revealing, false);
  assert.equal(revealToggleDisabled(state, null), false);
  assert.equal(state.reveal, null);
});

test('with nothing shown, the eye waits for the read that is out', () => {
  const state = run({ type: 'read-started' });
  assert.equal(revealToggleDisabled(state, null), true);
});

test('a read made only to edit from shows nothing', () => {
  const state = run({ type: 'read-started' }, { type: 'read-succeeded', reveal: null });
  assert.equal(state.reveal, null);
  assert.equal(state.revealing, false);
});

test('a new Copy clears the last one\'s complaint', () => {
  const state = run({ type: 'copy-failed', message: 'x' }, { type: 'copy-started' });
  assert.equal(state.copyError, null);
});
