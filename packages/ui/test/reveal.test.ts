import test from 'node:test';
import assert from 'node:assert/strict';

import { revealIsCurrent, stampedRead, type Read, type Reveal } from '../src/lib/reveal.ts';
import { valueToEdit } from '../src/lib/row-reads.ts';

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

test("a fork's key reset to its parent's retires its own plaintext, though both are v1", () => {
  const own: Reveal = { value: 'postgres://eu', version: 1, from: '.:', at: 0 };
  assert.equal(revealIsCurrent(own, 1, '.:'), true);
  assert.equal(revealIsCurrent(own, 1, 'prod:'), false);
});

/**
 * A row as the page shows it, its listing refetched by `refetch`, which moves
 * it to the next of `listings`; and the steps taken, in order.
 */
function page(row: { version: number | null; from: string }, ...listings: { version: number | null; from: string }[]) {
  const steps: string[] = [];
  const state = { row };
  return {
    steps,
    get row() {
      return state.row;
    },
    read: (opened: Read) => async () => (steps.push(`read v${opened.version}`), opened),
    refetch: async () => {
      steps.push('refetch');
      // The listing comes back later, as a request's would.
      await new Promise((settled) => setTimeout(settled, 1));
      state.row = listings.shift() ?? state.row;
    },
  };
}

test('a read of the version the row shows is stamped with it, and the listing is not asked again', async () => {
  const at = page({ version: 4, from: '.:' });
  const reveal = await stampedRead(at.row, at.read({ value: 'v4', version: 4 }), at.refetch);
  assert.deepEqual(at.steps, ['read v4']);
  assert.equal(revealIsCurrent(reveal, at.row.version, at.row.from), true);
});

test('a read that outran the listing waits for it: the row and the value then both say v5', async () => {
  // Someone saved v5 after the listing said v4; Reveal opens v5.
  const at = page({ version: 4, from: '.:' }, { version: 5, from: '.:' });
  const reveal = await stampedRead(at.row, at.read({ value: 'v5', version: 5 }), at.refetch);
  assert.deepEqual(at.steps, ['read v5', 'refetch']);
  assert.deepEqual([reveal.version, at.row.version], [5, 5]);
  assert.equal(revealIsCurrent(reveal, at.row.version, at.row.from), true);
});

test('a listing that moved past the read by then hides it: it is no longer the value', async () => {
  const at = page({ version: 4, from: '.:' }, { version: 6, from: '.:' });
  const reveal = await stampedRead(at.row, at.read({ value: 'v5', version: 5 }), at.refetch);
  assert.equal(revealIsCurrent(reveal, at.row.version, at.row.from), false);
});

test("an edit starts from what the read opened, under that read's number, the same way", async () => {
  const at = page({ version: 4, from: '.:' }, { version: 5, from: '.:' });
  const base = await valueToEdit({ value: null, readable: true }, () => stampedRead(at.row, at.read({ value: 'v5', version: 5 }), at.refetch), () => assert.fail('not a plain value'));
  assert.deepEqual([base?.value, base?.version], ['v5', 5]);
  assert.equal(revealIsCurrent(base, at.row.version, at.row.from), true);
});

test("a reference's row is numbered by its source, as the read is: shown at once", async () => {
  const at = page({ version: 7, from: '.:billing/prod/STRIPE_KEY' });
  const reveal = await stampedRead(at.row, at.read({ value: 'sk_live', version: 7 }), at.refetch);
  assert.deepEqual(at.steps, ['read v7']);
  assert.equal(revealIsCurrent(reveal, at.row.version, at.row.from), true);
});

test('a read across a reset is never shown under the wrong number: hidden, and a second click shows it', async () => {
  // API_KEY is its own v2. Bo resets it to its parent, whose value is v7; Reveal opens the parent's, 7.
  const at = page({ version: 2, from: '.:' }, { version: 7, from: 'prod:' });
  const reveal = await stampedRead(at.row, at.read({ value: "the parent's", version: 7 }), at.refetch);
  // Nothing said where it was held, so it keeps the row's `from` as asked: hidden, not shown as prod's.
  assert.equal(revealIsCurrent(reveal, at.row.version, at.row.from), false);
  // Bo overrides it again, its own v3: the parent's value is still not shown.
  assert.equal(revealIsCurrent(reveal, 3, '.:'), false);
  // A second click on the row as it is now shows the value under its own number.
  const again = await stampedRead({ version: 7, from: 'prod:' }, at.read({ value: "the parent's", version: 7 }), at.refetch);
  assert.equal(revealIsCurrent(again, 7, 'prod:'), true);
});
