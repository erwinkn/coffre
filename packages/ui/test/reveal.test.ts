import test from 'node:test';
import assert from 'node:assert/strict';

import { revealIsCurrent, stampedRead, type Read, type Reveal } from '../src/lib/reveal.ts';
import { valueToEdit } from '../src/lib/row-reads.ts';

const revealed: Reveal = { value: 'postgres://old', version: 3, from: 'own', at: 0 };

test('a reveal is shown only while its version is current', () => {
  assert.equal(revealIsCurrent(revealed, 3, 'own'), true);
});

test('a new version retires the old plaintext', () => {
  // Saving through the edit row, or anyone else writing, moves the version on.
  assert.equal(revealIsCurrent(revealed, 4, 'own'), false);
});

test('a rollback retires it too', () => {
  assert.equal(revealIsCurrent(revealed, 2, 'own'), false);
});

test('nothing revealed is never current', () => {
  assert.equal(revealIsCurrent(null, 3, 'own'), false);
});

test("a fork's key reset to its parent's retires its own plaintext, though both are v1", () => {
  const own: Reveal = { value: 'postgres://eu', version: 1, from: 'own', at: 0 };
  assert.equal(revealIsCurrent(own, 1, 'own'), true);
  assert.equal(revealIsCurrent(own, 1, 'parent'), false);
});

test('a value read from no secret the listing named is never current', () => {
  assert.equal(revealIsCurrent({ value: 'x', version: 1, from: null, at: 0 }, 1, null), false);
});

/** A row as the page shows it: its version's number, and the id of the secret it reads (`secret`). */
type Row = { version: number | null; from: string | null };

/**
 * A row as the page shows it, its listing refetched by `refetch`, which moves
 * it to the next of `listings`; and the steps taken, in order.
 */
function page(row: Row, ...listings: Row[]) {
  const steps: string[] = [];
  const state = { row };
  return {
    steps,
    get row() {
      return state.row;
    },
    read: (opened: Read) => async () => (steps.push(`read ${opened.from} v${opened.version}`), opened),
    refetch: async () => {
      steps.push('refetch');
      // The listing comes back later, as a request's would.
      await new Promise((settled) => setTimeout(settled, 1));
      state.row = listings.shift() ?? state.row;
    },
  };
}

test('a read of the version the row shows is stamped with it, and the listing is not asked again', async () => {
  const at = page({ version: 4, from: 'own' });
  const reveal = await stampedRead(at.row, at.read({ value: 'v4', version: 4, from: 'own' }), at.refetch);
  assert.deepEqual(at.steps, ['read own v4']);
  assert.equal(revealIsCurrent(reveal, at.row.version, at.row.from), true);
});

test('a read that outran the listing waits for it: the row and the value then both say v5', async () => {
  // Someone saved v5 after the listing said v4; Reveal opens v5.
  const at = page({ version: 4, from: 'own' }, { version: 5, from: 'own' });
  const reveal = await stampedRead(at.row, at.read({ value: 'v5', version: 5, from: 'own' }), at.refetch);
  assert.deepEqual(at.steps, ['read own v5', 'refetch']);
  assert.deepEqual([reveal.version, at.row.version], [5, 5]);
  assert.equal(revealIsCurrent(reveal, at.row.version, at.row.from), true);
});

test('a listing that moved past the read by then hides it: it is no longer the value', async () => {
  const at = page({ version: 4, from: 'own' }, { version: 6, from: 'own' });
  const reveal = await stampedRead(at.row, at.read({ value: 'v5', version: 5, from: 'own' }), at.refetch);
  assert.equal(revealIsCurrent(reveal, at.row.version, at.row.from), false);
});

test("an edit starts from what the read opened, under that read's number, the same way", async () => {
  const at = page({ version: 4, from: 'own' }, { version: 5, from: 'own' });
  const base = await valueToEdit({ value: null, readable: true }, () => stampedRead(at.row, at.read({ value: 'v5', version: 5, from: 'own' }), at.refetch), () => assert.fail('not a plain value'));
  assert.deepEqual([base?.value, base?.version], ['v5', 5]);
  assert.equal(revealIsCurrent(base, at.row.version, at.row.from), true);
});

test("a reference's row is numbered and named by its source, as the read is: shown at once", async () => {
  const at = page({ version: 7, from: 'stripe' });
  const reveal = await stampedRead(at.row, at.read({ value: 'sk_live', version: 7, from: 'stripe' }), at.refetch);
  assert.deepEqual(at.steps, ['read stripe v7']);
  assert.equal(revealIsCurrent(reveal, at.row.version, at.row.from), true);
});

test("a read across a reset is shown as the parent's, once the row says it reads the parent's", async () => {
  // API_KEY is its own v2. Bo resets it to its parent, whose value is v7; Reveal opens the parent's, 7.
  const at = page({ version: 2, from: 'own' }, { version: 7, from: 'parent' });
  const reveal = await stampedRead(at.row, at.read({ value: "the parent's", version: 7, from: 'parent' }), at.refetch);
  assert.deepEqual(at.steps, ['read parent v7', 'refetch']);
  assert.equal(revealIsCurrent(reveal, at.row.version, at.row.from), true);
  // Bo overrides it again, its own v3: the parent's value hides.
  assert.equal(revealIsCurrent(reveal, 3, 'own'), false);
});

test("a reset then an override under the parent's very number never shows the parent's value as the override's", async () => {
  // The fork's own API_KEY is v2, its parent's v3. Bo resets it; Reveal opens the parent's v3; before the
  // listing is read again, Bo writes a new override, which reset kept the history of: its own v3.
  const at = page({ version: 2, from: 'own' }, { version: 3, from: 'own' });
  const reveal = await stampedRead(at.row, at.read({ value: "the parent's", version: 3, from: 'parent' }), at.refetch);
  assert.deepEqual([reveal.version, at.row.version], [3, 3]);
  assert.equal(revealIsCurrent(reveal, at.row.version, at.row.from), false);
  // An edit started from it the same way has no base.
  const base = await valueToEdit({ value: null, readable: true }, () => stampedRead({ version: 2, from: 'own' }, at.read({ value: "the parent's", version: 3, from: 'parent' }), async () => {}), () => assert.fail('not a plain value'));
  assert.equal(revealIsCurrent(base, 3, 'own'), false);
});

test('a read of the same number from another secret asks the listing again, as a newer number does', async () => {
  // The row says own v3; Bo reset it to the parent, also at v3, just before the click.
  const at = page({ version: 3, from: 'own' }, { version: 3, from: 'parent' });
  const reveal = await stampedRead(at.row, at.read({ value: "the parent's", version: 3, from: 'parent' }), at.refetch);
  assert.deepEqual(at.steps, ['read parent v3', 'refetch']);
  assert.equal(revealIsCurrent(reveal, at.row.version, at.row.from), true);
});
