import test from 'node:test';
import assert from 'node:assert/strict';

import { copyAttempts, type CopyResult } from '../src/lib/copy-attempts.ts';

/** A copy the test finishes by hand: `end()` ends it, `end(reason)` fails it. */
function manualCopies() {
  const ends: Array<(failure?: unknown) => void> = [];
  const texts: Array<string | Promise<string>> = [];
  const copy = (text: string | Promise<string>) => {
    texts.push(text);
    return new Promise<void>((resolve, reject) => {
      ends.push((failure) => (failure === undefined ? resolve() : reject(failure)));
    });
  };
  return { copy, ends, texts };
}

const refused = new DOMException('no', 'NotAllowedError');

test('a lone copy reports how it ended', async () => {
  const { copy, ends } = manualCopies();
  const run = copyAttempts(copy);
  const done = run('x');
  ends[0]();
  assert.deepEqual(await done, { outcome: 'copied' });
  const failed = run('x');
  ends[1](refused);
  assert.deepEqual(await failed, { outcome: 'failed', failure: refused });
});

test('an early clipboard refusal, a retry, then the first read failing late: the retry is what shows', async () => {
  const { copy, ends } = manualCopies();
  const run = copyAttempts(copy);
  let failRead!: (reason: unknown) => void;
  const read = new Promise<string>((_, reject) => (failRead = reject));

  const first = run(read);
  ends[0](refused); // the clipboard refuses while the read is still out
  const retry = run(read.catch(() => 'v')); // a retry, started before the first has been heard
  ends[1](); // and it works
  failRead(new Error('late')); // then the first read fails

  // The retry began before the first's refusal was heard, so the first is dropped.
  assert.deepEqual(await first, { outcome: 'superseded' });
  assert.deepEqual(await retry, { outcome: 'copied' });
});

test('a refusal heard before the retry starts is reported, and the retry then replaces it', async () => {
  const { copy, ends } = manualCopies();
  const run = copyAttempts(copy);
  const first = run(new Promise<string>(() => {}));
  ends[0](refused);
  assert.deepEqual(await first, { outcome: 'failed', failure: refused });
  const retry = run('v');
  ends[1]();
  assert.deepEqual(await retry, { outcome: 'copied' });
});

test('a copy that outlives its button is superseded by the next, whichever button starts it', async () => {
  // The attempts belong to the row. Edit/Cancel or Archive/Keep replaces the button,
  // not the row, so the new button's copy meets the old one's.
  const { copy, ends } = manualCopies();
  const rowAttempts = copyAttempts(copy);
  const fromOldButton = rowAttempts(new Promise<string>(() => {}));
  // The button is unmounted and mounted again here: nothing of the row's changes.
  const fromNewButton = rowAttempts('v');
  ends[1]();
  ends[0](new Error('the old read failed late'));
  assert.deepEqual(await fromNewButton, { outcome: 'copied' });
  assert.deepEqual(await fromOldButton, { outcome: 'superseded' });
});

test('copying the shown value, hiding it, then copying the hidden one: the second is what shows', async () => {
  const { copy, ends, texts } = manualCopies();
  const run = copyAttempts(copy);
  const shownCopy = run('shown value'); // writeText of a string is still out ...
  const hiddenCopy = run(Promise.resolve('read value')); // ... when Hide, then Copy on the hidden value
  assert.deepEqual(texts.length, 2);
  ends[0](); // the first clipboard result lands now
  assert.deepEqual(await shownCopy, { outcome: 'superseded' });
  ends[1](refused);
  assert.deepEqual(await hiddenCopy, { outcome: 'failed', failure: refused });
});

test('a superseded copy is dropped whether it succeeded or failed', async () => {
  const { copy, ends } = manualCopies();
  const run = copyAttempts(copy);
  const results: CopyResult[] = [];
  const old = run('a').then((result) => results.push(result));
  const newest = run('b').then((result) => results.push(result));
  ends[0](refused);
  ends[1]();
  await Promise.all([old, newest]);
  assert.deepEqual(results, [{ outcome: 'superseded' }, { outcome: 'copied' }]);
});
