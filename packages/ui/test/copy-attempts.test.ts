import test from 'node:test';
import assert from 'node:assert/strict';

import { copyText, type ClipboardLike } from '../src/lib/clipboard.ts';
import { createCopier, type CopyFeedback, type CopyResult } from '../src/lib/copy-attempts.ts';

/** A copy the test finishes by hand: `ends[n]()` ends the nth, `ends[n](reason)` fails it. */
function manualCopies() {
  const ends: Array<(failure?: unknown) => void> = [];
  const copy = (text: string | Promise<string>) => {
    const ended = new Promise<void>((resolve, reject) => {
      ends.push((failure) => (failure === undefined ? resolve() : reject(failure)));
    });
    // Like write(): done when the clipboard says so and the payload has arrived, failed if either fails.
    return Promise.all([typeof text === 'string' ? text : text, ended]).then(() => {});
  };
  return { copy, ends };
}

const refused = new DOMException('no', 'NotAllowedError');

/** What a button subscribed to the copier would have shown, in order. */
function watch(copier: ReturnType<typeof createCopier>) {
  const seen: CopyFeedback[] = [copier.feedback()];
  copier.subscribe(() => seen.push(copier.feedback()));
  return seen;
}

test('a lone copy reports how it ended, and shows it', async () => {
  const { copy, ends } = manualCopies();
  const copier = createCopier({ copy, copiedMs: 5, failedMs: 5 });
  const seen = watch(copier);
  const done = copier.run('x');
  ends[0]();
  assert.deepEqual(await done, { outcome: 'copied' });
  assert.equal(copier.feedback(), 'copied');
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.deepEqual(seen, ['idle', 'pending', 'copied', 'idle']);
  const failed = copier.run('x');
  ends[1](refused);
  assert.deepEqual(await failed, { outcome: 'failed', failure: refused });
  assert.equal(copier.feedback(), 'failed');
});

test('an early clipboard refusal, a retry, then the first read failing late: the retry is what shows', async () => {
  const { copy, ends } = manualCopies();
  const copier = createCopier({ copy });
  let failRead!: (reason: unknown) => void;
  const read = new Promise<string>((_, reject) => (failRead = reject));

  const first = copier.run(read);
  const retry = copier.run('v'); // before the first's refusal is heard
  ends[0](refused);
  ends[1]();
  failRead(new Error('late'));

  assert.deepEqual(await first, { outcome: 'superseded' });
  assert.deepEqual(await retry, { outcome: 'copied' });
  assert.equal(copier.feedback(), 'copied');
});

test('a refusal heard before the retry starts is reported, and the retry then replaces it', async () => {
  const { copy, ends } = manualCopies();
  const copier = createCopier({ copy });
  const first = copier.run(new Promise<string>(() => {}));
  ends[0](refused);
  assert.deepEqual(await first, { outcome: 'failed', failure: refused });
  assert.equal(copier.feedback(), 'failed');
  const retry = copier.run('v');
  assert.equal(copier.feedback(), 'pending', 'the old failure is not left showing');
  ends[1]();
  assert.deepEqual(await retry, { outcome: 'copied' });
  assert.equal(copier.feedback(), 'copied');
});

test('a button replaced mid-copy picks the pending copy up, and its ending, from the copier', async () => {
  // The copier belongs to the row. Edit/Cancel or Archive/Keep replaces the button,
  // not the row: the new button subscribes and reads what the copier says now.
  const { copy, ends } = manualCopies();
  const copier = createCopier({ copy });
  const oldButton = watch(copier);
  const copying = copier.run(Promise.resolve('v'));
  const newButton = watch(copier); // mounted while the copy is out
  assert.equal(newButton[0], 'pending');
  ends[0]();
  assert.deepEqual(await copying, { outcome: 'copied' });
  assert.equal(newButton.at(-1), 'copied');
  assert.equal(oldButton.at(-1), 'copied');
});

test('copying the shown value, hiding it, then copying the hidden one: the second is what shows', async () => {
  const { copy, ends } = manualCopies();
  const copier = createCopier({ copy });
  const shownCopy = copier.run('shown value'); // its write is still out ...
  const hiddenCopy = copier.run(Promise.resolve('read value')); // ... when Hide, then Copy on the hidden value
  ends[0](); // the first clipboard result lands now
  assert.deepEqual(await shownCopy, { outcome: 'superseded' });
  assert.equal(copier.feedback(), 'pending', 'the first result does not end the second\'s pending state');
  ends[1](refused);
  assert.deepEqual(await hiddenCopy, { outcome: 'failed', failure: refused });
  assert.equal(copier.feedback(), 'failed');
});

test('another click after a finished copy starts clean: pending, not the last result', async () => {
  const { copy, ends } = manualCopies();
  const copier = createCopier({ copy });
  const first = copier.run('x');
  ends[0]();
  await first;
  assert.equal(copier.feedback(), 'copied');
  void copier.run('x');
  assert.equal(copier.feedback(), 'pending');
});

test('a superseded copy is dropped whether it succeeded or failed', async () => {
  const { copy, ends } = manualCopies();
  const copier = createCopier({ copy });
  const results: CopyResult[] = [];
  const old = copier.run('a').then((result) => results.push(result));
  const newest = copier.run('b').then((result) => results.push(result));
  ends[0](refused);
  ends[1]();
  await Promise.all([old, newest]);
  assert.deepEqual(results, [{ outcome: 'superseded' }, { outcome: 'copied' }]);
});

test('a read that returns after a newer copy began never reaches the clipboard', async () => {
  // Two copies across a version change, on the fetch-then-writeText path: the older
  // response arrives last and must not overwrite the newer value.
  const written: string[] = [];
  const clipboard: ClipboardLike = {
    async writeText(text) {
      written.push(text);
    },
  };
  const copier = createCopier({ copy: (text) => copyText(text, { clipboard, item: undefined }) });
  let release!: (value: string) => void;
  const slow = new Promise<string>((resolve) => (release = resolve));
  const older = copier.run(slow);
  const newer = copier.run(Promise.resolve('new value'));
  assert.deepEqual(await newer, { outcome: 'copied' });
  release('old value');
  assert.deepEqual(await older, { outcome: 'superseded' });
  assert.deepEqual(written, ['new value']);
});

test('the same on the ClipboardItem path: the older payload rejects, so it writes nothing', async () => {
  const written: string[] = [];
  class Item {
    parts: Record<string, Promise<string>>;
    constructor(parts: Record<string, Promise<string>>) {
      this.parts = parts;
    }
  }
  const clipboard: ClipboardLike = {
    async writeText() {},
    async write(items) {
      written.push(await (items as Item[])[0].parts['text/plain']);
    },
  };
  const copier = createCopier({ copy: (text) => copyText(text, { clipboard, item: Item }) });
  let release!: (value: string) => void;
  const slow = new Promise<string>((resolve) => (release = resolve));
  const older = copier.run(slow);
  const newer = copier.run(Promise.resolve('new value'));
  await newer;
  release('old value');
  assert.deepEqual(await older, { outcome: 'superseded' });
  assert.deepEqual(written, ['new value']);
});

test('no read is left unhandled when it fails after being superseded', async () => {
  const unhandled: unknown[] = [];
  const onUnhandled = (reason: unknown) => unhandled.push(reason);
  process.on('unhandledRejection', onUnhandled);
  try {
    const { copy, ends } = manualCopies();
    const copier = createCopier({ copy });
    let fail!: (reason: unknown) => void;
    const late = new Promise<string>((_, reject) => (fail = reject));
    const older = copier.run(late);
    const newer = copier.run('v');
    ends[1]();
    await newer;
    fail(new Error('late'));
    ends[0]?.(refused);
    await older;
    await new Promise((resolve) => setTimeout(resolve, 20));
    assert.deepEqual(unhandled, []);
  } finally {
    process.off('unhandledRejection', onUnhandled);
  }
});
