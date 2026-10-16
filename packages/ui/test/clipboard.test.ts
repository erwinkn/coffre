import test from 'node:test';
import assert from 'node:assert/strict';

import { copyText, type ClipboardLike } from '../src/lib/clipboard.ts';

/** A clipboard that records what it was given, the way a browser's resolves ClipboardItems. */
function fakeClipboard({ failWrite = false }: { failWrite?: boolean } = {}) {
  const calls: string[] = [];
  const clipboard: ClipboardLike = {
    async writeText(text) {
      if (failWrite) throw new DOMException('denied', 'NotAllowedError');
      calls.push(`writeText:${text}`);
    },
    async write(items) {
      if (failWrite) throw new DOMException('denied', 'NotAllowedError');
      for (const item of items as FakeItem[]) {
        calls.push(`write:${await item.parts['text/plain']}`);
      }
    },
  };
  return { clipboard, calls };
}

class FakeItem {
  parts: Record<string, Promise<string>>;
  constructor(parts: Record<string, Promise<string>>) {
    this.parts = parts;
  }
}

const PEM = '-----BEGIN KEY-----\nMIIB\r\nline two  \n-----END KEY-----\n';

test('a string goes to writeText exactly as it is', async () => {
  const { clipboard, calls } = fakeClipboard();
  await copyText(PEM, { clipboard, item: FakeItem });
  assert.deepEqual(calls, [`writeText:${PEM}`]);
});

test('a fetched value reaches the clipboard byte for byte: newlines, spaces and all', async () => {
  const { clipboard, calls } = fakeClipboard();
  await copyText(Promise.resolve(PEM), { clipboard, item: FakeItem });
  assert.deepEqual(calls, [`write:${PEM}`]);
});

test('write is called before the value arrives, which keeps the click gesture', async () => {
  const events: string[] = [];
  let release!: (value: string) => void;
  const pending = new Promise<string>((resolve) => (release = resolve));
  const clipboard: ClipboardLike = {
    async writeText() {
      events.push('writeText');
    },
    async write() {
      events.push('write');
    },
  };
  const done = copyText(pending, { clipboard, item: FakeItem });
  assert.deepEqual(events, ['write']);
  release('x');
  await done;
});

test('a leading byte order mark survives, as a Blob would have dropped it', async () => {
  const { clipboard, calls } = fakeClipboard();
  await copyText(Promise.resolve('\uFEFFstart'), { clipboard, item: FakeItem });
  assert.deepEqual(calls, ['write:\uFEFFstart']);
});

test('an empty value copies as empty', async () => {
  const { clipboard, calls } = fakeClipboard();
  await copyText(Promise.resolve(''), { clipboard, item: FakeItem });
  assert.deepEqual(calls, ['write:']);
});

test('without ClipboardItem the value is awaited, then written with writeText', async () => {
  const { clipboard, calls } = fakeClipboard();
  await copyText(Promise.resolve(PEM), { clipboard, item: undefined });
  assert.deepEqual(calls, [`writeText:${PEM}`]);
});

test('without clipboard.write the value is awaited, then written with writeText', async () => {
  const { clipboard, calls } = fakeClipboard();
  await copyText(Promise.resolve(PEM), { clipboard: { writeText: clipboard.writeText }, item: FakeItem });
  assert.deepEqual(calls, [`writeText:${PEM}`]);
});

test('a refused write fails the copy, on either path', async () => {
  const { clipboard } = fakeClipboard({ failWrite: true });
  await assert.rejects(copyText('secret', { clipboard, item: FakeItem }), { name: 'NotAllowedError' });
  await assert.rejects(copyText(Promise.resolve('secret'), { clipboard, item: FakeItem }), { name: 'NotAllowedError' });
  await assert.rejects(copyText(Promise.resolve('secret'), { clipboard, item: undefined }), { name: 'NotAllowedError' });
});

test('no clipboard at all is a failure, not a silent success', async () => {
  await assert.rejects(copyText('x', { clipboard: undefined, item: FakeItem }), /clipboard/i);
});

test('a read that fails after the copy has ended is not left unhandled', async () => {
  const unhandled: unknown[] = [];
  const onUnhandled = (reason: unknown) => unhandled.push(reason);
  process.on('unhandledRejection', onUnhandled);
  try {
    const refused: ClipboardLike = { async writeText() {}, async write() { throw new DOMException('no', 'NotAllowedError'); } };
    let fail!: (reason: unknown) => void;
    const late = new Promise<string>((_, reject) => (fail = reject));
    await assert.rejects(copyText(late, { clipboard: refused, item: FakeItem }), { name: 'NotAllowedError' });
    fail(new Error('late'));

    let failLater!: (reason: unknown) => void;
    const later = new Promise<string>((_, reject) => (failLater = reject));
    await assert.rejects(copyText(later, { clipboard: undefined, item: FakeItem }), /clipboard/i);
    failLater(new Error('late'));

    // Let the runtime report anything it considers unhandled.
    await new Promise((resolve) => setTimeout(resolve, 20));
    assert.deepEqual(unhandled, []);
  } finally {
    process.off('unhandledRejection', onUnhandled);
  }
});

