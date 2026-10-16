import test from 'node:test';
import assert from 'node:assert/strict';

import { copyText, ValueUnavailable, type ClipboardLike } from '../src/lib/clipboard.ts';

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
        const blob = await item.parts['text/plain'];
        assert.equal(blob.type, 'text/plain');
        calls.push(`write:${await blob.text()}`);
      }
    },
  };
  return { clipboard, calls };
}

class FakeItem {
  parts: Record<string, Promise<Blob>>;
  constructor(parts: Record<string, Promise<Blob>>) {
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

test('a value that cannot be read fails the copy and writes nothing', async () => {
  const { clipboard, calls } = fakeClipboard();
  const unread = Promise.reject(new ValueUnavailable());
  await assert.rejects(copyText(unread, { clipboard, item: FakeItem }), ValueUnavailable);
  await assert.rejects(copyText(Promise.reject(new ValueUnavailable()), { clipboard, item: undefined }), ValueUnavailable);
  assert.deepEqual(calls, []);
});

test('no clipboard at all is a failure, not a silent success', async () => {
  await assert.rejects(copyText('x', { clipboard: undefined, item: FakeItem }), /clipboard/i);
});
