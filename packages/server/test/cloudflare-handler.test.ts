import test from 'node:test';
import assert from 'node:assert/strict';

import { cloudflareHandler, drainUnread, PAGES_MISSING, postgres, type WorkersConfig } from '../src/cloudflare-handler.ts';

/** A body of `size` bytes, in chunks of 64 KiB, that says whether it was cancelled. */
function body(size: number) {
  let sent = 0;
  let cancelled = false;
  const stream = new ReadableStream<Uint8Array>({
    pull(controller) {
      if (sent >= size) return controller.close();
      const chunk = new Uint8Array(Math.min(65_536, size - sent));
      sent += chunk.byteLength;
      controller.enqueue(chunk);
    },
    cancel() {
      cancelled = true;
    },
  });
  return { stream, sent: () => sent, cancelled: () => cancelled };
}

test('a body answered unread is read to its end, a mebibyte at most, and then let go', async () => {
  const small = body(10_000);
  const request = new Request('https://coffre.example/api/reveals', { method: 'POST', body: small.stream, duplex: 'half' } as RequestInit);
  await drainUnread(request);
  assert.equal(small.sent(), 10_000);
  assert.equal(request.bodyUsed, true);

  const large = body(64 << 20);
  await drainUnread(new Request('https://coffre.example/api/reveals', { method: 'POST', body: large.stream, duplex: 'half' } as RequestInit));
  assert.ok(large.sent() <= (1 << 20) + 2 * 65_536, `read ${large.sent()} bytes of 64 MiB`);
  assert.equal(large.cancelled(), true);

  // Read already, or none: nothing to do.
  const read = new Request('https://coffre.example/api/x', { method: 'POST', body: 'x' });
  await read.text();
  await drainUnread(read);
  await drainUnread(new Request('https://coffre.example/livez'));
});

test("an app from before it was its own Start app has no pages, and is told how to move", async () => {
  const handler = cloudflareHandler(() => ({ database: postgres({ connectionString: 'postgres://x@127.0.0.1/x' }) }) as unknown as WorkersConfig);
  await assert.rejects(
    handler.fetch(new Request('https://coffre.example/livez'), {}, { waitUntil: () => {} }),
    (error: Error) => error.message === PAGES_MISSING && /npx @coffre\/cli@latest update/.test(error.message),
  );
});
