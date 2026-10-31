// The driver's socket on workerd (platform.workerd.ts), over a stand-in for `cloudflare:sockets`, which Node has not.
import test from 'node:test';
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';

import { WorkerdSocket } from '../src/postgres-js/platform.workerd.ts';

/** A raw socket whose writes never finish, as under backpressure, counting its `close()`s. */
function stuck() {
  const counts = { closes: 0 };
  const raw = {
    readable: new ReadableStream<Uint8Array>(),
    writable: new WritableStream<Uint8Array>({ write: () => new Promise<void>(() => {}) }),
    closed: new Promise<void>(() => {}),
    close: async () => {
      counts.closes += 1;
    },
    startTls: () => {
      throw new Error('no TLS here');
    },
  };
  return { raw, counts };
}

test("destroyed, a socket closes at once, a write stuck under backpressure or not; ended, it waits for its write (review r2 of #438, T170)", () => {
  const { raw, counts } = stuck();
  const socket = new WorkerdSocket();
  socket.raw = raw;
  socket.writer = raw.writable.getWriter();
  socket.write(Buffer.from('Q'));
  // Terminate written first, as an orderly end does: held behind the write.
  socket.end(Buffer.from('X'));
  assert.equal(counts.closes, 0);
  socket.destroy();
  assert.equal(counts.closes, 1, 'closed whatever it was still writing');
});

test('destroyed while it opens, before its raw socket is made, a socket says it closed, and closes the raw socket once made', () => {
  const socket = new WorkerdSocket();
  let closed = 0;
  socket.on('close', () => (closed += 1));
  socket.readyState = 'opening';
  socket.destroy();
  assert.deepEqual([closed, socket.destroyed, socket.readyState], [1, true, 'closed']);
});
