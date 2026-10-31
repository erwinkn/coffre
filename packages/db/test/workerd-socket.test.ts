// The driver's socket on workerd (platform.workerd.ts), over a stand-in for `cloudflare:sockets`, which Node has not.
// packages/vault/test/workers-socket.test.ts holds the real socket to the same in workerd.
import test from 'node:test';
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { setTimeout as sleep } from 'node:timers/promises';

import { WorkerdSocket } from '../src/postgres-js/platform.workerd.ts';

/** A raw socket whose writes never finish, as under backpressure, saying what was done to it. */
function stuck() {
  const done: string[] = [];
  const raw = {
    readable: new ReadableStream<Uint8Array>({ cancel: () => void done.push('reads cancelled') }),
    writable: new WritableStream<Uint8Array>({ write: () => new Promise<void>(() => {}) }),
    closed: new Promise<void>(() => {}),
    close: async () => {
      done.push('closed');
    },
    startTls: () => {
      throw new Error('no TLS here');
    },
  };
  return { raw, done };
}

test("destroyed, a socket aborts its writes, a write stuck under backpressure or not, then closes, and says so once; ended, it waits for its write (reviews r2 and r3 of #438, T170)", async () => {
  const { raw, done } = stuck();
  const socket = new WorkerdSocket();
  socket.raw = raw;
  socket.writer = raw.writable.getWriter();
  // A JS stream aborts its sink only once the write under way is done, which this one never is; workerd's native one
  // drops it (workers-socket.test.ts): what is asked of the writer is what counts here.
  const abort = socket.writer.abort.bind(socket.writer);
  socket.writer.abort = (reason?: unknown) => {
    done.push('writes aborted');
    return abort(reason);
  };
  socket.reader = raw.readable.getReader();
  const said: string[] = [];
  socket.on('close', () => said.push('close'));
  socket.on('error', () => said.push('error'));
  socket.write(Buffer.from('Q'));
  // Terminate written first, as an orderly end does: held behind the write.
  socket.end(Buffer.from('X'));
  await sleep(10);
  assert.deepEqual(done, []);
  socket.destroy();
  socket.destroy();
  await sleep(10);
  assert.deepEqual(done, ['writes aborted', 'reads cancelled', 'closed'], 'nothing buffered left to send before the close');
  // The writes the abort failed say nothing more: one close, no error after it.
  assert.deepEqual(said, ['close']);
});

test('destroyed while it opens, before its raw socket is made, a socket says it closed, once, a task later', async () => {
  const socket = new WorkerdSocket();
  let closed = 0;
  socket.on('close', () => (closed += 1));
  socket.readyState = 'opening';
  socket.destroy();
  assert.equal(closed, 0, 'a task later, as Node says it');
  await sleep(10);
  assert.deepEqual([closed, socket.destroyed, socket.readyState], [1, true, 'closed']);
});
