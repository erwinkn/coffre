// A raw sign in workerd, as on Cloudflare: SumSub's 10 MiB document upload signs as Node's createHmac signs it, and the
// isolate holds none of it. `workers/sign-worker.ts` mounts the credential proxy's own route, under wrangler's local
// workerd, with a stand-in for coffre's side.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { once } from 'node:events';
import { createServer, type AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { unstable_dev, type Unstable_DevWorker } from 'wrangler';
import { WebSocket } from 'ws';

const SECRET = 'sumsub_sk_0f1e2d3c4b5a69788796a5b4c3d2e1f0';
const HANDLE = `coffre_use_${'h'.repeat(43)}`;
/** ts + method + path, then the file: the message SumSub's document upload signs, 10 MiB of it the file's. */
const MESSAGE = (() => {
  const file = Buffer.alloc(10 * 1024 * 1024);
  for (let i = 0; i < file.length; i += 4) file.writeUInt32LE((i * 2654435761) >>> 0, i);
  return Buffer.concat([Buffer.from('1761480000POST/resources/applicants/abc/info/idDoc'), file]);
})();

let dir: string;
let worker: Unstable_DevWorker;
let at: string;
/** workerd's inspector, for the heap its isolate holds. */
let inspector: number;

before(async () => {
  dir = mkdtempSync(join(tmpdir(), 'coffre-sign-worker-'));
  writeFileSync(join(dir, 'wrangler.json'), JSON.stringify({ name: 'coffre-sign-workers-test', compatibility_date: '2026-08-06', compatibility_flags: ['nodejs_compat'], vars: { SUMSUB_SECRET_KEY: SECRET } }));
  // Bundled from the packages' sources, as the tests read them.
  process.env.WRANGLER_BUILD_CONDITIONS = 'coffre:source,workerd,worker,browser';
  const free = createServer().listen(0, '127.0.0.1');
  await once(free, 'listening');
  inspector = (free.address() as AddressInfo).port;
  free.close();
  worker = await unstable_dev(fileURLToPath(new URL('./workers/sign-worker.ts', import.meta.url)), {
    config: join(dir, 'wrangler.json'),
    local: true, ip: '127.0.0.1', port: 0, inspectorPort: inspector, persist: false, logLevel: 'error',
    experimental: { disableExperimentalWarning: true, disableDevRegistry: true },
  });
  at = `http://${worker.address}:${worker.port}`;
}, { timeout: 120_000 });

after(async () => {
  await worker?.stop();
  if (dir !== undefined) rmSync(dir, { recursive: true, force: true });
});

/** `bytes` in parts of 64 KiB, as an app's upload sends them; past `pause.at` bytes, nothing more until `pause.until` resolves. */
function parts(bytes: Uint8Array, pause?: { at: number; until: Promise<unknown>; reached: () => void }): ReadableStream<Uint8Array> {
  let sent = 0;
  return new ReadableStream<Uint8Array>({
    pull: async (out) => {
      if (pause !== undefined && sent >= pause.at) {
        pause.reached();
        await pause.until;
        pause = undefined;
      }
      if (sent >= bytes.length) return out.close();
      out.enqueue(bytes.subarray(sent, sent + 64 * 1024));
      sent += 64 * 1024;
    },
  });
}

/** A raw sign of `message` (`MESSAGE`) by sumsub-key, its digest declared, as `@coffre/client` sends it. */
function sign(body: ReadableStream<Uint8Array>, message: Uint8Array = MESSAGE): Promise<Response> {
  return fetch(`${at}/use/market/dev?sign=sumsub-key`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${HANDLE}`,
      'content-type': 'application/octet-stream',
      'content-length': String(message.length),
      'content-digest': `sha-256=:${createHash('sha256').update(message).digest('base64')}:`,
    },
    body,
    duplex: 'half',
  } as RequestInit);
}

test("SumSub's 10 MiB document upload signs raw in workerd as Node's createHmac signs it", { timeout: 60_000 }, async () => {
  const answer = await sign(parts(MESSAGE));
  assert.deepEqual([answer.status, await answer.json()], [200, { signature: createHmac('sha256', SECRET).update(MESSAGE).digest('hex') }]);
});

/**
 * What workerd's isolate holds, in bytes, through its inspector: its objects and the buffers behind them, outside its
 * heap, which would hold a body's bytes. Garbage not collected (`HeapProfiler.collectGarbage` gets no answer here, from a
 * Worker's isolate): a raw sign reads into one buffer, so it makes little, and a body held would only add to it.
 */
async function heapHeld(): Promise<number> {
  const [target] = (await (await fetch(`http://127.0.0.1:${inspector}/json`)).json()) as { webSocketDebuggerUrl: string }[];
  const cdp = new WebSocket(target!.webSocketDebuggerUrl);
  await once(cdp, 'open');
  let id = 0;
  type Usage = { usedSize: number; backingStorageSize: number };
  const call = (method: string) =>
    new Promise<{ result?: Usage }>((resolve) => {
      const mine = ++id;
      cdp.on('message', (data: Buffer) => {
        const answer = JSON.parse(data.toString()) as { id?: number; result?: Usage };
        if (answer.id === mine) resolve(answer);
      });
      cdp.send(JSON.stringify({ id: mine, method, params: {} }));
    });
  try {

    const { usedSize, backingStorageSize } = (await call('Runtime.getHeapUsage')).result!;
    assert.equal(typeof backingStorageSize, 'number', "the inspector says what the isolate's buffers hold");
    return usedSize + backingStorageSize;
  } finally {
    cdp.close();
  }
}

test('the isolate holds none of a raw message as it signs it: 9 MiB in, its heap is as it was', { timeout: 60_000 }, async () => {
  // A sign first: the isolate, and its inspector's target, start with its first request. A short one, so that `before`
  // holds no body-sized garbage a collection during the next sign could hide a held body behind.
  const warm = Buffer.from('warm');
  assert.equal((await sign(parts(warm), warm)).status, 200);
  const before = await heapHeld();
  let resume!: () => void;
  let reached!: () => void;
  const paused = new Promise<void>((resolve) => (reached = resolve));
  const answer = sign(parts(MESSAGE, { at: 9 * 1024 * 1024, until: new Promise<void>((resolve) => (resume = resolve)), reached: () => reached() }));
  await paused;
  // What was sent has reached the isolate, and been signed and let go: a body held would show 9 MiB here (it does, with
  // each part kept).
  await new Promise((resolve) => setTimeout(resolve, 500));
  const during = await heapHeld();
  resume();
  const signed = await answer;
  assert.deepEqual([signed.status, await signed.json()], [200, { signature: createHmac('sha256', SECRET).update(MESSAGE).digest('hex') }]);
  assert.ok(during - before < 2 * 1024 * 1024, `the isolate grew by ${during - before} bytes with 9 MiB of the message in`);
});
