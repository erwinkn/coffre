// The workload gate's Durable Object in workerd (docs/design/workload-access.md,
// section 5.2): one object per workload, a proof taken once, a limit's
// refusal, and a restart of workerd itself, its storage kept: the object's
// day of counts comes back, written by its alarm, and its epoch does not,
// so a proof taken before is refused for its nonce.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';

import type { GateAdmission } from '@coffre/core/identity';
import { unstable_dev, type Unstable_DevWorker } from 'wrangler';

import { FLUSH_MS } from '../src/gate.ts';

let dir: string;
let worker: Unstable_DevWorker | undefined;

async function start() {
  // Bundled from the packages' sources, as the tests read them.
  process.env.WRANGLER_BUILD_CONDITIONS = 'coffre:source,workerd,worker,browser';
  worker = await unstable_dev(fileURLToPath(new URL('./workers/gates-worker.ts', import.meta.url)), {
    config: join(dir, 'wrangler.json'),
    local: true, ip: '127.0.0.1', port: 0, inspectorPort: 0, persistTo: join(dir, 'state'), logLevel: 'error',
    experimental: { disableExperimentalWarning: true, disableDevRegistry: true },
  });
}

before(async () => {
  dir = mkdtempSync(join(tmpdir(), 'coffre-gates-worker-'));
  writeFileSync(
    join(dir, 'wrangler.json'),
    JSON.stringify({
      name: 'coffre-gates-workers-test',
      compatibility_date: '2026-08-06',
      compatibility_flags: ['nodejs_compat'],
      durable_objects: { bindings: [{ name: 'GATES', class_name: 'CoffreGates' }] },
      migrations: [{ tag: 'gates', new_sqlite_classes: ['CoffreGates'] }],
    }),
  );
  await start();
}, { timeout: 120_000 });

after(async () => {
  await worker?.stop();
  if (dir !== undefined) rmSync(dir, { recursive: true, force: true });
});

async function ask<T = GateAdmission>(body: Record<string, unknown>): Promise<T> {
  const response = await worker!.fetch('http://gate/', { method: 'POST', body: JSON.stringify(body) });
  assert.equal(response.status, 200, await response.clone().text());
  return (await response.json()) as T;
}

const SESSION = '0e7a4c1e-5b0c-4f53-9f43-8f5f1c2b9a10';
const DAY = { key: 'stripe', windowMs: 86_400_000, most: 2 };

test('in workerd: a proof taken once per workload, a limit refused, and after a restart the counts of a day but no epoch', { timeout: 120_000 }, async () => {
  const { nonce } = await ask<{ nonce: string }>({ principal: 'token:api', nonce: true });
  assert.match(nonce, /^g0\.[A-Za-z0-9_-]{22}$/);
  const proof = { session: SESSION, jti: 'pA6p8w2Yb3fQe1kHn0S9qg', nonce };
  assert.deepEqual(await ask({ principal: 'token:api', replay: proof, counts: [DAY] }), { ok: true, nonce });
  assert.deepEqual(await ask({ principal: 'token:api', replay: proof }), { ok: false, reason: 'replayed' });
  // Another workload's gate is another object, with a nonce of its own.
  const other = await ask({ principal: 'token:batch', replay: proof });
  assert.ok(!other.ok && other.reason === 'use_dpop_nonce' && other.nonce !== nonce);

  assert.equal((await ask({ principal: 'token:api', counts: [DAY] })).ok, true);
  const refused = await ask({ principal: 'token:api', counts: [DAY] });
  assert.ok(!refused.ok && refused.reason === 'limit' && refused.first && refused.retryAfterMs > 0);

  // The alarm writes the day's counts; then workerd stops, and starts again on the same storage.
  await sleep(FLUSH_MS + 2_000);
  await worker!.stop();
  worker = undefined;
  await start();
  const again = await ask({ principal: 'token:api', replay: proof, counts: [DAY] });
  assert.ok(!again.ok && again.reason === 'use_dpop_nonce' && again.nonce !== nonce, JSON.stringify(again));
  const counted = await ask({ principal: 'token:api', counts: [DAY] });
  assert.ok(!counted.ok && counted.reason === 'limit' && !counted.first, JSON.stringify(counted));
});
