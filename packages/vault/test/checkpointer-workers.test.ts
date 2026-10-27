// 0.15's checkpointer in workerd, as it runs on Cloudflare: its Durable
// Object ticking on its alarm with one connection through the vault's
// Hyperdrive, a change sealed through it, cosigned by the witness's object
// and archived in R2 (test/workers/checkpointer-worker.ts).
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { openPair, pairSigners, pairVerifiers } from '@coffre/core/merkle';
import { unstable_dev, type Unstable_DevWorker } from 'wrangler';

import { logOrigin } from '../src/checkpointer.ts';
import { logMacKey } from '../src/log-entry.ts';
import { ENGINE, openTestDatabase, VAULT_URL, type TestDatabase } from './database.ts';
import { logWriter } from './log-entries.ts';

const skip = ENGINE === 'postgres' ? false : 'Postgres only: Hyperdrive';

let db: TestDatabase;
let worker: Unstable_DevWorker;
let dir: string;
const seed = randomBytes(32);
let keys: { changes: string; uses: string };

before(async () => {
  if (skip) return;
  db = await openTestDatabase();
  const signers = await pairSigners(await logOrigin(seed), seed);
  keys = { changes: signers.changes.verifierKey, uses: signers.uses.verifierKey };
  dir = mkdtempSync(join(tmpdir(), 'coffre-checkpointer-worker-'));
  writeFileSync(join(dir, 'wrangler.json'), JSON.stringify({
    name: 'coffre-checkpointer-workers-test',
    compatibility_date: '2026-08-06',
    compatibility_flags: ['nodejs_compat'],
    vars: { VAULT_KEY: randomBytes(32).toString('base64'), SIGNING_KEY: seed.toString('base64'), WITNESS_KEY: randomBytes(32).toString('base64'), LOG_KEYS: JSON.stringify(keys) },
    hyperdrive: [{ binding: 'VAULT_HYPERDRIVE', id: 'checkpointer-workers-test', localConnectionString: VAULT_URL }],
    durable_objects: { bindings: [{ name: 'CHECKPOINTER', class_name: 'CoffreCheckpointer' }, { name: 'WITNESS', class_name: 'CoffreWitness' }] },
    migrations: [{ tag: 'v1', new_sqlite_classes: ['CoffreCheckpointer', 'CoffreWitness'] }],
    r2_buckets: [{ binding: 'ARCHIVE', bucket_name: 'checkpointer-archive' }],
  }));
  process.env.WRANGLER_BUILD_CONDITIONS = 'coffre:source,workerd,worker,browser';
  worker = await unstable_dev(fileURLToPath(new URL('./workers/checkpointer-worker.ts', import.meta.url)), {
    config: join(dir, 'wrangler.json'),
    local: true, ip: '127.0.0.1', port: 0, inspectorPort: 0, persist: false, logLevel: 'error',
    experimental: { disableExperimentalWarning: true, disableDevRegistry: true },
  });
});
after(async () => {
  await worker?.stop();
  await db?.close();
  if (dir) rmSync(dir, { recursive: true, force: true });
});

const ask = async <T>(op: string, number?: bigint): Promise<T> => {
  const response = await worker.fetch('/', { method: 'POST', body: JSON.stringify({ op, number: number === undefined ? undefined : String(number) }), signal: AbortSignal.timeout(20_000) });
  const body = (await response.json()) as T & { error?: string };
  assert.ok(response.ok, body.error ?? String(response.status));
  return body;
};

test('the checkpointer\'s object seals on its alarm, a change sealed through it is witnessed and archived', { skip, timeout: 120_000 }, async () => {
  const log = logWriter(db.owner, logMacKey(seed));
  await log.empty();
  await log.days();
  await ask('start');
  for (let i = 0; i < 20; i += 1) await log.use();
  const change = await log.change();
  const sealed = await ask<{ notes: { changes: string; uses: string }; witnessed: boolean | null; failures: string[]; cosigned: number; tree: string; number: string; ms: number }>('seal', change);
  assert.equal(sealed.number, String(change));
  assert.equal(sealed.tree, 'changes');
  assert.equal(sealed.witnessed, true, sealed.failures.join());
  assert.equal(sealed.cosigned, 1, 'the witness cosigned; the archive cosigns nothing');
  const pair = await openPair(sealed.notes, await pairVerifiers(keys));
  assert.ok(pair !== null && pair.uses.size >= 20);
  const archived = await ask<string[]>('archive');
  assert.ok(archived.includes(`audit/${String(pair!.upto).padStart(20, '0')}.json`), archived.join());
  // Its alarm keeps sealing with no one asking.
  const more = await log.use();
  const end = Date.now() + 10_000;
  for (;;) {
    const [row] = (await db.owner.execute(`SELECT max(upto)::text AS upto FROM log_checkpoints` as never)) as unknown as { upto: string }[];
    if (BigInt(row!.upto) >= more) break;
    assert.ok(Date.now() < end, 'sealed by the alarm');
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  assert.deepEqual(await ask('alarms'), []);
});
