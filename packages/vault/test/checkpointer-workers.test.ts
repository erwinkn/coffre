// 0.15's checkpointer in workerd, as it runs on Cloudflare: its Durable
// Object ticking on its alarm with one connection through the vault's
// Hyperdrive, a change sealed through it, cosigned by the witness's object
// and archived in R2 (test/workers/checkpointer-worker.ts); then deployed
// again under a new signing key, over the objects' storage (T168).
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
import { KEY_OBJECT, logMacKey } from '../src/log-entry.ts';
import { ENGINE, openTestDatabase, VAULT_URL, type TestDatabase } from './database.ts';
import { logWriter } from './log-entries.ts';

const skip = ENGINE === 'postgres' ? false : 'Postgres only: Hyperdrive';

let db: TestDatabase;
let worker: Unstable_DevWorker;
let dir: string;
const seed = randomBytes(32);
const vaultKey = randomBytes(32).toString('base64');
const witnessKey = randomBytes(32).toString('base64');
let keys: { changes: string; uses: string };

/** The log's two verifier keys under a signing key, as a witness's settings name them. */
async function logKeysOf(signingKey: Uint8Array): Promise<{ changes: string; uses: string }> {
  const signers = await pairSigners(await logOrigin(signingKey), signingKey);
  return { changes: signers.changes.verifierKey, uses: signers.uses.verifierKey };
}

/** The worker under `signingKey`, those it replaced kept: its objects' storage persisted across starts, as a deploy keeps it. */
async function start(signingKey: Uint8Array, replaced: readonly Uint8Array[] = []): Promise<void> {
  writeFileSync(join(dir, 'wrangler.json'), JSON.stringify({
    name: 'coffre-checkpointer-workers-test',
    compatibility_date: '2026-08-06',
    compatibility_flags: ['nodejs_compat'],
    vars: {
      VAULT_KEY: vaultKey, SIGNING_KEY: Buffer.from(signingKey).toString('base64'), WITNESS_KEY: witnessKey, LOG_KEYS: JSON.stringify(await logKeysOf(signingKey)),
      PREVIOUS_SIGNING_KEYS: JSON.stringify(replaced.map((key) => Buffer.from(key).toString('base64'))),
      PREVIOUS_LOG_KEYS: JSON.stringify(await Promise.all(replaced.map(logKeysOf))),
    },
    hyperdrive: [{ binding: 'VAULT_HYPERDRIVE', id: 'checkpointer-workers-test', localConnectionString: VAULT_URL }],
    durable_objects: { bindings: [{ name: 'CHECKPOINTER', class_name: 'CoffreCheckpointer' }, { name: 'WITNESS', class_name: 'CoffreWitness' }] },
    migrations: [{ tag: 'v1', new_sqlite_classes: ['CoffreCheckpointer', 'CoffreWitness'] }],
    r2_buckets: [{ binding: 'ARCHIVE', bucket_name: 'checkpointer-archive' }],
  }));
  process.env.WRANGLER_BUILD_CONDITIONS = 'coffre:source,workerd,worker,browser';
  worker = await unstable_dev(fileURLToPath(new URL('./workers/checkpointer-worker.ts', import.meta.url)), {
    config: join(dir, 'wrangler.json'),
    local: true, ip: '127.0.0.1', port: 0, inspectorPort: 0, persist: true, persistTo: join(dir, 'state'), logLevel: 'error',
    experimental: { disableExperimentalWarning: true, disableDevRegistry: true },
  });
}

before(async () => {
  if (skip) return;
  db = await openTestDatabase();
  keys = await logKeysOf(seed);
  dir = mkdtempSync(join(tmpdir(), 'coffre-checkpointer-worker-'));
  await start(seed);
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

test('deployed again under a new signing key, the object carries its memory across, rotates once, and the witness cosigns the first pair under it', { skip, timeout: 120_000 }, async () => {
  const log = logWriter(db.owner, logMacKey(seed));
  await log.use();
  await worker.stop();
  const next = randomBytes(32);
  await start(next, [seed]);
  await ask('start');
  const change = await logWriter(db.owner, logMacKey(next)).change();
  const sealed = await ask<{ notes: { changes: string; uses: string }; witnessed: boolean | null; failures: string[]; cosigned: number }>('seal', change);
  assert.equal(sealed.witnessed, true, sealed.failures.join());
  assert.ok(await openPair(sealed.notes, await pairVerifiers(await logKeysOf(next))), 'sealed under the new key');
  const [row] = (await db.owner.execute(`SELECT count(*)::int AS n FROM log_changes WHERE object = '${KEY_OBJECT}'` as never)) as unknown as { n: number }[];
  assert.equal(row!.n, 1);
  // The old key writes nothing more: its change is refused by the database.
  await assert.rejects(log.change(), (error: Error & { cause?: Error }) => /the log moved on/.test(`${error.message} ${error.cause?.message}`));
  // The rotation, said once where an operator sees it; nothing refused.
  const alarms = await ask<{ message: string }[]>('alarms');
  assert.deepEqual(alarms.map((a) => a.message.replace(/coffre\.log\/[0-9a-f]{16}/g, '<log>').replace(/at \d+:/, 'at <n>:')),
    ["the audit log moves on from <log> to this signer's key, <log>, at <n>: entries under <log> count only below it"]);
});
