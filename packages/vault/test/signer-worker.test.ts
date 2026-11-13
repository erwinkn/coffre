// The signer in workerd, as it runs on Cloudflare: a Durable Object with
// SQLite storage and an alarm, the database through a Hyperdrive binding,
// an alert sent over the network. signer-host.test.ts holds what it does
// case by case, over a storage played in memory; this holds that the real
// one is what that one plays.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { rowsOf } from '@coffre/db/dialect';
import { sql } from 'drizzle-orm';
import { unstable_dev, type Unstable_DevWorker } from 'wrangler';

import { pending } from '../src/entry.ts';
import { checked, keyOf } from '../src/rows.ts';
import { headText } from '../src/signer.ts';
import type { SignerAlert } from '../src/signer-host.ts';
import { emptyDatabase, openTestVault, VAULT_URL } from './database.ts';

const vault = await openTestVault();
const seed = randomBytes(32);
const key = keyOf(seed);

const alerts: SignerAlert[] = [];
const webhook = createServer((request, response) => {
  let body = '';
  request.on('data', (chunk) => (body += chunk)).on('end', () => {
    alerts.push(JSON.parse(body) as SignerAlert);
    response.end();
  });
});

let worker: Unstable_DevWorker;
let dir: string;
before(async () => {
  await emptyDatabase(vault.owner);
  await new Promise<void>((resolve) => webhook.listen(0, '127.0.0.1', resolve));
  dir = mkdtempSync(join(tmpdir(), 'coffre-signer-worker-'));
  writeFileSync(
    join(dir, 'wrangler.json'),
    JSON.stringify({
      name: 'coffre-signer-test',
      compatibility_date: '2026-08-06',
      compatibility_flags: ['nodejs_compat'],
      vars: { SIGNING_KEY: seed.toString('base64'), ALERT_URL: `http://127.0.0.1:${(webhook.address() as AddressInfo).port}/` },
      hyperdrive: [{ binding: 'HYPERDRIVE', id: 'signer-test', localConnectionString: VAULT_URL }],
      // As a deployment's vault/wrangler.jsonc: SQLite-backed, so that a run's changes are one transaction.
      durable_objects: { bindings: [{ name: 'SIGNER', class_name: 'CoffreSigner' }] },
      migrations: [{ tag: 'signer', new_sqlite_classes: ['CoffreSigner'] }],
    }),
  );
  // Bundled from the packages' sources, as the tests read them.
  process.env.WRANGLER_BUILD_CONDITIONS = 'coffre:source,workerd,worker,browser';
  worker = await unstable_dev(fileURLToPath(new URL('./workers/signer-worker.ts', import.meta.url)), {
    config: join(dir, 'wrangler.json'),
    local: true, ip: '127.0.0.1', port: 0, inspectorPort: 0, persist: false, logLevel: 'error',
    experimental: { disableExperimentalWarning: true, disableDevRegistry: true },
  });
});
after(async () => {
  await worker?.stop();
  rmSync(dir, { recursive: true, force: true });
  webhook.close();
  await vault.close();
});

async function call(body: { method: 'wake'; hash: string } | { method: 'status' | 'refusedStep' }): Promise<unknown> {
  const response = await worker.fetch('/', { method: 'POST', body: JSON.stringify(body), signal: AbortSignal.timeout(20_000) });
  const answer = (await response.json()) as { ok: boolean; result?: unknown; error?: string };
  assert.ok(answer.ok, answer.error ?? 'the call failed');
  return answer.result;
}

/** `ready`, asked every 100 ms, within `ms`. */
async function until(ready: () => Promise<boolean> | boolean, ms: number, what: string): Promise<void> {
  for (const end = Date.now() + ms; !(await ready()); ) {
    assert.ok(Date.now() < end, `${what}, within ${ms} ms`);
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
}

test('in workerd: a step\'s changes are stored all of them or none', { timeout: 120_000 }, async () => {
  assert.deepEqual(await call({ method: 'refusedStep' }), { refused: true, was: 1, new: null });
});

test('in workerd: an entry the vault told of is in the log a second later, under a head of the vault\'s, and one planted beside it is alerted', { timeout: 120_000 }, async () => {
  const entries = ['a', 'b'].map((name) => pending(key, { kept: name === 'a', action: 'secret.read', actor: 'user:ada@acme.example', credential: null, request: null, ip: null, objects: [`secret:${name}`], detail: {} }, Date.now(), []));
  const rows = JSON.stringify(entries.map(({ kept, body, mac }) => ({ kept, body, mac: mac.toString('hex') })));
  await vault.db.execute(sql`INSERT INTO log_pending (kept, body, mac) SELECT kept, body, decode(mac, 'hex') FROM jsonb_to_recordset(${rows}::jsonb) AS t(kept boolean, body text, mac text)`);
  await vault.owner.execute(sql`INSERT INTO log_pending (kept, body, mac) VALUES (false, '{}', decode(repeat('00', 36), 'hex'))`);
  const told = Date.now();
  for (const { hash } of entries) await call({ method: 'wake', hash: hash.toString('hex') });

  const count = async (table: 'log' | 'log_pending') => (await rowsOf<{ n: number }>(vault.owner, sql`SELECT count(*)::int AS n FROM ${sql.identifier(table)}`))[0]!.n;
  await until(async () => (await count('log')) === 2, 10_000, 'both entries are in the log');
  // The alarm, not a wake-up, ran it: a second after the vault told of the first.
  assert.ok(Date.now() - told >= 900, 'not before its second');
  assert.equal(await count('log_pending'), 0);
  const [head] = await rowsOf<{ size: number; keptSize: number; keptRoot: string; agingSize: number; agingRoot: string; agingFrom: number; signedAt: number; mac: Buffer }>(
    vault.owner,
    sql`SELECT size::int, kept_size::int AS "keptSize", encode(kept_root, 'hex') AS "keptRoot", aging_size::int AS "agingSize", encode(aging_root, 'hex') AS "agingRoot", aging_from::int AS "agingFrom", (extract(epoch FROM signed_at) * 1000)::float8 AS "signedAt", mac FROM log_head`,
  );
  assert.deepEqual([head!.size, head!.keptSize, head!.agingSize], [2, 1, 1]);
  assert.ok(checked([key], (each) => each.entries, headText(head!), head!.mac) !== undefined, 'the head is under the vault\'s MAC');

  await until(() => alerts.length > 0, 10_000, 'the alert is sent');
  assert.deepEqual(alerts.map((alert) => alert.findings), [[{ found: 'forged', of: 'pending:3' }]]);

  // What it signed is in its storage: put back, it is refused as signed already, by a run of its own.
  await vault.owner.execute(sql`INSERT INTO log_pending (kept, body, mac) VALUES (${entries[0]!.kept}, ${entries[0]!.body}, decode(${entries[0]!.mac.toString('hex')}, 'hex'))`);
  const next = pending(key, { kept: true, action: 'secret.read', actor: null, credential: null, request: null, ip: null, objects: [], detail: {} }, Date.now(), []);
  await vault.db.execute(sql`INSERT INTO log_pending (kept, body, mac) VALUES (true, ${next.body}, decode(${next.mac.toString('hex')}, 'hex'))`);
  await call({ method: 'wake', hash: next.hash.toString('hex') });
  await until(() => alerts.length > 1, 10_000, 'the second alert is sent');
  assert.deepEqual(alerts[1]!.findings, [{ found: 'replayed', of: entries[0]!.hash.toString('hex') }]);
  assert.deepEqual([await count('log'), await count('log_pending')], [3, 0]);

  const status = (await call({ method: 'status' })) as { checked: number; standing: unknown[] };
  assert.ok(status.checked <= Date.now() && status.checked > told - 60_000);
  assert.deepEqual(status.standing, []);
});
