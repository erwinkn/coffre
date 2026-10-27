// A page's check of 0.15's log (verifier.ts) costs a tick's worth of entries, however long the log (R25, R27, R48). At
// 1,000 uses a second, with 5k and 50k sealed below: the newest pair and the entries above it, 250 at a moment picked
// at random (half a 500 ms tick), 500 just before the tick, 1,000 when it is late. Its statements are the same
// whatever lies below. Its CPU, in the vault's process, is logged, and held only to R27's p99 bound (20 ms) at a
// tick's worth: CI's machines are slower than a developer's. Measured on one (docs/design/0.15-plan.md, "As built:
// PR 8"): about 2.7 ms and 7 µs an entry, so 4.5 ms at a random moment, 6.7 ms before the tick, 9 to 10 ms late.
// Postgres, as a deployment runs it.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';

import { decodePair } from '@coffre/core/merkle';
import { createDatabase, type Database } from '@coffre/db';
import { postgresClient } from '@coffre/db/connect';
import { sql } from 'drizzle-orm';

import { entryMac, logMacKey } from '../src/log-entry.ts';
import { openLogCheckpointer } from '../src/log-checkpointer.ts';
import { logStore } from '../src/log-store.ts';
import { verifierKeys, verifyTrees } from '../src/verifier.ts';
import { variableMemory } from './audit-tree.ts';
import { openTestDatabase, postgresOnly, run, VAULT_URL, type TestDatabase } from './database.ts';

let db: TestDatabase;
before(async () => {
  db = await openTestDatabase();
});
after(() => db.close());

/** `n` uses, MAC'd as the use path writes them, numbered from the log's sequence, `at` now: inserted 1,000 a statement. */
async function uses(n: number, mac: Buffer): Promise<void> {
  for (let done = 0; done < n; done += 1000) {
    const batch = Array.from({ length: Math.min(1000, n - done) }, () => {
      const row = { at: Date.now(), requestId: BigInt.asIntN(64, randomBytes(8).readBigUInt64BE()), credential: randomUUID(), secret: randomUUID(), purpose: 1, place: null };
      return sql`(nextval('log_number'), ${row.at}, ${row.requestId}, ${row.credential}, ${row.secret}, ${row.purpose}, ${entryMac(mac, { tree: 'uses', row })}, NULL)`;
    });
    await run(db.owner, sql`INSERT INTO log_uses (number, at, request_id, credential, secret, purpose, mac, place) VALUES ${sql.join(batch, sql`, `)}`);
  }
}

/** The vault's database, each statement counted as it is sent, those of its transactions too. */
function counting(): { db: Database; statements: () => number; close: () => Promise<void> } {
  let statements = 0;
  const pool = postgresClient(VAULT_URL, { max: 1 });
  const counted = <C extends object>(client: C): C => new Proxy(client, {
    get(target, key) {
      const value: unknown = Reflect.get(target, key, target);
      if (typeof value !== 'function') return value;
      if (key === 'unsafe') {
        return (...args: unknown[]) => {
          statements += 1;
          return (value as (...a: unknown[]) => unknown).apply(target, args);
        };
      }
      if (key === 'begin') {
        return (...args: unknown[]) => {
          const work = args.pop() as (tx: object) => unknown;
          return (value as (...a: unknown[]) => unknown).apply(target, [...args, (tx: object) => work(counted(tx))]);
        };
      }
      return (value as (...a: unknown[]) => unknown).bind(target);
    },
  });
  return { db: createDatabase(counted(pool)), statements: () => statements, close: () => pool.end() };
}

test('R25, R27: a page\'s check at 1,000 uses a second reads a tick\'s worth, its statements flat as the log grows', { ...postgresOnly('the deployed engine'), timeout: 600_000 }, async () => {
  for (const table of ['log_uses', 'log_bulk', 'log_checkpoints', 'log_tiles', 'log_changes']) await run(db.owner, sql.raw(`DELETE FROM ${table}`));
  await run(db.owner, sql`UPDATE log_fence SET at_floor = ${Date.now() - 60_000}`);
  const today = new Date().toISOString().slice(0, 10);
  await run(db.owner, sql`SELECT make_day(${today}::date - 1), make_day(${today}::date), make_day(${today}::date + 1)`);

  const seed = randomBytes(32);
  const mac = logMacKey(seed);
  const memory = variableMemory();
  const cp = await openLogCheckpointer({ store: logStore(db.vault), seed, memory });
  const keys = await verifierKeys([seed]);
  const { db: vault, statements, close } = counting();
  const measured: Record<string, { statements: number; cpuMs: number }> = {};
  try {
    let sealedBelow = 0;
    for (const below of [5_000, 50_000]) {
      // History, sealed a tick at a time; then a tick's worth above the newest pair, and a late tick's.
      for (; sealedBelow < below; sealedBelow += 5_000) {
        await uses(5_000, mac);
        assert.ok((await cp.tick()).signed);
      }
      let above = 0;
      for (const target of [250, 500, 1_000]) {
        await uses(target - above, mac);
        above = target;
        const anchors = [decodePair(memory.record!)!];
        const check = () => verifyTrees(vault, keys, { anchors });
        // Warm, as an isolate serving pages is; then the median of nine.
        for (let i = 0; i < 10; i += 1) assert.deepEqual((await check()).problems, []);
        const before = statements();
        const times: number[] = [];
        for (let i = 0; i < 9; i += 1) {
          const cpu = process.cpuUsage();
          const checked = await check();
          const spent = process.cpuUsage(cpu);
          times.push((spent.user + spent.system) / 1000);
          assert.ok(checked.ok && checked.unsealed === target && checked.sealed === 0, JSON.stringify(checked));
        }
        times.sort((a, b) => a - b);
        measured[`${below} below, ${target} above`] = { statements: (statements() - before) / 9, cpuMs: Math.round(times[4]! * 100) / 100 };
      }
      assert.ok((await cp.tick()).signed);
      sealedBelow += 1_000;
    }
  } finally {
    await close();
  }
  console.log(`a page's check: ${JSON.stringify(measured)}`);
  // The same statements, however much lies below: none of them reads history (R48).
  const counts = new Set(Object.values(measured).map((m) => m.statements));
  assert.equal(counts.size, 1, JSON.stringify(measured));
  // R27's p99 bound, at a tick's worth: CI's slower machines included.
  for (const [where, { cpuMs }] of Object.entries(measured)) if (!where.endsWith('1000 above')) assert.ok(cpuMs < 20, `${where}: ${cpuMs} ms`);
});
