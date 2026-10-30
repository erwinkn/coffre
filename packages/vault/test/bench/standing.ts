// How often a named use costs a second statement for its decision (T158, D153; formal/Probing.tla, DecideBeforeLock
// and DecideEachLock; docs/design/0.15-plan.md, "As built: D153"). A use whose key would take its principal's lock, to
// enter the cap's set or move on in it, asks `decide` first, each time, and is made by a second call once the vault
// allowed it: nothing is kept for a later use. Two cases, each counted exactly (`use_credential` statements beyond one
// a use):
//
// - a sidecar: one long-lived credential, 7 keys, 1,000 uses a second over 1 or 20 isolates, while changes land beside
//   (each a key written elsewhere in the log, as a grant, a key or a CI run's sign-in is), 0, 1 or 10 a second;
// - CI runs: each a new credential of one service (its issue a change), using its 7 keys one after the other, a run
//   every 2 s.
//
// Not part of the suite. On the suite's Postgres, as a test file:
//
//   node --conditions=coffre:source --import ./scripts/test-database-worker.mjs --test packages/vault/test/bench/standing.ts
//
// after `scripts/setup-test-database.sh` (scripts/test-suite.sh does both). The cap's window is the default, 15
// minutes, its rows moved on every minute; each sidecar run lasts 70 s, so that every key enters the set once and
// moves on once.
import test, { after, before } from 'node:test';
import { randomBytes, randomUUID } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';

import type { NamedUseInput, Vault } from '@coffre/core/vault';
import { createDatabase, tablesOf } from '@coffre/db';
import { postgresClient } from '@coffre/db/connect';
import { sql } from 'drizzle-orm';

import { newRequestId } from '../../src/use.ts';
import { openVault, prepareVault } from '../../src/vault.ts';
import { HOT_URL, openTestDatabase, postgresOnly, rows, run, type TestDatabase } from '../database.ts';
import { CONFIG, DAY, emptyLog, genesis, LOG_015, ROOT, useDatabases, world } from '../use-world.ts';

let db: TestDatabase;
before(async () => {
  db = await openTestDatabase();
  await useDatabases(db);
});
after(() => db.close());

/** A hot pool whose `use_credential` statements are counted as they are sent. */
function counted() {
  const counts = { use: 0 };
  const pool = new Proxy(postgresClient(HOT_URL, { max: 32 }), {
    get(target, key) {
      const value: unknown = Reflect.get(target, key, target);
      if (key !== 'unsafe') return value;
      return (...args: unknown[]) => {
        const text = String(args[0]);
        if (text.includes('use_credential(')) counts.use += 1;
        return (value as (...a: unknown[]) => unknown).apply(target, args);
      };
    },
  });
  return { pool, counts };
}

/** A credential of `principal`, its token's hash known, issued as a change of the log's (`credential.issue`'s object). */
async function credentialOf(principal: string): Promise<string> {
  const id = randomUUID();
  const tokenHash = randomBytes(32);
  const expiresAt = Date.now() + DAY;
  await db.owner.insert(tablesOf(db.owner).credentials).values({
    id, kind: 'service', authMac: Buffer.alloc(32), tokenHash, tokenHint: 'hint', generation: 0, principal, createdBy: ROOT, expiresAt: new Date(expiresAt), scope: null,
  });
  await genesis({ kind: 'credential', id }, { kind: 'credential', id, principal, caller: 'bearer', scope: null, expiresAt, revoked: false, generation: 0 });
  return tokenHash.toString('base64');
}

async function sidecar(isolates: number, changesPerSecond: number): Promise<string> {
  await emptyLog();
  const w = await world({ role: 'developer' });
  const names: string[] = [];
  for (let i = 0; i < 7; i += 1) {
    const id = await w.key();
    names.push((await rows<{ key: string }>(db.owner, sql`SELECT key FROM secrets WHERE id = ${id}`))[0]!.key);
  }
  const tokenHash = randomBytes(32);
  await run(db.owner, sql`UPDATE credentials SET token_hash = ${tokenHash} WHERE id = ${w.credentialId}`);
  const [project] = await rows<{ slug: string }>(db.owner, sql`SELECT slug FROM projects WHERE id = ${w.project}`);
  const { pool, counts } = counted();
  // Each isolate prepared on its own, with its own cache of names, seals and covers (review d2 of #416), and
  // admission wide enough that no use is refused before its call: what is counted is calls.
  const vaults: Vault[] = [];
  for (let i = 0; i < isolates; i += 1) {
    vaults.push(openVault(db.vault, await prepareVault(CONFIG, { ...LOG_015, uses: { inFlight: 1000 } }), createDatabase(pool)));
  }
  const ask = (key: string): NamedUseInput => {
    const at = Date.now();
    return { tokenHash: tokenHash.toString('base64'), place: { project: project!.slug, environment: 'dev' }, key, accepts: { signin: true, issuers: [] }, purpose: 'use', requestId: newRequestId(), at, deadline: at + 3000 };
  };
  // Each isolate's names read once, before the count starts: a sidecar's isolates are warm. Then the cap's rows go, so
  // that each key enters the set once while counted, and moves on once a minute later.
  for (const vault of vaults) for (const key of names) await vault.useNamed!(ask(key));
  await run(db.owner, sql`DELETE FROM log_bulk`);
  const start = { ...counts };
  const seconds = 70;
  const rate = 1000;
  let made = 0;
  const refused: Record<string, number> = {};
  const pending: Promise<unknown>[] = [];
  const until = Date.now() + seconds * 1000;
  let nextChange = Date.now();
  for (let tick = 0; Date.now() < until; tick += 1) {
    for (let i = 0; i < rate / 100; i += 1) {
      const vault = vaults[(tick * 10 + i) % isolates]!;
      const key = names[Math.floor(Math.random() * names.length)]!;
      made += 1;
      pending.push(vault.useNamed!(ask(key)).then((answer) => {
        const why = !answer.served ? 'unserved' : answer.outcome.ok ? null : 'busy' in answer.outcome ? answer.outcome.busy : answer.outcome.code;
        if (why !== null) refused[why] = (refused[why] ?? 0) + 1;
      }));
    }
    while (changesPerSecond > 0 && Date.now() >= nextChange) {
      pending.push(w.key());
      nextChange += 1000 / changesPerSecond;
    }
    await sleep(10);
  }
  await Promise.all(pending);
  await pool.end();
  // A use refused before its call (admission) made none.
  const calls = made - (refused.overloaded ?? 0);
  const extra = counts.use - start.use - calls;
  return `sidecar, ${isolates} isolate(s), ${changesPerSecond} change(s)/s: ${made} uses, refused ${JSON.stringify(refused)}, ${extra} second statements (${(extra / made * 100).toFixed(3)}% of uses)`;
}

async function ciRuns(runs: number): Promise<string> {
  await emptyLog();
  const w = await world({ role: 'developer' });
  const names: string[] = [];
  for (let i = 0; i < 7; i += 1) {
    const id = await w.key();
    names.push((await rows<{ key: string }>(db.owner, sql`SELECT key FROM secrets WHERE id = ${id}`))[0]!.key);
  }
  const [project] = await rows<{ slug: string }>(db.owner, sql`SELECT slug FROM projects WHERE id = ${w.project}`);
  const { pool, counts } = counted();
  // One isolate, as one Worker's would serve a run's requests: its cache warm for the service, cold for each new credential.
  const vault = openVault(db.vault, await prepareVault(CONFIG, LOG_015), createDatabase(pool));
  const perRun: number[][] = [];
  for (let r = 0; r < runs; r += 1) {
    const tokenHash = await credentialOf(w.principal);
    const run: number[] = [];
    perRun.push(run);
    for (const key of names) {
      const before = counts.use;
      const at = Date.now();
      const answer = await vault.useNamed!({ tokenHash, place: { project: project!.slug, environment: 'dev' }, key, accepts: { signin: true, issuers: [] }, purpose: 'use', requestId: newRequestId(), at, deadline: at + 3000 });
      if (!answer.served || !answer.outcome.ok) throw new Error(`run ${r}, ${key}: ${JSON.stringify(answer)}`);
      run.push(counts.use - before);
    }
    await sleep(2000);
  }
  await pool.end();
  return `CI, ${runs} runs of a new credential each, 7 keys one after the other, a run every 2 s: use_credential statements of each key, run by run:\n${perRun.map((run, i) => `  run ${i + 1}: ${run.join(' ')}`).join('\n')}`;
}

test('how often a named use is decided first, a second call (T158, D153)', { ...postgresOnly('the hot path'), timeout: 3_600_000 }, async () => {
  for (const isolates of [1, 20]) for (const changes of [0, 1, 10]) console.log(await sidecar(isolates, changes));
  console.log(await ciRuns(10));
});
