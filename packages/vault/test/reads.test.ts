// The reads' projection (T166, reads.ts): what the projector derives each read from, two projectors at once, and the
// whole log's check of what it listed, against a database writer and a projector stopped part way (review r3 of #434).
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';

import { tablesOf, type Database } from '@coffre/db';
import { sql } from 'drizzle-orm';

import type { Input } from '../src/inputs.ts';
import { openLogCheckpointer } from '../src/log-checkpointer.ts';
import { logStore } from '../src/log-store.ts';
import { checkReads, cursorHolds, projectReads } from '../src/reads.ts';
import { verifierKeys } from '../src/verifier.ts';
import { variableMemory } from './audit-tree.ts';
import { ENGINE, openTestDatabase, rows, run, withLogUnlocked, type TestDatabase } from './database.ts';
import { ask, emptyLog, genesis, isolate, ROOT, SIGNING_KEY, useDatabases, world } from './use-world.ts';

let db: TestDatabase;
before(async () => {
  db = await openTestDatabase();
  await useDatabases(db);
});
after(() => db.close());
beforeEach(async () => {
  await emptyLog();
  // And the trees: each test's signer starts with no memory, over a log of its own.
  for (const table of ['log_checkpoints', 'log_tiles']) await run(db.owner, sql.raw(`DELETE FROM ${table}`));
});

const keys = () => verifierKeys([SIGNING_KEY]);

/** A checkpointer over the vault's login, signing the log as it stands at each `tick`. */
async function signer() {
  const cp = await openLogCheckpointer({ store: logStore(db.vault), seed: SIGNING_KEY, memory: variableMemory(), record: () => {} });
  return async () => {
    const tick = await cp.tick();
    assert.ok(tick.failures.length === 0, tick.failures.join('; '));
  };
}

/** `count` reads by a fresh world's credential, a key each, through the use path. */
async function reads(count: number) {
  const w = await world();
  const { use } = await isolate();
  for (let i = 0; i < count; i += 1) {
    const outcome = await use(ask(w, await w.key()));
    assert.ok(outcome.ok, JSON.stringify(outcome));
  }
  return w;
}

/** Every stretch of the whole log's check, from the first, its problems together. */
async function checked(store = logStore(db.vault)) {
  const problems: string[] = [];
  for (let from: bigint | null = 0n; from !== null;) {
    const stretch = await checkReads(store, await keys(), from);
    problems.push(...stretch.problems);
    from = stretch.next;
  }
  return problems;
}

const count = async (table: string) => Number((await rows<{ n: string | number }>(db.owner, sql.raw(`SELECT count(*) AS n FROM ${table}`)))[0]!.n);

test("a change a read is derived from, edited since its seal, stops the projection: no read derived from it, and the whole log's check says so", async () => {
  const tick = await signer();
  const w = await reads(1);
  await tick();
  await projectReads(logStore(db.vault), await keys());
  assert.equal(await count('log_reads'), 1);
  // Whoever owns the database says the credential was issued to someone else, then the credential reads again.
  await withLogUnlocked(db.owner, async (owner) => {
    await run(owner, sql`UPDATE log_changes SET payload = replace(payload, ${w.principal}, 'user:bob@acme.example')
      WHERE number = (SELECT min(number) FROM log_changes WHERE payload LIKE ${`%${w.credentialId}%`})`);
  });
  const { use } = await isolate();
  assert.ok((await use(ask(w, await w.key()))).ok);
  await tick();
  await assert.rejects(projectReads(logStore(db.vault), await keys()), /does not hold to its MAC: edited since its seal/);
  assert.deepEqual((await rows<{ principal: string }>(db.owner, sql`SELECT principal FROM log_reads`)).map((row) => row.principal), [w.principal]);
  // The check walks that change's range again, and its tree says the same.
  assert.match((await checked()).join('\n'), /does not hold to the pair that sealed it|does not hold to its MAC/);
});

test("two projectors at once write each read and each of its places once, and the whole log's check finds nothing", async () => {
  const tick = await signer();
  await reads(6);
  await tick();
  // A store each, over a connection each on Postgres: the vault's login and the owner's.
  const other: Database = ENGINE === 'postgres' ? db.owner : db.vault;
  await Promise.all([projectReads(logStore(db.vault), await keys(), { atOnce: 2 }), projectReads(logStore(other), await keys(), { atOnce: 3 })]);
  assert.equal(await count('log_reads'), 6);
  assert.equal(await count('log_read_places'), 6);
  assert.deepEqual(await checked(), []);
});

test("the whole log's check holds the range the projector stopped in, as far as it went: a read deleted there is named", async () => {
  const tick = await signer();
  await reads(3);
  await tick();
  // Two of the range's three reads, and the projector stops.
  await projectReads(logStore(db.vault), await keys(), { steps: 1, atOnce: 2 });
  const listed = await rows<{ number: string | number }>(db.owner, sql`SELECT number FROM log_reads ORDER BY number`);
  assert.equal(listed.length, 2);
  assert.deepEqual(await checked(), []);
  const deleted = BigInt(listed[0]!.number);
  await run(db.owner, sql`DELETE FROM log_read_places WHERE number = ${deleted}`);
  await run(db.owner, sql`DELETE FROM log_reads WHERE number = ${deleted}`);
  assert.deepEqual(await checked(), [`read ${deleted} is sealed but not listed`, `read ${deleted} is not listed at a place it was read`]);
});

test("a read through a Cloudflare binding is its service's, as the binding's object names it (review r3)", async () => {
  const tick = await signer();
  const w = await world();
  const id = await w.key();
  // A binding of the service's, reaching `dev`, sealed as the vault makes one (use-ways.test.ts).
  const binding = randomUUID();
  const scope = [{ projectId: w.project, environmentId: w.dev, role: 'viewer' }];
  await db.owner.insert(tablesOf(db.owner).serviceBindings).values({
    id: binding, authMac: Buffer.alloc(32), principal: w.principal, generation: 0, profile: 'cloudflare', issuer: 'urn:coffre:cloudflare', jwksUri: 'urn:coffre:cloudflare',
    claims: '{}', scope: JSON.stringify(scope), policy: '{}', origin: 'https://coffre.test', createdBy: ROOT,
  });
  await genesis({ kind: 'binding', id: binding }, {
    kind: 'binding', id: binding, principal: w.principal, generation: 0, profile: 'cloudflare', issuer: 'urn:coffre:cloudflare', origin: 'https://coffre.test',
    jwksUri: 'urn:coffre:cloudflare', claims: '{}', scope, policy: '{}', revoked: false,
  } as Input);
  const outcome = await (await isolate()).use({ ...ask(w, id, { purpose: 'use' }), credential: binding, way: 'binding' });
  assert.ok(outcome.ok, JSON.stringify(outcome));
  await tick();
  await projectReads(logStore(db.vault), await keys());
  assert.deepEqual((await rows<{ principal: string }>(db.owner, sql`SELECT principal FROM log_reads`)).map((row) => row.principal), [w.principal]);
});

test("a read of a day with no reads' partition yet makes it: a log older than the days made ahead does not stop the projector (review r4)", { skip: ENGINE === 'postgres' ? false : 'Postgres only: partitions' }, async () => {
  const tick = await signer();
  await reads(2);
  await tick();
  const day = new Date().toISOString().slice(0, 10).replaceAll('-', '');
  for (const table of ['log_reads', 'log_read_places']) await run(db.owner, sql.raw(`DROP TABLE ${table}_${day}`));
  await projectReads(logStore(db.vault), await keys());
  assert.equal(await count('log_reads'), 2);
  assert.deepEqual(await checked(), []);
});

test('an unsigned cursor is the start only: anywhere else, or at another time, it is not the vault\'s', async () => {
  const { mac } = await keys();
  assert.equal(cursorHolds(mac, { through: 0n, pair: 0n, at: 0, mac: null }), true);
  assert.equal(cursorHolds(mac, { through: 0n, pair: 0n, at: Date.now() + 86_400_000, mac: null }), false);
  assert.equal(cursorHolds(mac, { through: 4n, pair: 0n, at: 0, mac: null }), false);
});

test("the objects of 300 reads are read in statements SQLite takes: no more than 500 terms of a compound SELECT", async () => {
  const asked = Array.from({ length: 600 }, (_, i) => ({ object: randomUUID(), below: BigInt(i + 1), first: i % 2 === 0 }));
  assert.equal((await logStore(db.vault).objects(asked)).filter((found) => found !== null).length, 0);
});
