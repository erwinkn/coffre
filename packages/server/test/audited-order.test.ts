// `audited` asks the head, its read, the policy and the work's first statements together, under one Sync (T179): the
// policy is read before anything the work writes, even a first write it leaves to `later`, so that a write of its own
// is never mistaken for a change to the policy (review r8 of #452).
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';

import { later } from '@coffre/db';
import { eq, sql } from 'drizzle-orm';

import { audited } from '../src/api/context.ts';
import { clientFor, contextFor, openTestDatabase, resetDatabase, testDeps, type FixtureDeps } from './api-fixture.ts';
import { environments } from '@coffre/db/schema';

const ROOT = 'admin@acme.example';

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;

before(async () => {
  db = await openTestDatabase();
  await resetDatabase(db.owner);
  deps = testDeps(db.runtime, [ROOT]);
  const root = clientFor(deps, ROOT);
  await root.projects.create('market', { name: 'Market' });
  await root.environments.create('market/prod');
  await root.environments.protect('market/prod');
});

after(async () => {
  await resetDatabase(db.owner);
  await db.close();
});

test("a work whose first statement is a `later` write to a protected environment's slug commits: the policy was read before it", async () => {
  const ctx = await contextFor(deps, ROOT);
  const [prod] = await db.owner.select({ id: environments.id }).from(environments).where(eq(environments.slug, 'prod'));
  await audited(ctx, async (tx) => {
    later(tx, sql`UPDATE environments SET slug = 'renamed' WHERE id = ${prod!.id}`);
  });
  const [now] = await db.owner.select({ slug: environments.slug }).from(environments).where(eq(environments.id, prod!.id));
  assert.equal(now?.slug, 'renamed');
});

test("a factor lock that fails fails the work with its own error, the head's queued behind it heard too: no unhandled rejection (review r13 of #500)", async () => {
  const ctx = await contextFor(deps, ROOT);
  const unhandled: unknown[] = [];
  const hear = (reason: unknown) => void unhandled.push(reason);
  process.on('unhandledRejection', hear);
  let release!: () => void;
  const released = new Promise<void>((resolve) => (release = resolve));
  let held!: () => void;
  const holding = new Promise<void>((resolve) => (held = resolve));
  // Another transaction holds the person's factor lock (`lockFactor`'s key).
  const holder = db.owner.transaction(async (tx) => {
    await tx.execute(sql`SELECT pg_advisory_xact_lock(1717658484, hashtext(${ROOT}))`);
    held();
    await released;
  });
  try {
    await holding;
    const work = audited(ctx, async () => 'done', null, ROOT);
    // Heard from the start: the cancel below is the test's own query, on its own connection, and the work's refusal may
    // reach this process before that query's answer does; left unheard until then, it is an unhandled rejection (T238).
    // The factor lock's own error, 57014, not the head's 25P02.
    const refused = assert.rejects(work, (error: unknown) => (error as { cause?: { code?: unknown } }).cause?.code === '57014');
    // The work's factor lock waits; cancelled, as a `lock_timeout` ends it, the head's statement behind it fails 25P02.
    // In this database: pg_locks shows the cluster's, and another test file's waiter on the same person's lock is not ours.
    let waiter: string | undefined;
    for (let i = 0; i < 200 && waiter === undefined; i++) {
      const rows = await db.owner.execute<{ pid: number }>(sql`SELECT pid FROM pg_locks WHERE locktype = 'advisory' AND NOT granted AND classid = 1717658484 AND database = (SELECT oid FROM pg_database WHERE datname = current_database())`);
      waiter = (rows as unknown as { pid: number }[])[0]?.pid?.toString();
      if (waiter === undefined) await new Promise((resolve) => setTimeout(resolve, 10));
    }
    assert.ok(waiter !== undefined, 'the work waits on the factor lock');
    await db.owner.execute(sql`SELECT pg_cancel_backend(${Number(waiter)})`);
    await refused;
    await new Promise((resolve) => setTimeout(resolve, 50));
    assert.deepEqual(unhandled, []);
  } finally {
    release();
    await holder;
    process.off('unhandledRejection', hear);
  }
});
