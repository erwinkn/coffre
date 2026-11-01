// `audited` asks the head, its read, the policy and the work's first statements together, under one Sync (T179): the
// policy is read before anything the work writes, even a first write it leaves to `later`, so that a write of its own
// is never mistaken for a change to the policy (review r8 of #452).
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';

import { later } from '@coffre/db';
import { eq, sql } from 'drizzle-orm';

import { audited } from '../src/api/context.ts';
import { clientFor, contextFor, openTestDatabase, resetDatabase, testDeps, type FixtureDeps } from './api-fixture.ts';
import { postgresOnly } from './db/engine.ts';
import { environments } from './db/tables.ts';

const POSTGRES = postgresOnly("orders statements within one Sync, Postgres's");
const ROOT = 'admin@acme.example';

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;

before(async () => {
  if (POSTGRES.skip) return;
  db = await openTestDatabase();
  await resetDatabase(db.owner);
  deps = testDeps(db.runtime, [ROOT]);
  const root = clientFor(deps, ROOT);
  await root.projects.create('market', { name: 'Market' });
  await root.environments.create('market/prod');
  await root.environments.protect('market/prod');
});

after(async () => {
  if (POSTGRES.skip) return;
  await resetDatabase(db.owner);
  await db.close();
});

test("a work whose first statement is a `later` write to a protected environment's slug commits: the policy was read before it", POSTGRES, async () => {
  const ctx = await contextFor(deps, ROOT);
  const [prod] = await db.owner.select({ id: environments.id }).from(environments).where(eq(environments.slug, 'prod'));
  await audited(ctx, async (tx) => {
    later(tx, sql`UPDATE environments SET slug = 'renamed' WHERE id = ${prod!.id}`);
  });
  const [now] = await db.owner.select({ slug: environments.slug }).from(environments).where(eq(environments.id, prod!.id));
  assert.equal(now?.slug, 'renamed');
});
