import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';

import { prepared, tablesOf, type Database, type Queryable } from '@coffre/db';
import * as server from '@coffre/db/schema';
import { and, asc, eq, sql, type Placeholder } from 'drizzle-orm';

import { insert } from '../../src/db/queries.ts';
import { openTestDatabase } from './engine.ts';

// A query built once and run with new values each time answers as its
// builder would, on whichever engine the suite runs: on the database, and
// inside a transaction, through the transaction.

let db: Database;
let close: () => Promise<void>;

before(async () => {
  ({ runtime: db, close } = await openTestDatabase());
});

after(() => close());

let builds = 0;

/** A project and its environments, by slug: a left join, whose missing side reads as null. With values, or placeholders for them. */
function projectAndEnvironments(on: Queryable, slug: string | Placeholder = sql.placeholder('slug'), limit: number | Placeholder = sql.placeholder('limit')) {
  const { projects, environments } = tablesOf(on);
  return on
    .select({ project: { id: projects.id, slug: projects.slug }, environment: { slug: environments.slug } })
    .from(projects)
    .leftJoin(environments, eq(environments.projectId, projects.id))
    .where(eq(projects.slug, slug))
    .orderBy(asc(environments.slug))
    .limit(limit);
}

const byProject = prepared((on) => {
  builds += 1;
  return projectAndEnvironments(on);
});

async function project(environments: string[]) {
  const id = randomUUID();
  const slug = `t${id.slice(0, 8)}`;
  await insert(db, server.projects, { id, slug, name: slug });
  for (const environment of environments) await insert(db, server.environments, { id: randomUUID(), projectId: id, slug: environment, name: environment });
  return { id, slug };
}

test('a prepared select answers as its builder does, for each set of values, built once', async () => {
  const market = await project(['dev', 'prod', 'staging']);
  const empty = await project([]);
  for (const [slug, limit] of [[market.slug, 10], [market.slug, 2], [empty.slug, 10], ['nobody', 10]] as const) {
    assert.deepEqual(await byProject(db, { slug, limit }), await projectAndEnvironments(db, slug, limit), `${slug}, at most ${limit}`);
  }
  assert.deepEqual(await byProject(db, { slug: empty.slug, limit: 10 }), [{ project: { id: empty.id, slug: empty.slug }, environment: null }]);
  assert.equal(builds, 1, 'built the first time only');
});

test('inside a transaction, a prepared select reads through it', async () => {
  const market = await project(['dev']);
  await assert.rejects(
    db.transaction(async (tx) => {
      await insert(tx, server.environments, { id: randomUUID(), projectId: market.id, slug: 'prod', name: 'prod' });
      const seen = await byProject(tx, { slug: market.slug, limit: 10 });
      assert.deepEqual(seen.map((row) => row.environment?.slug), ['dev', 'prod']);
      throw new Error('roll back');
    }),
    /roll back/,
  );
  const after = await byProject(db, { slug: market.slug, limit: 10 });
  assert.deepEqual(after.map((row) => row.environment?.slug), ['dev']);
});

/** The log's head by its number and hash: a bigint and bytes, which go to the driver as they are. */
function headAt(on: Queryable, seq: bigint | Placeholder = sql.placeholder('seq'), hash: Buffer | Placeholder = sql.placeholder('hash')) {
  const { auditChainHead } = tablesOf(on);
  return on
    .select({ nextSeq: auditChainHead.nextSeq, headHash: auditChainHead.headHash })
    .from(auditChainHead)
    .where(and(eq(auditChainHead.nextSeq, seq), eq(auditChainHead.headHash, hash)));
}

const headByValue = prepared((on) => headAt(on));

test('bigint and byte values bind as the builder binds them', async () => {
  const [head] = await db.select({ nextSeq: tablesOf(db).auditChainHead.nextSeq, headHash: tablesOf(db).auditChainHead.headHash }).from(tablesOf(db).auditChainHead);
  assert.ok(head !== undefined);
  const other = Buffer.from(head.headHash).fill(head.headHash[0]! ^ 1, 0, 1);
  for (const [seq, hash] of [[head.nextSeq, head.headHash], [head.nextSeq + 1n, head.headHash], [head.nextSeq, other]] as const) {
    const found = await headByValue(db, { seq, hash });
    assert.deepEqual(found, await headAt(db, seq, hash));
    assert.equal(found.length, seq === head.nextSeq && hash === head.headHash ? 1 : 0);
  }
});
