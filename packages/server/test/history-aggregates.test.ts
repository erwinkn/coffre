// The server's reads over a whole kind of history at once (T248, R48): each costs as much on a history ten times
// longer, against the shape that is worst for it (`holdsFlat`, db/growth.ts). The newest-entry reads are T245's
// (`newest-lookups.test.ts`); `packages/db/test/newest-lookups.test.ts` holds every aggregate over a log in the
// sources to one of these, or to why it needs none.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

import { tamperedMembers } from '@coffre/db/grants';
import { rowsOf } from '@coffre/db/dialect';
import { sql } from 'drizzle-orm';

import { DETAIL_ACTIONS } from '@coffre/db/log';

import { auditActionCounts, auditPage, HIDDEN_COUNTED, memberActivity } from '../src/db/queries.ts';
import { readsBy } from '../src/db/reads.ts';
import { clientFor, openTestDatabase, resetDatabase, testDeps } from './api-fixture.ts';
import { TEST_ENGINE } from './db/engine.ts';
import { append, holdsFlat } from './db/growth.ts';

const ROOT = 'admin@acme.example';
const MEMBER = 'user:m1@acme.example';
const OTHER = 'user:other@acme.example';

let db: Awaited<ReturnType<typeof openTestDatabase>>;
/** Three keys of market/dev, each at its version: what the reads here are of. */
let keys: { id: string; version: string; environment: string; project: string }[];
before(async () => {
  db = await openTestDatabase();
  await resetDatabase(db.owner);
  const root = clientFor(testDeps(db.runtime, [ROOT]), ROOT);
  await root.projects.create('market', { name: 'Market' });
  await root.environments.create('market/dev', { name: 'dev' });
  await root.secrets.set('market/dev', { A: 'fake-a', B: 'fake-b', C: 'fake-c' });
  keys = (await rowsOf<{ id: string; version: string; environment: string; project: string }>(db.owner, sql`
    SELECT CAST(id AS text) AS id, CAST(current_version_id AS text) AS version, CAST(environment_id AS text) AS environment, CAST(project_id AS text) AS project
      FROM secrets ORDER BY key`)).map((row) => ({ ...row }));
});
after(async () => {
  await resetDatabase(db.owner);
  await db.close();
});

/** `count` reads of 0.15's log by `principal`, today, of `keys` in turn at their versions, numbered after `from`. */
async function plantReads(principal: string, count: number, from: number): Promise<void> {
  const now = Date.now();
  if (TEST_ENGINE === 'postgres') await rowsOf(db.owner, sql`SELECT make_reads_day(${new Date(now).toISOString().slice(0, 10)}::date)`);
  const pick = (column: 'id' | 'version' | 'environment' | 'project') => sql.raw(`CASE g % 3 ${keys.map((key, i) => `WHEN ${i} THEN '${key[column]}'`).join(' ')} END`);
  const uuid = (value: ReturnType<typeof sql.raw>) => (TEST_ENGINE === 'postgres' ? sql`CAST(${value} AS uuid)` : value);
  for (let low = 0; low < count; low += 20_000) {
    await rowsOf(db.owner, sql`
      WITH RECURSIVE g (g) AS (SELECT CAST(${low} AS integer) UNION ALL SELECT g + 1 FROM g WHERE g < ${Math.min(count, low + 20_000) - 1})
      INSERT INTO log_reads (number, at, credential, purpose, principal, secret, environment, project, version, mac)
      SELECT CAST(${from} AS bigint) + g, CAST(${now} AS bigint) + g % 1000, ${uuid(sql.raw(`'${keys[0]!.id}'`))}, 1, ${principal}, ${uuid(pick('id'))}, ${uuid(pick('environment'))}, ${uuid(pick('project'))}, ${uuid(pick('version'))},
             ${Buffer.alloc(16)}
        FROM g`);
  }
  await rowsOf(db.owner, sql`INSERT INTO log_read_days (principal, day) VALUES (${principal}, ${Math.floor(now / 86_400_000)}) ON CONFLICT DO NOTHING`);
}

test("every member's findings, the members list's (`tamperedMembers`): a step for each member reported, however many reports about them", { timeout: 600_000 }, () => holdsFlat(db.owner, {
  // An access entry about each, then their findings: 0.14's, newer than it, and 0.15's, each naming a change that is
  // not their newest; two members, so that the members reported are a walk of more than one.
  grow: async (owner, size) => {
    for (const member of ['user:t1@acme.example', 'user:t2@acme.example']) {
      await append(owner, { author: 'vault', action: 'access.grant', count: 1, subject: member });
      await append(owner, { author: 'vault', action: 'vault.tampered', decision: 'deny', code: 'mac', count: size / 4, subject: member });
      await append(owner, { author: 'vault', action: 'vault.tampered', decision: 'deny', code: 'stale', count: size / 4, subject: member, metadata: JSON.stringify({ change: randomBytes(16).toString('hex') }) });
    }
  },
  ask: async (app) => {
    assert.deepEqual([...(await tamperedMembers(app))].sort(), ['user:t1@acme.example', 'user:t2@acme.example']);
    assert.deepEqual([...(await tamperedMembers(app, 'user:t1@acme.example'))], ['user:t1@acme.example']);
  },
  indexes: ['audit_log_tamper_idx'],
}));

test("a member's reads by key and version, an offboarding report's (`readsBy`): a step for each, however many times they read it", { timeout: 600_000 }, () => holdsFlat(db.owner, {
  // Theirs, of three keys again and again, and as many of someone else's, on the same day.
  grow: async (_, size) => {
    await plantReads(MEMBER, size, 1_000_000);
    await plantReads(OTHER, size, 2_000_000);
  },
  ask: async (app) => assert.equal((await readsBy(app, [MEMBER])).length, keys.length),
  indexes: ['log_reads_seen_idx'],
}));

test("a member's activity in 0.14's log, an offboarding report's (`memberActivity`): their reads and writes, and the restores of the keys they saw", { timeout: 600_000 }, () => holdsFlat(db.owner, {
  // A few reads and a write of theirs, and the restores that make the value of a key they read its current one: 7 put
  // back from 5, 5 from 1, which they read, and one a writer planted pointing up, which the walk back passes by. Then,
  // growing, everyone else's reads, entries of theirs of other kinds, restores of a key they never saw, and of the
  // key they read, from 1 again and again, none of which its current value comes from (review r1 of #559).
  grow: async (owner, size) => {
    const [a, b] = keys;
    await rowsOf(owner, sql`UPDATE secrets SET current_version = 7 WHERE id = ${a!.id}`);
    await append(owner, { author: 'vault', action: 'secret.read', count: 3, actor: MEMBER, secret: a!.id, project: a!.project, metadata: JSON.stringify({ version: 1 }) });
    await append(owner, { author: 'app', action: 'secret.write', count: 1, actor: MEMBER, secret: b!.id, project: b!.project, metadata: JSON.stringify({ version: 1 }) });
    await append(owner, { author: 'app', action: 'secret.restore', count: 1, actor: `user:${ROOT}`, secret: a!.id, project: a!.project, metadata: JSON.stringify({ version: 7, from: 5 }) });
    await append(owner, { author: 'app', action: 'secret.restore', count: 1, actor: `user:${ROOT}`, secret: a!.id, project: a!.project, metadata: JSON.stringify({ version: 5, from: 1 }) });
    await append(owner, { author: 'app', action: 'secret.restore', count: 1, actor: `user:${ROOT}`, secret: a!.id, project: a!.project, metadata: JSON.stringify({ version: 5, from: 9 }) });
    await append(owner, { author: 'vault', action: 'secret.read', count: size, actor: OTHER, secret: a!.id, project: a!.project, metadata: JSON.stringify({ version: 1 }) });
    await append(owner, { author: 'app', action: 'sign_in', count: size, actor: MEMBER });
    await append(owner, { author: 'app', action: 'secret.restore', count: size / 10, actor: `user:${ROOT}`, secret: keys[2]!.id, project: a!.project, metadata: JSON.stringify({ version: 2, from: 1 }) });
    await append(owner, { author: 'app', action: 'secret.restore', count: size / 10, actor: `user:${ROOT}`, secret: a!.id, project: a!.project, metadata: JSON.stringify({ version: 3, from: 1 }) });
  },
  ask: async (app) => {
    const activity = await memberActivity(app, ['m1@acme.example']);
    assert.deepEqual(activity.map((row) => row.action).sort(), ['secret.read', 'secret.read', 'secret.read', 'secret.restore', 'secret.restore', 'secret.write']);
    assert.deepEqual(activity.filter((row) => row.action === 'secret.restore').map((row) => JSON.parse(row.metadata) as unknown).sort((x, y) => JSON.stringify(x) < JSON.stringify(y) ? -1 : 1), [{ from: 1, version: 5 }, { from: 5, version: 7 }]);
  },
  indexes: ['audit_log_seen_idx', 'audit_log_restore_idx'],
}));

test('an ordinary audit page back from the newest, past every heartbeat since (`auditPage`): a step of what it shows', { timeout: 600_000 }, () => holdsFlat(db.owner, {
  grow: async (owner, size) => {
    await append(owner, { author: 'app', action: 'project.create', count: 5, actor: `user:${ROOT}` });
    await append(owner, { author: 'app', action: 'audit.heartbeat', count: size });
  },
  ask: async (app) => assert.equal((await auditPage(app, { excludeActions: DETAIL_ACTIONS, limit: 5 })).rows.length, 5),
  indexes: ['audit_log_shown_idx'],
}));

test("a page's count of what it hides, with nothing older to show (`auditActionCounts`): of `HIDDEN_COUNTED` at most, whatever its filter, and whether there were more", { timeout: 600_000 }, () => holdsFlat(db.owner, {
  grow: async (owner, size) => append(owner, { author: 'app', action: 'audit.heartbeat', count: size }),
  ask: async (app, size) => {
    // Past `HIDDEN_COUNTED` (SQLite's smaller size is not), the count stops there and says there were more.
    const more = size > HIDDEN_COUNTED;
    assert.deepEqual(await auditActionCounts(app, { limit: 100 }), { counts: [{ action: 'audit.heartbeat', count: Math.min(size, HIDDEN_COUNTED) }], more });
    // A project's page and a page of refusals, which none of them is: as many weighed, none counted.
    assert.deepEqual(await auditActionCounts(app, { projectId: keys[0]!.project, limit: 100 }), { counts: [], more });
    assert.deepEqual(await auditActionCounts(app, { decision: 'deny', limit: 100 }), { counts: [], more });
  },
  indexes: ['audit_log_detail_idx'],
}));

// The guard itself: a `LIMIT` in a statement does not make its scan of a log a bounded walk (review r2 of #559). Each
// read here counts or filters the whole log.
for (const [name, statement] of [
  // On SQLite through the table, `SCAN audit_log`, rather than a covering index: the plan r1's guard let pass.
  ['a count of the whole log, under a `LIMIT 1`', sql`SELECT count(*) AS n FROM audit_log ${sql.raw(TEST_ENGINE === 'postgres' ? '' : 'NOT INDEXED ')}LIMIT 1`],
  ['a filter no index serves, beside a `LIMIT` of a subquery its own', sql`SELECT seq FROM audit_log WHERE metadata LIKE '%needle%' AND 1 = (SELECT 1 LIMIT 1)`],
] as const) {
  test(`the guard refuses ${name}`, { timeout: 600_000 }, async () => {
    await assert.rejects(holdsFlat(db.owner, {
      grow: async (owner, size) => append(owner, { author: 'app', action: 'audit.heartbeat', count: size }),
      ask: async (app) => void await rowsOf(app, statement),
    }), TEST_ENGINE === 'postgres' ? /reads as many pages/ : /scans no log whole/);
  });
}
