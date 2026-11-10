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
import { append, holdsFlat, SMALL } from './db/growth.ts';

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

/**
 * `count` reads of 0.15's log by `principal`, of `keys` in turn at their versions, numbered after `from`, over `days`
 * days back from today, as many each.
 */
async function plantReads(principal: string, count: number, from: number, days = 1): Promise<void> {
  const now = Date.now();
  const today = Math.floor(now / 86_400_000);
  if (TEST_ENGINE === 'postgres') {
    for (let back = 0; back < days; back++) await rowsOf(db.owner, sql`SELECT make_reads_day(${new Date((today - back) * 86_400_000).toISOString().slice(0, 10)}::date)`);
  }
  const pick = (column: 'id' | 'version' | 'environment' | 'project') => sql.raw(`CASE g % 3 ${keys.map((key, i) => `WHEN ${i} THEN '${key[column]}'`).join(' ')} END`);
  const uuid = (value: ReturnType<typeof sql.raw>) => (TEST_ENGINE === 'postgres' ? sql`CAST(${value} AS uuid)` : value);
  for (let low = 0; low < count; low += 20_000) {
    await rowsOf(db.owner, sql`
      WITH RECURSIVE g (g) AS (SELECT CAST(${low} AS integer) UNION ALL SELECT g + 1 FROM g WHERE g < ${Math.min(count, low + 20_000) - 1})
      INSERT INTO log_reads (number, at, credential, purpose, principal, secret, environment, project, version, mac)
      SELECT CAST(${from} AS bigint) + g, CAST(${now} AS bigint) - (g % ${days}) * CAST(86400000 AS bigint) + g % 1000, ${uuid(sql.raw(`'${keys[0]!.id}'`))}, 1, ${principal}, ${uuid(pick('id'))}, ${uuid(pick('environment'))}, ${uuid(pick('project'))}, ${uuid(pick('version'))},
             ${Buffer.alloc(16)}
        FROM g`);
  }
  for (let back = 0; back < days; back++) await rowsOf(db.owner, sql`INSERT INTO log_read_days (principal, day) VALUES (${principal}, ${today - back}) ON CONFLICT DO NOTHING`);
}

/** `count` reads of 0.15's log, numbered after `from`, today, each by a member of its own, of a key and version of its own. */
async function plantOthers(count: number, from: number): Promise<void> {
  const now = Date.now();
  const id = (salt: string) => (TEST_ENGINE === 'postgres' ? sql.raw(`md5('${salt}' || g)::uuid`) : sql.raw(`lower(hex(randomblob(16)))`));
  for (let low = 0; low < count; low += 20_000) {
    await rowsOf(db.owner, sql`
      WITH RECURSIVE g (g) AS (SELECT CAST(${low} AS integer) UNION ALL SELECT g + 1 FROM g WHERE g < ${Math.min(count, low + 20_000) - 1})
      INSERT INTO log_reads (number, at, credential, purpose, principal, secret, environment, project, version, mac)
      SELECT CAST(${from} AS bigint) + g, CAST(${now} AS bigint) + g % 1000, ${id('c')}, 1, 'user:' || g || '@acme.example', ${id('s')}, ${id('e')}, ${id('p')}, ${id('v')}, ${Buffer.alloc(16)}
        FROM g`);
  }
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

test("a member's reads by key and version, an offboarding report's (`readsBy`): a step for each, however many times and on however many days they read it", { timeout: 600_000 }, () => holdsFlat(db.owner, {
  // Theirs, of three keys again and again, over 4 days, then 40: a probe of each day they read on was the walk that
  // retention's keeping every day made grow (review r1 of #559). As many of someone else's on the same days, and as
  // many others', each of a key and version of its own, which `log_read_newest` holds a row each of (T252).
  grow: async (_, size) => {
    await plantReads(MEMBER, size, 1_000_000, (4 * size) / SMALL);
    await plantReads(OTHER, size, 2_000_000, (4 * size) / SMALL);
    await plantOthers(size, 3_000_000);
  },
  ask: async (app) => assert.equal((await readsBy(app, [MEMBER])).length, keys.length),
  indexes: ['log_read_newest_pkey'],
  also: ['log_read_newest', 'secret_versions'],
}));

/**
 * Versions `from` to `to` of `into`, each the value of `secret`'s version `of`, its very ciphertext, as a restore of it
 * makes: of another key, a value of its own beside that key's.
 */
async function copies(owner: Parameters<Parameters<typeof holdsFlat>[1]['grow']>[0], secret: string, of: number, from: number, to: number, into = secret): Promise<void> {
  const id = TEST_ENGINE === 'postgres' ? sql`gen_random_uuid()` : sql`lower(hex(randomblob(16)))`;
  await rowsOf(owner, sql`
    WITH RECURSIVE g (n) AS (SELECT CAST(${from} AS integer) UNION ALL SELECT n + 1 FROM g WHERE n < ${to})
    INSERT INTO secret_versions (id, secret_id, version, envelope_version, ciphertext, iv, auth_tag, wrapped_dek, kek_provider, kek_id, kek_version, created_by)
    SELECT ${id}, ${into}, g.n, v.envelope_version, v.ciphertext, v.iv, v.auth_tag, v.wrapped_dek, v.kek_provider, v.kek_id, v.kek_version, v.created_by
      FROM g, secret_versions v WHERE v.secret_id = ${secret} AND v.version = ${of}`);
}

test("a member's activity in 0.14's log, an offboarding report's (`memberActivity`): their reads and writes, and whether each is of its key's current value", { timeout: 600_000 }, () => holdsFlat(db.owner, {
  // A few reads and a write of theirs: A's version 1, whose value an owner put back again and again, each restore of
  // the last (`size / 10` versions, the newest current: a walk back stepped through each; review r2 of #559); B's
  // version 1, current; C's version 1, which a new value replaced. Then everyone else's reads, and entries of theirs
  // of other kinds.
  grow: async (owner, size) => {
    const [a, b, c] = keys;
    await rowsOf(owner, sql`DELETE FROM secret_versions WHERE version > 1`);
    await copies(owner, a!.id, 1, 2, 1 + size / 10);
    await rowsOf(owner, sql`UPDATE secrets SET current_version = ${1 + size / 10} WHERE id = ${a!.id}`);
    // C's version 2, a value of its own: B's ciphertext, under another IV and tag than C's version 1.
    await copies(owner, b!.id, 1, 2, 2, c!.id);
    await rowsOf(owner, sql`UPDATE secrets SET current_version = 2 WHERE id = ${c!.id}`);
    await append(owner, { author: 'vault', action: 'secret.read', count: 3, actor: MEMBER, secret: a!.id, project: a!.project, metadata: JSON.stringify({ version: 1 }) });
    await append(owner, { author: 'app', action: 'secret.write', count: 1, actor: MEMBER, secret: b!.id, project: b!.project, metadata: JSON.stringify({ version: 1 }) });
    await append(owner, { author: 'vault', action: 'secret.read', count: 1, actor: MEMBER, secret: c!.id, project: c!.project, metadata: JSON.stringify({ version: 1 }) });
    await append(owner, { author: 'vault', action: 'secret.read', count: size, actor: OTHER, secret: a!.id, project: a!.project, metadata: JSON.stringify({ version: 1 }) });
    await append(owner, { author: 'app', action: 'sign_in', count: size, actor: MEMBER });
  },
  ask: async (app) => {
    const activity = await memberActivity(app, ['m1@acme.example']);
    const [a, b, c] = keys;
    const named = new Map([[a!.id, 'A'], [b!.id, 'B'], [c!.id, 'C']]);
    assert.deepEqual(activity.map((row) => `${row.action} ${named.get(row.secretId!)} ${row.current}`).sort(), [
      'secret.read A true', 'secret.read A true', 'secret.read A true', 'secret.read C false', 'secret.write B true',
    ]);
  },
  indexes: ['audit_log_seen_idx', 'secret_versions_secret_id_version_key'],
  also: ['secret_versions'],
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
