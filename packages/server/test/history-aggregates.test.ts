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

import { auditActionCounts, auditPage, HIDDEN_COUNTED, memberActivity } from '../src/db/queries.ts';
import { clientFor, openTestDatabase, resetDatabase, testDeps } from './api-fixture.ts';
import { TEST_ENGINE } from './db/engine.ts';
import { append, holdsFlat } from './db/growth.ts';

const ROOT = 'admin@acme.example';
const MEMBER = 'user:m1@acme.example';
const OTHER = 'user:other@acme.example';
/** Who writes the audit watch's heartbeats (`watch.ts`). */
const SCHEDULER = 'system:coffre-scheduler';

let db: Awaited<ReturnType<typeof openTestDatabase>>;
/** Three keys of market/dev, each at its version: what the reads here are of. */
let keys: { id: string; version: string; environment: string; project: string }[];
/** Another project, whose entries a page of market's passes by. */
let shop: string;
before(async () => {
  db = await openTestDatabase();
  await resetDatabase(db.owner);
  const root = clientFor(testDeps(db.runtime, [ROOT]), ROOT);
  await root.projects.create('market', { name: 'Market' });
  await root.environments.create('market/dev', { name: 'dev' });
  await root.secrets.set('market/dev', { A: 'fake-a', B: 'fake-b', C: 'fake-c' });
  await root.projects.create('shop', { name: 'Shop' });
  [{ id: shop }] = await rowsOf<{ id: string }>(db.owner, sql`SELECT CAST(id AS text) AS id FROM projects WHERE slug = 'shop'`) as [{ id: string }];
  keys = (await rowsOf<{ id: string; version: string; environment: string; project: string }>(db.owner, sql`
    SELECT CAST(id AS text) AS id, CAST(current_version_id AS text) AS version, CAST(environment_id AS text) AS environment, CAST(project_id AS text) AS project
      FROM secrets ORDER BY key`)).map((row) => ({ ...row }));
});
after(async () => {
  await resetDatabase(db.owner);
  await db.close();
});

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

test("a member's activity in 0.14's log, an offboarding report's (`memberActivity`): their reads and writes, and the restores of the keys they saw", { timeout: 600_000 }, () => holdsFlat(db.owner, {
  // A few reads and a write of theirs, and the restores that make the value of a key they read its current one: 7 put
  // back from 5, 5 from 1, which they read, and one a writer planted pointing up, which the walk back passes by. Then,
  // growing, everyone else's reads of a key they never saw, entries of theirs of other kinds, and restores of that key.
  // Not the history of a key they saw: the walk back (`restoresBack`) reads its entries at each step, until T252
  // replaces it with a probe of each version seen.
  grow: async (owner, size) => {
    const [a, b] = keys;
    await rowsOf(owner, sql`UPDATE secrets SET current_version = 7 WHERE id = ${a!.id}`);
    await append(owner, { author: 'vault', action: 'secret.read', count: 3, actor: MEMBER, secret: a!.id, project: a!.project, metadata: JSON.stringify({ version: 1 }) });
    await append(owner, { author: 'app', action: 'secret.write', count: 1, actor: MEMBER, secret: b!.id, project: b!.project, metadata: JSON.stringify({ version: 1 }) });
    await append(owner, { author: 'app', action: 'secret.restore', count: 1, actor: `user:${ROOT}`, secret: a!.id, project: a!.project, metadata: JSON.stringify({ version: 7, from: 5 }) });
    await append(owner, { author: 'app', action: 'secret.restore', count: 1, actor: `user:${ROOT}`, secret: a!.id, project: a!.project, metadata: JSON.stringify({ version: 5, from: 1 }) });
    await append(owner, { author: 'app', action: 'secret.restore', count: 1, actor: `user:${ROOT}`, secret: a!.id, project: a!.project, metadata: JSON.stringify({ version: 5, from: 9 }) });
    await append(owner, { author: 'vault', action: 'secret.read', count: size, actor: OTHER, secret: keys[2]!.id, project: a!.project, metadata: JSON.stringify({ version: 1 }) });
    await append(owner, { author: 'app', action: 'sign_in', count: size, actor: MEMBER });
    await append(owner, { author: 'app', action: 'secret.restore', count: size / 10, actor: `user:${ROOT}`, secret: keys[2]!.id, project: a!.project, metadata: JSON.stringify({ version: 2, from: 1 }) });
  },
  ask: async (app) => {
    const activity = await memberActivity(app, ['m1@acme.example']);
    assert.deepEqual(activity.map((row) => row.action).sort(), ['secret.read', 'secret.read', 'secret.read', 'secret.restore', 'secret.restore', 'secret.write']);
    assert.deepEqual(activity.filter((row) => row.action === 'secret.restore').map((row) => JSON.parse(row.metadata) as unknown).sort((x, y) => JSON.stringify(x) < JSON.stringify(y) ? -1 : 1), [{ from: 1, version: 5 }, { from: 5, version: 7 }]);
  },
  indexes: ['audit_log_seen_idx', 'audit_log_secret_idx'],
}));

test('an ordinary audit page back from the newest, past every heartbeat since (`auditPage`): a step of what it shows', { timeout: 600_000 }, () => holdsFlat(db.owner, {
  grow: async (owner, size) => {
    await append(owner, { author: 'app', action: 'project.create', count: 5, actor: `user:${ROOT}` });
    await append(owner, { author: 'app', action: 'audit.heartbeat', count: size });
  },
  ask: async (app) => assert.equal((await auditPage(app, { detail: false, limit: 5 })).rows.length, 5),
  indexes: ['audit_log_shown_idx'],
}));

// An actor's page (`?actor=`, which every entry's actor links to), past every entry of their own it leaves out: the
// scheduler's findings behind its heartbeats, one every five minutes, and a member's who only ever signed in (Fable
// r1 of #559). Then everyone else's entries shown, which a walk of what pages show (`audit_log_shown_idx`) would pass.
test("the scheduler's audit page, past every heartbeat of its own (`auditPage`, `?actor=`): a step of what it shows", { timeout: 600_000 }, () => holdsFlat(db.owner, {
  grow: async (owner, size) => {
    await append(owner, { author: 'app', action: 'audit.finding', count: 5, actor: SCHEDULER });
    await append(owner, { author: 'app', action: 'audit.heartbeat', count: size, actor: SCHEDULER });
    await append(owner, { author: 'app', action: 'project.update', count: size, actor: `user:${ROOT}` });
  },
  ask: async (app) => assert.equal((await auditPage(app, { actors: [SCHEDULER], detail: false, limit: 5 })).rows.length, 5),
  indexes: ['audit_log_shown_actor_idx'],
}));

test("a member's audit page who only ever signed in (`auditPage`, `?actor=`): a step to find it empty", { timeout: 600_000 }, () => holdsFlat(db.owner, {
  grow: async (owner, size) => {
    await append(owner, { author: 'app', action: 'sign_in', count: size, actor: MEMBER });
    await append(owner, { author: 'app', action: 'project.update', count: size, actor: `user:${ROOT}` });
  },
  ask: async (app) => assert.deepEqual(await auditPage(app, { actors: [MEMBER], detail: false, limit: 5 }), { rows: [], more: false }),
  indexes: ['audit_log_shown_actor_idx'],
}));

// A member's page under a place (`?path=…&actor=`, or any page of theirs a project's reader asks, `within`): a step
// of what an actor's pages show, whatever the place (`audit_log_shown_actor_idx`), so flat past the entries of theirs
// it hides. It still walks those it shows at other places, as main does: T254's (Fable r3 of #559).
// Fenced as a place's page, it walked back their sign-ins: 158 pages 4,000 in, 1,538 at 40,000 (Fable r2 of #559).
test("a member's audit page under a place, behind their sign-ins (`auditPage`, `within` and `?actor=`): a step of what it shows", { timeout: 600_000 }, () => holdsFlat(db.owner, {
  grow: async (owner, size) => {
    await append(owner, { author: 'app', action: 'secret.write', count: 5, actor: MEMBER, project: keys[0]!.project });
    await append(owner, { author: 'app', action: 'sign_in', count: size, actor: MEMBER });
    await append(owner, { author: 'app', action: 'project.update', count: size, actor: `user:${ROOT}`, project: keys[0]!.project });
  },
  ask: async (app) => {
    const within = { projectIds: [keys[0]!.project], environmentIds: [] };
    assert.equal((await auditPage(app, { within, actors: [MEMBER], detail: false, limit: 5 })).rows.length, 5);
  },
  indexes: ['audit_log_shown_actor_idx'],
}));

// A place's page (`?path=`, and every page of a project's reader, `within`) with no actor, its entries the oldest:
// through its own indexes (`audit_log_project_idx`, a bitmap of it and `audit_log_also_project_idx`), as on main,
// never back through everything pages show (`audit_log_shown_idx`), which passes every other place's entries since:
// 8 pages 2,000 entries in, 2,267 at 20,000 (`?path=market`, the sweep of #559 before `shownOffIndex`). In a log led
// by heartbeats, one entry in ten shown: main's condition, which keeps the action's statistics, reads 6 pages; an
// expression in its place (`action || ''`) priced the page as if most were shown and walked the primary key back,
// 7,802 pages at 240,000 entries (Fable r2 of #559). A place behind its own detail entries is T254's.
test("a project's audit page in a log of heartbeats, behind every other place's entries shown since (`auditPage`, `?path=`): its own entries' steps", { timeout: 600_000 }, () => holdsFlat(db.owner, {
  grow: async (owner, size) => {
    await append(owner, { author: 'app', action: 'secret.write', count: 22, actor: `user:${ROOT}`, project: keys[0]!.project });
    // Six times the size, 240,000 entries in all at the larger, one in ten shown: another place's reads and reads of
    // no place, then the scheduler's heartbeats.
    await append(owner, { author: 'vault', action: 'secret.read', count: (size * 3) / 10, actor: OTHER, project: shop });
    await append(owner, { author: 'vault', action: 'secret.read', count: (size * 3) / 10, actor: OTHER });
    await append(owner, { author: 'app', action: 'audit.heartbeat', count: (size * 27) / 5, actor: SCHEDULER });
  },
  ask: async (app) => {
    assert.equal((await auditPage(app, { projectId: keys[0]!.project, detail: false, limit: 100 })).rows.length, 22);
    // A project's reader's page, the same entries (`within`).
    assert.equal((await auditPage(app, { within: { projectIds: [keys[0]!.project], environmentIds: [] }, detail: false, limit: 100 })).rows.length, 22);
  },
  indexes: ['audit_log_project_idx'],
}));

test("a page's count of what it hides, with nothing older to show (`auditActionCounts`): of `HIDDEN_COUNTED` at most, whatever its filter, and whether there were more", { timeout: 600_000 }, () => holdsFlat(db.owner, {
  grow: async (owner, size) => append(owner, { author: 'app', action: 'audit.heartbeat', count: size }),
  ask: async (app, size) => {
    // Past `HIDDEN_COUNTED` (SQLite's smaller size is not), the count stops there and says there were more.
    const more = size > HIDDEN_COUNTED;
    assert.deepEqual(await auditActionCounts(app, { detail: false, limit: 100 }), { counts: [{ action: 'audit.heartbeat', count: Math.min(size, HIDDEN_COUNTED) }], more });
    // A project's page and a page of refusals, which none of them is: as many weighed, none counted.
    assert.deepEqual(await auditActionCounts(app, { projectId: keys[0]!.project, detail: false, limit: 100 }), { counts: [], more });
    assert.deepEqual(await auditActionCounts(app, { decision: 'deny', detail: false, limit: 100 }), { counts: [], more });
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
