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
/** Another environment of market's, and two other projects' keys: the places beside a page's own. */
let prod: string;
let other: { id: string; environment: string; project: string };
let shop: { id: string; environment: string; project: string };
before(async () => {
  db = await openTestDatabase();
  await resetDatabase(db.owner);
  const root = clientFor(testDeps(db.runtime, [ROOT]), ROOT);
  await root.projects.create('market', { name: 'Market' });
  await root.environments.create('market/dev', { name: 'dev' });
  await root.secrets.set('market/dev', { A: 'fake-a', B: 'fake-b', C: 'fake-c' });
  await root.environments.create('market/prod', { name: 'prod' });
  await root.projects.create('other', { name: 'Other' });
  await root.environments.create('other/dev', { name: 'dev' });
  await root.secrets.set('other/dev', { X: 'fake-x' });
  await root.projects.create('shop', { name: 'Shop' });
  await root.environments.create('shop/dev', { name: 'dev' });
  await root.secrets.set('shop/dev', { S: 'fake-s' });
  const rows = await rowsOf<{ id: string; version: string; environment: string; project: string; key: string; slug: string }>(db.owner, sql`
    SELECT CAST(s.id AS text) AS id, CAST(s.current_version_id AS text) AS version, CAST(s.environment_id AS text) AS environment,
      CAST(s.project_id AS text) AS project, s.key, p.slug FROM secrets s JOIN projects p ON p.id = s.project_id ORDER BY s.key`);
  keys = rows.filter((row) => row.slug === 'market').map(({ id, version, environment, project }) => ({ id, version, environment, project }));
  other = rows.find((row) => row.slug === 'other')!;
  shop = rows.find((row) => row.slug === 'shop')!;
  [{ id: prod }] = await rowsOf<{ id: string }>(db.owner, sql`SELECT CAST(e.id AS text) AS id FROM environments e JOIN projects p ON p.id = e.project_id WHERE p.slug = 'market' AND e.slug = 'prod'`) as [{ id: string }];
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

// A place's page (`auditPage`, `?path=`), behind what it hides of its own and the entries shown about the places beside
// it (T254): five entries it shows, then, newer, `size` detail entries about the place itself, and `size` shown entries
// about each place beside it (another key of its environment, another environment of its project, another project),
// so that a walk of the place's own entries, or of every entry shown, grows with one or the other.
type Place = Omit<Parameters<typeof append>[1], 'count' | 'author' | 'action'>;
const PLACE_SHOWN = 5;
/**
 * 0.14's reads of several keys at a key's environment, none listing it (`LISTED_READS`): as many at either size, the
 * one exemption from growth here, and for these rows alone. No index can key a list, so a key's page reads every one
 * between its newest entries; and this release writes none once its vault serves 0.15's uses, which every request of a
 * deployment's comes in on (docs/history-sweep.md, T255): how many there are is fixed once a deployment runs it.
 */
const LEGACY_READS = 2_000;
for (const [name, filter, place, beside, indexes, legacy] of [
  ["a project's page, behind its own `mcp.read` entries and another project's writes", () => ({ projectId: keys[0]!.project }),
    (): Place => ({ project: keys[0]!.project }),
    (): Place[] => [{ project: other.project, environment: other.environment, secret: other.id }],
    ['audit_log_project_shown_idx', 'audit_log_also_project_shown_idx'], false],
  ["an environment's page, behind its own detail and its project's other environment's writes", () => ({ projectId: keys[0]!.project, environmentId: keys[0]!.environment }),
    (): Place => ({ project: keys[0]!.project, environment: keys[0]!.environment }),
    (): Place[] => [{ project: keys[0]!.project, environment: prod }, { project: other.project, environment: other.environment, secret: other.id }],
    ['audit_log_environment_shown_idx', 'audit_log_also_environment_shown_idx'], false],
  ["a key's page, behind its own rewraps, its environment's other keys' writes and 0.14's reads of them (`LEGACY_READS`)", () => ({ projectId: keys[0]!.project, environmentId: keys[0]!.environment, secretId: keys[0]!.id }),
    (): Place => ({ project: keys[0]!.project, environment: keys[0]!.environment, secret: keys[0]!.id }),
    (): Place[] => [{ project: keys[1]!.project, environment: keys[1]!.environment, secret: keys[1]!.id }, { project: keys[0]!.project, environment: prod }],
    ['audit_log_secret_shown_idx', 'audit_log_also_secret_shown_idx', 'audit_log_listed_idx', 'audit_log_listed_also_idx'], true],
] as const) {
  test(`${name} (\`auditPage\`): a step of each of its streams`, { timeout: 600_000 }, () => holdsFlat(db.owner, {
    grow: async (owner, size) => {
      await append(owner, { ...place(), author: 'app', action: 'secret.write', actor: `user:${ROOT}`, count: PLACE_SHOWN });
      if (legacy) {
        await append(owner, { author: 'vault', action: 'secret.read', actor: `user:${ROOT}`, count: LEGACY_READS, project: keys[0]!.project, environment: keys[0]!.environment,
          metadata: JSON.stringify({ secrets: [{ secretId: keys[1]!.id }, { secretId: keys[2]!.id }] }) });
      }
      await append(owner, { ...place(), author: 'app', action: 'mcp.read', actor: `user:${ROOT}`, count: size / 2 });
      await append(owner, { ...place(), author: 'vault', action: 'key.rewrap', count: size / 2 });
      for (const at of beside()) await append(owner, { ...at, author: 'app', action: 'secret.write', actor: `user:${ROOT}`, count: size });
    },
    ask: async (app) => assert.equal((await auditPage(app, { ...filter(), excludeActions: DETAIL_ACTIONS, limit: PLACE_SHOWN })).rows.length, PLACE_SHOWN),
    indexes: [...indexes],
  }));
}

test("a key's page behind the ends of its environment's other references, which name the environment besides (`auditPage`; Sol r1 of #562): a step of its streams", { timeout: 600_000 }, () => holdsFlat(db.owner, {
  // Its five: three writes, and two of 0.14's reads of several keys through references held in shop, which name its
  // environment besides (`also`) and list it as a holder's; 0.14's reads of several keys elsewhere, as many at either
  // size, and on Postgres enough that the index of all such reads is no shortcut (Sol's 100,000); then, newer, the ends of shop's references to B, its environment's other key, which name the environment
  // besides too. The stream of the reads naming it besides read the index of every shown entry naming it so, past each
  // end: 293 buffers to 2,781 at 4,000 and 40,000 of them.
  grow: async (owner, size) => {
    const [a, b] = keys;
    await append(owner, { author: 'app', action: 'secret.write', actor: `user:${ROOT}`, count: 3, project: a!.project, environment: a!.environment, secret: a!.id });
    await append(owner, { author: 'vault', action: 'secret.read', actor: `user:${ROOT}`, count: 2, project: shop.project, environment: shop.environment,
      metadata: JSON.stringify({ also: { projectId: a!.project, environmentId: a!.environment }, secrets: [{ secretId: shop.id, also: { secretId: a!.id } }] }) });
    await append(owner, { author: 'vault', action: 'secret.read', actor: `user:${ROOT}`, count: TEST_ENGINE === 'postgres' ? 100_000 : LEGACY_READS, project: other.project, environment: other.environment,
      metadata: JSON.stringify({ secrets: [{ secretId: other.id }] }) });
    await append(owner, { author: 'vault', action: 'reference.end', count: size, project: shop.project, environment: shop.environment, secret: shop.id,
      metadata: JSON.stringify({ also: { projectId: b!.project, environmentId: b!.environment, secretId: b!.id } }) });
  },
  ask: async (app) => {
    const page = await auditPage(app, { projectId: keys[0]!.project, environmentId: keys[0]!.environment, secretId: keys[0]!.id, excludeActions: DETAIL_ACTIONS, limit: 100 });
    assert.deepEqual([page.rows.length, page.more], [PLACE_SHOWN, false]);
  },
  indexes: ['audit_log_secret_shown_idx', 'audit_log_listed_idx', 'audit_log_listed_also_idx'],
}));

test("a project's page behind every other place's entries shown since, and the heartbeats after (`auditPage`; W367's shape): a step of its streams", { timeout: 600_000 }, () => holdsFlat(db.owner, {
  // Its 22 shown entries, the oldest; then reads shown about another project and about no place; then heartbeats.
  // main walked `audit_log_pkey` back over all of it: 7,802 pages for its 22 at 240,000 entries (W367, A615).
  grow: async (owner, size) => {
    await append(owner, { author: 'app', action: 'secret.write', actor: `user:${ROOT}`, count: 22, project: keys[0]!.project });
    await append(owner, { author: 'app', action: 'secret.read', actor: OTHER, count: size * 3 / 8, project: other.project });
    await append(owner, { author: 'app', action: 'secret.read', actor: OTHER, count: size * 3 / 8 });
    await append(owner, { author: 'app', action: 'audit.heartbeat', actor: 'system:coffre-scheduler', count: size * 3 / 4 });
  },
  ask: async (app) => {
    const page = await auditPage(app, { projectId: keys[0]!.project, excludeActions: DETAIL_ACTIONS, limit: 100 });
    assert.deepEqual([page.rows.length, page.more], [22, false]);
  },
  indexes: ['audit_log_project_shown_idx'],
}));

// A log as deployments' are, heartbeat-led: a tenth of it shown (Fable r2 of #559). A place's and a reader's pages, their
// few shown entries the oldest, behind runs of a hundred others' shown entries and nine hundred heartbeats. An auditor of
// market alone, as `/audit` asks for them, a page of five and one with detail: main walked `audit_log_pkey` back over the
// whole log for either, 517 pages at 2,000 entries of each shape to 5,016 at 20,000, and 8 to 5,023 for detail's, its
// project's bitmap at the smaller size (W367's sweep12 of #559).
const SHOWN = { excludeActions: DETAIL_ACTIONS, limit: 100 };
const MARKET = () => ({ within: { projectIds: [keys[0]!.project], environmentIds: [] } });
for (const [name, filter, indexes] of [
  ["a project's page", () => ({ ...SHOWN, projectId: keys[0]!.project }), ['audit_log_project_shown_idx']],
  ["a key's page", () => ({ ...SHOWN, projectId: keys[0]!.project, environmentId: keys[0]!.environment, secretId: keys[0]!.id }), ['audit_log_secret_shown_idx']],
  ["a reader's page of market and of other/dev", () => ({ ...SHOWN, within: { projectIds: [keys[0]!.project], environmentIds: [other.environment] } }), ['audit_log_project_shown_idx', 'audit_log_environment_shown_idx']],
  ["an auditor of market's page of five (`/audit?limit=5`)", () => ({ ...MARKET(), excludeActions: DETAIL_ACTIONS, limit: PLACE_SHOWN }), ['audit_log_project_shown_idx']],
  ["an auditor of market's page with detail (`/audit?detail=1`)", () => ({ ...MARKET(), limit: 100 }), ['audit_log_project_idx']],
] as const) {
  test(`${name} in a log a tenth shown, heartbeats the rest (\`auditPage\`): a step of its streams`, { timeout: 600_000 }, () => holdsFlat(db.owner, {
    grow: async (owner, size) => {
      await append(owner, { author: 'app', action: 'secret.write', actor: `user:${ROOT}`, count: PLACE_SHOWN, project: keys[0]!.project, environment: keys[0]!.environment, secret: keys[0]!.id });
      for (let done = 0; done < size; done += 1_000) {
        await append(owner, { author: 'app', action: 'secret.write', actor: OTHER, count: 100, project: shop.project, environment: shop.environment, secret: shop.id });
        await append(owner, { author: 'app', action: 'audit.heartbeat', actor: 'system:coffre-scheduler', count: 900 });
      }
    },
    ask: async (app) => {
      const asked = filter();
      const page = await auditPage(app, asked);
      // A page of five is full, and may have more; one of a hundred holds all five.
      assert.deepEqual([page.rows.length, page.more], [PLACE_SHOWN, asked.limit === PLACE_SHOWN]);
    },
    indexes: [...indexes],
  }));
}

test("an environment's page among its own shown entries and detail, a decision asked (`auditPage`): a step of its streams, never all of its entries", { timeout: 600_000 }, () => holdsFlat(db.owner, {
  // As many of its own writes as detail, in runs of a thousand: what it shows is near, but every one of either a read
  // of all its entries would take, sorted.
  grow: async (owner, size) => {
    for (let done = 0; done < size; done += 1_000) {
      await append(owner, { author: 'app', action: 'secret.write', actor: `user:${ROOT}`, count: 1_000, project: keys[0]!.project, environment: keys[0]!.environment, secret: keys[0]!.id });
      await append(owner, { author: 'app', action: 'mcp.read', actor: `user:${ROOT}`, count: 1_000, project: keys[0]!.project, environment: keys[0]!.environment });
    }
  },
  ask: async (app) => {
    const at = { projectId: keys[0]!.project, environmentId: keys[0]!.environment, excludeActions: DETAIL_ACTIONS, limit: PLACE_SHOWN };
    assert.equal((await auditPage(app, at)).rows.length, PLACE_SHOWN);
    assert.equal((await auditPage(app, { ...at, decision: 'allow' })).rows.length, PLACE_SHOWN);
  },
  indexes: ['audit_log_environment_shown_idx'],
}));

test("a reader's page of their places, behind what it hides of them, the instance's entries and another project's (`auditPage`, `within`): a step of each place's streams", { timeout: 600_000 }, () => holdsFlat(db.owner, {
  // An auditor of market and of other/dev: what they read there, then each place's detail, and shown entries about no
  // place, the instance's, and about shop, neither of them theirs.
  grow: async (owner, size) => {
    await append(owner, { author: 'app', action: 'secret.write', actor: `user:${ROOT}`, count: 3, project: keys[0]!.project, environment: keys[0]!.environment, secret: keys[0]!.id });
    await append(owner, { author: 'app', action: 'secret.write', actor: `user:${ROOT}`, count: 2, project: other.project, environment: other.environment, secret: other.id });
    await append(owner, { author: 'app', action: 'mcp.read', actor: `user:${ROOT}`, count: size / 2, project: keys[0]!.project });
    await append(owner, { author: 'app', action: 'mcp.read', actor: `user:${ROOT}`, count: size / 2, project: other.project, environment: other.environment });
    await append(owner, { author: 'app', action: 'member.add', actor: `user:${ROOT}`, count: size });
    await append(owner, { author: 'app', action: 'secret.write', actor: `user:${ROOT}`, count: size, project: shop.project, environment: shop.environment, secret: shop.id });
  },
  ask: async (app) => {
    const page = await auditPage(app, { within: { projectIds: [keys[0]!.project], environmentIds: [other.environment] }, excludeActions: DETAIL_ACTIONS, limit: PLACE_SHOWN });
    assert.equal(page.rows.length, PLACE_SHOWN);
  },
  indexes: ['audit_log_project_shown_idx', 'audit_log_environment_shown_idx'],
}));

test('a page of refusals, behind what was allowed since and the refusals it hides (`auditPage`, `?decision=deny`): a step of their index', { timeout: 600_000 }, () => holdsFlat(db.owner, {
  grow: async (owner, size) => {
    await append(owner, { author: 'app', action: 'secret.write', decision: 'deny', code: 'forbidden', actor: `user:${ROOT}`, count: PLACE_SHOWN, project: keys[0]!.project });
    await append(owner, { author: 'app', action: 'sign_in', decision: 'deny', code: 'forbidden', actor: `user:${ROOT}`, count: size / 2 });
    await append(owner, { author: 'app', action: 'secret.write', actor: `user:${ROOT}`, count: size, project: other.project, environment: other.environment, secret: other.id });
  },
  ask: async (app) => assert.equal((await auditPage(app, { decision: 'deny', excludeActions: DETAIL_ACTIONS, limit: PLACE_SHOWN })).rows.length, PLACE_SHOWN),
  indexes: ['audit_log_denied_idx'],
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
