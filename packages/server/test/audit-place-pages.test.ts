// A place's audit page read as streams of its indexes (T254, `placeStreams`) lists what the filter alone does: every
// entry about the place by its column, by `also`, or, on a key's page, a read of several keys that lists it; once each,
// newest first, a page at a time to the end. Held to the filter written out here over the whole log, on a history of
// every shape interleaved, under each place, with and without detail, a decision, and a reader's scope.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';

import { rowsOf } from '@coffre/db/dialect';
import { DETAIL_ACTIONS } from '@coffre/db/log';
import { sql } from 'drizzle-orm';

import { auditPage, type AuditFilter } from '../src/db/queries.ts';
import { clientFor, openTestDatabase, resetDatabase, testDeps } from './api-fixture.ts';
import { append, emptyLogs, type Rows } from './db/growth.ts';

const ROOT = 'admin@acme.example';

let db: Awaited<ReturnType<typeof openTestDatabase>>;
type Key = { id: string; environment: string; project: string };
/** market/dev's A and B, market/prod's P, other/dev's X. */
let A: Key, B: Key, P: Key, X: Key;

before(async () => {
  db = await openTestDatabase();
  await resetDatabase(db.owner);
  const root = clientFor(testDeps(db.runtime, [ROOT]), ROOT);
  await root.projects.create('market', { name: 'Market' });
  for (const environment of ['dev', 'prod']) await root.environments.create(`market/${environment}`, { name: environment });
  await root.secrets.set('market/dev', { A: 'fake-a', B: 'fake-b' });
  await root.secrets.set('market/prod', { P: 'fake-p' });
  await root.projects.create('other', { name: 'Other' });
  await root.environments.create('other/dev', { name: 'dev' });
  await root.secrets.set('other/dev', { X: 'fake-x' });
  const keys = await rowsOf<Key & { key: string }>(db.owner, sql`
    SELECT s.key, CAST(s.id AS text) AS id, CAST(s.environment_id AS text) AS environment, CAST(s.project_id AS text) AS project FROM secrets s`);
  [A, B, P, X] = ['A', 'B', 'P', 'X'].map((name) => keys.find((key) => key.key === name)!) as unknown as [Key, Key, Key, Key];
  await emptyLogs(db.owner);
  await grow();
});
after(async () => {
  await resetDatabase(db.owner);
  await db.close();
});

const at = (key: Key, level: 'project' | 'environment' | 'secret' = 'secret') => ({
  project: key.project, environment: level === 'project' ? null : key.environment, secret: level === 'secret' ? key.id : null,
});
const also = (key: Key, level: 'project' | 'environment' | 'secret' = 'secret') => ({
  projectId: key.project, ...(level === 'project' ? {} : { environmentId: key.environment }), ...(level === 'secret' ? { secretId: key.id } : {}),
});

/** `also`s that name no place's uuid: no constraint holds the metadata to name one. */
const MALFORMED: unknown[] = [
  { projectId: 'not-a-uuid', environmentId: 42, secretId: { nested: 'x' } },
  { environmentId: '00000000-0000-0000-0000-00000000000g', secretId: null },
  'market/dev',
  7,
];

/** Every shape a place's page reads, by column, `also` or a list, shown or detail, allowed or refused, about each place. */
function shapes(): Omit<Rows, 'count'>[] {
  const read = { author: 'vault', action: 'secret.read' } as const;
  return [
    { author: 'app', action: 'secret.write', ...at(A) },
    { author: 'app', action: 'secret.write', decision: 'deny', code: 'forbidden', ...at(B) },
    { author: 'app', action: 'environment.update', ...at(A, 'environment') },
    { author: 'app', action: 'project.update', ...at(A, 'project') },
    { author: 'app', action: 'secret.write', ...at(P) },
    { author: 'app', action: 'secret.write', ...at(X) },
    { author: 'app', action: 'member.add' },
    // What a page hides, about each place.
    { author: 'app', action: 'mcp.read', ...at(A) },
    { author: 'app', action: 'mcp.read', ...at(A, 'project') },
    { author: 'vault', action: 'key.rewrap', ...at(B) },
    // A read through other/dev's reference to A: at X, A besides; and one about A on both sides, which two streams hold.
    { ...read, ...at(X), metadata: JSON.stringify({ also: also(A) }) },
    { ...read, ...at(A), metadata: JSON.stringify({ also: also(A) }) },
    { ...read, decision: 'deny', code: 'forbidden', ...at(X), metadata: JSON.stringify({ also: also(A, 'environment') }) },
    { author: 'vault', action: 'reference.create', ...at(X), metadata: JSON.stringify({ also: also(A) }) },
    { author: 'app', action: 'secret.write', ...at(X), metadata: JSON.stringify({ also: also(P, 'project') }) },
    // `also` as a use's list (`key.wrap`'s), naming no place.
    { author: 'vault', action: 'key.wrap', ...at(A), metadata: JSON.stringify({ also: [{ use: 1 }] }) },
    // And `also`s naming no uuid, which nothing refuses: the indexes keyed by `also` (`besideKey`) take them, as text.
    ...MALFORMED.map((besides) => ({ author: 'app', action: 'secret.write', ...at(A), metadata: JSON.stringify({ also: besides }) }) as const),
    // Reads of several keys (`readsByPlace`): at dev, listing A, or B alone; and at other/dev through dev's references,
    // dev besides, its keys listed with the holder each read through.
    { ...read, ...at(A, 'environment'), metadata: JSON.stringify({ secrets: [{ secretId: A.id }, { secretId: B.id }] }) },
    { ...read, ...at(A, 'environment'), metadata: JSON.stringify({ secrets: [{ secretId: B.id }] }) },
    { ...read, ...at(X, 'environment'), metadata: JSON.stringify({ also: also(A, 'environment'), secrets: [{ secretId: X.id, also: { secretId: A.id } }] }) },
    { ...read, decision: 'deny', code: 'forbidden', ...at(X, 'environment'), metadata: JSON.stringify({ also: also(B, 'environment'), secrets: [{ secretId: X.id, also: { secretId: B.id } }] }) },
  ];
}

/** Thirty rounds of every shape, each round in an order of its own, in runs of one to three: every shape before and after every other. */
async function grow(): Promise<void> {
  const all = shapes();
  let seed = 254;
  // The high bits of a linear congruential draw, whose low bits repeat.
  const draw = (n: number) => {
    seed = (seed * 1_103_515_245 + 12_345) % 2_147_483_648;
    return Math.floor(seed / 65_536) % n;
  };
  for (let round = 0; round < 30; round += 1) {
    const order = all.map((shape) => ({ shape, at: draw(1_000) })).sort((x, y) => x.at - y.at);
    for (const { shape } of order) await append(db.owner, { actor: `user:${ROOT}`, ...shape, count: 1 + draw(3) });
  }
}

type Entry = { seq: bigint; action: string; decision: string; project: string | null; environment: string | null; secret: string | null; metadata: string };
type Place = 'projectId' | 'environmentId' | 'secretId';

/** The filter as the page's condition says it (`auditWhere`), over every entry. */
function matches(entry: Entry, filter: Omit<AuditFilter, 'limit'>): boolean {
  const metadata = JSON.parse(entry.metadata) as { also?: unknown; secrets?: { secretId?: string; also?: { secretId?: string } }[] };
  const besides = typeof metadata.also === 'object' && metadata.also !== null && !Array.isArray(metadata.also) ? metadata.also as Partial<Record<Place, string>> : {};
  const column = { projectId: entry.project, environmentId: entry.environment, secretId: entry.secret };
  const about = (place: Place, ids: readonly string[]) => ids.some((id) => column[place] === id || besides[place] === id);
  const listed = (id: string) => entry.action === 'secret.read' && entry.secret === null && (metadata.secrets ?? []).some((one) => one.secretId === id || one.also?.secretId === id);
  const { within } = filter;
  return (within === undefined || about('projectId', within.projectIds) || about('environmentId', within.environmentIds))
    && (within?.except === undefined || (!within.except.includes(entry.environment!) && !within.except.includes(besides.environmentId!)))
    && (filter.projectId === undefined || about('projectId', [filter.projectId]))
    && (filter.environmentId === undefined || about('environmentId', [filter.environmentId]))
    && (filter.secretId === undefined || about('secretId', [filter.secretId]) || listed(filter.secretId))
    && (filter.decision === undefined || entry.decision === filter.decision)
    && (filter.excludeActions === undefined || !filter.excludeActions.includes(entry.action));
}

const places = (): [string, Omit<AuditFilter, 'limit'>][] => [
  ['no place', {}],
  ['market', { projectId: A.project }],
  ['market/dev', { projectId: A.project, environmentId: A.environment }],
  ['market/dev/A', { projectId: A.project, environmentId: A.environment, secretId: A.id }],
  ['market/dev/B', { projectId: B.project, environmentId: B.environment, secretId: B.id }],
  ['market/prod', { projectId: P.project, environmentId: P.environment }],
  ['other', { projectId: X.project }],
  ['other/dev/X', { projectId: X.project, environmentId: X.environment, secretId: X.id }],
];
const scopes = (): [string, AuditFilter['within']][] => [
  ['the whole log', undefined],
  ['market but prod', { projectIds: [A.project], environmentIds: [], except: [P.environment] }],
  ['market/dev and other/dev', { projectIds: [], environmentIds: [A.environment, X.environment] }],
];

test("a place's page lists what its filter matches, once each, newest first, a page at a time to the end", { timeout: 300_000 }, async () => {
  const entries = (await rowsOf<Entry>(db.owner, sql`
    SELECT seq, action, decision, CAST(project_id AS text) AS project, CAST(environment_id AS text) AS environment, CAST(secret_id AS text) AS secret, metadata
      FROM audit_log ORDER BY seq DESC`)).map((entry) => ({ ...entry, seq: BigInt(entry.seq) }));
  let asked = 0;
  for (const [place, where] of places()) {
    for (const [scope, within] of scopes()) {
      for (const detail of [false, true]) {
        for (const decision of [undefined, 'deny', 'allow']) {
          const filter: Omit<AuditFilter, 'limit'> = { ...where, within, decision, excludeActions: detail ? undefined : DETAIL_ACTIONS };
          const expected = entries.filter((entry) => matches(entry, filter)).map((entry) => entry.seq);
          const listed: bigint[] = [];
          for (let beforeSeq: bigint | undefined, more = true; more;) {
            const page = await auditPage(db.runtime, { ...filter, beforeSeq, limit: 7 });
            listed.push(...page.rows.map((row) => row.seq));
            more = page.more;
            beforeSeq = page.rows.at(-1)?.seq;
            if (page.rows.length === 0) break;
          }
          const name = `${place} in ${scope}${detail ? ', with detail' : ''}${decision === undefined ? '' : `, ${decision}`}`;
          assert.deepEqual(listed, expected, name);
          asked += 1;
        }
      }
    }
  }
  assert.equal(asked, 8 * 3 * 2 * 3);
  // The history holds what the pages tell apart: one entry about A on both sides of a reference, listed reads of A's.
  const ofA = entries.filter((entry) => matches(entry, { secretId: A.id, environmentId: A.environment, projectId: A.project }));
  assert.ok(ofA.some((entry) => entry.secret === A.id && entry.metadata.includes(A.id)), 'an entry about A in its column and besides');
  assert.ok(ofA.some((entry) => entry.secret === null && entry.environment === X.environment), "a read of several keys through dev's reference, at other/dev");
});

test('an entry whose `also` names no uuid is written, its insert intact, and read by its place', async () => {
  const before = await rowsOf<{ n: number }>(db.owner, sql`SELECT CAST(count(*) AS integer) AS n FROM audit_log`);
  for (const besides of MALFORMED) {
    await append(db.owner, { actor: `user:${ROOT}`, author: 'app', action: 'secret.write', ...at(X), metadata: JSON.stringify({ also: besides }), count: 1 });
  }
  const written = await rowsOf<{ seq: bigint }>(db.owner, sql`SELECT seq FROM audit_log ORDER BY seq DESC LIMIT ${MALFORMED.length}`);
  const [{ n }] = await rowsOf<{ n: number }>(db.owner, sql`SELECT CAST(count(*) AS integer) AS n FROM audit_log`);
  assert.equal(n, before[0].n + MALFORMED.length);
  // X's page, through the streams by its column and by `also`, lists them; A's page, which none names, does not.
  const ofX = await auditPage(db.runtime, { projectId: X.project, environmentId: X.environment, secretId: X.id, excludeActions: DETAIL_ACTIONS, limit: MALFORMED.length });
  assert.deepEqual(ofX.rows.map((row) => BigInt(row.seq)), written.map((row) => BigInt(row.seq)));
  const ofA = await auditPage(db.runtime, { projectId: A.project, environmentId: A.environment, secretId: A.id, excludeActions: DETAIL_ACTIONS, limit: 50 });
  assert.ok(ofA.rows.every((row) => !written.some((one) => BigInt(one.seq) === BigInt(row.seq))));
});
