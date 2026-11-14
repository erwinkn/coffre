// The audit page on the 0.16 log (docs/design/0.16.md, "The log's head, when
// asked", and "Pages"): entries the vault wrote, signed by the real signer,
// each proven from the tiles against the head the vault vouched for in the
// page's own call; one past that head not proven, one edited failed, and a
// deleted one a hole on a page of the whole log, which a filtered page cannot
// see. Who reads what follows 0.14.7: the whole log to whoever reads it all,
// else the entries of the places they hold audit.read at.
import assert from 'node:assert/strict';
import { after, beforeEach, test } from 'node:test';

import type { Queryable } from '@coffre/db';
import { rowsOf } from '@coffre/db/dialect';
import { sql } from 'drizzle-orm';

import { credential, emptyDatabase, environment, grant, instance, principal, project, role, rows, signerOf, user, write } from '@coffre/vault/testing';

import { holesOf } from '../src/api/audit.ts';
import { logStretch, stretchOf } from '../src/db/queries/audit.ts';
import { openApp } from './app-fixture.ts';

const app = await openApp();
const { world } = app;
after(() => app.close());

const [ada, al, aud, bo, cy, ed] = ['ada', 'al', 'aud', 'bo', 'cy', 'ed'].map(user) as [string, string, string, string, string, string];

type Entry = { seq: number; action: string; decision: string; reason: string | null; actorId: string; project: string | null; environment: string | null; key: string | null; version: number | null; detail: boolean; proof: string; token: { id: string; label: string } | null };
type Page = { entries: Entry[]; more: boolean; next: number | null; hidden?: { action: string; count: number }[]; head: { size: number; signedAt: string } | null; holes: { above: number | null; below: number | null; kept: number; aging: number }[] | null };
type Body = { error?: string; reason?: string; message?: string } & Record<string, unknown>;

const call = async (label: string, method: string, path: string, body?: unknown): Promise<[number, Body]> => {
  const got = await app.request(`/api${path}`, { method, headers: { authorization: `Bearer ${label}` }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  return [got.status, (await got.json()) as Body];
};
/** A page, with what it asked of the vault and how many statements it ran. */
async function page(label: string, query = ''): Promise<[Page, string[], number]> {
  const [calls, statements] = [app.calls.length, app.statements];
  const [status, body] = await call(label, 'GET', `/audit${query}`);
  assert.equal(status, 200, JSON.stringify(body));
  return [body as unknown as Page, app.calls.slice(calls), app.statements - statements];
}
/** Each entry as `action place proof`. */
const brief = (listed: Page) => listed.entries.map((entry) => `${entry.action} ${[entry.project, entry.environment, entry.key].filter((part) => part !== null).join('/')} ${entry.proof}`.replace('  ', ' '));
const log = async () => rowsOf<{ seq: number; kept: boolean; leaf: number; action: string }>(world.owner, sql`SELECT seq::float8 AS seq, kept, leaf::float8 AS leaf, body::jsonb ->> 'action' AS action FROM log ORDER BY seq DESC`);

let sign: () => Promise<void>;
/**
 * market: prod, staging (protected), dev. billing: prod.
 *
 * Cy owns the instance; Aud is an Auditor, who reads the whole log. Al is
 * an Admin scoped to market. Bo leads market, which reads its log but in
 * a protected environment; Ed watches market/dev alone, its secrets and
 * its log. Ada views market,
 * and reads no log.
 *
 * The log, oldest first: shop made, market/qa made, market filed in a
 * folder (an entry about the project alone), market/dev's API_KEY
 * and staging's TOKEN written, billing/prod's X written, a token made for
 * ci, who views billing (a detail entry), Bo's reveal of API_KEY (a use, which ages out), and
 * Ada's refused attempt at a project (a refusal ages out too). Before
 * them all, the rows the test wrote, one entry of `write`'s.
 */
beforeEach(async () => {
  await emptyDatabase(world.owner);
  for (const kept of [world.memory.reads, world.memory.callers, world.memory.logged, world.memory.touched, world.refused]) kept.clear();
  world.woken.length = 0;
  ({ sign } = await signerOf(world));
  const [market, billing] = [project('market'), project('billing')];
  const dev = environment(market, 'dev');
  await write(
    world,
    ...rows('projects', market, billing),
    ...rows('environments', environment(market, 'prod'), environment(market, 'staging', { protected: true }), dev, environment(billing, 'prod')),
    ...rows('roles',
      role(false, 'viewer', ['secret.read'], []),
      role(false, 'lead', ['secret.read', 'secret.write', 'environment.manage', 'audit.read'], []),
      role(false, 'watcher', ['secret.read', 'audit.read'], []),
      role(true, 'owner', ['secret.read', 'secret.write', 'environment.manage', 'project.manage', 'grant.manage', 'audit.read']),
      role(true, 'admin', ['secret.read', 'secret.write', 'environment.manage', 'project.manage', 'grant.manage', 'audit.read']),
      role(true, 'auditor', ['audit.read']),
      role(true, 'member', [])),
    ...rows('principals', principal(ada), principal(al, { role: 'admin', scope: JSON.stringify({ projects: { only: [market.id] }, environments: 'all' }) }), principal(aud, { role: 'auditor' }), principal(bo), principal(cy, { role: 'owner' }), principal(ed), principal('token:ci')),
    ...rows('policy', instance()),
    ...rows('grants', grant(ada, 'viewer', { project: market }), grant(bo, 'lead', { project: market }), grant('token:ci', 'viewer', { project: billing }), grant(ed, 'watcher', { environment: dev })),
    ...rows('credentials', ...[ada, al, aud, bo, cy, ed].map((who) => credential(`${who.slice(5, who.indexOf('@'))}-cli`, who))),
  );
  for (const [label, method, path, body] of [
    ['cy-cli', 'PUT', '/projects/shop', { name: 'Shop' }],
    ['cy-cli', 'PUT', '/projects/market/qa', {}],
    ['cy-cli', 'PATCH', '/projects/market', { folder: 'apps' }],
    ['cy-cli', 'PATCH', '/secrets/market/dev', { API_KEY: 'v1' }],
    ['cy-cli', 'PATCH', '/secrets/market/staging', { TOKEN: 's1' }],
    ['cy-cli', 'PATCH', '/secrets/billing/prod', { X: 'x1' }],
    ['cy-cli', 'POST', '/members/token:ci/tokens', { label: 'deploy', expiresInDays: 1 }],
    ['bo-cli', 'POST', '/reveals', { path: 'market/dev/API_KEY' }],
  ] as const) {
    const [status, answer] = await call(label, method, path, body);
    assert.equal(status, 200, `${method} ${path}: ${JSON.stringify(answer)}`);
  }
  assert.equal((await call('ada-cli', 'PUT', '/projects/nope', {}))[0], 403);
  await sign();
  app.calls.length = 0;
});

const ALL = [
  'project.create proven',
  'secret.read market/dev/API_KEY proven',
  'secret.write billing/prod/X proven',
  'secret.write market/staging/TOKEN proven',
  'secret.write market/dev/API_KEY proven',
  'project.move market proven',
  'environment.create market/qa proven',
  'project.create shop proven',
  // The rows the test wrote, logged as one entry.
  'test.write proven',
];

test('the whole log, newest first, each entry proven against the head the vault signed: one call to the vault, two statements', async () => {
  const [listed, calls, statements] = await page('aud-cli');
  assert.deepEqual(brief(listed), ALL);
  assert.deepEqual([calls, statements], [['caller'], 2], 'the caller with the head, then the stretch, then its tiles and names');
  assert.equal(listed.head?.size, 10);
  assert.deepEqual(listed.holes, []);
  assert.deepEqual(listed.hidden, [{ action: 'token.create', count: 1 }]);
  assert.deepEqual([listed.more, listed.next], [false, null]);
  // Ada's refusal ages out with the uses, and says why; Bo's read names the key and its version.
  const [refusal, read] = listed.entries;
  assert.deepEqual([refusal!.decision, refusal!.reason, refusal!.actorId], ['deny', 'no_access', 'ada@acme.example']);
  assert.deepEqual([read!.actorId, read!.key, read!.version], ['bo@acme.example', 'API_KEY', 1]);
  assert.deepEqual(brief((await page('aud-cli', '?decision=deny'))[0]), ['project.create proven']);
  // With the detail, the token's making too, and nothing hidden.
  const [detailed] = await page('aud-cli', '?detail=1');
  assert.deepEqual(detailed.entries.map((entry) => entry.action).slice(0, 3), ['project.create', 'secret.read', 'token.create']);
  assert.equal(detailed.hidden, undefined);
});

test('an entry past the head is not proven: an older head put back leaves the newest outside it, and no head leaves every one', async () => {
  const [old] = await rowsOf<Record<string, unknown>>(world.owner, sql`SELECT * FROM log_head`);
  assert.equal((await call('cy-cli', 'PATCH', '/secrets/market/prod', { LATE: 'l1' }))[0], 200);
  await sign();
  assert.deepEqual(brief((await page('aud-cli'))[0]).slice(0, 2), ['secret.write market/prod/LATE proven', 'project.create proven']);
  // The head that covered what came before, whole, its MAC with it: the vault answers it, and the newest stands past it.
  await world.owner.execute(sql`UPDATE log_head SET size = ${old!.size}, kept_size = ${old!.kept_size}, kept_root = ${old!.kept_root}, aging_size = ${old!.aging_size}, aging_root = ${old!.aging_root}, aging_from = ${old!.aging_from}, signed_at = ${old!.signed_at}, mac = ${old!.mac}`);
  const [stale] = await page('aud-cli');
  assert.deepEqual(brief(stale), ['secret.write market/prod/LATE unproven', ...ALL]);
  assert.deepEqual([stale.head?.size, stale.holes], [10, []], 'past the head is outside it: no hole');
  // No head under the vault's keys: nothing proves, and nothing is missing that the page could know of.
  await world.owner.execute(sql`DELETE FROM log_head`);
  const [none] = await page('aud-cli');
  assert.ok(none.entries.every((entry) => entry.proof === 'unproven'));
  assert.deepEqual([none.head, none.holes], [null, null]);
});

test('an entry edited within the head fails its proof, and so does one whose tiles a writer cut', async () => {
  await world.owner.execute(sql`UPDATE log SET body = replace(body, '"slug":"shop"', '"slug":"shoq"') WHERE body LIKE '%"action":"project.create"%' AND kept`);
  const [edited] = await page('aud-cli');
  assert.deepEqual(brief(edited), [...ALL.slice(0, -2), 'project.create shop failed', ALL.at(-1)]);
  // A time no date holds does not take the page down: the entry shows, with none, and fails.
  await world.owner.execute(sql`UPDATE log SET body = regexp_replace(body, '"at":[0-9.e+]+', '"at":100000000000000000000') WHERE body LIKE '%"action":"project.create"%' AND kept`);
  const [timeless] = await page('aud-cli');
  const created = timeless.entries.find((entry) => entry.action === 'project.create' && entry.decision === 'allow')!;
  assert.deepEqual([(created as Entry & { occurredAt: string }).occurredAt, created.proof], ['', 'failed']);
  // Nor does an action or an actor a writer made an object no string can be made of: the entry shows, with none, and fails.
  await world.owner.execute(sql`UPDATE log SET body = replace(replace(body, '"action":"project.create"', '"action":{"toString":null}'), '"actor":"', '"actor":{"toString":null},"was":"') WHERE body LIKE '%"slug":"shoq"%' AND kept`);
  const [actionless] = await page('aud-cli');
  assert.deepEqual(actionless.entries.filter((entry) => entry.action === '').map((entry) => entry.proof), ['failed']);
  assert.equal((await page('aud-cli', '?actor=cy@acme.example'))[0].entries.every((entry) => entry.action !== ''), true);
  await world.owner.execute(sql`DELETE FROM log_tiles WHERE NOT kept`);
  // The aging tree holds two entries, which prove from one another's leaf in the lowest tile: gone, neither proves.
  assert.deepEqual((await page('aud-cli'))[0].entries.slice(0, 2).map((entry) => entry.proof), ['failed', 'failed']);
});

test("an entry moved past its own tree but within the other fails: its tree and leaf are columns a writer edits, and no entry the head numbered stands there", async () => {
  const [{ keptSize }] = (await rowsOf<{ keptSize: number }>(world.owner, sql`SELECT kept_size::float8 AS "keptSize" FROM log_head`)) as [{ keptSize: number }];
  const [refusal, read] = (await log()).map(({ seq }) => seq) as [number, number];
  // Ada's refusal, a use, its reason edited and filed as the kept tree's next: past that tree, within the uses'.
  await world.owner.execute(sql`UPDATE log SET body = replace(body, '"no_access"', '"bulk_limit"'), kept = true, leaf = ${keptSize} WHERE seq = ${refusal}`);
  const [moved] = await page('aud-cli');
  assert.deepEqual([moved.entries[0]!.reason, moved.entries[0]!.proof], ['bulk_limit', 'failed']);
  // Where it stood, the uses' tree lacks one.
  assert.deepEqual(moved.holes, [{ above: null, below: read, kept: 0, aging: 1 }]);
  // Numbered past the head too, it stands where one signed since would: the page cannot tell, and says so; the hole stays.
  await world.owner.execute(sql`UPDATE log SET seq = ${refusal + 1} WHERE seq = ${refusal}`);
  const [past] = await page('aud-cli');
  assert.deepEqual([past.entries[0]!.reason, past.entries[0]!.proof], ['bulk_limit', 'unproven']);
  assert.deepEqual(past.holes, [{ above: null, below: read, kept: 0, aging: 1 }]);
});

test('a deleted entry is a hole on a page of the whole log, by tree; a filtered page cannot see it', async () => {
  const entries = await log();
  const written = entries.find((entry) => entry.action === 'secret.write' && entry.kept)!;
  await world.owner.execute(sql`DELETE FROM log WHERE seq = ${written.seq}`);
  const [listed] = await page('aud-cli');
  assert.deepEqual(listed.holes, [{ above: written.seq + 1, below: written.seq - 1, kept: 1, aging: 0 }]);
  assert.equal(listed.entries.length, ALL.length - 1);
  // The newest of each tree goes too: the head says how many there were.
  await world.owner.execute(sql`DELETE FROM log WHERE seq = ${entries[0]!.seq}`);
  assert.deepEqual((await page('aud-cli'))[0].holes, [{ above: null, below: entries[1]!.seq, kept: 0, aging: 1 }, { above: written.seq + 1, below: written.seq - 1, kept: 1, aging: 0 }]);
  // The first: the log's start.
  await world.owner.execute(sql`DELETE FROM log WHERE seq = 0`);
  assert.deepEqual((await page('aud-cli'))[0].holes?.at(-1), { above: 1, below: null, kept: 1, aging: 0 });
  // By a path or an actor the page reads the index, and says nothing of what is not there.
  assert.equal((await page('aud-cli', '?path=market'))[0].holes, null);
  assert.equal((await page('aud-cli', '?actor=cy@acme.example'))[0].holes, null);
});

test('pages tile the log: each goes on from the last, a hole at the edge between two is found on the second', async () => {
  const seen: string[] = [];
  let next: number | null = null;
  let pages = 0;
  do {
    const [listed]: [Page, string[], number] = await page('aud-cli', `?limit=2${next === null ? '' : `&before=${next}`}`);
    seen.push(...brief(listed));
    assert.deepEqual(listed.holes, []);
    next = listed.next;
    pages += 1;
  } while (next !== null && pages < 20);
  assert.deepEqual(seen, ALL);
  assert.equal(pages, 5);
  // A filtered page goes on below its last too, and shows none twice.
  const filtered: string[] = [];
  next = null;
  do {
    const [listed]: [Page, string[], number] = await page('bo-cli', `?path=market&limit=1${next === null ? '' : `&before=${next}`}`);
    filtered.push(...brief(listed));
    next = listed.next;
  } while (next !== null && filtered.length < 20);
  assert.deepEqual(filtered, brief((await page('bo-cli', '?path=market'))[0]));
  // An entry two of a reader's places name (Bo's read: market and market/dev) comes once, and costs its page no other.
  const scoped: string[] = [];
  next = null;
  do {
    const [listed]: [Page, string[], number] = await page('al-cli', `?limit=1${next === null ? '' : `&before=${next}`}`);
    scoped.push(...brief(listed));
    next = listed.next;
  } while (next !== null && scoped.length < 20);
  assert.deepEqual(scoped, brief((await page('al-cli'))[0]));
  // A stretch that reached the log's first entry is its end, filtered or not; and 0, below which nothing is, is a cursor.
  const [denied] = await page('aud-cli', '?decision=deny&limit=5');
  assert.deepEqual([brief(denied), denied.more, denied.next], [['project.create proven'], false, null]);
  for (const query of ['?before=0', '?path=market&before=0']) {
    const [bottom] = await page('aud-cli', query);
    assert.deepEqual([bottom.entries, bottom.more, bottom.next], [[], false, null], query);
  }
  // A page that shows nothing of what it read goes on from where it stopped: below Ada's refusal, Bo's read and the token.
  const refusal = (await page('aud-cli'))[0].entries[0]!.seq;
  const [empty] = await page('aud-cli', `?decision=deny&limit=1&before=${refusal}`);
  assert.deepEqual([empty.entries, empty.more, empty.next], [[], true, refusal - 2]);
  // The entry just below the first page's last.
  const [first] = await page('aud-cli', '?limit=2');
  await world.owner.execute(sql`DELETE FROM log WHERE seq = ${first.next! - 1}`);
  const [second] = await page('aud-cli', `?limit=2&before=${first.next}`);
  assert.deepEqual(second.holes?.map(({ above, below }) => [above, below]), [[first.next, first.next! - 2]]);
});

test('whoever does not read the whole log reads the entries of the places they hold audit.read at, every place an entry names, and nothing of the instance', async () => {
  // Al, an Admin scoped to market: market's, its protected staging's too; not shop, billing, the token or the refusal.
  const [scoped, , statements] = await page('al-cli');
  assert.deepEqual(brief(scoped), ['secret.read market/dev/API_KEY proven', 'secret.write market/staging/TOKEN proven', 'secret.write market/dev/API_KEY proven', 'project.move market proven', 'environment.create market/qa proven']);
  assert.deepEqual([scoped.holes, statements], [null, 3], 'their places, the stretch, its tiles and names');
  assert.deepEqual(scoped.hidden, []);
  // Bo leads market, which reads no log in a protected environment.
  assert.deepEqual(brief((await page('bo-cli'))[0]), ['secret.read market/dev/API_KEY proven', 'secret.write market/dev/API_KEY proven', 'project.move market proven', 'environment.create market/qa proven']);
  // Ed watches market/dev: not market's own entries, nor another environment's.
  assert.deepEqual(brief((await page('ed-cli'))[0]), ['secret.read market/dev/API_KEY proven', 'secret.write market/dev/API_KEY proven']);
  // By Cy's hand, of all Cy did: market's filing in a folder is about market alone, which Ed does not read.
  assert.deepEqual(brief((await page('ed-cli', `?actor=${encodeURIComponent(cy)}`))[0]), ['secret.write market/dev/API_KEY proven']);
  // By an actor, the page reads the actor's entries: Ada's refusal names no place, and is not Al's.
  assert.deepEqual((await page('al-cli', `?actor=${encodeURIComponent(ada)}`))[0].entries, []);
  // Ada reads no log anywhere: refused before any statement.
  const [calls, before] = [app.calls.length, app.statements];
  const [status, body] = await call('ada-cli', 'GET', '/audit');
  assert.deepEqual([status, body.error, app.calls.slice(calls), app.statements - before], [403, 'forbidden', ['caller'], 0]);
});

test('a path reads that place, an environment or a key of it; one the caller may not read is refused as one that is not there', async () => {
  assert.deepEqual(brief((await page('aud-cli', '?path=market/dev/API_KEY'))[0]), ['secret.read market/dev/API_KEY proven', 'secret.write market/dev/API_KEY proven']);
  const [environmentPage, , statements] = await page('bo-cli', '?path=market/dev');
  assert.deepEqual([brief(environmentPage), statements], [['secret.read market/dev/API_KEY proven', 'secret.write market/dev/API_KEY proven'], 3]);
  assert.deepEqual(brief((await page('aud-cli', '?path=billing'))[0]), ['secret.write billing/prod/X proven']);
  // An index row that files market's entry under billing does not make it billing's: the body's objects decide.
  const [moved] = await rowsOf<{ seq: number; billing: string }>(world.owner, sql`SELECT l.seq::float8 AS seq, (SELECT id::text FROM projects WHERE slug = 'billing') AS billing FROM log l WHERE l.body LIKE '%"action":"project.move"%'`);
  await world.owner.execute(sql`INSERT INTO log_index (object, seq) VALUES (${`project:${moved!.billing}`}, ${moved!.seq})`);
  assert.deepEqual(brief((await page('aud-cli', '?path=billing'))[0]), ['secret.write billing/prod/X proven']);
  // Bo: staging is protected, and nowhere is not there; the same answer. To whoever reads it all, not there is not found.
  for (const path of ['market/staging', 'market/nowhere', 'billing', 'gone']) {
    const [status, body] = await call('bo-cli', 'GET', `/audit?path=${path}`);
    assert.deepEqual([status, body.error], [403, 'forbidden'], path);
  }
  for (const path of ['market/nowhere', 'gone', 'market/dev/NOPE']) assert.equal((await call('aud-cli', 'GET', `/audit?path=${path}`))[0], 404, path);
  // What names no place reaches no statement.
  for (const path of ['market/de%00v', 'Market', 'market/dev/a-b', 'market/dev/%ED%A0%80']) assert.equal((await call('aud-cli', 'GET', `/audit?path=${path}`))[0], 400, path);
});

test("a path's entry that names another project too is the caller's if they read that one's log as well, and no one else's", async () => {
  const [billing] = await rowsOf<{ id: string }>(world.owner, sql`SELECT id::text AS id FROM projects WHERE slug = 'billing'`);
  await write(world, ...rows('grants', grant(bo, 'lead', { project: billing! })));
  for (const [method, path, body] of [['PATCH', '/projects/billing', { folder: 'apps' }], ['PATCH', '/folders/apps', { name: 'tools' }]] as const) {
    const [status, answer] = await call('cy-cli', method, path, body);
    assert.equal(status, 200, `${method} ${path}: ${JSON.stringify(answer)}`);
  }
  await sign();
  const refiles = async (label: string, query: string) => (await page(label, query))[0].entries.filter((entry) => entry.action === 'folder.refile').map((entry) => entry.proof);
  // Apps held market and billing: its renaming names both, and Bo reads both, whichever the path.
  for (const query of ['', '?path=market', '?path=billing']) assert.deepEqual(await refiles('bo-cli', query), ['proven'], query);
  // Al reads market's log alone: billing's mention keeps it from Al, by a path or not.
  for (const query of ['', '?path=market']) assert.deepEqual(await refiles('al-cli', query), [], query);
});

test('an actor, in full or bare, reads what they did, by the index and held to the body', async () => {
  for (const actor of ['user:bo@acme.example', 'BO@acme.example', 'bo@acme.example']) {
    assert.deepEqual(brief((await page('aud-cli', `?actor=${encodeURIComponent(actor)}`))[0]), ['secret.read market/dev/API_KEY proven'], actor);
  }
  // An index row that says an entry is Bo's does not make it so: the body's actor decides.
  const [made] = await rowsOf<{ seq: number }>(world.owner, sql`SELECT seq::float8 AS seq FROM log WHERE body LIKE '%"action":"project.create"%' AND kept`);
  await world.owner.execute(sql`INSERT INTO log_index (object, seq) VALUES (${`principal:${bo}`}, ${made!.seq})`);
  assert.deepEqual(brief((await page('aud-cli', `?actor=${encodeURIComponent(bo)}`))[0]), ['secret.read market/dev/API_KEY proven']);
  for (const actor of ['user:bo%00', 'bo%00', 'user:']) assert.equal((await call('aud-cli', 'GET', `/audit?actor=${actor}`))[0], 400, actor);
});

test("holes by the trees' counts: uses below the first not pruned are not missing, and those above are", () => {
  // Kept: 3 entries (leaves 0..2). Aging: 5 (leaves 0..4), of which 0 and 1 are pruned. seq: K0 A0 A1 K1 A2 A3 K2 A4.
  const head = { size: 8, keptSize: 3, keptRoot: '', agingSize: 5, agingRoot: '', agingFrom: 2, signedAt: '' };
  const at = (seq: number, kept: boolean, leaf: number) => ({ seq, kept, leaf, body: '' });
  const all = [at(7, false, 4), at(6, true, 2), at(5, false, 3), at(4, false, 2), at(3, true, 1), at(0, true, 0)];
  assert.deepEqual(holesOf(head, 'head', all, false), [], 'A0 and A1 pruned');
  // A3 gone, above the first kept: a hole of one use.
  assert.deepEqual(holesOf(head, 'head', all.filter((row) => row.seq !== 5), false), [{ above: 6, below: 4, kept: 0, aging: 1 }]);
  // K0 gone: the last page reaches the log's start, and lacks it.
  assert.deepEqual(holesOf(head, 'head', all.slice(0, -1), false), [{ above: 3, below: null, kept: 1, aging: 0 }]);
  // Not the last page: the stretch goes on below, and nothing is said past it.
  assert.deepEqual(holesOf(head, 'head', all.slice(0, -1), true), []);
  // From the page above's last, A4: K2 must follow.
  assert.deepEqual(holesOf(head, at(7, false, 4), all.slice(2), false), [{ above: 7, below: 5, kept: 1, aging: 0 }]);
  // That entry missing: the page starts at its own first.
  assert.deepEqual(holesOf(head, null, all.slice(2), false), []);
});

test('a stretch by many objects streams them, reading twice its rows in index rows and one more per object, and any plan shows the same', async () => {
  // 60,000 entries, each about one of 200 environments, 20 to each of 10 projects, and so in the index under both: 120,000 rows.
  await world.owner.execute(sql`INSERT INTO log (seq, kept, leaf, body) SELECT g, true, g, '{}' FROM generate_series(1000000, 1059999) g`);
  await world.owner.execute(sql`INSERT INTO log_index (object, seq) SELECT o, g FROM generate_series(1000000, 1059999) g, LATERAL (VALUES ('environment:e' || g % 200), ('project:p' || g % 200 / 20)) objects(o)`);
  await world.owner.execute(sql`ANALYZE log_index`);
  const objects = [...Array.from({ length: 10 }, (_, p) => `project:p${p}`), ...Array.from({ length: 200 }, (_, e) => `environment:e${e}`)];
  const at = { objects, below: null, rows: 1000 };
  const [plan] = await rowsOf<{ 'QUERY PLAN': [{ Plan: Node }] }>(world.owner, sql`EXPLAIN (ANALYZE, FORMAT JSON) ${stretchOf(at)}`);
  type Node = { 'Relation Name'?: string; 'Actual Rows': number; 'Actual Loops': number; Plans?: Node[] };
  const indexRows = (node: Node): number => (node['Relation Name'] === 'log_index' ? node['Actual Rows'] * node['Actual Loops'] : 0) + (node.Plans ?? []).reduce((sum, child) => sum + indexRows(child), 0);
  const read = indexRows(plan!['QUERY PLAN'][0].Plan);
  // A hash of every object's newest would read 70,000: each project's 1,000 and each environment's 300.
  assert.ok(read <= 2 * 1000 + objects.length, `${read} index rows`);
  // Ten environments hold about what the merge needs: Postgres may sort each one's 300 rather than stream them, and reads each once.
  const ten = { objects: objects.slice(10, 20), below: null, rows: 1000 };
  const [tenPlan] = await rowsOf<{ 'QUERY PLAN': [{ Plan: Node }] }>(world.owner, sql`EXPLAIN (ANALYZE, FORMAT JSON) ${stretchOf(ten)}`);
  const tenRead = indexRows(tenPlan!['QUERY PLAN'][0].Plan);
  assert.ok(tenRead <= 10 * 300, `${tenRead} index rows`);
  assert.deepEqual(await logStretch(world.owner, ten).then(({ rows, more }) => [rows.length, rows[0]!.seq, rows.at(-1)!.seq, more]), [1000, 1059809, 1040000, true]);
  // Ten projects of 6,000 entries each, more than the merge takes: streamed, whatever their count.
  const projects = { objects: objects.slice(0, 10), below: null, rows: 1000 };
  const shownBy = (tx: Queryable) => logStretch(tx, projects).then(({ rows, more }) => [rows.length, rows[0]!.seq, rows.at(-1)!.seq, more]);
  const [projectPlan] = await rowsOf<{ 'QUERY PLAN': [{ Plan: Node }] }>(world.owner, sql`EXPLAIN (ANALYZE, FORMAT JSON) ${stretchOf(projects)}`);
  assert.ok(indexRows(projectPlan!['QUERY PLAN'][0].Plan) <= 2 * 1000 + 10, `${indexRows(projectPlan!['QUERY PLAN'][0].Plan)} index rows`);
  assert.deepEqual(await shownBy(world.owner), [1000, 1059999, 1059000, true]);
  // A sort, forced, reads every entry they hold, and shows the same page: the bound on what it reads is the plan's, not the statement's.
  await world.owner.transaction(async (tx) => {
    await tx.execute(sql`SET LOCAL enable_indexscan = off`);
    await tx.execute(sql`SET LOCAL enable_indexonlyscan = off`);
    const [sorted] = await rowsOf<{ 'QUERY PLAN': [{ Plan: Node }] }>(tx, sql`EXPLAIN (ANALYZE, FORMAT JSON) ${stretchOf(projects)}`);
    assert.equal(indexRows(sorted!['QUERY PLAN'][0].Plan), 60000);
    assert.deepEqual(await shownBy(tx), [1000, 1059999, 1059000, true]);
  });
  // The newest thousand, each once, and more below.
  const stretch = await logStretch(world.owner, at);
  assert.deepEqual([stretch.rows.length, stretch.rows[0]!.seq, stretch.rows.at(-1)!.seq, stretch.more], [1000, 1059999, 1059000, true]);
  // The last of them: the end, not more.
  assert.deepEqual(await logStretch(world.owner, { objects: ['environment:e7'], below: 1000207, rows: 3 }).then(({ rows, more }) => [rows.map(({ seq }) => seq), more]), [[1000207, 1000007], false]);
});

test('a page about more places than the index is read by reads the log itself, and shows the same', async () => {
  // Market grows ten thousand environments: Al reads the log of each, which no statement could read the index by.
  await world.owner.execute(sql`
    INSERT INTO environments SELECT (jsonb_populate_record(NULL::environments, to_jsonb(e) || jsonb_build_object('id', gen_random_uuid(), 'slug', 'more-' || g, 'name', 'more-' || g))).*
    FROM environments e JOIN projects p ON p.id = e.project_id, generate_series(1, 10000) g WHERE p.slug = 'market' AND e.slug = 'prod'`);
  const [scoped, , statements] = await page('al-cli');
  assert.deepEqual(brief(scoped), ['secret.read market/dev/API_KEY proven', 'secret.write market/staging/TOKEN proven', 'secret.write market/dev/API_KEY proven', 'project.move market proven', 'environment.create market/qa proven']);
  assert.deepEqual([scoped.holes, scoped.more, statements], [null, false, 3]);
  // Two at a time, a page reads four of the log and shows what of them is Al's: the pages go on where each stopped, and show it all.
  const shown: string[] = [];
  let next: number | null = null;
  do {
    const [paged]: [Page, string[], number] = await page('al-cli', `?limit=2${next === null ? '' : `&before=${next}`}`);
    shown.push(...brief(paged));
    next = paged.next;
  } while (next !== null);
  assert.deepEqual(shown, brief(scoped));
});
