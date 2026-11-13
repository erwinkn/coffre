import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import { BATCH_BYTES } from '@coffre/db/log';
import { sql, type SQL } from 'drizzle-orm';

import { eventsPage, PLACES_APART, WINDOW, type EventsFilter, type Position } from '../src/db/events.ts';
import { openTestDatabase, resetDatabase } from './api-fixture.ts';

// Paging the projection by `next`: a page passes over `WINDOW` rows of its stream at most past
// those it shows, and stops at `BATCH_BYTES` of detail, so its filters can leave it short, or empty, with more below.
// Followed to the end, the pages tile the stream: each entry shown once, or counted once, and none left out.

let db: Awaited<ReturnType<typeof openTestDatabase>>;

before(async () => {
  db = await openTestDatabase();
});

after(async () => {
  await resetDatabase(db.owner);
  await db.close();
});

beforeEach(async () => {
  await resetDatabase(db.owner);
});

/** Entries `1..count`, the newest last, each one's `shown`, `allowed` and detail as `shape` says. */
async function plant(count: number, shape: { shown: SQL; allowed: SQL; detail?: SQL }) {
  await db.owner.execute(sql`
    INSERT INTO audit_events (at, number, log, author, action, shown, allowed, code, actor, subject, credential, project, environment, secret, version, places,
                              request_id, operation_id, related, source_ip, detail, mac)
    SELECT 1700000000000 + i * 10, i, 16, 'vault', CASE WHEN ${shape.shown} THEN 'secret.read' ELSE 'mcp.read' END, ${shape.shown}, ${shape.allowed},
      CASE WHEN ${shape.allowed} THEN NULL ELSE 'no_grant' END, 'user:ada@x', NULL, NULL, NULL, NULL, NULL, NULL, '{}', NULL, NULL, NULL, NULL,
      ${shape.detail ?? sql`'{}'`}, ${Buffer.alloc(16)}
    FROM generate_series(1, ${count}::bigint) i`);
}

/** Every page of `filter`, by `next`, to the end: the numbers each showed, what each counted, and how many pages. */
async function walk(filter: Omit<EventsFilter, 'before'>) {
  const shown: bigint[][] = [];
  const hidden = new Map<string, number>();
  let before: Position | undefined;
  for (let pages = 0; pages < 100; pages++) {
    const page = await eventsPage(db.runtime, { ...filter, ...(before === undefined ? {} : { before }) });
    shown.push(page.rows.map((row) => row.number));
    for (const [action, n] of page.hidden) hidden.set(action, (hidden.get(action) ?? 0) + n);
    if (page.next === null) return { shown, hidden };
    before = page.next;
  }
  throw new Error('paged a hundred times without reaching the end');
}

const numbers = (from: number, to: number, step = 1) => Array.from({ length: Math.floor((to - from) / step) + 1 }, (_, i) => BigInt(to - i * step));

test('pages followed by next show each entry once and count each hidden one once, across stretches of more than a window that hold none', async () => {
  // The newest 2,500 hidden (detail), the 500 below them shown: the first pages pass over a window each, showing nothing.
  const count = 3_000;
  await plant(count, { shown: sql`i <= 500`, allowed: sql`i % 300 <> 0` });
  const counted = await walk({ stream: { all: true, shownOnly: false }, match: {}, detail: false, counted: true, limit: 100 });
  assert.ok(counted.shown.slice(0, 2).every((page) => page.length === 0), 'a window of hidden entries shows nothing, and goes on');
  assert.deepEqual(counted.shown.flat(), numbers(1, 500));
  assert.deepEqual([...counted.hidden], [['mcp.read', 2_500]]);
  assert.ok(WINDOW < 2_500);

  // A filter that matches one row in 300, detail included: short pages, each refusal once, newest first.
  const refused = await walk({ stream: { all: true, shownOnly: false }, match: { allowed: false }, detail: true, counted: false, limit: 3 });
  assert.deepEqual(refused.shown.flat(), numbers(300, 3_000, 300));
  // The shown entries' own stream, the same filter: the refusals among them.
  const shownRefused = await walk({ stream: { all: true, shownOnly: true }, match: { allowed: false }, detail: false, counted: false, limit: 3 });
  assert.deepEqual(shownRefused.shown.flat(), [300n]);
});

test('a first entry past BATCH_BYTES is shown alone, and the next page goes on below it, never the end of the log', async () => {
  // The newest entry's detail alone is past the cap; four below it are small.
  await plant(5, { shown: sql`true`, allowed: sql`true`, detail: sql`CASE WHEN i = 5 THEN '{"x":"' || repeat('a', ${BATCH_BYTES + 1_000}) || '"}' ELSE '{}' END` });
  const first = await eventsPage(db.runtime, { stream: { all: true, shownOnly: true }, match: {}, detail: false, counted: false, limit: 100 });
  assert.deepEqual(first.rows.map((row) => row.number), [5n]);
  assert.notEqual(first.next, null);
  const paged = await walk({ stream: { all: true, shownOnly: true }, match: {}, detail: false, counted: false, limit: 100 });
  assert.deepEqual(paged.shown, [[5n], [4n, 3n, 2n, 1n]]);
});

test('two entries that are past BATCH_BYTES together are shown a page each', async () => {
  const half = Math.ceil(BATCH_BYTES / 2) + 1_000;
  await plant(4, { shown: sql`true`, allowed: sql`true`, detail: sql`CASE WHEN i >= 3 THEN '{"x":"' || repeat('a', ${half}) || '"}' ELSE '{}' END` });
  const paged = await walk({ stream: { all: true, shownOnly: true }, match: {}, detail: false, counted: false, limit: 100 });
  assert.deepEqual(paged.shown, [[4n], [3n, 2n, 1n]]);
});

test('a reader of more places than PLACES_APART is shown the entries at their places, as one of fewer is, its first page empty where those are rare', async () => {
  // Places 0 to PLACES_APART + 1; entries 1..1,500, the newest 1,200 at the last place, which no reader here holds, the 300 below one at each other place in turn.
  const count = PLACES_APART + 2;
  const places = Array.from({ length: count }, (_, i) => `00000000-0000-4000-8000-${String(i).padStart(12, '0')}`);
  const place = sql`(string_to_array(${places.join(',')}, ','))[CASE WHEN i > 300 THEN ${count} ELSE 1 + i % ${count - 1} END]::uuid`;
  await db.owner.execute(sql`
    INSERT INTO audit_events (at, number, log, author, action, shown, allowed, code, actor, subject, credential, project, environment, secret, version, places,
                              request_id, operation_id, related, source_ip, detail, mac)
    SELECT 1700000000000 + i * 10, i, 16, 'vault', 'secret.read', true, true, NULL, 'user:ada@x', NULL, NULL, NULL, NULL, NULL, NULL, ARRAY[${place}],
      NULL, NULL, NULL, NULL, '{}', ${Buffer.alloc(16)}
    FROM generate_series(1, 1500::bigint) i`);
  await db.owner.execute(sql`INSERT INTO audit_event_places (place, at, number, log) SELECT unnest(places), at, number, log FROM audit_events`);
  const reader = (held: number) => walk({ stream: { places: places.slice(0, held) }, match: {}, detail: false, counted: false, limit: 100 });
  // PLACES_APART places: each read on its own index, so the first page fills.
  const apart = await reader(PLACES_APART);
  assert.equal(apart.shown[0]!.length, 100);
  assert.deepEqual(apart.shown.flat(), numbers(1, 300).filter((n) => Number(n % BigInt(count - 1)) < PLACES_APART));
  // One more: everyone's stream, held to their places, a window at most past what it shows, so the first page reads
  // the newest 1,100 entries, none theirs, and shows nothing; followed by next, the pages show every entry of theirs once.
  const together = await reader(PLACES_APART + 1);
  assert.deepEqual(together.shown[0], []);
  assert.deepEqual(together.shown.flat(), numbers(1, 300));
});
