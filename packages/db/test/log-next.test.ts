// 0089_log_next: the log numbers from `log_next`, so that a 0.15.0 append held inside its function's body
// across the upgrade's commit fails rather than write. Each held call is 0.15's body, planned once before, blocked on
// the table lock the migration's transaction holds; the migration's own statements run in that transaction.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { MIGRATION_LOCK_WAIT_MS, migrationsFolder } from '../src/migrate.ts';
import { onlineIndex } from '../src/online-indexes.ts';
import { postgresClient, postgresSession, quoteIdentifier, type PostgresClient } from '../src/postgres.ts';
import { holdingRoles } from './roles-lock.ts';

const TAG = '0089_log_next';
const BASE = `postgresql://coffre_owner:local-dev-only@127.0.0.1:${process.env.COFFRE_POSTGRES_PORT ?? '55432'}/${process.env.COFFRE_TEST_DATABASE ?? 'coffre_test'}`;
const NAME = `${new URL(BASE).pathname.slice(1)}_next_${randomBytes(4).toString('hex')}`;
const url = Object.assign(new URL(BASE), { pathname: `/${NAME}` }).toString();
const statements = (tag: string) => readFileSync(join(migrationsFolder(), `${tag}.sql`), 'utf8').split('--> statement-breakpoint');
const SWAP = statements(TAG);
/** A psql script of the schema tests, without its meta-commands. */
const fixture = (file: string) => readFileSync(new URL(file, import.meta.url), 'utf8').replace(/^\\.*$/gm, '');

/** The world log-guarantees.sql makes, as far as a use needs: every input sealed by its genesis change, today's day. */
const GENESIS = `DO $$
DECLARE
    t bigint := (extract(epoch FROM clock_timestamp()) * 1000)::bigint;
    o record;
BEGIN
    FOR o IN SELECT * FROM (VALUES ('policy', 'instance', '{"op":"genesis","value":{"bulk":{"count":9,"windowMs":86400000}}}'),
        ('roles', 'instance', '{"op":"genesis","value":{"kind":"roles","roles":{},"instanceRoles":{}}}'),
        ('principal', 'token:deploy', '{"op":"genesis"}'), ('credential', '33333333-3333-3333-3333-333333333333', '{"op":"genesis"}'),
        ('secret', '44444444-4444-4444-4444-444444444441', '{"op":"genesis"}'), ('environment', '22222222-2222-2222-2222-222222222222', '{"op":"genesis"}')) AS v (kind, id, payload) LOOP
        PERFORM change_input(o.kind, o.id, 'genesis-' || o.kind, t, 'system:test', o.payload, NULL, NULL, decode(repeat('5e', 16), 'hex'), decode(repeat('ee', 16), 'hex'));
    END LOOP;
    PERFORM make_day((now() AT TIME ZONE 'UTC')::date);
END $$`;

const NOW = `(extract(epoch FROM clock_timestamp()) * 1000)::bigint`;
/** A refused write's record, request `r`: an append to log_changes. */
const refusal = (r: string) =>
  `SELECT log_refusal(${NOW}, '${r}', 'system:test', '{"code":"x","op":"write.refused","ref":{"kind":"request","id":"${r}"}}', decode(repeat('00', 16), 'hex'))::text AS n`;
/** A decided use, request `r`: an append to log_uses. */
const use = (r: number) =>
  `SELECT (use_credential('33333333-3333-3333-3333-333333333333', '44444444-4444-4444-4444-444444444441', ${r}, ${NOW}, 1::smallint, NULL,
     decode(repeat('00', 16), 'hex'), ${NOW} + 2000, p_decided => true)::jsonb ->> 'number') AS n`;
/**
 * Every function of the schema, its row as text but for its name and body, which the swap alone may change. A default's
 * parse tree keeps where it stood in the CREATE's text (`:location`, for an error's cursor), which another text moves.
 */
const FUNCTIONS = `SELECT p.oid::regprocedure::text AS id, p.proname AS name, p.prosrc AS body, (to_jsonb(p) - 'oid' - 'proname' - 'prosrc' - 'proargdefaults')::text AS rest,
    regexp_replace(p.proargdefaults::text, ':location -?[0-9]+', '', 'g') AS defaults,
    obj_description(p.oid, 'pg_proc') AS comment FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace ORDER BY id`;
const SEQUENCE = (name: string) => `SELECT pg_get_userbyid(c.relowner) AS owner, c.relacl::text AS acl, (to_jsonb(s) - 'seqrelid')::text AS params
    FROM pg_class c JOIN pg_sequence s ON s.seqrelid = c.oid WHERE c.oid = to_regclass('public.${name}')`;

before(async () => {
  // The schema the swap meets: every migration before it, in one transaction as the migrator runs them, without the
  // indexes it builds after the commit (`online-indexes.ts`), which no statement here needs.
  const { entries } = JSON.parse(readFileSync(join(migrationsFolder(), 'meta/_journal.json'), 'utf8')) as { entries: { tag: string }[] };
  const admin = postgresClient(BASE, { max: 1 });
  await admin.unsafe(`CREATE DATABASE ${quoteIdentifier(NAME)}`).finally(() => admin.end());
  const owner = postgresSession(url);
  try {
    await holdingRoles(BASE, () => owner.begin(async (tx) => {
      await tx.unsafe('CREATE SCHEMA drizzle');
      await tx.unsafe('CREATE TABLE drizzle.__drizzle_migrations (id SERIAL PRIMARY KEY, hash text NOT NULL, created_at bigint)');
      for (const { tag } of entries.slice(0, entries.findIndex((entry) => entry.tag === TAG))) {
        for (const statement of statements(tag)) if (onlineIndex(statement) === null) await tx.unsafe(statement);
      }
    }));
    for (const script of [fixture('schema-fixture.sql'), fixture('log-fixture.sql'), GENESIS]) await owner.unsafe(script);
  } finally {
    await owner.end();
  }
});

after(async () => {
  const admin = postgresClient(BASE, { max: 1 });
  await admin.unsafe(`DROP DATABASE IF EXISTS ${quoteIdentifier(NAME)} WITH (FORCE)`).finally(() => admin.end());
});

/** Whether session `pid` waits for a lock. */
async function waiting(observer: PostgresClient, pid: number): Promise<boolean> {
  const [row] = await observer.unsafe<{ waiting: boolean }[]>(`SELECT wait_event_type = 'Lock' AS waiting FROM pg_stat_activity WHERE pid = ${pid}`);
  return row?.waiting === true;
}

test(`${TAG}: a rotation numbered before the swap holds the sequence: the swap fails on its lock_timeout, the rotation appends`, async (t) => {
  const migrator = postgresSession(url);
  const rotation = postgresSession(url);
  t.after(() => Promise.all([migrator, rotation].map((client) => client.end())));
  await rotation.unsafe('BEGIN');
  const [taken] = await rotation.unsafe<{ n: string }[]>(`SELECT log_rotate_number(decode('ffffffff', 'hex'))::text AS n`);
  await migrator.unsafe('BEGIN');
  await migrator.unsafe(`SET LOCAL lock_timeout = '${MIGRATION_LOCK_WAIT_MS}ms'`);
  let failing: string | undefined;
  await assert.rejects(async () => { for (const statement of SWAP) { failing = statement; await migrator.unsafe(statement); } }, { code: '55P03' });
  assert.match(failing!, /^\s*DROP SEQUENCE/, 'the sequence, not a table, holds the swap');
  await migrator.unsafe('ROLLBACK');
  await rotation.unsafe(`SELECT log_rotate(${taken!.n}, 'rotate', ${NOW}, '{"op":"rotate","at":"${taken!.n}"}', decode(repeat('11', 16), 'hex'), decode('ffffffff', 'hex'))`);
  await rotation.unsafe('COMMIT');
  const [found] = await migrator.unsafe<{ number: string }[]>(`SELECT number::text FROM log_changes WHERE request_id = 'rotate'`);
  assert.equal(found?.number, taken!.n);
});

test(`${TAG}: an append held across the swap's commit fails, 42P01, and writes nothing; every function keeps all but its body`, async (t) => {
  const migrator = postgresSession(url);
  const changes = postgresSession(url);
  const uses = postgresSession(url);
  const observer = postgresClient(url, { max: 1 });
  t.after(() => Promise.all([migrator, changes, uses, observer].map((client) => client.end())));

  // Each session plans its append once, as a 0.15.0 connection would have: the held call runs a cached plan.
  const [first] = await changes.unsafe<{ n: string }[]>(refusal('warm'));
  const [second] = await uses.unsafe<{ n: string }[]>(use(1));
  assert.equal(BigInt(second!.n), BigInt(first!.n) + 1n, 'both logs number from one sequence');
  const functions = await observer.unsafe<{ id: string; name: string; body: string; rest: string; defaults: string | null; comment: string | null }[]>(FUNCTIONS);
  const [sequence] = await observer.unsafe(SEQUENCE('log_number'));
  assert.ok(functions.some((f) => f.body.includes('public.log_number')));

  await migrator.unsafe('BEGIN');
  await migrator.unsafe('LOCK TABLE log_changes, log_uses IN ACCESS EXCLUSIVE MODE');
  const pids = await Promise.all([changes, uses].map(async (s) => (await s.unsafe<{ pid: number }[]>('SELECT pg_backend_pid() AS pid'))[0]!.pid));
  const held = [changes.unsafe(refusal('held')), uses.unsafe(use(2))].map((call) => call.then(() => 'wrote', (error: { code?: string }) => error.code));
  for (const end = Date.now() + 5_000; !(await waiting(observer, pids[0]!)) || !(await waiting(observer, pids[1]!));) {
    assert.ok(Date.now() < end, 'both appends wait for the migration');
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  for (const statement of SWAP) await migrator.unsafe(statement);
  await migrator.unsafe('COMMIT');

  assert.deepEqual(await Promise.all(held), ['42P01', '42P01']);
  const [found] = await observer.unsafe<{ changes: number; uses: number }[]>(
    `SELECT (SELECT count(*)::int FROM log_changes WHERE request_id = 'held') AS changes, (SELECT count(*)::int FROM log_uses WHERE request_id = 2) AS uses`);
  assert.deepEqual({ ...found }, { changes: 0, uses: 0 });

  // Every function is the same row, but for the sequence its body names, and log_retention's name (and object ID: made anew).
  const swapped = await observer.unsafe<typeof functions>(FUNCTIONS);
  const expected = new Map(functions.map((f) => [f.id.replace(/^log_retention\(/, 'append_retention('), {
    ...f, name: f.name === 'log_retention' ? 'append_retention' : f.name, body: f.body.replaceAll('public.log_number', 'public.log_next'),
  }]));
  const drift = swapped.flatMap((f) => {
    const was = expected.get(f.id);
    return was === undefined ? [`${f.name}: new`] : (['name', 'body', 'rest', 'defaults', 'comment'] as const).filter((k) => f[k] !== was[k]).map((k) => `${f.name}: ${k}`);
  });
  assert.deepEqual(drift, []);
  assert.equal(swapped.length, functions.length);
  assert.deepEqual({ ...(await observer.unsafe(SEQUENCE('log_next')))[0] }, { ...sequence }, 'the same owner, grants and parameters');

  // The next append takes the next number: none skipped, none taken twice.
  const [next] = await observer.unsafe<{ n: string }[]>(refusal('after'));
  assert.equal(BigInt(next!.n), BigInt(second!.n) + 1n);
});

test(`${TAG}: once migrated, no log_number, and no log_retention a 0.15.0 call could resolve to`, async (t) => {
  const db = postgresClient(BASE, { max: 1 });
  t.after(() => db.end());
  const [row] = await db.unsafe(`SELECT to_regclass('public.log_number') IS NULL AS gone, to_regclass('public.log_next') IS NOT NULL AS made,
      has_sequence_privilege('coffre_backup', 'public.log_next', 'SELECT') AS backup,
      (SELECT count(*)::int FROM pg_proc WHERE prosrc LIKE '%log_number%') AS naming,
      to_regproc('public.log_retention') IS NULL AS renamed, to_regprocedure('public.append_retention(text, bigint, text, bytea)') IS NOT NULL AS retention`);
  assert.deepEqual({ ...row }, { gone: true, made: true, backup: true, naming: 0, renamed: true, retention: true });
});
