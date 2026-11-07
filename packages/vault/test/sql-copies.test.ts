// The numbers the hot path's SQL holds as literals, held to the constants the
// TypeScript reads: a migration never changes once applied, so its functions
// keep their own copies of the use deadline, the clock-ahead minute, the bulk
// refresh, its periods' phases and the hot login's timeouts, and a table's constraint its own copy
// of a role id's length. Each test reads what the migrated database runs, the
// newest definition of each function and constraint, never a migration's
// text. The functions and logins are Postgres's: SQLite has neither, and its
// statements take these from the constants themselves (`log-store.ts`,
// `use.sqlite.ts`). The constraint is on both engines.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';

import { ROLE_ID, ROLE_ID_MAX } from '@coffre/core/access';
import { CLOCK_SKEW_MS, HOT_LOCK_TIMEOUT_MS, HOT_STATEMENT_TIMEOUT_MS, USE_DEADLINE_MS } from '@coffre/core/vault';
import { HOT_SETTINGS } from '@coffre/db/migrate';
import { sql } from 'drizzle-orm';

import { randomUUID } from 'node:crypto';

import { periodOf, phaseOf, REFRESH_MAX_MS, REFRESH_WINDOW_SHARE, USE_AHEAD_MS } from '../src/bulk.ts';
import { HELD_PAST_DEADLINE_MS } from '../src/use.ts';
import { ENGINE, openTestDatabase, postgresOnly, rows, type TestDatabase } from './database.ts';

let db: TestDatabase;
/** Every function of the public schema the migrations made, its name and source; none on SQLite. */
let functions: { name: string; source: string }[] = [];
before(async () => {
  db = await openTestDatabase();
  if (ENGINE !== 'postgres') return;
  functions = await rows(db.owner, sql`
    SELECT p.proname AS name, p.prosrc AS source FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'public' AND p.prokind = 'f' ORDER BY p.proname, p.oid`);
});
after(() => db?.close());

/** Each match of `pattern` in every function's source: the function's name and the captured groups. */
function found(pattern: RegExp): { name: string; groups: string[] }[] {
  return functions.flatMap(({ name, source }) => [...source.matchAll(pattern)].map((match) => ({ name, groups: match.slice(1) })));
}

const POSTGRES = postgresOnly('a Postgres function holds these copies');

test('deadline_max() is the use deadline, USE_DEADLINE_MS', POSTGRES, async () => {
  const [row] = await rows<{ deadline: string }>(db.owner, sql`SELECT public.deadline_max()::text AS deadline`);
  assert.equal(Number(row!.deadline), USE_DEADLINE_MS);
});

test("every function's clock-ahead minute is USE_AHEAD_MS: a use stamped past the database's clock, and the other keys' bound past the deadline", POSTGRES, () => {
  const ahead = found(/clock_timestamp\(\)\) \* 1000\)::bigint \+ (\d+)/g);
  const past = found(/deadline_max\(\) - (\d+)\b(?! AS before)/g);
  assert.ok(ahead.some(({ name }) => name === 'use_credential') && past.some(({ name }) => name === 'use_credential'), 'use_credential holds both, as the pattern finds them');
  for (const { name, groups } of [...ahead, ...past]) assert.equal(Number(groups[0]), USE_AHEAD_MS, name);
});

test("every function's bulk refresh is refreshMs's: least(REFRESH_MAX_MS, window / REFRESH_WINDOW_SHARE)", POSTGRES, () => {
  const refresh = found(/least\((\d+), [\w.]+ \/ (\d+)\)/g);
  assert.ok(refresh.some(({ name }) => name === 'use_credential') && refresh.some(({ name }) => name === 'prune_bulk'), 'the uses and the prune hold it, as the pattern finds them');
  for (const { name, groups } of refresh) assert.deepEqual(groups.map(Number), [REFRESH_MAX_MS, REFRESH_WINDOW_SHARE], name);
});

test("bulk_period is periodOf's, from phaseOf's phase (T204): every key's period where the replay's starts", POSTGRES, async () => {
  // Principals of every way in, a person's name beyond ASCII, uuids either case; times about now, near zero and before
  // it; refreshes of a minute, a tenth of short windows, and 1 ms.
  const principals = ['token:ci-build', 'user:5b0f7f0e-1f7e-4c55-a2a8-8d1c4b7c2e11', 'service:deploy', 'user:zoë@acme.example'];
  const cases = Array.from({ length: 400 }, (_, i) => {
    const secret = randomUUID();
    return {
      principal: principals[i % principals.length]!, secret: i % 3 === 0 ? secret.toUpperCase() : secret,
      at: [Date.now() + i * 997, i * 13, -i * 7_919, 1_793_830_000_000 + i][i % 4]!, refresh: [60_000, 6_000, 150, 1, 7][i % 5]!,
    };
  });
  const [row] = await rows<{ periods: string[] }>(db.owner, sql`
    SELECT array_agg(public.bulk_period(c.principal, c.secret, c.at, c.refresh)::text ORDER BY c.i) AS periods
      FROM unnest(${sql.param(cases.map((c) => c.principal))}::text[], ${sql.param(cases.map((c) => c.secret))}::uuid[],
                  ${sql.param(cases.map((c) => String(c.at)))}::bigint[], ${sql.param(cases.map((c) => String(c.refresh)))}::bigint[])
           WITH ORDINALITY AS c (principal, secret, at, refresh, i)`);
  assert.deepEqual(row!.periods.map(Number), cases.map((c) => periodOf(c.at, c.refresh, phaseOf(c.principal, c.secret, c.refresh))));
});

test("no function works out a key's period but through bulk_period", POSTGRES, () => {
  assert.ok(found(/public\.bulk_period\(/g).some(({ name }) => name === 'use_credential'), "use_credential's period is bulk_period's");
  assert.deepEqual(found(/(% (?:[\w.]*refresh)\) \+)/g), [], "a period worked out in place, its phase every key's 0: call bulk_period");
});

test('no function holds another copy of the minute or the deadline than the ones above', POSTGRES, () => {
  // sign_in's own minute (0037): a credential's expiry may run that far past its longest by the app's clock, which is
  // CLOCK_SKEW_MS, the app's clock against the vault's, as the TypeScript checks (credentials.ts, credentials.sqlite.ts).
  // Once in each overload: 0037's, which the previous release's vault calls, and 0075's (T192).
  const signIn = found(/now_ms \+ p_longest \+ (\d+)\b/g);
  const overloads = functions.filter(({ name }) => name === 'sign_in').length;
  assert.deepEqual(signIn.map(({ name }) => name), Array<string>(overloads).fill('sign_in'), "sign_in's minute is sign_in's alone, and written once in each of its overloads");
  assert.deepEqual(signIn.map(({ groups }) => Number(groups[0])), Array<number>(overloads).fill(CLOCK_SKEW_MS), "sign_in's minute is CLOCK_SKEW_MS");
  const minutes = found(/\b(60000)\b/g).length;
  const counted = found(/clock_timestamp\(\)\) \* 1000\)::bigint \+ 60000\b/g).length + found(/deadline_max\(\) - 60000\b/g).length
    + found(/least\(60000, /g).length + signIn.length;
  assert.equal(minutes, counted, 'a new copy of 60000 in a function: take it from a constant, and add it here');
  assert.deepEqual(found(/\b(3000)\b/g).map(({ name }) => name), ['deadline_max'], 'the deadline is deadline_max(), written once');
});

test("the hot login's timeouts are HOT_LOCK_TIMEOUT_MS and HOT_STATEMENT_TIMEOUT_MS, the ones a place's lapse is counted from", POSTGRES, async () => {
  const [role] = await rows<{ settings: string[] }>(db.owner, sql`
    SELECT setconfig AS settings FROM pg_db_role_setting WHERE setrole = 'coffre_vault_hot'::regrole AND setdatabase = 0`);
  assert.deepEqual(HOT_SETTINGS, { lock_timeout: `${HOT_LOCK_TIMEOUT_MS / 1000}s`, statement_timeout: `${HOT_STATEMENT_TIMEOUT_MS / 1000}s` });
  for (const [name, value] of Object.entries(HOT_SETTINGS)) assert.ok(role!.settings.includes(`${name}=${value}`), `${name}=${value} in ${role!.settings.join(', ')}`);
  assert.equal(HELD_PAST_DEADLINE_MS, HOT_STATEMENT_TIMEOUT_MS);
});

test("a grant's role check takes a role id as ROLE_ID does: 2 to ROLE_ID_MAX characters", async () => {
  if (ENGINE === 'postgres') {
    const [row] = await rows<{ definition: string }>(db.owner, sql`
      SELECT pg_get_constraintdef(oid) AS definition FROM pg_constraint WHERE conname = 'grants_role_check'`);
    assert.ok(row!.definition.includes(`'${ROLE_ID.source}'`), row!.definition);
  } else {
    const [row] = await rows<{ sql: string }>(db.owner, sql`SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'grants'`);
    assert.ok(row!.sql.includes(`BETWEEN 2 AND ${ROLE_ID_MAX} AND`), row!.sql);
  }
  assert.equal(ROLE_ID.source, `^[a-z][a-z0-9-]{1,${ROLE_ID_MAX - 1}}$`);
});
