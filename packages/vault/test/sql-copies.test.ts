// The numbers the hot path's SQL holds as literals, held to the constants the
// TypeScript reads: a migration never changes once applied, so its functions
// keep their own copies of the use deadline, the clock-ahead minute, the bulk
// refresh and the hot login's timeouts. Each test reads what the migrated
// database runs, the newest definition of each function, never a migration's
// text. Postgres only: SQLite has no functions or logins, and its statements
// take these from the constants themselves (`log-store.ts`, `use.sqlite.ts`).
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';

import { HOT_LOCK_TIMEOUT_MS, HOT_STATEMENT_TIMEOUT_MS, USE_DEADLINE_MS } from '@coffre/core/vault';
import { HOT_SETTINGS } from '@coffre/db/migrate';
import { sql } from 'drizzle-orm';

import { REFRESH_MAX_MS, REFRESH_WINDOW_SHARE, USE_AHEAD_MS } from '../src/bulk.ts';
import { HELD_PAST_DEADLINE_MS } from '../src/use.ts';
import { openTestDatabase, postgresOnly, rows, type TestDatabase } from './database.ts';

let db: TestDatabase;
/** Every function of the public schema the migrations made, its name and source. */
let functions: { name: string; source: string }[];
before(async () => {
  db = await openTestDatabase();
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

test('no function holds another copy of the minute or the deadline than the ones above', POSTGRES, () => {
  const minutes = found(/\b(60000)\b/g).length;
  const counted = found(/clock_timestamp\(\)\) \* 1000\)::bigint \+ 60000\b/g).length + found(/deadline_max\(\) - 60000\b/g).length
    + found(/least\(60000, /g).length
    // sign_in's own minute (0037): a credential's expiry may run that far past its longest by the app's clock. Not the
    // use's clock-ahead minute, though the same length; the vault's SQLite path holds it as `60_000` (credentials.sqlite.ts).
    + found(/now_ms \+ p_longest \+ 60000\b/g).length;
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
