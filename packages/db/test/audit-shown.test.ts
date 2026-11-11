// `audit_shown(action)` (T254, `SHOWN_CALL`): the list of what an audit page hides, behind a call that T254's indexes
// say on Postgres. Its list is `KINDS.shown`'s word for word, it answers what that list does for every action, NULL
// included, and it never changes: an action newly hidden fails here until a new function and new indexes carry it.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { getTableConfig } from 'drizzle-orm/pg-core';
import { PgDialect } from 'drizzle-orm/pg-core';

import { DETAIL_ACTIONS, KINDS, SHOWN_CALL } from '../src/access-entries.ts';
import { migrationsFolder } from '../src/migrate.ts';
import { postgresClient } from '../src/postgres.ts';
import { auditLog } from '../src/schema.ts';

const skip = process.env.COFFRE_TEST_ENGINE === 'sqlite' ? 'Postgres only' : false;
const URL_ = `postgresql://coffre_owner:local-dev-only@127.0.0.1:${process.env.COFFRE_POSTGRES_PORT ?? '55432'}/${process.env.COFFRE_TEST_DATABASE ?? 'coffre_test'}`;
const MIGRATION = readFileSync(join(migrationsFolder('postgres'), '0085_place_pages.sql'), 'utf8');
/** `KINDS.shown`'s list, `action NOT IN (…)`. */
const LIST = /action NOT IN \([^)]*\)/.exec(KINDS.shown)![0];

let client: ReturnType<typeof postgresClient> | undefined;
before(() => {
  if (!skip) client = postgresClient(URL_, { max: 1 });
});
after(async () => {
  await client?.end();
});

test("the migration's function says KINDS.shown's list word for word, before any index says it", () => {
  const made = /CREATE FUNCTION audit_shown\(action text\) RETURNS boolean\n LANGUAGE plpgsql\n IMMUTABLE PARALLEL SAFE\nAS \$function\$\nBEGIN\n {4}RETURN (action NOT IN \([^)]*\));\nEND\n\$function\$;/.exec(MIGRATION);
  assert.ok(made, '0085 makes audit_shown(action text), plpgsql, IMMUTABLE PARALLEL SAFE, of one RETURN of a list');
  // A newly hidden action (DETAIL_ACTIONS) fails here: make `audit_shown_2` and T254's indexes again on it, never change this one.
  assert.equal(made[1], LIST);
  assert.deepEqual(made[1].match(/'[^']*'/g)!.map((quoted) => quoted.slice(1, -1)), [...DETAIL_ACTIONS]);
  const callers = [...MIGRATION.matchAll(/CREATE INDEX CONCURRENTLY "(\w+)"[^;]*audit_shown\(action\)/g)];
  assert.deepEqual(callers.map(([, name]) => name).sort(), [
    'audit_log_also_environment_shown_idx', 'audit_log_also_project_shown_idx', 'audit_log_also_secret_shown_idx', 'audit_log_denied_idx',
    'audit_log_environment_shown_idx', 'audit_log_project_shown_idx', 'audit_log_secret_shown_idx',
  ]);
  assert.ok(callers.every((caller) => caller.index! > made.index), 'the function is made before the indexes that say it');
  assert.ok(!/action NOT IN/.test(MIGRATION.slice(made.index + made[0].length)), 'no index of 0085 says the list');
});

test("the Postgres schema's indexes say the call, never the list beside it", () => {
  const dialect = new PgDialect();
  const conditions = Object.fromEntries(getTableConfig(auditLog).indexes.map((index) => [index.config.name, index.config.where === undefined ? '' : dialect.sqlToQuery(index.config.where).sql]));
  for (const name of ['audit_log_denied_idx', 'audit_log_project_shown_idx', 'audit_log_also_secret_shown_idx']) {
    assert.ok(conditions[name]!.includes(SHOWN_CALL) && !conditions[name]!.includes('NOT IN'), name);
  }
  // 0083's keep the list (A622, step 6).
  assert.ok(conditions['audit_log_shown_idx']!.includes(LIST) && !conditions['audit_log_shown_idx']!.includes(SHOWN_CALL));
});

test('audit_shown answers what the list does, for every action and NULL', { skip }, async () => {
  const actions = [...DETAIL_ACTIONS, 'secret.read', 'secret.write', 'secret.reference', 'reference.end', 'mcp.call', 'key.rotate', 'audit.read', 'policy.change', '', 'SIGN_IN', ' sign_in', 'sign_in ', 'mcp.read.x', null];
  const rows = await client!.unsafe<{ action: string | null; called: boolean | null; listed: boolean | null }[]>(
    `SELECT action, audit_shown(action) AS called, ${LIST} AS listed FROM unnest($1::text[]) AS asked(action)`,
    [actions as never],
  );
  assert.equal(rows.length, actions.length);
  for (const row of rows) assert.equal(row.called, row.listed, String(row.action));
  assert.equal(rows.find((row) => row.action === null)!.called, null);
  assert.equal(rows.filter((row) => row.called === false).length, DETAIL_ACTIONS.length);
});

test('audit_shown is plpgsql, IMMUTABLE, PARALLEL SAFE, of no setting of its own, and anyone may run it', { skip }, async () => {
  const [made] = await client!.unsafe<{ language: string; volatile: string; parallel: string; settings: string[] | null; definer: boolean; public: boolean }[]>(`
    SELECT l.lanname AS language, p.provolatile AS volatile, p.proparallel AS parallel, p.proconfig AS settings, p.prosecdef AS definer,
           has_function_privilege('public', p.oid, 'EXECUTE') AS public
      FROM pg_proc p JOIN pg_language l ON l.oid = p.prolang WHERE p.oid = 'audit_shown(text)'::regprocedure`);
  assert.deepEqual({ ...made }, { language: 'plpgsql', volatile: 'i', parallel: 's', settings: null, definer: false, public: true });
});

test("audit_shown stays runnable by every login where the migration's owner revoked a new function's EXECUTE from PUBLIC", { skip }, async () => {
  // Sol r2: a deployment's owner may have narrowed its default privileges; 0085 grants by name, so the pages' reads keep it.
  const made = MIGRATION.split('--> statement-breakpoint').filter((statement) => !statement.includes('CREATE INDEX'));
  assert.ok(made.some((statement) => statement.includes('GRANT EXECUTE ON FUNCTION audit_shown(text) TO PUBLIC')));
  const runnable = async (statements: string[]) => {
    let answer: boolean | undefined;
    await client!
      .begin(async (tx) => {
        await tx.unsafe('ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC');
        await tx.unsafe('CREATE SCHEMA t254_revoked');
        await tx.unsafe('SET LOCAL search_path = t254_revoked');
        for (const statement of statements) await tx.unsafe(statement);
        const [row] = await tx.unsafe<{ public: boolean }[]>(`SELECT has_function_privilege('public', 't254_revoked.audit_shown(text)'::regprocedure, 'EXECUTE') AS public`);
        answer = row!.public;
        throw new Error('rolled back');
      })
      .catch((error: unknown) => {
        if (!(error instanceof Error) || error.message !== 'rolled back') throw error;
      });
    return answer;
  };
  assert.equal(await runnable(made.filter((statement) => !statement.includes('GRANT'))), false, 'the revoked default reaches a function made without the grant');
  assert.equal(await runnable(made), true);
});
