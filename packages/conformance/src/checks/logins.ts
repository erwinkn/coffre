// Each component's database login writes what it must and nothing else
// (docs/design/0.16.md, "Four rules"): the app's only reads; the vault's
// writes every row and entry, but not 0.14's archived log, and neither
// changes the schema or steps around its privileges. 0.14 also held the
// vault's login off the app's tables and both off rewriting the log; in
// 0.16 the vault writes every table, the log's included, and the signer
// holds what the log is held to.
import { using, type Sql } from '../database.ts';
import type { Deployment } from '../harness.ts';
import { expect } from '../report.ts';
import { quoted, tables } from './storage.ts';

/** What neither login may do: make or drop a table, empty one, or turn off the database's own checks. */
const BYPASSES = [
  'CREATE TABLE conformance_probe (id integer)', 'CREATE TEMP TABLE conformance_probe (id integer)',
  'DROP TABLE log', 'TRUNCATE log', 'TRUNCATE secret_versions',
  'ALTER TABLE log_pending DISABLE TRIGGER USER', "SET session_replication_role = 'replica'",
  'SET ROLE coffre_owner',
];

async function refuses(sql: Sql, statements: string[]): Promise<number> {
  for (const statement of statements) {
    await sql.exec('BEGIN');
    let error: unknown;
    try {
      await sql.exec(statement);
    } catch (failure) {
      error = failure;
    } finally {
      await sql.exec('ROLLBACK');
    }
    expect(error !== undefined, `the login could: ${statement}`);
    expect((error as { code?: string }).code === '42501', `${statement} failed for a reason other than privilege`, error);
  }
  return statements.length;
}

/** Neither table nor column grants may let a login write these tables. */
async function noWrites(sql: Sql, names: readonly string[]): Promise<void> {
  const columns = await sql.query<{ table_name: string; column_name: string; insertable: boolean; updatable: boolean; deletable: boolean; truncatable: boolean }>(
    `SELECT table_name, column_name,
      has_column_privilege(current_user, quote_ident(table_name), column_name, 'INSERT') AS insertable,
      has_column_privilege(current_user, quote_ident(table_name), column_name, 'UPDATE') AS updatable,
      has_table_privilege(current_user, quote_ident(table_name), 'DELETE') AS deletable,
      has_table_privilege(current_user, quote_ident(table_name), 'TRUNCATE') AS truncatable
     FROM information_schema.columns WHERE table_schema = 'public'`);
  for (const name of names) {
    const inspected = columns.filter((column) => column.table_name === name);
    // A table hidden entirely from this login still needs its privileges checked.
    const [table] = await sql.query<{ writable: boolean }>(`SELECT
      has_table_privilege(current_user, $1, 'INSERT, UPDATE, DELETE, TRUNCATE') AS writable`, [name]);
    expect(!table.writable, `the login has a table write privilege on ${name}`);
    expect(inspected.every((column) => !column.insertable && !column.updatable && !column.deletable && !column.truncatable),
      `the login has a column write privilege on ${name}`, inspected);
  }
}

/** The app's login writes no table: every row is the vault's. */
export async function appLogin(deployment: Deployment): Promise<string> {
  const all = await using(deployment.database(), tables);
  return using(deployment.runtime(), async (sql) => {
    await noWrites(sql, all);
    const statements = [...BYPASSES, 'SET ROLE coffre_vault',
      "INSERT INTO log_pending (kept, body, mac) VALUES (true, '{}', decode(repeat('00', 36), 'hex'))",
      'UPDATE log SET body = body', 'DELETE FROM log', 'UPDATE log_head SET size = size',
      'UPDATE secret_versions SET id = id', 'DELETE FROM secrets', 'UPDATE principals SET role = role', 'UPDATE grants SET role = role'];
    for (const table of all) statements.push(`DELETE FROM ${quoted(table)}`, `TRUNCATE ${quoted(table)}`);
    const count = await refuses(sql, statements);
    return `${count} writes and bypasses refused; no write privilege on any of ${all.length} tables`;
  });
}

/** The vault's login writes coffre's rows, never 0.14's archived log, and empties no table. */
export async function vaultLogin(deployment: Deployment): Promise<string> {
  const all = await using(deployment.database(), tables);
  return using(deployment.vaultRuntime(), async (sql) => {
    await noWrites(sql, ['audit_archive']);
    const statements = [...BYPASSES, 'SET ROLE coffre_app',
      'UPDATE audit_archive SET action = action', 'DELETE FROM audit_archive', 'INSERT INTO audit_archive SELECT * FROM audit_archive LIMIT 1'];
    for (const table of all) statements.push(`TRUNCATE ${quoted(table)}`);
    const count = await refuses(sql, statements);
    return `${count} writes and bypasses refused; 0.14's archived log not writable`;
  });
}
