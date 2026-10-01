// Each component's database login writes its own tables and nothing else:
// the app cannot write members, grants or the vault's entries, the vault
// cannot write the app's tables, and neither can rewrite the log. Postgres
// only: SQLite has no logins.
import { using, type Sql } from '../database.ts';
import type { Deployment } from '../harness.ts';
import { expect, Skip } from '../report.ts';
import { quoted, tables } from './storage.ts';

const ZEROS = "decode(repeat('00', 32), 'hex')";
const appendAs = (author: string) => `INSERT INTO audit_log
  (seq, author, key_id, occurred_at, actor, action, decision, prev_hash, mac, hash)
  VALUES (9000000000, '${author}', '${author}:0', 0, 'system:conformance', 'probe', 'allow', ${ZEROS}, ${ZEROS}, ${ZEROS})`;
const IMMUTABLE = [
  "UPDATE audit_log SET action = 'rewritten' WHERE author = 'app'",
  "UPDATE audit_log SET action = 'rewritten' WHERE author = 'vault'",
  'DELETE FROM audit_log', 'TRUNCATE audit_log', 'DROP TABLE audit_log',
  'UPDATE secret_versions SET id = id', 'DELETE FROM secret_versions',
  'DELETE FROM vault_members', 'CREATE TABLE conformance_probe (id integer)',
  'CREATE TEMP TABLE conformance_probe (id integer)',
  'ALTER TABLE audit_log DISABLE TRIGGER USER', "SET session_replication_role = 'replica'",
  'SET ROLE coffre_owner',
];

/** A column of each app table, for an update that would change nothing, if it were allowed. */
const APP_COLUMNS: Record<string, string> = {
  projects: 'id', environments: 'id', secrets: 'id', secret_versions: 'id', identities: 'id',
  credentials: 'id', device_authorizations: 'id', syncs: 'id', sync_keys: 'key',
};

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

/** Neither table nor column grants may let a login write outside its component. */
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

export async function appLogin(deployment: Deployment): Promise<string> {
  if (deployment.kind === 'node') throw new Skip('SQLite has no database logins');
  expect(deployment.runtime !== null, 'the app runtime login is missing');
  const protectedTables = (await using(deployment.database(), tables)).filter((name) => name.startsWith('vault_'));
  return using(deployment.runtime(), async (sql) => {
    await noWrites(sql, protectedTables);
    const statements = [...IMMUTABLE, appendAs('vault'), 'SET ROLE coffre_vault', 'DELETE FROM secrets'];
    for (const table of protectedTables) {
      statements.push(`INSERT INTO ${table} SELECT * FROM ${table} LIMIT 1`, `UPDATE ${table} SET principal = principal`,
        `DELETE FROM ${table}`, `TRUNCATE ${table}`);
    }
    const count = await refuses(sql, statements);
    return `${count} writes and bypasses refused; no member or grant write privileges`;
  });
}

export async function vaultLogin(deployment: Deployment): Promise<string> {
  if (deployment.kind === 'node') throw new Skip('SQLite has no database logins');
  expect(deployment.vaultRuntime !== null, 'the vault runtime login is missing');
  const appTables = (await using(deployment.database(), tables)).filter((name) =>
    !['vault_members', 'vault_grants', 'audit_log', 'audit_chain_head'].includes(name));
  return using(deployment.vaultRuntime(), async (sql) => {
    await noWrites(sql, appTables);
    const [head] = await sql.query<{ insertable: boolean; deletable: boolean; identity_updatable: boolean; truncatable: boolean }>(`SELECT
      has_table_privilege(current_user, 'audit_chain_head', 'INSERT') AS insertable,
      has_table_privilege(current_user, 'audit_chain_head', 'DELETE') AS deletable,
      has_table_privilege(current_user, 'audit_chain_head', 'TRUNCATE') AS truncatable,
      has_column_privilege(current_user, 'audit_chain_head', 'only_row', 'UPDATE') AS identity_updatable`);
    expect(!head.insertable && !head.deletable && !head.truncatable && !head.identity_updatable, 'the vault can replace the head row', head);
    const statements = [...IMMUTABLE, appendAs('app'), 'SET ROLE coffre_app',
      'UPDATE audit_chain_head SET only_row = only_row', 'DELETE FROM audit_chain_head', 'TRUNCATE audit_chain_head',
      'UPDATE vault_members SET principal = principal', 'UPDATE vault_grants SET role = role'];
    for (const table of appTables) {
      const column = APP_COLUMNS[table];
      if (column !== undefined) statements.push(`UPDATE ${quoted(table)} SET ${column} = ${column}`);
    }
    const count = await refuses(sql, statements);
    return `${count} writes and bypasses refused; app tables have no write privileges`;
  });
}
