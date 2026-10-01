import type { Sql } from '../database.ts';
import { expect } from '../report.ts';

export const TABLES = [
  'projects', 'environments', 'secrets', 'secret_versions', 'vault_members', 'vault_grants',
  'audit_log', 'audit_chain_head', 'identities', 'credentials', 'device_authorizations', 'syncs', 'sync_keys',
] as const;

/** Inspect every table, including any a deployment added. Missing shared tables fail. */
export async function tables(sql: Sql): Promise<string[]> {
  const rows = await sql.query<{ name: string }>(sql.engine === 'postgres'
    ? `SELECT table_name AS name FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE'`
    : `SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'`);
  const names = rows.map((row) => row.name);
  const missing = TABLES.filter((name) => !names.includes(name));
  expect(missing.length === 0, 'shared tables could not be inspected', missing);
  return names;
}

export function quoted(name: string): string {
  return `"${name.replaceAll('"', '""')}"`;
}

/** Both drivers return binary columns as bytes; casting records to text hides bytea. */
export async function scanTables(sql: Sql, names: string[], look: (where: string, bytes: string | Uint8Array) => void): Promise<void> {
  for (const name of names) {
    for (const row of await sql.query(`SELECT * FROM ${quoted(name)}`)) {
      for (const value of Object.values(row)) {
        look(`the database's ${name} table`, value instanceof Uint8Array ? value : JSON.stringify(value) ?? '');
      }
    }
  }
}

/** Parameters use one spelling in the checks, whatever the database. */
export function query<Row = Record<string, unknown>>(sql: Sql, statement: string, params: unknown[] = []): Promise<Row[]> {
  return sql.query<Row>(sql.engine === 'sqlite' ? statement.replace(/\$\d+/g, '?') : statement, params);
}

/** Put a saved row back without changing its bytes or its generated columns. */
export async function restoreRow(sql: Sql, table: string, row: Record<string, unknown>, key: string): Promise<void> {
  const fields = Object.keys(row).filter((field) => field !== key && field !== 'active_subject');
  await query(sql, `UPDATE ${quoted(table)} SET ${fields.map((field, i) => `${quoted(field)} = $${i + 1}`).join(', ')} WHERE ${quoted(key)} = $${fields.length + 1}`,
    [...fields.map((field) => row[field]), row[key]]);
}

/** Keep a deliberate rewrite, and its restoration, invisible until each is complete. */
export async function transaction<T>(sql: Sql, work: () => Promise<T>): Promise<T> {
  await sql.exec('BEGIN');
  try {
    const result = await work();
    await sql.exec('COMMIT');
    return result;
  } catch (error) {
    await sql.exec('ROLLBACK');
    throw error;
  }
}
