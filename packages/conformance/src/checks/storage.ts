// SQL around coffre, as the database's owner: what the checks read, change
// and put back behind its back, on Postgres or SQLite alike.
import type { Sql } from '../database.ts';
import { expect } from '../report.ts';

export const TABLES = [
  'projects', 'environments', 'secrets', 'secret_versions', 'vault_members', 'vault_grants',
  'audit_log', 'audit_chain_head', 'identities', 'credentials', 'device_authorizations',
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

/** Insert a saved or forged row as it is, but for its generated columns. */
export async function insertRow(sql: Sql, table: string, row: Record<string, unknown>): Promise<void> {
  const fields = Object.keys(row).filter((field) => field !== 'active_subject');
  await query(sql, `INSERT INTO ${quoted(table)} (${fields.map(quoted).join(', ')}) VALUES (${fields.map((_, i) => `$${i + 1}`).join(', ')})`,
    fields.map((field) => row[field]));
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

/**
 * `work` with the audit log's append-only triggers lifted, as only its owner
 * can: Postgres disables them for the session, SQLite drops them and makes
 * them again after.
 */
export async function appendOnlyLifted<T>(sql: Sql, work: () => Promise<T>): Promise<T> {
  if (sql.engine === 'postgres') {
    await sql.exec('ALTER TABLE audit_log DISABLE TRIGGER USER');
    try {
      return await work();
    } finally {
      await sql.exec('ALTER TABLE audit_log ENABLE TRIGGER USER');
    }
  }
  const triggers = await sql.query<{ name: string; sql: string }>(
    `SELECT name, sql FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'audit_log'`,
  );
  for (const trigger of triggers) await sql.exec(`DROP TRIGGER ${trigger.name}`);
  try {
    return await work();
  } finally {
    for (const trigger of triggers) await sql.exec(trigger.sql);
  }
}

export const LOG_REFUSAL = 'coffre-conformance: the log refuses writes';

/**
 * `work` with the audit log refusing appends, of one action or all, as a
 * full disk or a lost connection would, without changing the deployment's
 * code: a trigger, dropped after.
 */
export async function logRefuses<T>(sql: Sql, work: () => Promise<T>, action?: string): Promise<T> {
  const when = action === undefined ? '' : ` WHEN (NEW.action = '${action}')`;
  const create = sql.engine === 'postgres'
    ? `CREATE FUNCTION conformance_refuse() RETURNS trigger LANGUAGE plpgsql AS $$
       BEGIN RAISE EXCEPTION '${LOG_REFUSAL}'; END $$;
       CREATE TRIGGER conformance_refuse BEFORE INSERT ON audit_log FOR EACH ROW${when} EXECUTE FUNCTION conformance_refuse();`
    : `CREATE TRIGGER conformance_refuse BEFORE INSERT ON audit_log${when}
       BEGIN SELECT RAISE(ABORT, '${LOG_REFUSAL}'); END;`;
  await sql.exec(create);
  try {
    return await work();
  } finally {
    await sql.exec(sql.engine === 'postgres'
      ? 'DROP TRIGGER conformance_refuse ON audit_log; DROP FUNCTION conformance_refuse();'
      : 'DROP TRIGGER conformance_refuse;');
  }
}

/** The log's fields in the order its format (`coffre.audit.v2`) encodes them. */
const ENTRY_FIELDS = [
  'seq', 'author', 'key_id', 'occurred_at', 'actor', 'action', 'decision', 'code', 'subject_principal', 'project_id',
  'environment_id', 'secret_id', 'secret_version_id', 'operation_id', 'request_id', 'source_ip', 'related_seq', 'metadata',
] as const;

/**
 * An entry's fields as its MAC and hash cover them, written here from the
 * format rather than taken from coffre, so a check does not trust the code
 * it checks: each field length-prefixed in order, null as length -1.
 */
export function entryFields(row: Record<string, unknown>): Buffer {
  return Buffer.concat(ENTRY_FIELDS.flatMap((field) => {
    const header = Buffer.alloc(4);
    const value = row[field];
    if (value === null || value === undefined) {
      header.writeInt32BE(-1);
      return [header];
    }
    const bytes = Buffer.from(String(value));
    header.writeInt32BE(bytes.length);
    return [header, bytes];
  }));
}
