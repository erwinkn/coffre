// SQL around coffre, as the database's owner: what the checks read, change
// and put back behind its back.
import type { Sql } from '../database.ts';
import type { Deployment } from '../harness.ts';
import { expect, until } from '../report.ts';

export const TABLES = [
  'projects', 'environments', 'secrets', 'secret_versions', 'principals', 'grants',
  'log_pending', 'log', 'log_head', 'identities', 'credentials', 'device_logins',
] as const;

/** Inspect every table, including any a deployment added. Missing shared tables fail. */
export async function tables(sql: Sql): Promise<string[]> {
  const rows = await sql.query<{ name: string }>(
    `SELECT table_name AS name FROM information_schema.tables WHERE table_schema = $1 AND table_type = 'BASE TABLE'`, [sql.schema]);
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
  return sql.query<Row>(statement, params);
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

export const LOG_REFUSAL = 'coffre-conformance: the log refuses writes';

/**
 * `work` with the log refusing appends, of one action or all, as a full
 * disk or a lost connection would, without changing the deployment's code:
 * a trigger on `log_pending`, where the vault appends each entry, dropped
 * after.
 */
export async function logRefuses<T>(sql: Sql, work: () => Promise<T>, action?: string): Promise<T> {
  const when = action === undefined ? '' : ` WHEN ((NEW.body::jsonb)->>'action' = '${action}')`;
  await sql.exec(`CREATE FUNCTION conformance_refuse() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN RAISE EXCEPTION '${LOG_REFUSAL}'; END $$;
    CREATE TRIGGER conformance_refuse BEFORE INSERT ON log_pending FOR EACH ROW${when} EXECUTE FUNCTION conformance_refuse();`);
  try {
    return await work();
  } finally {
    await sql.exec('DROP TRIGGER conformance_refuse ON log_pending; DROP FUNCTION conformance_refuse();');
  }
}

/** A log entry's body as the vault writes it (`Entry` in @coffre/vault): the fields the checks read. */
export type Body = {
  action: string;
  actor: string | null;
  request: string | null;
  objects: string[];
  detail: Record<string, unknown>;
};

/** Every entry, signed (`log`) or waiting to be (`log_pending`), oldest first, read in one statement. */
export async function logBodies(sql: Sql): Promise<Body[]> {
  const rows = await sql.query<{ body: string }>('SELECT body FROM (SELECT seq, 0 AS waiting, body FROM log UNION ALL SELECT id, 1, body FROM log_pending) entries ORDER BY waiting, seq');
  return rows.map((row) => JSON.parse(row.body) as Body);
}

/**
 * Wait for the signer's alert naming a row (`nameOf` in @coffre/vault:
 * its table and key), in the processes' output, where a deployment with no
 * `alert` of its own sends it. Its check runs each minute.
 */
export async function alerted(deployment: Deployment, table: string, ...key: unknown[]): Promise<void> {
  const named = `- row ${JSON.stringify([table, ...key])}:`;
  await until(`the signer's alert naming ${named}`, async () => deployment.output().includes(named), 150);
}
