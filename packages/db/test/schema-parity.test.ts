import test from 'node:test';
import assert from 'node:assert/strict';

import { getTableName, is, Table } from 'drizzle-orm';
import { getTableConfig as postgresConfig } from 'drizzle-orm/pg-core';
import { getTableConfig as sqliteConfig } from 'drizzle-orm/sqlite-core';

import { ENGINES, journal, staleness } from '../src/baseline.ts';
import { KNOWN_MIGRATIONS } from '../src/schema-version.ts';
import * as postgres from '../src/schema.ts';
import * as sqlite from '../src/schema.sqlite.ts';

/**
 * Both schemas are one schema, and each migration tree ends where its
 * schema is. Together: the trees are in step. A schema change made on one
 * engine fails the first test until the other schema follows, and the
 * second until `pnpm db:generate` has appended the migrations.
 *
 * Row types are checked at compile time, in portable.ts. Check constraints
 * are compared by name only: their bodies are each dialect's own. So are
 * the indexes `KEYED_APART` names, each keyed for its engine's planner.
 */

/**
 * The indexes keyed apart on each engine, compared by name, and why.
 * `audit_log_access_idx` (T239): by principal on Postgres, which takes
 * `author = 'vault'`, implied by its condition, for no bound, so `author`
 * first would leave each step past a principal to scan from the start; and
 * `author` first on SQLite, as the subject index, which SQLite's planner
 * otherwise picks over it for matching more equalities. `audit_log_vault_idx`
 * and `audit_log_app_idx` (T245): by `seq` alone on Postgres; `author` first
 * on SQLite, which otherwise takes `audit_log_key_idx` for its `author` and
 * sorts every entry of that author's. `audit_log_signed_idx` and
 * `audit_log_vault_refused_idx` (T245): without the columns their
 * conditions fix on Postgres (`seq` alone for the first); with them on
 * SQLite, which otherwise picks `audit_log_action_idx`.
 */
const KEYED_APART = new Set(['audit_log_access_idx', 'audit_log_vault_idx', 'audit_log_app_idx', 'audit_log_signed_idx', 'audit_log_vault_refused_idx']);

type Config = ReturnType<typeof postgresConfig>;
type AnyColumn = Config['columns'][number];

const names = (columns: { name: string }[]) => columns.map((column) => column.name).join(',');

/** A table as the parity test sees it: what can be compared across dialects. */
function shape(config: Config) {
  const primaryKey = config.primaryKeys.length > 0
    ? names(config.primaryKeys[0].columns)
    : names(config.columns.filter((column: AnyColumn) => column.primary));
  const unique = [
    ...config.uniqueConstraints.map((constraint) => `${constraint.name}(${names(constraint.columns)})`),
    ...config.columns
      .filter((column: AnyColumn) => column.isUnique)
      .map((column: AnyColumn) => `${column.uniqueName}(${column.name})`),
  ];
  const indexes = config.indexes.map((index) => {
    const { name, unique: isUnique, columns } = index.config as { name: string; unique: boolean; columns: { name: string }[] };
    return `${isUnique ? 'unique ' : ''}${name}${KEYED_APART.has(name) ? '' : `(${names(columns)})`}`;
  });
  const foreignKeys = config.foreignKeys.map((foreignKey) => {
    const { columns, foreignColumns, foreignTable } = foreignKey.reference();
    return `${foreignKey.getName()}(${names(columns)}) -> ${getTableName(foreignTable)}(${names(foreignColumns)}) on delete ${foreignKey.onDelete ?? 'no action'}`;
  });
  return {
    columns: config.columns.map((column: AnyColumn) =>
      `${column.name}${column.notNull ? ' not null' : ''}${column.generated ? ' generated' : ''}`),
    primaryKey,
    unique: unique.sort(),
    indexes: indexes.sort(),
    foreignKeys: foreignKeys.sort(),
    checks: config.checks.map((check) => check.name).sort(),
  };
}

function shapes(schema: Record<string, unknown>, config: (table: never) => unknown) {
  return Object.fromEntries(
    Object.values(schema)
      .filter((value) => is(value, Table))
      .map((table) => [getTableName(table as Table), shape(config(table as never) as Config)])
      .sort(([a], [b]) => String(a).localeCompare(String(b))),
  );
}

test('the SQLite schema has the Postgres tables, columns, nullability and keys', () => {
  const expected = shapes(postgres, postgresConfig);
  assert.deepEqual(Object.keys(expected), ['audit_chain_head', 'audit_log', 'bulk_cap', 'capped_alerts', 'checkpoint_fence', 'credentials', 'device_logins', 'dismissed_keys', 'enrollment_codes', 'environments', 'grants', 'identities', 'log_changes', 'log_checkpoints', 'log_config', 'log_read_days', 'log_read_place_days', 'log_reads', 'log_reads_cursor', 'log_tiles', 'log_uses', 'mcp_approvals', 'mcp_connections', 'oauth_clients', 'passkeys', 'policy', 'principals', 'projects', 'proxy_definitions', 'proxy_reserved', 'roles', 'secret_references', 'secret_versions', 'secrets', 'service_bindings', 'spent_id_tokens', 'vault_releases']);
  assert.deepEqual(shapes(sqlite, sqliteConfig), expected);
});

test('each migration tree ends at its schema and starts at its baseline', async () => {
  const stale = Object.fromEntries(await Promise.all(ENGINES.map(async (engine) => [engine, await staleness(engine)])));
  // Anything listed here needs `pnpm db:generate`.
  assert.deepEqual(stale, { postgres: [], sqlite: [] });
});

test('the app knows every migration in each tree, by its journal, as a Worker without files does', async () => {
  for (const engine of ENGINES) {
    assert.deepEqual(KNOWN_MIGRATIONS[engine], (await journal(engine)).map((entry) => entry.tag), engine);
  }
});
