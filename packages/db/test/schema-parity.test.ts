import test from 'node:test';
import assert from 'node:assert/strict';

import { getTableName, is, Table } from 'drizzle-orm';
import { getTableConfig as postgresConfig } from 'drizzle-orm/pg-core';
import { getTableConfig as sqliteConfig } from 'drizzle-orm/sqlite-core';

import { ENGINES, journal, staleness } from '../src/baseline.ts';
import { REQUIRED_MIGRATIONS } from '../src/schema-version.ts';
import * as postgres from '../src/schema.ts';
import * as sqlite from '../src/schema.sqlite.ts';

/**
 * Both schemas are one schema, and each migration tree ends where its
 * schema is. Together: the trees are in step. A schema change made on one
 * engine fails the first test until the other schema follows, and the
 * second until `pnpm db:generate` has appended the migrations.
 *
 * Row types are checked at compile time, in portable.ts. Check constraints
 * are compared by name only: their bodies are each dialect's own.
 */

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
    return `${isUnique ? 'unique ' : ''}${name}(${names(columns)})`;
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
  assert.deepEqual(Object.keys(expected), ['audit_chain_head', 'audit_log', 'consumed_tokens', 'credentials', 'device_authorizations', 'dismissed_keys', 'environments', 'identities', 'project_folders', 'projects', 'secret_folders', 'secret_references', 'secret_versions', 'secrets', 'service_bindings', 'vault_grants', 'vault_members']);
  assert.deepEqual(shapes(sqlite, sqliteConfig), expected);
});

test('each migration tree ends at its schema and preserves its original baseline', async () => {
  const stale = Object.fromEntries(await Promise.all(ENGINES.map(async (engine) => [engine, await staleness(engine)])));
  // Anything listed here needs `pnpm db:generate`.
  assert.deepEqual(stale, { postgres: [], sqlite: [] });
});

test('the runtime requires a nonempty prefix that exists in each migration tree', async () => {
  for (const engine of ENGINES) {
    const required = REQUIRED_MIGRATIONS[engine];
    assert.ok(Number.isSafeInteger(required) && required > 0, engine);
    assert.ok(required <= (await journal(engine)).length, engine);
  }
});
