import assert from 'node:assert/strict';
import test from 'node:test';

import { getTableConfig as getMysqlTableConfig } from 'drizzle-orm/mysql-core';
import { getTableConfig as getPostgresTableConfig } from 'drizzle-orm/pg-core';
import { getTableConfig as getSqliteTableConfig } from 'drizzle-orm/sqlite-core';

import * as mysqlSchema from './schema.mysql.ts';
import * as postgresSchema from './schema.postgres.ts';
import * as sqliteSchema from './schema.sqlite.ts';

type Equal<Left, Right> =
  (<Value>() => Value extends Left ? 1 : 2) extends
  (<Value>() => Value extends Right ? 1 : 2)
    ? true
    : false;
type Assert<Condition extends true> = Condition;

type SelectContract<Schema extends {
  projects: { $inferSelect: unknown };
  environments: { $inferSelect: unknown };
  secrets: { $inferSelect: unknown };
  secretVersions: { $inferSelect: unknown };
  auditChainHead: { $inferSelect: unknown };
  auditLog: { $inferSelect: unknown };
}> = {
  [Table in keyof Schema]: Schema[Table] extends { $inferSelect: infer Select }
    ? Select
    : never;
};

type PostgresData = SelectContract<typeof postgresSchema>;
type MysqlDataMatches = Assert<Equal<SelectContract<typeof mysqlSchema>, PostgresData>>;
type SqliteDataMatches = Assert<Equal<SelectContract<typeof sqliteSchema>, PostgresData>>;

// These aliases make drift in selected TypeScript data a compile error. SQLite
// integer primary keys are optional in Drizzle's inferred insert model because
// SQLite can generate rowids, so application insert contracts remain explicit.
const dataContractsMatch: MysqlDataMatches & SqliteDataMatches = true;

type TableContract = Record<string, Array<{
  name: string;
  notNull: boolean;
  primary: boolean;
}>>;

function contract(
  schema: Record<string, unknown>,
  getConfig: (table: never) => { name: string; columns: Array<{
    name: string;
    notNull: boolean;
    primary: boolean;
  }> },
): TableContract {
  return Object.values(schema).reduce<TableContract>((result, table) => {
    const config = getConfig(table as never);
    result[config.name] = config.columns
      .map((column) => ({
        name: column.name,
        notNull: column.notNull,
        primary: column.primary,
      }))
      .sort((left, right) => left.name.localeCompare(right.name));
    return result;
  }, {});
}

test('all dialect schemas expose the same tables, columns, nullability and primary keys', () => {
  assert.equal(dataContractsMatch, true);
  const postgres = contract(postgresSchema, getPostgresTableConfig);
  assert.deepEqual(contract(mysqlSchema, getMysqlTableConfig), postgres);
  assert.deepEqual(contract(sqliteSchema, getSqliteTableConfig), postgres);
});
