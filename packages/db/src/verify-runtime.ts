import assert from 'node:assert/strict';
import { getTableName, is, Table } from 'drizzle-orm';
import { postgresClient } from './postgres.ts';
import * as schema from './schema.ts';

function requiredEnvironment(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

const expectedRole = requiredEnvironment('COFFRE_RUNTIME_ROLE');
const client = postgresClient(requiredEnvironment('DATABASE_URL'), { application_name: 'coffre-runtime-verification', max: 1 });

try {
  const identity = await client.unsafe<{
    current_user: string;
    memberships: string[];
    safe_membership: boolean;
    unsafe_attributes: boolean;
  }[]>(
    `SELECT current_user,
            (
              role.rolsuper OR role.rolcreatedb OR role.rolcreaterole
              OR role.rolreplication OR role.rolbypassrls
            ) AS unsafe_attributes,
            ARRAY(
              SELECT granted.rolname
                FROM pg_auth_members membership
                JOIN pg_roles granted ON granted.oid = membership.roleid
               WHERE membership.member = role.oid
               ORDER BY granted.rolname
            )::text[] AS memberships,
            (
              SELECT NOT membership.admin_option
                     AND membership.inherit_option
                     AND NOT membership.set_option
                FROM pg_auth_members membership
                JOIN pg_roles granted ON granted.oid = membership.roleid
               WHERE membership.member = role.oid
                 AND granted.rolname = 'coffre_app'
            ) AS safe_membership
       FROM pg_roles role
      WHERE role.rolname = current_user`,
  );
  assert.deepEqual([...identity], [{
    current_user: expectedRole,
    memberships: ['coffre_app'],
    safe_membership: true,
    unsafe_attributes: false,
  }]);

  const ownership = await client.unsafe<{ object_count: number }[]>(
    `SELECT count(*)::int AS object_count
       FROM pg_shdepend dependency
       JOIN pg_roles role ON role.oid = dependency.refobjid
      WHERE dependency.refclassid = 'pg_authid'::regclass
        AND dependency.deptype = 'o'
        AND role.rolname = current_user`,
  );
  assert.equal(ownership[0]?.object_count, 0, 'runtime role owns database objects');

  // In 0.16 the app's login only reads: coffre's tables, and which migrations ran (docs/design/0.16.md, "Four rules").
  // It must read each of coffre's tables and write none in the schema: another role's table there may stay
  // unreadable to it (0022 leaves those alone), but never writable.
  const tables = Object.values(schema).filter((value) => is(value, Table)).map((table) => getTableName(table as Table));
  const privileges = await client.unsafe<{
    database_create: boolean;
    database_temporary: boolean;
    migrations_select: boolean;
    schema_create: boolean;
    unreadable: string[];
    writable: string[];
  }[]>(
    `SELECT has_database_privilege(current_user, current_database(), 'CREATE') AS database_create,
            has_database_privilege(current_user, current_database(), 'TEMPORARY') AS database_temporary,
            has_schema_privilege(current_user, 'public', 'CREATE') AS schema_create,
            has_table_privilege(
              current_user, 'drizzle.__drizzle_migrations', 'SELECT'
            ) AS migrations_select,
            ARRAY(
              SELECT name FROM unnest($1::text[]) AS name
               WHERE to_regclass(format('public.%I', name)) IS NULL
                  OR NOT has_table_privilege(current_user, to_regclass(format('public.%I', name)), 'SELECT')
               ORDER BY name
            )::text[] AS unreadable,
            ARRAY(
              SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
               WHERE n.nspname = 'public' AND c.relkind IN ('r', 'S')
                 AND (CASE WHEN c.relkind = 'S' THEN has_sequence_privilege(current_user, c.oid, 'USAGE, UPDATE')
                      ELSE has_table_privilege(current_user, c.oid, 'INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER')
                        OR has_any_column_privilege(current_user, c.oid, 'INSERT, UPDATE, REFERENCES') END)
               ORDER BY c.relname
            )::text[] AS writable`,
    [tables],
  );
  assert.deepEqual([...privileges], [{
    database_create: false,
    database_temporary: false,
    migrations_select: true,
    schema_create: false,
    unreadable: [],
    writable: [],
  }]);

  console.log(`runtime database role ${expectedRole} passed privilege verification`);
} finally {
  await client.end();
}
