import assert from 'node:assert/strict';
import pg from 'pg';

import { postgresConnection } from './postgres.ts';

function requiredEnvironment(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

const expectedRole = requiredEnvironment('COFFRE_RUNTIME_ROLE');
const pool = new pg.Pool({
  application_name: 'coffre-runtime-verification',
  ...postgresConnection(requiredEnvironment('DATABASE_URL')),
  max: 1,
});

try {
  const identity = await pool.query<{
    current_user: string;
    memberships: string[];
    safe_membership: boolean;
    unsafe_attributes: boolean;
  }>(
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
  assert.deepEqual(identity.rows, [{
    current_user: expectedRole,
    memberships: ['coffre_app'],
    safe_membership: true,
    unsafe_attributes: false,
  }]);

  const ownership = await pool.query<{ object_count: number }>(
    `SELECT count(*)::int AS object_count
       FROM pg_shdepend dependency
       JOIN pg_roles role ON role.oid = dependency.refobjid
      WHERE dependency.refclassid = 'pg_authid'::regclass
        AND dependency.deptype = 'o'
        AND role.rolname = current_user`,
  );
  assert.equal(ownership.rows[0]?.object_count, 0, 'runtime role owns database objects');

  const privileges = await pool.query<{
    audit_delete: boolean;
    audit_truncate: boolean;
    audit_update: boolean;
    database_create: boolean;
    database_temporary: boolean;
    head_next_seq_update: boolean;
    head_hash_update: boolean;
    migrations_select: boolean;
    schema_create: boolean;
  }>(
    `SELECT has_database_privilege(current_user, current_database(), 'CREATE') AS database_create,
            has_database_privilege(current_user, current_database(), 'TEMPORARY') AS database_temporary,
            has_schema_privilege(current_user, 'public', 'CREATE') AS schema_create,
            has_table_privilege(current_user, 'public.audit_log', 'UPDATE') AS audit_update,
            has_table_privilege(current_user, 'public.audit_log', 'DELETE') AS audit_delete,
            has_table_privilege(current_user, 'public.audit_log', 'TRUNCATE') AS audit_truncate,
            has_column_privilege(
              current_user, 'public.audit_chain_head', 'next_seq', 'UPDATE'
            ) AS head_next_seq_update,
            has_column_privilege(
              current_user, 'public.audit_chain_head', 'head_hash', 'UPDATE'
            ) AS head_hash_update,
            has_table_privilege(
              current_user, 'drizzle.__drizzle_migrations', 'SELECT'
            ) AS migrations_select`,
  );
  assert.deepEqual(privileges.rows, [{
    audit_delete: false,
    audit_truncate: false,
    audit_update: false,
    database_create: false,
    database_temporary: false,
    head_next_seq_update: true,
    head_hash_update: true,
    migrations_select: true,
    schema_create: false,
  }]);

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // What every append does to the log's head, rolled back.
    const head = await client.query(
      `UPDATE audit_chain_head SET next_seq = next_seq, head_hash = head_hash WHERE only_row`,
    );
    assert.equal(head.rowCount, 1, 'runtime head update did not affect the singleton');
  } finally {
    await client.query('ROLLBACK');
    client.release();
  }

  console.log(`runtime database role ${expectedRole} passed privilege verification`);
} finally {
  await pool.end();
}
