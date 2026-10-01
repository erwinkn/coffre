import test from 'node:test';
import assert from 'node:assert/strict';
import pg from 'pg';

import {
  TEST_OWNER_DATABASE_URL,
  TEST_RUNTIME_DATABASE_URL,
} from './connections.ts';

const EXPECTED_UPDATE_COLUMNS = [
  'audit_chain_head.head_hash',
  'audit_chain_head.next_seq',
  'audit_chain_head.updated_at',
  'audit_heartbeat.last_beat_at',
  'audit_heartbeat.last_seq',
  'credentials.last_used_at',
  'credentials.last_used_ip',
  'credentials.revoked_at',
  'credentials.revoked_by',
  'device_authorizations.consumed_at',
  'device_authorizations.decided_at',
  'device_authorizations.decision',
  'device_authorizations.principal_id',
  'device_authorizations.principal_type',
  'environments.archived_at',
  'environments.name',
  'environments.slug',
  'grants.created_by',
  'grants.expires_at',
  'grants.role_id',
  'identities.email',
  'identities.last_sign_in_at',
  'identities.revoked_at',
  'identities.revoked_by',
  'principals.active',
  'principals.created_at',
  'principals.created_by',
  'principals.instance_role',
  'projects.archived_at',
  'projects.name',
  'projects.slug',
  'secrets.archived_at',
  'secrets.current_version_id',
  'secrets.key',
  'secrets.updated_at',
  'sync_keys.pushed_at',
  'sync_keys.removed_at',
  'sync_keys.secret_version_id',
  'syncs.archived_at',
  'syncs.config',
  'syncs.credential_secret_id',
  'syncs.last_error',
  'syncs.last_run_at',
  'syncs.last_status',
  'syncs.lease_until',
  'syncs.paused_at',
];

test('Drizzle migrations preserve the restricted runtime database identity', async () => {
  const owner = new pg.Pool({ connectionString: TEST_OWNER_DATABASE_URL });
  const runtime = new pg.Pool({ connectionString: TEST_RUNTIME_DATABASE_URL });
  try {
    const migrations = await owner.query<{ count: number }>(
      'SELECT count(*)::int AS count FROM drizzle.__drizzle_migrations',
    );
    assert.equal(migrations.rows[0].count, 3);

    const identity = await runtime.query<{
      current_user: string;
      session_user: string;
      inherits_app: boolean;
      unsafe_attributes: boolean;
      memberships: string[];
      safe_membership: boolean;
    }>(
      `SELECT current_user,
              session_user,
              pg_has_role(current_user, 'coffre_app', 'USAGE') AS inherits_app,
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
      current_user: 'coffre_runtime',
      session_user: 'coffre_runtime',
      inherits_app: true,
      unsafe_attributes: false,
      memberships: ['coffre_app'],
      safe_membership: true,
    }]);

    const ownership = await owner.query<{ object_count: number }>(
      `SELECT count(*)::int AS object_count
         FROM pg_shdepend dependency
         JOIN pg_roles role ON role.oid = dependency.refobjid
        WHERE dependency.refclassid = 'pg_authid'::regclass
          AND dependency.deptype = 'o'
          AND role.rolname = 'coffre_runtime'`,
    );
    assert.equal(ownership.rows[0].object_count, 0);

    const updateColumns = await owner.query<{ column_name: string; table_name: string }>(
      `SELECT table_name, column_name
         FROM information_schema.column_privileges
        WHERE grantee = 'coffre_app'
          AND table_schema = 'public'
          AND privilege_type = 'UPDATE'
        ORDER BY table_name, column_name`,
    );
    assert.deepEqual(
      updateColumns.rows.map((row) => `${row.table_name}.${row.column_name}`),
      EXPECTED_UPDATE_COLUMNS,
    );
  } finally {
    await runtime.end();
    await owner.end();
  }
});
