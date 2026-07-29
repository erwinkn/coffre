import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import pg from 'pg';

import {
  TEST_OWNER_DATABASE_URL,
  TEST_RUNTIME_DATABASE_URL,
} from './connections.ts';

const execFileAsync = promisify(execFile);
const ROOT = fileURLToPath(new URL('../../..', import.meta.url));
const PROVISION = fileURLToPath(
  new URL('../../../scripts/provision-runtime-role.sh', import.meta.url),
);

test('external provisioning requires an explicit runtime password', async () => {
  await assert.rejects(
    execFileAsync(PROVISION, {
      cwd: ROOT,
      env: {
        ...process.env,
        COFFRE_OWNER_DATABASE_URL:
          'postgresql://owner:secret@database.example/coffre',
        COFFRE_RUNTIME_PASSWORD: '',
      },
    }),
    (error: unknown) =>
      error instanceof Error &&
      'stderr' in error &&
      /COFFRE_RUNTIME_PASSWORD is required/.test(String(error.stderr)),
  );
});

test('owner migrations and provisioning create the restricted runtime login', async () => {
  await execFileAsync(PROVISION, {
    cwd: ROOT,
    env: {
      ...process.env,
      COMPOSE_PROJECT_NAME: 'coffre',
      COFFRE_DATABASE_NAME: 'coffre_test',
      COFFRE_RUNTIME_ROLE: 'coffre_test_app',
      COFFRE_RUNTIME_PASSWORD: 'test-runtime-only',
    },
  });

  const owner = new pg.Pool({ connectionString: TEST_OWNER_DATABASE_URL });
  const runtime = new pg.Pool({ connectionString: TEST_RUNTIME_DATABASE_URL });
  try {
    const migrations = await owner.query<{ name: string }>(
      'SELECT name FROM schema_migrations ORDER BY name',
    );
    assert.deepEqual(
      migrations.rows.map((row) => row.name),
      [
        '0001_init.sql',
        '0002_audit_log.sql',
        '0003_roles.sql',
        '0004_project_grants_and_archiving.sql',
        '0005_roles_and_secret_archiving.sql',
        '0006_principal_directory.sql',
        '0007_principal_lifecycle.sql',
        '0008_runtime_role.sql',
      ],
    );

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
      current_user: 'coffre_test_app',
      session_user: 'coffre_test_app',
      inherits_app: true,
      unsafe_attributes: false,
      memberships: ['coffre_app'],
      safe_membership: true,
    }]);
  } finally {
    await runtime.end();
    await owner.end();
  }
});
