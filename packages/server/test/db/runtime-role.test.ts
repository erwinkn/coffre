import test from 'node:test';
import assert from 'node:assert/strict';
import { postgresClient } from '@coffre/db/connect';
import { migrateDatabase } from '@coffre/db/migrate';
import { KNOWN_MIGRATIONS } from '@coffre/db/schema-version';

import {
  TEST_OWNER_DATABASE_URL,
  TEST_RUNTIME_DATABASE_URL,
} from './connections.ts';


test(
  'Drizzle migrations preserve the restricted runtime database identity',
  async () => {
    const owner = postgresClient(TEST_OWNER_DATABASE_URL);
    const runtime = postgresClient(TEST_RUNTIME_DATABASE_URL);
    try {
      const [migrations] = await owner.unsafe<[{ count: number }]>(
        'SELECT count(*)::int AS count FROM drizzle.__drizzle_migrations',
      );
      assert.equal(migrations.count, KNOWN_MIGRATIONS.length);

      const identity = await runtime.unsafe<{
        current_user: string;
        session_user: string;
        inherits_app: boolean;
        unsafe_attributes: boolean;
        memberships: string[];
        safe_membership: boolean;
      }[]>(
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

      assert.deepEqual([...identity], [{
        current_user: 'coffre_runtime',
        session_user: 'coffre_runtime',
        inherits_app: true,
        unsafe_attributes: false,
        memberships: ['coffre_app'],
        safe_membership: true,
      }]);

      const [ownership] = await owner.unsafe<[{ object_count: number }]>(
        `SELECT count(*)::int AS object_count
           FROM pg_shdepend dependency
           JOIN pg_roles role ON role.oid = dependency.refobjid
          WHERE dependency.refclassid = 'pg_authid'::regclass
            AND dependency.deptype = 'o'
            AND role.rolname = 'coffre_runtime'`,
      );
      assert.equal(ownership.object_count, 0);

      // In 0.16 the app writes nothing: every change is the vault's (docs/design/0.16.md, "Tables"). Its
      // group holds SELECT and nothing else, on no table and no column of one.
      const writes = await owner.unsafe<{ privilege: string }[]>(
        `SELECT format('%s.%s', table_name, privilege_type) AS privilege
           FROM information_schema.table_privileges
          WHERE grantee = 'coffre_app' AND table_schema = 'public' AND privilege_type <> 'SELECT'
         UNION ALL
         SELECT format('%s.%s.%s', table_name, column_name, privilege_type)
           FROM information_schema.column_privileges
          WHERE grantee = 'coffre_app' AND table_schema = 'public' AND privilege_type <> 'SELECT'
          ORDER BY 1`,
      );
      assert.deepEqual(writes.map(({ privilege }) => privilege), []);
    } finally {
      await runtime.end();
      await owner.end();
    }
  },
);

test(
  'migrate reasserts database privileges even when no migrations are pending',
  async () => {
    const owner = postgresClient(TEST_OWNER_DATABASE_URL);
    const revoke = `DO $$ BEGIN
      EXECUTE format(
        'REVOKE CREATE, TEMPORARY ON DATABASE %I FROM PUBLIC, coffre_app, coffre_runtime, coffre_vault, coffre_vault_runtime, coffre_backup',
        current_database()
      );
    END $$`;
    const privileges = async () => [...await owner.unsafe<{ role: string; create: boolean; temporary: boolean }[]>(
      `SELECT role,
              has_database_privilege(role, current_database(), 'CREATE') AS create,
              has_database_privilege(role, current_database(), 'TEMPORARY') AS temporary
         FROM unnest(ARRAY['coffre_app', 'coffre_backup', 'coffre_runtime', 'coffre_vault', 'coffre_vault_runtime']) AS role
        ORDER BY role`,
    )];
    try {
      // A one-database dump leaves these privileges behind, including PUBLIC's defaults.
      await owner.unsafe(`DO $$ BEGIN
        EXECUTE format(
          'GRANT CREATE, TEMPORARY ON DATABASE %I TO PUBLIC, coffre_app, coffre_runtime, coffre_vault, coffre_vault_runtime, coffre_backup',
          current_database()
        );
      END $$`);
      assert.ok((await privileges()).every((row) => row.create && row.temporary));

      for (let run = 0; run < 2; run++) {
        await migrateDatabase(TEST_OWNER_DATABASE_URL);
        assert.deepEqual(await privileges(), [
          { role: 'coffre_app', create: false, temporary: false },
          { role: 'coffre_backup', create: false, temporary: false },
          { role: 'coffre_runtime', create: false, temporary: false },
          { role: 'coffre_vault', create: false, temporary: false },
          { role: 'coffre_vault_runtime', create: false, temporary: false },
        ]);
      }
    } finally {
      await owner.unsafe(revoke);
      await owner.end();
    }
  },
);
