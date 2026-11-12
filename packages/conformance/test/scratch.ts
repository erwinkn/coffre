import { randomBytes } from 'node:crypto';
import type test from 'node:test';

import { postgres, using, type Sql } from '../src/database.ts';

const DATABASE = `postgresql://coffre_owner:local-dev-only@127.0.0.1:${process.env.COFFRE_POSTGRES_PORT ?? '55432'}/${process.env.COFFRE_TEST_DATABASE ?? 'coffre_test'}`;

/**
 * A schema of the test's own in the test database, dropped after it: the tables a check reads, as a fixture makes them,
 * beside none of the migrated ones. Each call opens a session on it.
 */
export async function scratch(t: test.TestContext): Promise<() => Promise<Sql>> {
  const schema = `conformance_${randomBytes(6).toString('hex')}`;
  await using(postgres(DATABASE), (sql) => sql.exec(`CREATE SCHEMA ${schema}`));
  t.after(() => using(postgres(DATABASE), (sql) => sql.exec(`DROP SCHEMA ${schema} CASCADE`)));
  const url = `${DATABASE}?options=${encodeURIComponent(`-c search_path=${schema}`)}`;
  return () => postgres(url, schema);
}
