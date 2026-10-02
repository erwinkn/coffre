// Called by test-schema-owner.sh against its local TLS server.
import assert from 'node:assert/strict';
import { sql } from 'drizzle-orm';

import { openDatabase } from '../src/connect.ts';
import { migrateDatabase } from '../src/migrate.ts';

const [url, expected] = process.argv.slice(2);
assert.ok(url, 'a local Postgres URL is required');
const connection = await openDatabase(url);
try {
  const query = () => connection.db.execute(sql`SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()`);
  if (expected === undefined) {
    await migrateDatabase(url);
    assert.deepEqual((await query()).rows, [{ ssl: true }]);
  } else {
    assert.ok(['DEPTH_ZERO_SELF_SIGNED_CERT', 'ERR_TLS_CERT_ALTNAME_INVALID'].includes(expected));
    const refused = (error: Error & { code?: string; cause?: { code: string } }) => {
      assert.equal(error.cause?.code ?? error.code, expected);
      return true;
    };
    await assert.rejects(query(), refused);
    await assert.rejects(migrateDatabase(url), refused);
  }
} finally {
  await connection.close();
}
console.log(`Postgres TLS: ${expected ?? 'trusted CA and hostname verified'}`);
