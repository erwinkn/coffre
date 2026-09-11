import { Client } from 'pg';
import { readFile } from 'node:fs/promises';
import assert from 'node:assert/strict';
const admin = new Client({ connectionString: process.env.TEST_POSTGRES_URL });
await admin.connect();
try {
  await admin.query("CREATE ROLE coffre_runtime LOGIN PASSWORD 'synthetic-runtime-password'");
  await admin.query(await readFile('packages/storage/migrations/postgres-runtime-role.sql', 'utf8'));
  const url = new URL(process.env.TEST_POSTGRES_URL); url.username = 'coffre_runtime'; url.password = 'synthetic-runtime-password';
  const client = new Client({ connectionString: url.href }); await client.connect();
  try {
    for (const query of ['UPDATE coffre_audit SET record=record', 'DELETE FROM coffre_audit', 'TRUNCATE coffre_audit']) {
      await assert.rejects(client.query(query), error => error.code === '42501');
    }
    const result = await client.query("SELECT has_table_privilege(current_user,'coffre_audit','INSERT') AS can_insert, has_table_privilege(current_user,'coffre_audit','SELECT') AS can_select");
    assert.equal(result.rows[0].can_insert, true); assert.equal(result.rows[0].can_select, true);
    console.log('Restricted PostgreSQL runtime role cannot UPDATE, DELETE, or TRUNCATE audit rows.');
  } finally { await client.end(); }
} finally { await admin.end(); }
