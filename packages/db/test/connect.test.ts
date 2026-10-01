import test from 'node:test';
import assert from 'node:assert/strict';

import { engineOfUrl, openDatabase } from '../src/connect.ts';
import { migrateDatabase } from '../src/migrate.ts';

test('MySQL URLs are refused before opening a connection or running migrations', async () => {
  const url = 'mysql://unused:unused@127.0.0.1:1/coffre';
  const error = { message: 'coffre supports Postgres; MySQL support was removed' };
  assert.throws(() => engineOfUrl(url), error);
  await assert.rejects(openDatabase(url), error);
  await assert.rejects(migrateDatabase(url), error);
});

test('Postgres and local SQLite URLs retain their database engines', () => {
  assert.equal(engineOfUrl('postgres://localhost/coffre'), 'postgres');
  assert.equal(engineOfUrl('postgresql://localhost/coffre'), 'postgres');
  assert.equal(engineOfUrl('file:coffre.db'), 'sqlite');
});
