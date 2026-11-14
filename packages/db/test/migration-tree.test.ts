import test from 'node:test';
import assert from 'node:assert/strict';

import { getTableName, is, Table } from 'drizzle-orm';

import { journal, staleness } from '../src/baseline.ts';
import { KNOWN_MIGRATIONS } from '../src/schema-version.ts';
import * as schema from '../src/schema.ts';

// A table added, renamed or dropped changes this list in the same change, on purpose.
test('the schema has exactly its tables', () => {
  const names = Object.values(schema).filter((value) => is(value, Table)).map((table) => getTableName(table as Table)).sort();
  assert.deepEqual(names, ['audit_archive', 'bindings', 'credentials', 'device_logins', 'dismissed_keys', 'enrollment_codes', 'environments', 'exposures', 'grants', 'identities', 'log', 'log_head', 'log_index', 'log_pending', 'log_tiles', 'mcp_approvals', 'oauth_clients', 'policy', 'principals', 'projects', 'roles', 'secret_versions', 'secrets', 'spent_id_tokens']);
});

// A schema change fails this test until `pnpm db:generate` has appended its migration.
test('the migration tree ends at the schema and starts at its baseline', async () => {
  assert.deepEqual(await staleness(), []);
});

test('the app knows every migration in the tree, by its journal, as a Worker without files does', async () => {
  assert.deepEqual(KNOWN_MIGRATIONS, (await journal()).map((entry) => entry.tag));
});
