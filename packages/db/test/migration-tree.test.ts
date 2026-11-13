import test from 'node:test';
import assert from 'node:assert/strict';

import { getTableName, is, Table } from 'drizzle-orm';

import { journal, staleness } from '../src/baseline.ts';
import { KNOWN_MIGRATIONS } from '../src/schema-version.ts';
import * as schema from '../src/schema.ts';

// A table added, renamed or dropped changes this list in the same change, on purpose.
test('the schema has exactly its tables', () => {
  const names = Object.values(schema).filter((value) => is(value, Table)).map((table) => getTableName(table as Table)).sort();
  assert.deepEqual(names, ['audit_chain_head', 'audit_cursor', 'audit_event_places', 'audit_events', 'audit_log', 'audit_member_keys', 'bulk_cap', 'capped_alerts', 'checkpoint_fence', 'credentials', 'device_logins', 'dismissed_keys', 'enrollment_codes', 'environments', 'grants', 'identities', 'log_changes', 'log_checkpoints', 'log_config', 'log_keys', 'log_read_days', 'log_read_place_days', 'log_reads', 'log_reads_cursor', 'log_tiles', 'log_uses', 'mcp_approvals', 'mcp_connections', 'oauth_clients', 'passkeys', 'policy', 'principals', 'projects', 'proxy_definitions', 'proxy_reserved', 'roles', 'secret_references', 'secret_versions', 'secrets', 'service_bindings', 'settings', 'spent_id_tokens', 'vault_releases']);
});

// A schema change fails this test until `pnpm db:generate` has appended its migration.
test('the migration tree ends at the schema and starts at its baseline', async () => {
  assert.deepEqual(await staleness(), []);
});

test('the app knows every migration in the tree, by its journal, as a Worker without files does', async () => {
  assert.deepEqual(KNOWN_MIGRATIONS, (await journal()).map((entry) => entry.tag));
});
