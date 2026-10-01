import test from 'node:test';
import assert from 'node:assert/strict';

import { createDatabase } from '../../src/db/database.ts';
import { findCredential } from '../../src/db/queries.ts';

// Hyperdrive caches a read for up to a minute unless its config was created
// with --caching-disabled, and never caches one that calls a stable or
// volatile function. The credential lookup runs on every request, outside a
// transaction, so it carries the database clock whatever the config says.

/** A Postgres database whose pool records each statement and finds nothing. */
function recording() {
  const statements: string[] = [];
  const query = async (config: string | { text: string }) => {
    statements.push(typeof config === 'string' ? config : config.text);
    return { rows: [], fields: [], rowCount: 0 };
  };
  const db = createDatabase({ query, connect: async () => ({ query, release: () => {} }) } as never);
  return { db, statements };
}

test('the credential lookup calls a function Hyperdrive never caches', async () => {
  const { db, statements } = recording();
  assert.equal(await findCredential(db, { tokenHash: Buffer.alloc(32) }), null);
  assert.equal(await findCredential(db, { id: '00000000-0000-4000-8000-000000000000' }), null);
  assert.equal(statements.length, 2);
  for (const statement of statements) assert.match(statement, /CURRENT_TIMESTAMP/);
});
