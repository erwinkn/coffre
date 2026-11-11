import test from 'node:test';
import assert from 'node:assert/strict';

import { journal, staleness } from '../src/baseline.ts';
import { KNOWN_MIGRATIONS } from '../src/schema-version.ts';

// A schema change fails the first test until `pnpm db:generate` has appended its migration.
test('the migration tree ends at the schema and starts at its baseline', async () => {
  assert.deepEqual(await staleness(), []);
});

test('the app knows every migration in the tree, by its journal, as a Worker without files does', async () => {
  assert.deepEqual(KNOWN_MIGRATIONS, (await journal()).map((entry) => entry.tag));
});
