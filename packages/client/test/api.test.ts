import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { generate } from '../scripts/generate-api.ts';

// api.ts is the generator's output, never edited by hand: a route added, removed or changed on the server fails
// this until `pnpm --filter @coffre/client generate` has written it again.
test('api.ts is what the route table says today', () => {
  const written = readFileSync(new URL('../src/api.ts', import.meta.url), 'utf8');
  assert.ok(written === generate(), 'packages/client/src/api.ts is out of date: run `pnpm --filter @coffre/client generate`');
});
