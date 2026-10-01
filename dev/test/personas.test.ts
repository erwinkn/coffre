import assert from 'node:assert/strict';
import { test } from 'node:test';

import { PERSONAS } from '@coffre/conformance/idp';

import { LOCAL_SEED_DIRECTORY } from '../seed-config.mjs';

test('the personas are the seeded users', () => {
  const seeded = LOCAL_SEED_DIRECTORY.filter((p) => p.principalType === 'user').map((p) => p.principalId);
  assert.deepEqual(
    PERSONAS.map((p) => p.email).sort(),
    ['admin@acme.example', ...seeded].sort(),
  );
});
