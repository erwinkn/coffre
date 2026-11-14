import { test } from 'node:test';
import assert from 'node:assert/strict';

import { displayName, principalId } from '@coffre/core/schemas';

test('shared nonblank schemas reject whitespace and canonicalize valid input', () => {
  for (const schema of [displayName, principalId]) {
    assert.equal(schema.safeParse('   ').success, false);
    assert.equal(schema.parse('  visible  '), 'visible');
  }
});
