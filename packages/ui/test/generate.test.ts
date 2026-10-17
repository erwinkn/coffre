import test from 'node:test';
import assert from 'node:assert/strict';

import { pairNameProblem } from '../src/lib/generate.ts';

// The values and their recipes are @coffre/core/recipe's, tested there.

test("a key pair's two names are each a secret's name, and differ", () => {
  assert.equal(pairNameProblem('JWT_PRIVATE_KEY', 'JWT_PUBLIC_KEY'), null);
  assert.equal(pairNameProblem('', 'JWT_PUBLIC_KEY'), 'Give each key a name.');
  assert.equal(pairNameProblem('JWT', 'JWT'), 'The two keys need different names.');
  assert.equal(pairNameProblem('JWT', 'JWT-PUBLIC'), 'JWT-PUBLIC: Letters, digits and underscores only.');
});
