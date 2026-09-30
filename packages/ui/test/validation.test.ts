import test from 'node:test';
import assert from 'node:assert/strict';

import { secretKey, slug } from '@coffre/core/schemas';

import { secretKeyProblem, slugProblem } from '../src/lib/validation.ts';

// The form hints are a copy of the server's rules. If the two ever disagree, a
// form either blocks a valid name or waves through one the server refuses.
const SLUGS = [
  'market',
  'm',
  'kyc-bridge',
  '0day',
  'issuer-portal-2',
  'a'.repeat(63),
  'a'.repeat(64),
  '-leading',
  'Market',
  'with space',
  'under_score',
  '',
  'dots.here',
];

const KEYS = [
  'DATABASE_URL',
  '_PRIVATE',
  'a',
  'mixedCase_1',
  'A'.repeat(128),
  'A'.repeat(129),
  '1PASSWORD',
  'WITH-DASH',
  'WITH SPACE',
  '',
  'ÉTÉ',
  'constructor',
];

test('slug hints agree with the server schema', () => {
  for (const value of SLUGS) {
    assert.equal(slugProblem(value) === null, slug.safeParse(value).success, value);
  }
});

test('secret key hints agree with the server schema', () => {
  for (const value of KEYS) {
    assert.equal(secretKeyProblem(value) === null, secretKey.safeParse(value).success, value);
  }
});
