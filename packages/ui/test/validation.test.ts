import test from 'node:test';
import assert from 'node:assert/strict';

import { PROJECT_PAGES } from '@coffre/core/pages';
import { environmentSlug, folderName, secretKey, slug } from '@coffre/core/schemas';

import { environmentSlugProblem, folderProblem, secretKeyProblem, slugProblem } from '../src/lib/validation.ts';

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

test("environment slug hints agree with the server schema, a project page's name refused", () => {
  for (const value of [...SLUGS, ...PROJECT_PAGES, 'settings-2']) {
    assert.equal(environmentSlugProblem(value) === null, environmentSlug.safeParse(value).success, value);
  }
  for (const page of PROJECT_PAGES) assert.equal(environmentSlugProblem(page), 'Taken by a page of the project.');
});

test('secret key hints agree with the server schema', () => {
  for (const value of KEYS) {
    assert.equal(secretKeyProblem(value) === null, secretKey.safeParse(value).success, value);
  }
});

const FOLDERS = ['stripe', 'Clients', 'Clients · EU', 'a'.repeat(64), 'a'.repeat(65), 'a/b', ' padded', 'padded ', 'tab\there', 'line\nbreak', 'x'];

test('folder hints agree with the server schema, for any name a form sends', () => {
  for (const value of FOLDERS) {
    assert.equal(folderProblem(value) === null, folderName.safeParse(value).success, value);
  }
});
