import test from 'node:test';
import assert from 'node:assert/strict';

import type { SecretKey } from '@coffre/client';

import { sortKeys } from '../src/lib/secret-order.ts';

const key = (name: string, updatedAt: string | null): SecretKey => ({
  key: name,
  reference: null,
  folder: null,
  archived: false,
  version: updatedAt === null ? null : 1,
  updatedAt,
  updatedBy: updatedAt === null ? null : 'ada@acme.example',
});

// As the list comes: by name.
const LISTED = [
  key('API_KEY', '2026-03-01T00:00:00.000Z'),
  key('DATABASE_URL', '2024-11-20T00:00:00.000Z'),
  key('EMPTY', null),
  key('SENTRY_DSN', '2026-03-01T00:00:00.000Z'),
  key('STRIPE_KEY', '2025-06-12T00:00:00.000Z'),
];
const names = (entries: SecretKey[]) => entries.map((entry) => entry.key);

test('by name, the list keeps its order, or turns it round', () => {
  assert.equal(sortKeys(LISTED, { by: 'key', descending: false }), LISTED);
  assert.deepEqual(names(sortKeys(LISTED, { by: 'key', descending: true })), ['STRIPE_KEY', 'SENTRY_DSN', 'EMPTY', 'DATABASE_URL', 'API_KEY']);
});

test('by age, the oldest value first or last, keys written together by name, and a key with no value last either way', () => {
  assert.deepEqual(names(sortKeys(LISTED, { by: 'written', descending: false })), ['DATABASE_URL', 'STRIPE_KEY', 'API_KEY', 'SENTRY_DSN', 'EMPTY']);
  assert.deepEqual(names(sortKeys(LISTED, { by: 'written', descending: true })), ['API_KEY', 'SENTRY_DSN', 'STRIPE_KEY', 'DATABASE_URL', 'EMPTY']);
  assert.deepEqual(names(LISTED), ['API_KEY', 'DATABASE_URL', 'EMPTY', 'SENTRY_DSN', 'STRIPE_KEY']);
});
