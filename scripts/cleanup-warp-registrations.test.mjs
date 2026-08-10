import assert from 'node:assert/strict';
import test from 'node:test';
import {
  isStaleCoffreRegistration,
  positiveHours,
} from './cleanup-warp-registrations.mjs';

const boundary = {
  cutoff: Date.parse('2026-08-10T12:00:00Z'),
  identity: 'non_identity@equisafe.cloudflareaccess.com',
  policyId: '11111111-1111-1111-1111-111111111111',
};

function registration(overrides = {}) {
  return {
    created_at: '2026-08-10T04:00:00Z',
    deleted_at: null,
    last_seen_at: '2026-08-10T05:00:00Z',
    policy: { id: boundary.policyId },
    user: { email: boundary.identity },
    ...overrides,
  };
}

test('cleanup selects only inactive registrations from the exact Coffre profile', () => {
  assert.equal(isStaleCoffreRegistration(registration(), boundary), true);
  assert.equal(isStaleCoffreRegistration(registration({
    last_seen_at: '2026-08-10T12:00:00Z',
  }), boundary), false);
  assert.equal(isStaleCoffreRegistration(registration({
    policy: { id: '22222222-2222-2222-2222-222222222222' },
  }), boundary), false);
  assert.equal(isStaleCoffreRegistration(registration({
    user: { email: 'someone@example.com' },
  }), boundary), false);
  assert.equal(isStaleCoffreRegistration(registration({
    deleted_at: '2026-08-10T06:00:00Z',
  }), boundary), false);
});

test('cleanup rejects unsafe retention windows', () => {
  assert.equal(positiveHours(undefined), 6);
  assert.equal(positiveHours('1'), 1);
  assert.equal(positiveHours('168'), 168);
  assert.throws(() => positiveHours('0'), /integer from 1 through 168/);
  assert.throws(() => positiveHours('1.5'), /integer from 1 through 168/);
  assert.throws(() => positiveHours('169'), /integer from 1 through 168/);
});
