import test from 'node:test';
import assert from 'node:assert/strict';

import { loginSearch, signinErrorMessage } from '../src/lib/signin-errors.ts';

test('a sign-in error is a sentence of its own, naming no provider', () => {
  assert.equal(
    signinErrorMessage('account_mismatch'),
    'Your email already signs in with a different account. Use that one, then link this account from your account page.',
  );
  assert.equal(signinErrorMessage('no_such_code'), 'The sign-in did not complete. Try again.');
  assert.equal(signinErrorMessage(undefined), null);
});

test("the sign-in page's search keeps a same-origin next and an error code, and nothing else", () => {
  // 0.14's `with` and `via` are dropped: 0.16 never sends them.
  assert.deepEqual(loginSearch({ next: '/projects', error: 'account_mismatch', with: 'github', via: 'oidc' }), {
    next: '/projects',
    error: 'account_mismatch',
  });
  assert.deepEqual(loginSearch({ next: 'https://evil.example/', error: 'Not A Code' }), {});
  assert.deepEqual(loginSearch({ next: '//evil.example/' }), {});
});
