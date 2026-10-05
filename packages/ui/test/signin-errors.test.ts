import test from 'node:test';
import assert from 'node:assert/strict';

import { loginSearch, signinErrorMessage } from '../src/lib/signin-errors.ts';

test('an email that already signs in elsewhere names the provider, and only that', () => {
  assert.equal(
    signinErrorMessage('account_mismatch', { providers: ['GitHub'], via: 'Google' }),
    'Your email already signs in with GitHub. Sign in with GitHub, then link this account from your account page.',
  );
  assert.equal(
    signinErrorMessage('account_mismatch', { providers: ['GitHub', 'Google'], via: 'Okta' }),
    'Your email already signs in with GitHub and Google. Sign in with one of them, then link this account from your account page.',
  );
  // Another account of the same provider: a second GitHub account, say.
  assert.equal(
    signinErrorMessage('account_mismatch', { providers: ['GitHub'], via: 'GitHub' }),
    'Your email already signs in with another GitHub account. Sign in with that one, then link this account from your account page.',
  );
  assert.equal(
    signinErrorMessage('account_mismatch', { providers: ['GitHub', 'Google', 'Okta'], via: 'Google' }),
    'Your email already signs in with GitHub, another Google account and Okta. Sign in with one of them, then link this account from your account page.',
  );
  // Nothing known, as from an older server or a provider no longer configured: the sentence as before.
  assert.equal(
    signinErrorMessage('account_mismatch', { providers: [] }),
    'Your email already signs in with a different account. Use that one, then link this account from your account page.',
  );
  assert.equal(signinErrorMessage(undefined), null);
});

test("the sign-in page's search keeps provider ids, and nothing else, for the message", () => {
  assert.deepEqual(loginSearch({ error: 'account_mismatch', with: 'github,google', via: 'oidc' }), {
    error: 'account_mismatch',
    with: 'github,google',
    via: 'oidc',
  });
  // An address or markup slipped into the URL is dropped, not shown.
  assert.deepEqual(loginSearch({ error: 'account_mismatch', with: 'github,ada@acme.example,<b>x</b>', via: 'Evil Corp' }), {
    error: 'account_mismatch',
    with: 'github',
  });
  assert.deepEqual(loginSearch({ next: 'https://evil.example/', error: 'Not A Code' }), {});
});
