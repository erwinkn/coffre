import test from 'node:test';
import assert from 'node:assert/strict';

import { parseRootAdmins } from '../src/config.ts';
import { isRootAdmin } from '../src/services/permissions.ts';

test('cloudflare mode requires valid human email bootstrap identities', () => {
  assert.deepEqual(
    parseRootAdmins('cloudflare', 'first.admin@example.com, second@example.org'),
    ['first.admin@example.com', 'second@example.org'],
  );
  assert.throws(() => parseRootAdmins('cloudflare', ''), /at least one/);
  assert.throws(
    () => parseRootAdmins('cloudflare', 'admin@example,com'),
    /human email identities/,
  );
  assert.throws(
    () => parseRootAdmins('cloudflare', 'ci-deploy.access'),
    /human email identities/,
  );
  for (const malformed of [
    'admin@.example.com',
    'admin@example..com',
    'admin@example.com.',
    '.admin@example.com',
    'admin..root@example.com',
    'admin@-example.com',
  ]) {
    assert.throws(
      () => parseRootAdmins('cloudflare', malformed),
      /human email identities/,
      malformed,
    );
  }
});

test('only a user principal can match a configured root-admin email', () => {
  const roots = ['root@example.com'];
  assert.equal(
    isRootAdmin(
      {
        type: 'user',
        id: 'root@example.com',
        email: 'root@example.com',
        subject: 'user-subject',
      },
      roots,
    ),
    true,
  );
  assert.equal(
    isRootAdmin(
      {
        type: 'service',
        id: 'root@example.com',
        commonName: 'root@example.com',
      },
      roots,
    ),
    false,
  );
});
