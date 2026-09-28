import test from 'node:test';
import assert from 'node:assert/strict';

import { loadConfig, parseRootAdmins } from '../src/server/config.ts';
import { isConfiguredRootAdmin } from '../src/server/api/caller.ts';

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
    isConfiguredRootAdmin(
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
    isConfiguredRootAdmin(
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

test('normal web wiring rejects an owner database URL', () => {
  const previous = process.env.COFFRE_OWNER_DATABASE_URL;
  process.env.COFFRE_OWNER_DATABASE_URL = 'obsolete-owner-url';
  try {
    assert.throws(
      () => loadConfig(),
      /is obsolete; migration and web processes each use DATABASE_URL/,
    );
  } finally {
    if (previous === undefined) {
      delete process.env.COFFRE_OWNER_DATABASE_URL;
    } else {
      process.env.COFFRE_OWNER_DATABASE_URL = previous;
    }
  }
});
