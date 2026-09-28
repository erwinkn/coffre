import test from 'node:test';
import assert from 'node:assert/strict';

import { loadConfig } from '../src/server/config.ts';

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
