import test from 'node:test';
import assert from 'node:assert/strict';

import { loadConfig } from '../src/server/config.ts';

const key = Buffer.alloc(32, 7).toString('base64');
const base = {
  COFFRE_AUTH_MODE: 'dev',
  COFFRE_ACCESS_ISSUER: 'http://127.0.0.1:8081',
  COFFRE_ACCESS_JWKS_URL: 'http://127.0.0.1:8081/cdn-cgi/access/certs',
  COFFRE_ACCESS_AUD: 'coffre-dev-aud',
  COFFRE_DEV_IDP_URL: 'http://127.0.0.1:8081',
  COFFRE_AUDIT_CHAIN_KEY: key,
};

test('the web runtime reads its one database identity from DATABASE_URL', () => {
  const config = loadConfig({
    ...base,
    DATABASE_URL: 'postgresql://coffre_runtime@db.internal/coffre',
  });
  assert.equal(
    config.databaseUrl,
    'postgresql://coffre_runtime@db.internal/coffre',
  );
});

test('the obsolete COFFRE_DATABASE_URL cannot silently configure the web runtime', () => {
  assert.throws(
    () =>
      loadConfig({
        ...base,
        COFFRE_DATABASE_URL: 'postgresql://obsolete@db.internal/coffre',
      }),
    /missing required environment variable: DATABASE_URL/,
  );
});

test('the web runtime refuses to start with a key that belongs to the vault', () => {
  for (const name of ['COFFRE_KEK_LOCAL', 'COFFRE_ROOT_ADMINS', 'COFFRE_VAULT_SIGNING_KEY']) {
    assert.throws(
      () =>
        loadConfig({
          ...base,
          DATABASE_URL: 'postgresql://coffre_runtime@db.internal/coffre',
          [name]: key,
        }),
      new RegExp(`${name} belong to the vault Worker; the app holds no key`),
    );
  }
});
