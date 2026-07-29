import test from 'node:test';
import assert from 'node:assert/strict';

import { loadLocalSeedConfig } from '../../../scripts/seed-config.mjs';

const local = {
  COFFRE_AUTH_MODE: 'dev',
  COFFRE_OWNER_DATABASE_URL:
    'postgresql://coffre_owner:local-dev-only@127.0.0.1:55432/coffre',
  COFFRE_API_URL: 'http://127.0.0.1:8080',
  COFFRE_DEV_IDP_URL: 'http://127.0.0.1:8081',
  COFFRE_ACCESS_AUD: 'coffre-local-dev-aud',
  COFFRE_ROOT_ADMINS: 'erwin@equisafe.io',
};

test('seed accepts only the checked-in local development targets', () => {
  assert.deepEqual(loadLocalSeedConfig(local), {
    ownerDatabaseUrl:
      'postgresql://coffre_owner:local-dev-only@127.0.0.1:55432/coffre',
    apiUrl: 'http://127.0.0.1:8080',
    idpUrl: 'http://127.0.0.1:8081',
    audience: 'coffre-local-dev-aud',
    rootAdmin: 'erwin@equisafe.io',
  });
});

test('seed rejects a production database exported over the dev env file', () => {
  assert.throws(
    () =>
      loadLocalSeedConfig({
        ...local,
        COFFRE_OWNER_DATABASE_URL: 'postgresql://coffre@db.internal.example/coffre',
      }),
    /refuses non-local ownerDatabaseUrl/,
  );
});

test('seed rejects a foreign root admin before resetting local data', () => {
  assert.throws(
    () =>
      loadLocalSeedConfig({
        ...local,
        COFFRE_ROOT_ADMINS: 'production.admin@example.com',
      }),
    /refuses non-local rootAdmin/,
  );
  assert.throws(
    () => loadLocalSeedConfig({ ...local, COFFRE_ROOT_ADMINS: '' }),
    /refuses non-local rootAdmin/,
  );
});

test('seed rejects remote API, IdP, audience, and a non-dev mode', () => {
  assert.throws(
    () => loadLocalSeedConfig({ ...local, COFFRE_API_URL: 'https://coffre.example.com' }),
    /refuses non-local apiUrl/,
  );
  assert.throws(
    () =>
      loadLocalSeedConfig({
        ...local,
        COFFRE_DEV_IDP_URL: 'https://idp.example.com',
      }),
    /refuses non-local idpUrl/,
  );
  assert.throws(
    () => loadLocalSeedConfig({ ...local, COFFRE_ACCESS_AUD: 'production-aud' }),
    /refuses non-local audience/,
  );
  assert.throws(
    () => loadLocalSeedConfig({ ...local, COFFRE_AUTH_MODE: 'cloudflare' }),
    /COFFRE_AUTH_MODE=dev/,
  );
});
