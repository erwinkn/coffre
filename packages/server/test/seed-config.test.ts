import test from 'node:test';
import assert from 'node:assert/strict';

import {
  loadLocalSeedConfig,
  LOCAL_SEED_DIRECTORY,
  LOCAL_SEED_GRANTS,
} from '../../../scripts/seed-config.mjs';

const local = {
  COFFRE_AUTH_MODE: 'dev',
  DATABASE_URL: 'postgresql://coffre_owner:local-dev-only@127.0.0.1:55432/coffre',
  COFFRE_API_URL: 'http://127.0.0.1:3000',
  COFFRE_DEV_IDP_URL: 'http://127.0.0.1:8081',
  COFFRE_ACCESS_AUD: 'coffre-local-dev-aud',
  COFFRE_ROOT_ADMINS: 'admin@acme.example',
};

test('seed accepts the checked-in local development targets', () => {
  assert.deepEqual(loadLocalSeedConfig(local), {
    databaseUrl:
      'postgresql://coffre_owner:local-dev-only@127.0.0.1:55432/coffre',
    apiUrl: 'http://127.0.0.1:3000',
    idpUrl: 'http://127.0.0.1:8081',
    audience: 'coffre-local-dev-aud',
    rootAdmin: 'admin@acme.example',
  });
});

test('seed accepts a second local stack, on its own database and ports', () => {
  const second = loadLocalSeedConfig({
    ...local,
    DATABASE_URL: 'postgresql://coffre_owner:local-dev-only@127.0.0.1:55432/coffre_step6',
    COFFRE_API_URL: 'http://127.0.0.1:3080',
    COFFRE_DEV_IDP_URL: 'http://127.0.0.1:3081',
  });
  assert.equal(second.apiUrl, 'http://127.0.0.1:3080');
});

test('seed rejects a production database exported over the dev env file', () => {
  assert.throws(
    () =>
      loadLocalSeedConfig({
        ...local,
        DATABASE_URL: 'postgresql://coffre@db.internal.example/coffre',
      }),
    /refuses non-local databaseUrl/,
  );
  assert.throws(
    () =>
      loadLocalSeedConfig({
        ...local,
        DATABASE_URL: 'postgresql://coffre_owner:local-dev-only@127.0.0.1:55432/postgres',
      }),
    /refuses non-local databaseUrl/,
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

test('every seeded grant principal is registered in the directory first', () => {
  for (const grant of LOCAL_SEED_GRANTS) {
    assert.ok(
      LOCAL_SEED_DIRECTORY.some(
        (entry) =>
          entry.principalType === grant.principalType &&
          entry.principalId === grant.principalId,
      ),
      `${grant.principalType}:${grant.principalId} is granted without a directory row`,
    );
  }
});

test('the closed-door persona is in the directory with no grant', () => {
  assert.ok(
    LOCAL_SEED_DIRECTORY.some(
      (entry) => entry.principalType === 'user' && entry.principalId === 'outsider@acme.example',
    ),
  );
  assert.equal(
    LOCAL_SEED_GRANTS.some((grant) => (grant.principalId as string) === 'outsider@acme.example'),
    false,
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
