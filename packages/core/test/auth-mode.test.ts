import test from 'node:test';
import assert from 'node:assert/strict';

import { loadAuthConfig } from '../src/identity/auth-mode.ts';

const cloudflare = {
  COFFRE_AUTH_MODE: 'cloudflare',
  COFFRE_ACCESS_ISSUER: 'https://acme.cloudflareaccess.com',
  COFFRE_ACCESS_JWKS_URL:
    'https://acme.cloudflareaccess.com/cdn-cgi/access/certs',
  COFFRE_ACCESS_AUD:
    'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90',
} as const;

const dev = {
  COFFRE_AUTH_MODE: 'dev',
  COFFRE_DEV_IDP_URL: 'http://127.0.0.1:8081',
  COFFRE_ACCESS_ISSUER: 'http://127.0.0.1:8081',
  COFFRE_ACCESS_JWKS_URL: 'http://127.0.0.1:8081/cdn-cgi/access/certs',
  COFFRE_ACCESS_AUD: 'coffre-local-dev-aud',
} as const;

test('auth mode is explicit rather than inferred from other variables', () => {
  assert.throws(
    () => loadAuthConfig({ ...dev, COFFRE_AUTH_MODE: undefined }),
    /COFFRE_AUTH_MODE/,
  );
  assert.throws(
    () => loadAuthConfig({ ...dev, COFFRE_AUTH_MODE: 'production' }),
    /exactly "signin", "cloudflare" or "dev"/,
  );
});

test('cloudflare mode accepts the exact team issuer, cert URL, and AUD', () => {
  assert.deepEqual(loadAuthConfig(cloudflare), {
    mode: 'cloudflare',
    access: {
      issuer: cloudflare.COFFRE_ACCESS_ISSUER,
      jwksUrl: cloudflare.COFFRE_ACCESS_JWKS_URL,
      audience: cloudflare.COFFRE_ACCESS_AUD,
    },
  });
});

test('cloudflare mode rejects every dev minting configuration', () => {
  assert.throws(
    () => loadAuthConfig({ ...cloudflare, COFFRE_DEV_IDP_URL: 'http://127.0.0.1:8081' }),
    /must not be set/,
  );
});

test('cloudflare mode rejects a non-Access issuer or a derived JWKS mismatch', () => {
  assert.throws(
    () =>
      loadAuthConfig({
        ...cloudflare,
        COFFRE_ACCESS_ISSUER: 'https://login.example.com',
        COFFRE_ACCESS_JWKS_URL: 'https://login.example.com/cdn-cgi/access/certs',
      }),
    /Cloudflare Access team domain/,
  );
  assert.throws(
    () =>
      loadAuthConfig({
        ...cloudflare,
        COFFRE_ACCESS_JWKS_URL: 'https://other.cloudflareaccess.com/cdn-cgi/access/certs',
      }),
    /must be exactly/,
  );
});

test('dev mode requires the local IdP to own both issuer and JWKS URL', () => {
  assert.equal(loadAuthConfig(dev).mode, 'dev');
  assert.throws(
    () =>
      loadAuthConfig({
        ...dev,
        COFFRE_ACCESS_ISSUER: 'http://127.0.0.1:9999',
      }),
    /must match COFFRE_DEV_IDP_URL/,
  );
  assert.throws(
    () =>
      loadAuthConfig({
        ...dev,
        COFFRE_ACCESS_JWKS_URL: 'http://127.0.0.1:8081/not-certs',
      }),
    /must be exactly/,
  );
});
