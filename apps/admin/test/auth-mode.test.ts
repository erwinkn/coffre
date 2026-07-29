import test from 'node:test';
import assert from 'node:assert/strict';

import type { AuthConfig } from '../../../packages/core/src/identity/auth-mode.ts';
import {
  missingIdentityMessage,
  selectAdminToken,
} from '../src/lib/auth-mode.ts';

const access = {
  issuer: 'https://equisafe.cloudflareaccess.com',
  jwksUrl: 'https://equisafe.cloudflareaccess.com/cdn-cgi/access/certs',
  audience: 'access-aud',
};

const cloudflare: AuthConfig = { mode: 'cloudflare', access };
const dev: AuthConfig = {
  mode: 'dev',
  access: {
    issuer: 'http://127.0.0.1:8081',
    jwksUrl: 'http://127.0.0.1:8081/cdn-cgi/access/certs',
    audience: 'coffre-local-dev-aud',
  },
  devIdpUrl: 'http://127.0.0.1:8081',
};

test('cloudflare mode accepts only the forwarded Access JWT', () => {
  assert.equal(
    selectAdminToken(cloudflare, {
      forwardedAccessJwt: 'forwarded-access-jwt',
      devCookie: 'seeded-persona-cookie',
    }),
    'forwarded-access-jwt',
  );
  assert.equal(
    selectAdminToken(cloudflare, { devCookie: 'seeded-persona-cookie' }),
    null,
  );
});

test('dev mode retains the persona cookie and ignores forwarded-looking input', () => {
  assert.equal(
    selectAdminToken(dev, {
      forwardedAccessJwt: 'client-supplied-header',
      devCookie: 'seeded-persona-cookie',
    }),
    'seeded-persona-cookie',
  );
});

test('missing Cloudflare identity explains the closed production boundary', () => {
  assert.match(missingIdentityMessage(cloudflare), /Cloudflare Access/);
  assert.match(missingIdentityMessage(cloudflare), /Access-protected hostname/);
});
