import test from 'node:test';
import assert from 'node:assert/strict';

import type { AuthConfig } from '../../../packages/core/src/identity/auth-mode.ts';
import type { Principal } from '../../../packages/core/src/identity/types.ts';
import type { Access } from '../../../packages/vault/src/types.ts';
import { accessTokenForRequest, authenticateRequest } from '../src/server/auth.ts';
import {
  allowsAnonymousTransport,
  isApiPath,
  isPublicHealthPath,
} from '../src/server/request-identity.ts';
import { shouldValidateCsrf, startInstance } from '../src/start.ts';

const cloudflare: AuthConfig = {
  mode: 'cloudflare',
  access: {
    issuer: 'https://acme.cloudflareaccess.com',
    jwksUrl: 'https://acme.cloudflareaccess.com/cdn-cgi/access/certs',
    audience: 'coffre-aud',
  },
};

const dev: AuthConfig = {
  mode: 'dev',
  access: {
    issuer: 'http://127.0.0.1:8081',
    jwksUrl: 'http://127.0.0.1:8081/cdn-cgi/access/certs',
    audience: 'coffre-dev-aud',
  },
  devIdpUrl: 'http://127.0.0.1:8081',
};

/**
 * A vault that knows only these members, by principal (`user:<email>`,
 * `token:<name>`); everyone else is a stranger to it.
 */
function vaultKnowing(known: Record<string, Partial<Access>>, onAsk = (_principal: string) => {}) {
  return {
    access: async (principal: string): Promise<Access> => {
      onAsk(principal);
      return { principal, status: 'unknown', isRootAdmin: false, isOwner: false, grants: [], since: null, by: null, ...known[principal] };
    },
  };
}

const root: Principal = {
  type: 'user',
  id: 'admin@acme.example',
  email: 'admin@acme.example',
  subject: 'root-subject',
};

test('only the two health endpoints are public in production', () => {
  assert.equal(isPublicHealthPath('/livez'), true);
  assert.equal(isPublicHealthPath('/readyz'), true);
  assert.equal(isPublicHealthPath('/livez/'), false);
  assert.equal(isPublicHealthPath('/api/me'), false);
});

test('the API boundary matches only the native API namespace', () => {
  assert.equal(isApiPath('/api'), true);
  assert.equal(isApiPath('/api/me'), true);
  assert.equal(isApiPath('/apiary'), false);
  assert.equal(isApiPath('/v1/me'), false);
});

test('anonymous page and sign-in transport reaches its route-specific boundary', () => {
  assert.equal(
    allowsAnonymousTransport(
      new Request('https://coffre.test/login'),
      'router',
      '/login',
    ),
    true,
  );
  assert.equal(
    allowsAnonymousTransport(
      new Request('https://coffre.test/auth/signout', { method: 'POST' }),
      'router',
      '/auth/signout',
    ),
    true,
  );
  assert.equal(
    allowsAnonymousTransport(
      new Request('https://coffre.test/login', { method: 'POST' }),
      'router',
      '/login',
    ),
    false,
  );
  assert.equal(
    allowsAnonymousTransport(
      new Request('https://coffre.test/_serverFn/session', { method: 'POST' }),
      'serverFn',
      '/_serverFn/session',
    ),
    false,
  );
});

test('the Start instance keeps explicit CSRF and request identity layers', async () => {
  const options = await startInstance.getOptions();
  assert.equal(options.requestMiddleware?.length, 2);
  assert.equal(options.functionMiddleware?.length ?? 0, 0);
});

test('Start checks the origin of page posts, and leaves /api to check its own', () => {
  assert.equal(
    shouldValidateCsrf('router', new Request('https://coffre.test/api/projects')),
    false,
  );
  // /api knows whether a cookie or a token signed the change; see fetch-api.test.ts.
  assert.equal(
    shouldValidateCsrf(
      'router',
      new Request('https://coffre.test/api/projects/market/archive', {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
      }),
    ),
    false,
  );
  assert.equal(
    shouldValidateCsrf(
      'router',
      new Request('https://coffre.test/auth/signout', {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
      }),
    ),
    true,
  );
  assert.equal(
    shouldValidateCsrf(
      'router',
      new Request('https://coffre.test/auth/dev', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
      }),
    ),
    true,
  );
});

test('Cloudflare mode ignores the dev cookie and dev mode ignores the Access header', () => {
  const request = new Request('https://coffre.example.test', {
    headers: {
      'cf-access-jwt-assertion': 'access-token',
      cookie: 'coffre_dev_token=dev-token',
    },
  });
  assert.equal(accessTokenForRequest(request, cloudflare), 'access-token');
  assert.equal(accessTokenForRequest(request, dev), 'dev-token');
});

test('a root admin is whoever the vault says, in one call', async () => {
  const asked: string[] = [];
  const result = await authenticateRequest(
    new Request('https://coffre.example.test/api/me', {
      headers: {
        'cf-access-jwt-assertion': 'valid',
        'cf-connecting-ip': '203.0.113.10',
      },
    }),
    {
      auth: cloudflare,
      verifier: { verify: async () => root },
      vault: vaultKnowing(
        { 'user:admin@acme.example': { status: 'active', isRootAdmin: true, isOwner: true } },
        (principal) => asked.push(principal),
      ),
    } as never,
    'request-id',
  );

  assert.equal(result instanceof Response, false);
  assert.deepEqual(asked, ['user:admin@acme.example']);
  if (!(result instanceof Response)) {
    assert.equal(result.requestId, 'request-id');
    assert.equal(result.registered, true);
    assert.equal(result.sourceIp, '203.0.113.10');
    assert.deepEqual(result.principal, root);
  }
});

test('an unregistered non-root identity is marked for the closed-door boundary', async () => {
  const principal: Principal = {
    type: 'user',
    id: 'new@acme.example',
    email: 'new@acme.example',
    subject: 'new-subject',
  };
  const result = await authenticateRequest(
    new Request('https://coffre.example.test/api/me', {
      headers: { 'cf-access-jwt-assertion': 'valid' },
    }),
    {
      auth: cloudflare,
      verifier: { verify: async () => principal },
      vault: vaultKnowing({}),
    } as never,
    'unregistered-request',
  );

  assert.equal(result instanceof Response, false);
  assert.deepEqual(result, {
    principal,
    registered: false,
    caller: {
      principal: { type: 'user', id: 'new@acme.example' },
      registered: false,
      isRootAdmin: false,
      isOwner: false,
      instanceRole: 'user',
      grants: [],
    },
    requestId: 'unregistered-request',
    sourceIp: null,
    credentialId: null,
  });
});

test('production fails closed when the Access assertion is missing', async () => {
  let verified = false;
  const result = await authenticateRequest(
    new Request('https://coffre.example.test/projects'),
    {
      auth: cloudflare,
      verifier: {
        verify: async () => {
          verified = true;
          return root;
        },
      },
      vault: vaultKnowing({}),
    } as never,
  );

  assert.equal(verified, false);
  assert.equal(result instanceof Response, true);
  assert.equal((result as Response).status, 401);
  assert.equal(((await (result as Response).json()) as { error: string }).error, 'unauthenticated');
});

test('an active registered identity receives an auditable request context', async () => {
  const principal: Principal = {
    type: 'service',
    id: 'reporting.access',
    commonName: 'reporting.access',
  };
  const result = await authenticateRequest(
    new Request('http://127.0.0.1:3000/api/me', {
      headers: { cookie: 'coffre_dev_token=valid' },
    }),
    {
      auth: dev,
      verifier: { verify: async () => principal },
      vault: vaultKnowing({ 'token:reporting.access': { status: 'active' } }),
    } as never,
    'registered-request',
  );

  assert.equal(result instanceof Response, false);
  if (!(result instanceof Response)) {
    assert.deepEqual(result, {
      principal,
      registered: true,
      caller: {
        principal: { type: 'service', id: 'reporting.access' },
        registered: true,
        isRootAdmin: false,
        isOwner: false,
        instanceRole: 'user',
        grants: [],
      },
      requestId: 'registered-request',
      sourceIp: null,
      credentialId: null,
    });
  }
});

test('a principal lookup that fails answers unavailable, not unauthenticated', async () => {
  const principal: Principal = {
    type: 'user',
    id: 'person@acme.example',
    email: 'person@acme.example',
    subject: 'person-subject',
  };
  const result = await authenticateRequest(
    new Request('https://coffre.example.test/api/me', {
      headers: { 'cf-access-jwt-assertion': 'valid' },
    }),
    {
      auth: cloudflare,
      verifier: { verify: async () => principal },
      vault: vaultKnowing({}, () => {
        throw new Error('connection refused');
      }),
    } as never,
  );

  assert.equal(result instanceof Response, true);
  assert.equal((result as Response).status, 503);
  assert.equal(((await (result as Response).json()) as { error: string }).error, 'unavailable');
});
