import test from 'node:test';
import assert from 'node:assert/strict';

import type { AuthConfig } from '../../../packages/core/src/identity/auth-mode.ts';
import type { Principal } from '../../../packages/core/src/identity/types.ts';
import { createDatabase } from '../../../packages/db/src/database.ts';
import {
  accessTokenForRequest,
  accessTokenForBoundary,
  authenticateRequest,
  allowsAnonymousTransport,
  DEV_TOKEN_COOKIE,
  isApiPath,
  isPublicHealthPath,
} from '../src/server/auth.ts';
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
 * A database whose principal lookup answers `rows`, in Drizzle's array row
 * mode: active, instance role, then the joined grant columns.
 */
function principalsDatabase(rows: unknown[][], onQuery = () => {}) {
  const query = async () => {
    onQuery();
    return { rows, fields: [] };
  };
  return createDatabase({ query, connect: async () => ({ query, release: () => {} }) } as never);
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

test('anonymous page and session transport reaches its route-specific boundary', () => {
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
      new Request('https://coffre.test/api/me'),
      'router',
      '/api/me',
    ),
    false,
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
      new Request('https://coffre.test/_serverFn/session'),
      'serverFn',
      '/_serverFn/session',
    ),
    true,
  );
});

test('the Start instance keeps explicit CSRF and request identity layers', async () => {
  const options = await startInstance.getOptions();
  assert.equal(options.requestMiddleware?.length, 2);
  assert.equal(options.functionMiddleware?.length ?? 0, 0);
});

test('native API mutations require origin checks unless the request is non-simple JSON', () => {
  assert.equal(
    shouldValidateCsrf('router', new Request('https://coffre.test/api/projects')),
    false,
  );
  assert.equal(
    shouldValidateCsrf(
      'router',
      new Request('https://coffre.test/api/projects', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
      }),
    ),
    false,
  );
  assert.equal(
    shouldValidateCsrf(
      'router',
      new Request('https://coffre.test/api/projects/market/archive', {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
      }),
    ),
    true,
  );
  assert.equal(
    shouldValidateCsrf(
      'serverFn',
      new Request('https://coffre.test/_serverFn/update', {
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

test('dev direct API calls accept only the local Access-shaped assertion', () => {
  const request = new Request('http://127.0.0.1:3000/api/me', {
    headers: {
      cookie: `${DEV_TOKEN_COOKIE}=browser-token`,
      'cf-access-jwt-assertion': 'cli-token',
    },
  });
  assert.equal(accessTokenForBoundary(request, dev, '/api/me'), 'cli-token');
  assert.equal(accessTokenForBoundary(request, dev, '/projects'), 'browser-token');
});

test('a configured root admin authenticates without a principals row lookup', async () => {
  let queried = false;
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
      db: principalsDatabase([], () => {
        queried = true;
      }),
      rootAdmins: [root.id],
    } as never,
    'request-id',
  );

  assert.equal(result instanceof Response, false);
  assert.equal(queried, false);
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
      db: principalsDatabase([]),
      rootAdmins: [root.id],
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
      db: principalsDatabase([]),
      rootAdmins: [root.id],
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
      db: principalsDatabase([[true, 'user', null, null, null, null, null, null]]),
      rootAdmins: [],
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
      db: principalsDatabase([], () => {
        throw new Error('connection refused');
      }),
      rootAdmins: [root.id],
    } as never,
  );

  assert.equal(result instanceof Response, true);
  assert.equal((result as Response).status, 503);
  assert.equal(((await (result as Response).json()) as { error: string }).error, 'unavailable');
});
