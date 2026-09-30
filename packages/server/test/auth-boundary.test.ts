import test from 'node:test';
import assert from 'node:assert/strict';

import type { AuthConfig, Principal } from '@coffre/core/identity';
import type { Access } from '@coffre/core/vault';

import { handleRequest } from '../src/app.ts';
import { accessTokenForRequest, authenticateRequest, cloudflareSourceIp } from '../src/auth.ts';

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

/** The app with nothing behind it: health and routing need no database. */
function appRuntime(auth: AuthConfig) {
  return {
    auth,
    publicUrl: 'https://coffre.test',
    signin: null,
    verifier: { verify: async () => root },
    vault: vaultKnowing({}),
    db: null,
  } as never;
}

/** A stand-in for `@coffre/ui` that remembers what it was handed. */
function fakeUi() {
  const seen: { nonce: string; path: string }[] = [];
  return {
    seen,
    fetch: async (request: Request, init: { context: { cspNonce: string } }) => {
      seen.push({ nonce: init.context.cspNonce, path: new URL(request.url).pathname });
      return new Response('<html></html>', { headers: { 'content-type': 'text/html' } });
    },
  };
}

test('health is public, and every response carries the security headers', async () => {
  const response = await handleRequest(new Request('https://coffre.test/livez'), appRuntime(cloudflare), fakeUi(), null);
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { ok: true });
  assert.equal(response.headers.get('x-frame-options'), 'DENY');
  assert.match(response.headers.get('strict-transport-security') ?? '', /max-age=/);
  // Access's logout form posts to Access itself.
  assert.match(response.headers.get('content-security-policy') ?? '', /form-action 'self' https:\/\/acme\.cloudflareaccess\.com/);
});

test('pages get the response nonce; everything else stays away from the UI', async () => {
  const ui = fakeUi();
  const runtime = appRuntime(dev);
  const page = await handleRequest(new Request('https://coffre.test/projects'), runtime, ui, null);
  assert.equal(page.status, 200);
  assert.equal(ui.seen.length, 1);
  assert.equal(ui.seen[0].path, '/projects');
  assert.ok(page.headers.get('content-security-policy')?.includes(`'nonce-${ui.seen[0].nonce}'`));

  const api = await handleRequest(new Request('https://coffre.test/api/me'), runtime, ui, null);
  assert.equal(api.status, 401);
  const apiary = await handleRequest(new Request('https://coffre.test/apiary'), runtime, ui, null);
  assert.equal(apiary.status, 200, '/apiary is a page, not the API');
  const post = await handleRequest(new Request('https://coffre.test/projects', { method: 'POST' }), runtime, ui, null);
  assert.equal(post.status, 405);
  assert.equal(ui.seen.length, 2);
});

test('the Next.js middleware header is refused outright', async () => {
  const response = await handleRequest(
    new Request('https://coffre.test/livez', { headers: { 'x-middleware-subrequest': 'middleware' } }),
    appRuntime(dev),
    fakeUi(),
    null,
  );
  assert.equal(response.status, 400);
});

test('sign-in routes take one method, and browser posts only from coffre itself', async () => {
  const runtime = appRuntime(dev);
  const signout = (headers: Record<string, string>, method = 'POST') =>
    handleRequest(new Request('https://coffre.test/auth/signout', { method, headers }), runtime, fakeUi(), null);

  assert.equal((await signout({}, 'GET')).status, 405);
  const refusals: Record<string, string>[] = [{ 'sec-fetch-site': 'cross-site' }, { origin: 'https://evil.test' }, {}];
  for (const headers of refusals) {
    const refused = await signout(headers);
    assert.equal(refused.status, 403, JSON.stringify(headers));
    assert.equal(((await refused.json()) as { error: string }).error, 'cross_origin');
  }
  const signedOut = await signout({ 'sec-fetch-site': 'same-origin' });
  assert.equal(signedOut.status, 303);
  assert.equal(signedOut.headers.get('location'), '/login');
  assert.match(signedOut.headers.get('set-cookie') ?? '', /coffre_dev_token=;/);

  const dev_ = await handleRequest(
    new Request('https://coffre.test/auth/dev', { method: 'POST', headers: { origin: 'https://evil.test' } }),
    runtime,
    fakeUi(),
    null,
  );
  assert.equal(dev_.status, 403);
  // Signin mode's own routes are not there in dev mode.
  const device = await handleRequest(
    new Request('https://coffre.test/api/auth/device', { method: 'POST' }),
    runtime,
    fakeUi(),
    null,
  );
  assert.equal(device.status, 404);
});

test('on Workers the address is Cloudflare\'s header, and nobody\'s in dev mode', () => {
  const request = new Request('https://coffre.test/api/me', { headers: { 'cf-connecting-ip': '203.0.113.10' } });
  assert.equal(cloudflareSourceIp(request, cloudflare), '203.0.113.10');
  assert.equal(cloudflareSourceIp(request, dev), null);
  assert.equal(
    cloudflareSourceIp(new Request('https://coffre.test', { headers: { 'cf-connecting-ip': 'not an address' } }), cloudflare),
    null,
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
    undefined,
    '203.0.113.10',
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
