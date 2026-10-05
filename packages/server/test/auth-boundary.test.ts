import test from 'node:test';
import assert from 'node:assert/strict';

import type { CoffreClient } from '@coffre/client';
import { github, signin, type AuthConfig, type Principal } from '@coffre/core/identity';
import type { Access } from '@coffre/core/vault';

import { answer } from './start-fixture.ts';
import { accessTokenForRequest, authenticateRequest, cloudflareSourceIp } from '../src/auth.ts';

const cloudflare: AuthConfig = {
  mode: 'cloudflare',
  access: {
    issuer: 'https://acme.cloudflareaccess.com',
    jwksUrl: 'https://acme.cloudflareaccess.com/cdn-cgi/access/certs',
    audience: 'coffre-aud',
  },
};

const own: AuthConfig = signin({ providers: [github({ clientId: 'id', clientSecret: 'secret' })] }).resolve(
  'https://coffre.test',
);

/**
 * A vault that knows only these members, by principal (`user:<email>`,
 * `token:<name>`); everyone else is a stranger to it.
 */
function vaultKnowing(known: Record<string, Partial<Access>>, onAsk = (_principal: string) => {}) {
  return {
    access: async (principal: string): Promise<Access> => {
      onAsk(principal);
      return { principal, status: 'unknown', generation: 0, isRootAdmin: false, isOwner: false, grants: [], since: null, by: null, ...known[principal] };
    },
  };
}

const root: Principal = {
  type: 'user',
  id: 'admin@acme.example',
  email: 'admin@acme.example',
  subject: 'root-subject',
};

/** The app with nothing behind it, its database migrated: health and routing need no database. */
function appRuntime(auth: AuthConfig) {
  return {
    auth,
    publicUrl: 'https://coffre.test',
    signin: null,
    verifier: { verify: async () => root },
    vault: vaultKnowing({}),
    db: null,
    schema: { migrated: true },
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

test('a monitor may ask the health checks with HEAD; other methods are refused', async () => {
  const head = await answer(new Request('https://coffre.test/livez', { method: 'HEAD' }), appRuntime(cloudflare), fakeUi(), null);
  assert.equal(head.status, 200);
  const post = await answer(new Request('https://coffre.test/livez', { method: 'POST' }), appRuntime(cloudflare), fakeUi(), null);
  assert.equal(post.status, 405);
});

test('health is public, and every response carries the security headers', async () => {
  const response = await answer(new Request('https://coffre.test/livez'), appRuntime(cloudflare), fakeUi(), null);
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { ok: true });
  assert.equal(response.headers.get('x-frame-options'), 'DENY');
  assert.match(response.headers.get('strict-transport-security') ?? '', /max-age=/);
  // Access's logout form posts to Access itself.
  assert.match(response.headers.get('content-security-policy') ?? '', /form-action 'self' https:\/\/acme\.cloudflareaccess\.com/);
});

test('pages get the response nonce; everything else stays away from the UI', async () => {
  const ui = fakeUi();
  const runtime = appRuntime(own);
  const page = await answer(new Request('https://coffre.test/projects'), runtime, ui, null);
  assert.equal(page.status, 200);
  assert.equal(ui.seen.length, 1);
  assert.equal(ui.seen[0].path, '/projects');
  assert.ok(page.headers.get('content-security-policy')?.includes(`'nonce-${ui.seen[0].nonce}'`));

  const api = await answer(new Request('https://coffre.test/api/me'), runtime, ui, null);
  assert.equal(api.status, 401);
  const apiary = await answer(new Request('https://coffre.test/apiary'), runtime, ui, null);
  assert.equal(apiary.status, 200, '/apiary is a page, not the API');
  const post = await answer(new Request('https://coffre.test/projects', { method: 'POST' }), runtime, ui, null);
  assert.equal(post.status, 405);
  assert.equal(ui.seen.length, 2);
});

/** A stand-in for `@coffre/ui` that renders as Start does: its loader asks the API, and a loader that throws makes a 500 page. */
function renderingUi(ask: (client: CoffreClient) => Promise<unknown>, fails = false) {
  const html = { 'content-type': 'text/html' };
  return {
    fetch: async (_request: Request, init: { context: { client: CoffreClient } }) => {
      try {
        await ask(init.context.client);
        if (fails) throw new Error('a bug in the page');
        return new Response('<html>the page</html>', { headers: html });
      } catch {
        return new Response('<html>This page could not be shown</html>', { status: 500, headers: html });
      }
    },
  };
}

test('a page whose render met an outage shows its error state, with the security headers', async () => {
  const page = () => new Request('https://coffre.test/projects', { headers: { 'cf-access-jwt-assertion': 'assertion' } });
  const unreachable = Object.assign(appRuntime(cloudflare) as object, {
    vault: { access: async () => Promise.reject(new Error('the vault is unreachable')) },
  }) as never;
  const outage = await answer(page(), unreachable, renderingUi((client) => client.me()), null);
  assert.equal(outage.status, 500);
  assert.equal(await outage.text(), '<html>This page could not be shown</html>');
  assert.ok(outage.headers.get('content-security-policy'), 'the security headers');

  const fine = await answer(page(), unreachable, renderingUi((client) => client.auth()), null);
  assert.equal(fine.status, 200);
  const bug = await answer(page(), unreachable, renderingUi((client) => client.auth(), true), null);
  assert.equal(bug.status, 500);
});

test('sign-in routes take one method, and browser posts only from coffre itself', async () => {
  const runtime = appRuntime(own);
  const signout = (headers: Record<string, string>, method = 'POST') =>
    answer(new Request('https://coffre.test/auth/signout', { method, headers }), runtime, fakeUi(), null);

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
  assert.match(signedOut.headers.get('set-cookie') ?? '', /^__Host-coffre_session=;/);

  // Behind Access, the session is Access's, and so are CLI logins.
  const behindAccess = appRuntime(cloudflare);
  const accessSignout = await answer(
    new Request('https://coffre.test/auth/signout', { method: 'POST', headers: { 'sec-fetch-site': 'same-origin' } }),
    behindAccess,
    fakeUi(),
    null,
  );
  assert.equal(accessSignout.headers.get('location'), '/cdn-cgi/access/logout');
  const device = await answer(
    new Request('https://coffre.test/api/auth/device', { method: 'POST' }),
    behindAccess,
    fakeUi(),
    null,
  );
  assert.equal(device.status, 404);
});

test('on Workers the address is Cloudflare\'s header, when it is an address', () => {
  const request = new Request('https://coffre.test/api/me', { headers: { 'cf-connecting-ip': '203.0.113.10' } });
  assert.equal(cloudflareSourceIp(request), '203.0.113.10');
  assert.equal(cloudflareSourceIp(new Request('https://coffre.test', { headers: { 'cf-connecting-ip': '2001:db8::1' } })), '2001:db8::1');
  assert.equal(cloudflareSourceIp(new Request('https://coffre.test', { headers: { 'cf-connecting-ip': 'not an address' } })), null);
  assert.equal(cloudflareSourceIp(new Request('https://coffre.test', { headers: { 'cf-connecting-ip': '300.1.1.1' } })), null);
});

test('Cloudflare mode ignores the session cookie and signin mode ignores the Access header', () => {
  const request = new Request('https://coffre.example.test', {
    headers: {
      'cf-access-jwt-assertion': 'access-token',
      cookie: '__Host-coffre_session=session-token',
    },
  });
  assert.equal(accessTokenForRequest(request, cloudflare), 'access-token');
  assert.equal(accessTokenForRequest(request, own), 'session-token');
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
      tampered: false,
      generation: 0,
      isRootAdmin: false,
      isOwner: false,
      instanceRole: 'user',
      grants: [],
    },
    requestId: 'unregistered-request',
    sourceIp: null,
    credentialId: null,
    provenance: null, via: null,
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
    new Request('https://coffre.test/api/me', {
      headers: { cookie: '__Host-coffre_session=valid' },
    }),
    {
      auth: own,
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
        tampered: false,
        generation: 0,
        isRootAdmin: false,
        isOwner: false,
        instanceRole: 'user',
        grants: [],
      },
      requestId: 'registered-request',
      sourceIp: null,
      credentialId: null,
      provenance: null, via: null,
    });
  }
});

test('a principal lookup that fails answers unavailable, not unauthenticated, and logs why with the request id', async (t) => {
  const report = t.mock.method(console, 'error', () => {});
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
    'request-1',
  );

  assert.equal(result instanceof Response, true);
  assert.equal((result as Response).status, 503);
  assert.equal(((await (result as Response).json()) as { error: string }).error, 'unavailable');
  const [message, fields] = report.mock.calls[0]!.arguments as [string, { requestId: string; error: { message: string } }];
  assert.deepEqual([report.mock.callCount(), message, fields.requestId, fields.error.message], [1, 'checking who called failed', 'request-1', 'connection refused']);
});

test('removal between credential verification and caller loading cannot use the new membership', async () => {
  const runtime = {
    auth: own,
    verifier: { verify: async () => ({ ...root, credentialId: 'old-session', credentialGeneration: 0 }) },
    vault: vaultKnowing({ [`user:${root.id}`]: { status: 'active', generation: 1 } }),
  };
  const result = await authenticateRequest(new Request('https://coffre.test/api/me'), runtime as never,
    'request', 'coffre_web_old');
  assert.ok(result instanceof Response);
  assert.equal(result.status, 401);
  assert.equal((await result.json() as { error: string }).error, 'unauthenticated');
});
