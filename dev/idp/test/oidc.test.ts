import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { createRemoteJWKSet, decodeJwt, jwtVerify } from 'jose';

import { DevIdp } from '../src/idp.ts';
import { defaultSubject, PERSONAS } from '../src/people.ts';
import { LOCAL_SEED_DIRECTORY } from '../../seed-config.mjs';
import { basic, form, get, location, pkce, REDIRECT_URI } from './helpers.ts';

const CLIENT_ID = 'coffre-local';
const CLIENT_SECRET = 'coffre-local-secret';

let idp: DevIdp;

before(async () => {
  idp = new DevIdp({
    autoApprove: true,
    clients: [{ clientId: 'strict', clientSecret: 'strict-secret', redirectUris: ['https://app.example/cb'] }],
  });
  await idp.start();
});

after(async () => {
  await idp.stop();
});

function authorizeUrl(params: Record<string, string>): URL {
  const url = new URL('/oauth/authorize', idp.origin);
  for (const [name, value] of Object.entries(params)) url.searchParams.set(name, value);
  return url;
}

/** Run the front channel with auto-approve; returns the code and what redeems it. */
async function authorize(opts: { email?: string; nonce?: string; redirectUri?: string } = {}) {
  const { verifier, challenge } = pkce();
  const params: Record<string, string> = {
    response_type: 'code',
    client_id: CLIENT_ID,
    redirect_uri: opts.redirectUri ?? REDIRECT_URI,
    scope: 'openid email profile',
    state: 'state-123',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    login_hint: opts.email ?? 'dev@acme.example',
  };
  if (opts.nonce) params.nonce = opts.nonce;
  const back = location(await get(authorizeUrl(params)));
  const code = back.searchParams.get('code');
  assert.ok(code, `no code in ${back.href}`);
  return { code, verifier, back };
}

async function redeem(params: Record<string, string>, init: RequestInit = {}) {
  const response = await fetch(`${idp.origin}/oauth/token`, {
    ...form({ grant_type: 'authorization_code', redirect_uri: REDIRECT_URI, ...params }),
    ...init,
  });
  return { status: response.status, headers: response.headers, body: await response.json() };
}

test('discovery advertises the code flow with PKCE', async () => {
  const response = await get(`${idp.origin}/.well-known/openid-configuration`);
  const metadata = await response.json();

  assert.equal(metadata.issuer, idp.origin);
  assert.equal(metadata.issuer.endsWith('/'), false);
  assert.equal(metadata.authorization_endpoint, `${idp.origin}/oauth/authorize`);
  assert.equal(metadata.token_endpoint, `${idp.origin}/oauth/token`);
  assert.equal(metadata.userinfo_endpoint, `${idp.origin}/oauth/userinfo`);
  assert.equal(metadata.jwks_uri, idp.jwksUrl);
  assert.deepEqual(metadata.code_challenge_methods_supported, ['S256']);
  assert.deepEqual(metadata.response_types_supported, ['code']);
  assert.equal(metadata.authorization_response_iss_parameter_supported, true);
});

test('the full code flow issues a verifiable ID token and a usable access token', async () => {
  const { code, verifier, back } = await authorize({ email: 'lead@acme.example' });
  assert.equal(back.origin + back.pathname, REDIRECT_URI);
  assert.equal(back.searchParams.get('state'), 'state-123');
  assert.equal(back.searchParams.get('iss'), idp.issuer);

  const { status, headers, body } = await redeem(
    { code, code_verifier: verifier },
    { headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: basic(CLIENT_ID, CLIENT_SECRET) } },
  );
  assert.equal(status, 200);
  assert.equal(headers.get('cache-control'), 'no-store');
  assert.equal(body.token_type, 'Bearer');
  assert.equal(body.scope, 'openid email profile');
  assert.equal(typeof body.expires_in, 'number');

  const jwks = createRemoteJWKSet(new URL(idp.jwksUrl));
  const { payload, protectedHeader } = await jwtVerify(body.id_token, jwks, {
    issuer: idp.issuer,
    audience: CLIENT_ID,
  });
  assert.equal(protectedHeader.kid, idp.kid);
  assert.equal(payload.email, 'lead@acme.example');
  assert.equal(payload.email_verified, true);
  assert.equal(payload.name, 'Lea Lead');
  assert.equal(payload.sub, defaultSubject('lead@acme.example'));
  assert.match(payload.sub!, /^dev-[0-9a-f]{24}$/);
  assert.equal(typeof payload.auth_time, 'number');
  assert.equal(payload.nonce, undefined);

  const userinfo = await get(`${idp.origin}/oauth/userinfo`, {
    headers: { authorization: `Bearer ${body.access_token}` },
  });
  assert.equal(userinfo.status, 200);
  assert.deepEqual(await userinfo.json(), {
    sub: payload.sub,
    email: 'lead@acme.example',
    email_verified: true,
    name: 'Lea Lead',
  });
});

test('the nonce is echoed into the ID token', async () => {
  const { code, verifier } = await authorize({ nonce: 'n-0S6_WzA2Mj' });
  const { body } = await redeem({ code, code_verifier: verifier, client_id: CLIENT_ID, client_secret: CLIENT_SECRET });
  assert.equal(decodeJwt(body.id_token).nonce, 'n-0S6_WzA2Mj');
});

test('a code is single-use, and replaying it revokes the token it produced', async () => {
  const { code, verifier } = await authorize();
  const creds = { client_id: CLIENT_ID, client_secret: CLIENT_SECRET };
  const first = await redeem({ code, code_verifier: verifier, ...creds });
  assert.equal(first.status, 200);

  const second = await redeem({ code, code_verifier: verifier, ...creds });
  assert.equal(second.status, 400);
  assert.equal(second.body.error, 'invalid_grant');

  const userinfo = await get(`${idp.origin}/oauth/userinfo`, {
    headers: { authorization: `Bearer ${first.body.access_token}` },
  });
  assert.equal(userinfo.status, 401);
});

test('a wrong code_verifier is rejected', async () => {
  const { code } = await authorize();
  const { status, body } = await redeem({
    code,
    code_verifier: pkce().verifier,
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
  });
  assert.equal(status, 400);
  assert.equal(body.error, 'invalid_grant');
});

test('a redirect_uri other than the one authorized is rejected at the token endpoint', async () => {
  const { code, verifier } = await authorize();
  const { status, body } = await redeem({
    code,
    code_verifier: verifier,
    redirect_uri: 'http://127.0.0.1:3000/elsewhere',
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
  });
  assert.equal(status, 400);
  assert.equal(body.error, 'invalid_grant');
});

test('a wrong client secret is invalid_client', async () => {
  const { code, verifier } = await authorize();
  const { status, headers, body } = await redeem({
    code,
    code_verifier: verifier,
    client_id: CLIENT_ID,
    client_secret: 'nope',
  });
  assert.equal(status, 401);
  assert.equal(body.error, 'invalid_client');
  assert.ok(headers.get('www-authenticate'));
});

test('unknown clients and unregistered redirect URIs get an error page, never a redirect', async () => {
  const { challenge } = pkce();
  const base = {
    response_type: 'code',
    scope: 'openid',
    state: 's',
    code_challenge: challenge,
    code_challenge_method: 'S256',
  };
  const cases = [
    { ...base, client_id: 'who', redirect_uri: REDIRECT_URI },
    { ...base, client_id: 'strict', redirect_uri: 'https://app.example/cb/../evil' },
    { ...base, client_id: 'strict', redirect_uri: 'https://evil.example/cb' },
    { ...base, client_id: CLIENT_ID, redirect_uri: 'https://evil.example/cb' },
    { ...base, client_id: CLIENT_ID },
  ];
  for (const params of cases) {
    const response = await get(authorizeUrl(params));
    assert.equal(response.status, 400, JSON.stringify(params));
    assert.equal(response.headers.get('location'), null);
    assert.match(response.headers.get('content-type')!, /^text\/html/);
  }
});

test('the built-in client accepts any loopback port, registered clients match exactly', async () => {
  const { back } = await authorize({ redirectUri: 'http://localhost:5173/callback?x=1' });
  assert.equal(back.origin, 'http://localhost:5173');
  assert.equal(back.searchParams.get('x'), '1');

  const { challenge } = pkce();
  const response = await get(
    authorizeUrl({
      response_type: 'code',
      client_id: 'strict',
      redirect_uri: 'https://app.example/cb',
      scope: 'openid',
      state: 's',
      code_challenge: challenge,
      code_challenge_method: 'S256',
      login_hint: 'dev@acme.example',
    }),
  );
  assert.equal(location(response).origin, 'https://app.example');
});

test('bad requests to a trusted redirect URI come back as RFC 6749 errors', async () => {
  const { challenge } = pkce();
  const good = {
    response_type: 'code',
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    scope: 'openid',
    state: 's',
    code_challenge: challenge,
    code_challenge_method: 'S256',
  };
  const cases: Array<[Record<string, string>, string]> = [
    [{ ...good, response_type: 'token' }, 'unsupported_response_type'],
    [{ ...good, scope: 'email' }, 'invalid_scope'],
    [{ ...good, code_challenge_method: 'plain' }, 'invalid_request'],
    [{ ...good, code_challenge_method: '' }, 'invalid_request'],
    [{ ...good, code_challenge: '' }, 'invalid_request'],
  ];
  for (const [params, error] of cases) {
    const back = location(await get(authorizeUrl(params)));
    assert.equal(back.origin + back.pathname, REDIRECT_URI);
    assert.equal(back.searchParams.get('error'), error, JSON.stringify(params));
    assert.equal(back.searchParams.get('state'), 's');
    assert.equal(back.searchParams.get('iss'), idp.issuer);
  }
});

test('without auto-approve the persona page shows, escapes, and posts back', async () => {
  const manual = new DevIdp();
  await manual.start();
  try {
    const { verifier, challenge } = pkce();
    const params = {
      response_type: 'code',
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      scope: 'openid',
      state: '"><script>alert(1)</script>',
      code_challenge: challenge,
      code_challenge_method: 'S256',
      login_hint: 'dev@acme.example',
    };
    const url = new URL('/oauth/authorize', manual.origin);
    for (const [name, value] of Object.entries(params)) url.searchParams.set(name, value);

    const page = await get(url);
    assert.equal(page.status, 200);
    const html = await page.text();
    assert.ok(!html.includes('<script>'));
    assert.ok(html.includes('&quot;&gt;&lt;script&gt;'));
    for (const persona of PERSONAS) assert.ok(html.includes(persona.email));

    const approved = await fetch(`${manual.origin}/oauth/authorize`, form({ ...params, email: 'Auditor@Acme.example' }));
    const back = location(approved);
    assert.equal(back.searchParams.get('state'), params.state);

    const token = await fetch(`${manual.origin}/oauth/token`, form({
      grant_type: 'authorization_code',
      code: back.searchParams.get('code')!,
      redirect_uri: REDIRECT_URI,
      code_verifier: verifier,
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
    }));
    assert.equal(decodeJwt((await token.json()).id_token).email, 'auditor@acme.example');

    const denied = location(await fetch(`${manual.origin}/oauth/authorize`, form({ ...params, deny: '1' })));
    assert.equal(denied.searchParams.get('error'), 'access_denied');
    assert.equal(denied.searchParams.get('code'), null);
  } finally {
    await manual.stop();
  }
});

test('setSubject gives a recycled email a new subject', async () => {
  const email = 'recycled@example.com';
  const creds = { client_id: CLIENT_ID, client_secret: CLIENT_SECRET };

  const before = await authorize({ email });
  const first = decodeJwt((await redeem({ code: before.code, code_verifier: before.verifier, ...creds })).body.id_token);

  idp.setSubject(email, 'dev-new-owner');
  const after = await authorize({ email });
  const second = await redeem({ code: after.code, code_verifier: after.verifier, ...creds });

  assert.notEqual(first.sub, email);
  assert.equal(decodeJwt(second.body.id_token).sub, 'dev-new-owner');
  const userinfo = await get(`${idp.origin}/oauth/userinfo`, {
    headers: { authorization: `Bearer ${second.body.access_token}` },
  });
  assert.equal((await userinfo.json()).sub, 'dev-new-owner');
});

test('userinfo refuses missing and unknown tokens', async () => {
  const missing = await get(`${idp.origin}/oauth/userinfo`);
  assert.equal(missing.status, 401);
  const unknown = await get(`${idp.origin}/oauth/userinfo`, { headers: { authorization: 'Bearer nope' } });
  assert.equal(unknown.status, 401);
  assert.match(unknown.headers.get('www-authenticate')!, /invalid_token/);
});

test('the Access endpoints still work', async () => {
  const minted = await (await get(`${idp.origin}/dev/mint?email=dev@acme.example`)).json();
  assert.equal(decodeJwt(minted.token).email, 'dev@acme.example');
  const jwks = await (await get(idp.jwksUrl)).json();
  assert.equal(jwks.keys[0].kid, idp.kid);
});

test('the personas are the seeded users', () => {
  const seeded = LOCAL_SEED_DIRECTORY.filter((p) => p.principalType === 'user').map((p) => p.principalId);
  assert.deepEqual(
    PERSONAS.map((p) => p.email).sort(),
    ['admin@acme.example', ...seeded].sort(),
  );
});
