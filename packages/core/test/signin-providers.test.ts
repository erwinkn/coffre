import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';

import { DevIdp } from '@coffre/conformance/idp';
import {
  github,
  GitHubSigninProvider,
  oidc,
  OidcSigninProvider,
  SigninError,
  type OidcProviderConfig,
  type PendingSignin,
  type SigninErrorCode,
  type SigninProvider,
} from '../src/identity/signin/index.ts';

// Real round trips against the dev IdP: coffre's providers run their
// production code paths against a local OpenID Connect provider and a local
// imitation of GitHub, with nothing stubbed but, where a test says so, one
// field of one response.

const REDIRECT_URI = 'http://127.0.0.1:3000/auth/callback/dev';
const CREDENTIALS = { clientId: 'coffre-local', clientSecret: 'coffre-local-secret' };

let idp: DevIdp;

before(async () => {
  idp = new DevIdp({ autoApprove: true });
  await idp.start();
});

after(async () => {
  await idp.stop();
});

function oidcConfig(overrides: Partial<OidcProviderConfig> = {}): OidcProviderConfig {
  return {
    ...oidc({ ...CREDENTIALS, id: 'dev', label: 'Dev IdP', issuer: idp.issuer }).config,
    ...overrides,
  };
}

function githubProvider(options: { organization?: string; clientSecret?: string } = {}): SigninProvider {
  return github({
    ...CREDENTIALS,
    ...options,
    id: 'dev-github',
    webUrl: `${idp.origin}/github`,
    apiUrl: `${idp.origin}/github/api`,
  });
}

/** Follow the provider's redirect back to coffre, as the browser would. */
async function authorize(url: URL): Promise<URL> {
  const response = await fetch(url, { redirect: 'manual' });
  const location = response.headers.get('location');
  assert.ok(location, `expected a redirect from ${url.pathname}, got ${response.status}`);
  return new URL(location);
}

/** Press "Deny" on the provider's page. */
async function deny(url: URL): Promise<URL> {
  const body = new URLSearchParams(url.searchParams);
  body.set('deny', '1');
  const response = await fetch(new URL(url.pathname, url), {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body,
    redirect: 'manual',
  });
  const location = response.headers.get('location');
  assert.ok(location, `expected a redirect, got ${response.status}`);
  return new URL(location);
}

async function signIn(provider: SigninProvider, email: string) {
  const { url, pending } = await provider.start(REDIRECT_URI, { loginHint: email });
  const callback = await authorize(url);
  return provider.finish(callback, REDIRECT_URI, pending);
}

async function refusal(promise: Promise<unknown>, code: SigninErrorCode): Promise<void> {
  await assert.rejects(promise, (error: unknown) => {
    assert.ok(error instanceof SigninError, `expected a SigninError, got ${String(error)}`);
    assert.equal(error.code, code, error.message);
    return true;
  });
}

/**
 * A fetch that edits the ID token's claims on the way back from the token
 * endpoint. The signature is left stale on purpose: coffre takes the ID token
 * straight from the token endpoint and does not check it (OIDC Core 3.1.3.7),
 * so only the claims matter.
 */
function editIdToken(edit: (claims: Record<string, unknown>) => void): typeof fetch {
  return async (input, init) => {
    const response = await fetch(input, init);
    const url = new URL(input instanceof Request ? input.url : String(input));
    if (url.pathname !== '/oauth/token' || !response.ok) return response;
    const body = (await response.json()) as { id_token: string };
    const [header, payload, signature] = body.id_token.split('.');
    const claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    edit(claims);
    body.id_token = [header, Buffer.from(JSON.stringify(claims)).toString('base64url'), signature].join('.');
    return new Response(JSON.stringify(body), { status: 200, headers: response.headers });
  };
}

// --- OpenID Connect ---------------------------------------------------------

test('OIDC: a round trip yields the subject and the verified email', async () => {
  const provider = new OidcSigninProvider(oidcConfig());
  const { url, pending } = await provider.start(REDIRECT_URI, { loginHint: 'Dev@Acme.example' });

  assert.equal(url.origin + url.pathname, `${idp.origin}/oauth/authorize`);
  assert.equal(url.searchParams.get('client_id'), 'coffre-local');
  assert.equal(url.searchParams.get('redirect_uri'), REDIRECT_URI);
  assert.equal(url.searchParams.get('scope'), 'openid email profile');
  assert.equal(url.searchParams.get('state'), pending.state);
  assert.equal(url.searchParams.get('nonce'), pending.nonce);
  assert.equal(url.searchParams.get('code_challenge_method'), 'S256');

  const profile = await provider.finish(await authorize(url), REDIRECT_URI, pending);
  assert.deepEqual(profile, {
    subject: idp.subjectFor('dev@acme.example'),
    emails: ['dev@acme.example'],
    name: 'Devon Dev',
  });
});

test('OIDC: the subject follows the account, not the email', async () => {
  const provider = new OidcSigninProvider(oidcConfig());
  idp.setSubject('recycled@acme.example', 'someone-new');
  const profile = await signIn(provider, 'recycled@acme.example');
  assert.equal(profile.subject, 'someone-new');
  assert.deepEqual(profile.emails, ['recycled@acme.example']);
});

test('OIDC: extra authorization parameters are sent', async () => {
  const provider = new OidcSigninProvider(
    oidcConfig({ authorizationParams: { prompt: 'select_account', hd: 'acme.example' } }),
  );
  const { url } = await provider.start(REDIRECT_URI);
  assert.equal(url.searchParams.get('prompt'), 'select_account');
  assert.equal(url.searchParams.get('hd'), 'acme.example');
  assert.equal(url.searchParams.get('login_hint'), null);
});

test('OIDC: a callback for another sign-in is a state mismatch', async () => {
  const provider = new OidcSigninProvider(oidcConfig());
  const first = await provider.start(REDIRECT_URI, { loginHint: 'dev@acme.example' });
  const second = await provider.start(REDIRECT_URI, { loginHint: 'dev@acme.example' });
  const callback = await authorize(first.url);
  await refusal(provider.finish(callback, REDIRECT_URI, second.pending), 'state_mismatch');

  const forged = new URL(callback);
  forged.searchParams.set('state', 'forged');
  await refusal(provider.finish(forged, REDIRECT_URI, first.pending), 'state_mismatch');

  const noIssuer = new URL(callback);
  noIssuer.searchParams.delete('iss');
  await refusal(provider.finish(noIssuer, REDIRECT_URI, first.pending), 'state_mismatch');
});

test('OIDC: pressing Deny is a provider denial', async () => {
  const provider = new OidcSigninProvider(oidcConfig());
  const { url, pending } = await provider.start(REDIRECT_URI);
  const callback = await deny(url);
  assert.equal(callback.searchParams.get('error'), 'access_denied');
  await refusal(provider.finish(callback, REDIRECT_URI, pending), 'provider_denied');
});

test('OIDC: a code is redeemed once, and only with its redirect URI and verifier', async () => {
  const provider = new OidcSigninProvider(oidcConfig());

  const { url, pending } = await provider.start(REDIRECT_URI, { loginHint: 'dev@acme.example' });
  const callback = await authorize(url);
  await provider.finish(callback, REDIRECT_URI, pending);
  await refusal(provider.finish(callback, REDIRECT_URI, pending), 'provider_denied');

  const other = await provider.start(REDIRECT_URI, { loginHint: 'dev@acme.example' });
  await refusal(
    provider.finish(await authorize(other.url), 'http://127.0.0.1:3000/elsewhere', other.pending),
    'provider_denied',
  );

  const third = await provider.start(REDIRECT_URI, { loginHint: 'dev@acme.example' });
  const wrongVerifier: PendingSignin = { ...third.pending, codeVerifier: 'x'.repeat(43) };
  await refusal(provider.finish(await authorize(third.url), REDIRECT_URI, wrongVerifier), 'provider_denied');
});

test('OIDC: a nonce that does not match is not trusted', async () => {
  const provider = new OidcSigninProvider(oidcConfig());
  const { url, pending } = await provider.start(REDIRECT_URI, { loginHint: 'dev@acme.example' });
  await refusal(
    provider.finish(await authorize(url), REDIRECT_URI, { ...pending, nonce: 'another-nonce' }),
    'invalid_response',
  );
});

test('OIDC: an email the provider marks unverified is dropped', async () => {
  const provider = new OidcSigninProvider(oidcConfig(), {
    fetch: editIdToken((claims) => {
      claims.email_verified = false;
    }),
  });
  const profile = await signIn(provider, 'dev@acme.example');
  assert.deepEqual(profile.emails, []);
  assert.equal(profile.subject, idp.subjectFor('dev@acme.example'));
});

test('OIDC: a token without email yields no email; one without email_verified is trusted', async () => {
  const missing = new OidcSigninProvider(oidcConfig(), {
    fetch: editIdToken((claims) => {
      delete claims.email;
    }),
  });
  assert.deepEqual((await signIn(missing, 'dev@acme.example')).emails, []);

  // Entra sends no email_verified at all.
  const silent = new OidcSigninProvider(oidcConfig(), {
    fetch: editIdToken((claims) => {
      delete claims.email_verified;
      claims.email = '  Dev@Acme.EXAMPLE ';
    }),
  });
  assert.deepEqual((await signIn(silent, 'dev@acme.example')).emails, ['dev@acme.example']);
});

test('OIDC: a hosted domain is checked on the hd claim, not the request', async () => {
  const config = oidcConfig({ hostedDomain: 'acme.example', authorizationParams: { hd: 'acme.example' } });
  await refusal(signIn(new OidcSigninProvider(config), 'dev@acme.example'), 'wrong_domain');

  const other = new OidcSigninProvider(config, {
    fetch: editIdToken((claims) => {
      claims.hd = 'gmail.com';
    }),
  });
  await refusal(signIn(other, 'dev@acme.example'), 'wrong_domain');

  const member = new OidcSigninProvider(config, {
    fetch: editIdToken((claims) => {
      claims.hd = 'acme.example';
    }),
  });
  assert.deepEqual((await signIn(member, 'dev@acme.example')).emails, ['dev@acme.example']);
});

test('OIDC: an ID token for another client is not trusted', async () => {
  const provider = new OidcSigninProvider(oidcConfig(), {
    fetch: editIdToken((claims) => {
      claims.aud = 'someone-else';
    }),
  });
  await refusal(signIn(provider, 'dev@acme.example'), 'invalid_response');
});

test('OIDC: an issuer that cannot be reached is provider_unavailable', async () => {
  const gone = new DevIdp();
  await gone.start();
  const issuer = gone.issuer;
  await gone.stop();

  const provider = oidc({ ...CREDENTIALS, id: 'gone', label: 'Gone', issuer });
  await refusal(provider.start(REDIRECT_URI), 'provider_unavailable');
});

// --- GitHub -----------------------------------------------------------------

test('GitHub: a round trip yields the numeric id and verified emails, primary first', async () => {
  const provider = githubProvider();
  const { url, pending } = await provider.start(REDIRECT_URI, { loginHint: 'lead@acme.example' });
  assert.equal(url.origin + url.pathname, `${idp.origin}/github/login/oauth/authorize`);
  assert.equal(url.searchParams.get('scope'), 'read:user user:email');
  assert.equal(url.searchParams.get('allow_signup'), 'false');
  assert.equal(url.searchParams.get('login'), 'lead@acme.example');
  assert.equal(pending.nonce, null);

  const profile = await provider.finish(await authorize(url), REDIRECT_URI, pending);
  const account = idp.gitHubUserFor('lead@acme.example');
  assert.deepEqual(profile, {
    subject: String(account.id),
    emails: ['lead@acme.example'],
    name: 'Lea Lead',
  });

  idp.setGitHubUser('multi@acme.example', {
    emails: [
      { email: 'Personal@Example.com' },
      { email: 'multi@acme.example', primary: true },
      { email: 'old@acme.example', verified: false },
    ],
  });
  assert.deepEqual((await signIn(provider, 'multi@acme.example')).emails, [
    'multi@acme.example',
    'personal@example.com',
  ]);
});

test('GitHub: an unverified address on the account is never reported', async () => {
  // The fake outsider account lists lead's address, unverified.
  assert.ok(idp.gitHubUserFor('outsider@acme.example').emails.some((e) => e.email === 'lead@acme.example'));
  const profile = await signIn(githubProvider(), 'outsider@acme.example');
  assert.deepEqual(profile.emails, ['outsider@acme.example']);
});

test('GitHub: an account with no verified email yields none', async () => {
  idp.setGitHubUser('unverified@acme.example', {
    emails: [{ email: 'unverified@acme.example', verified: false }],
  });
  const profile = await signIn(githubProvider(), 'unverified@acme.example');
  assert.deepEqual(profile.emails, []);
  assert.equal(profile.subject, String(idp.gitHubUserFor('unverified@acme.example').id));
});

test('GitHub: the name falls back to the login', async () => {
  // The fake always has a name; GitHub sends null for an account without one.
  const provider = new GitHubSigninProvider(
    github({ ...CREDENTIALS, id: 'dev-github', webUrl: `${idp.origin}/github`, apiUrl: `${idp.origin}/github/api` }).config,
    {
      fetch: async (input, init) => {
        const response = await fetch(input, init);
        if (!String(input).endsWith('/github/api/user')) return response;
        const body = (await response.json()) as Record<string, unknown>;
        return Response.json({ ...body, name: null });
      },
    },
  );
  assert.equal((await signIn(provider, 'noname@acme.example')).name, 'noname');
});

test('GitHub: an organization admits its members only, and asks for read:org', async () => {
  const provider = githubProvider({ organization: 'Acme' });
  const { url } = await provider.start(REDIRECT_URI, { loginHint: 'dev@acme.example' });
  assert.equal(url.searchParams.get('scope'), 'read:user user:email read:org');

  assert.deepEqual((await signIn(provider, 'dev@acme.example')).emails, ['dev@acme.example']);

  idp.setGitHubUser('contractor@acme.example', { orgs: ['elsewhere'] });
  await refusal(signIn(provider, 'contractor@acme.example'), 'not_in_organization');
});

test('GitHub: a callback for another sign-in is a state mismatch, even when it reports an error', async () => {
  const provider = githubProvider();
  const first = await provider.start(REDIRECT_URI, { loginHint: 'dev@acme.example' });
  const second = await provider.start(REDIRECT_URI, { loginHint: 'dev@acme.example' });
  const callback = await authorize(first.url);
  await refusal(provider.finish(callback, REDIRECT_URI, second.pending), 'state_mismatch');

  const denied = await deny(second.url);
  await refusal(provider.finish(denied, REDIRECT_URI, first.pending), 'state_mismatch');
});

test('GitHub: pressing Deny is a provider denial', async () => {
  const provider = githubProvider();
  const { url, pending } = await provider.start(REDIRECT_URI);
  const callback = await deny(url);
  assert.equal(callback.searchParams.get('error'), 'access_denied');
  await refusal(provider.finish(callback, REDIRECT_URI, pending), 'provider_denied');
});

test('GitHub: a callback without a code is not trusted', async () => {
  const provider = githubProvider();
  const { pending } = await provider.start(REDIRECT_URI);
  const callback = new URL(REDIRECT_URI);
  callback.searchParams.set('state', pending.state);
  await refusal(provider.finish(callback, REDIRECT_URI, pending), 'invalid_response');
});

test('GitHub: a spent code, a wrong verifier or a wrong secret is refused by GitHub', async () => {
  const provider = githubProvider();
  const { url, pending } = await provider.start(REDIRECT_URI, { loginHint: 'dev@acme.example' });
  const callback = await authorize(url);
  await provider.finish(callback, REDIRECT_URI, pending);
  await refusal(provider.finish(callback, REDIRECT_URI, pending), 'provider_denied');

  const other = await provider.start(REDIRECT_URI, { loginHint: 'dev@acme.example' });
  await refusal(
    provider.finish(await authorize(other.url), REDIRECT_URI, { ...other.pending, codeVerifier: 'x'.repeat(43) }),
    'provider_denied',
  );

  const wrongSecret = githubProvider({ clientSecret: 'not-the-secret' });
  await refusal(signIn(wrongSecret, 'dev@acme.example'), 'provider_denied');
});

test('GitHub: an API that cannot be reached is provider_unavailable', async () => {
  const gone = new DevIdp();
  await gone.start();
  const origin = gone.origin;
  await gone.stop();

  const provider = github({ ...CREDENTIALS, id: 'gone', webUrl: `${origin}/github`, apiUrl: `${origin}/github/api` });
  const { pending } = await provider.start(REDIRECT_URI);
  const callback = new URL(REDIRECT_URI);
  callback.searchParams.set('state', pending.state);
  callback.searchParams.set('code', 'some-code');
  await refusal(provider.finish(callback, REDIRECT_URI, pending), 'provider_unavailable');
});
