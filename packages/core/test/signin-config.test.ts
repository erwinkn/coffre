import test from 'node:test';
import assert from 'node:assert/strict';

import {
  defineSignin,
  github,
  google,
  loadSigninConfig,
  microsoft,
  oidc,
  publicOrigin,
} from '../src/identity/signin/config.ts';

const TENANT = '6f1c2a3b-4d5e-4f60-8a9b-0c1d2e3f4a5b';
const CREDENTIALS = { clientId: 'id', clientSecret: 'secret' };

const base = {
  COFFRE_PUBLIC_URL: 'https://secrets.equisafe.io',
  COFFRE_SIGNIN_PROVIDERS: 'github',
  COFFRE_SIGNIN_GITHUB_CLIENT_ID: 'Iv23li-github',
  COFFRE_SIGNIN_GITHUB_CLIENT_SECRET: 'github-secret',
} as const;

test('the documented GitHub + Okta example loads', () => {
  const config = loadSigninConfig({
    ...base,
    COFFRE_SIGNIN_PROVIDERS: 'github,okta',
    COFFRE_SIGNIN_OKTA_TYPE: 'oidc',
    COFFRE_SIGNIN_OKTA_ISSUER: 'https://equisafe.okta.com',
    COFFRE_SIGNIN_OKTA_CLIENT_ID: 'okta-id',
    COFFRE_SIGNIN_OKTA_CLIENT_SECRET: 'okta-secret',
  });
  assert.deepEqual(config, {
    publicUrl: 'https://secrets.equisafe.io',
    providers: [
      {
        kind: 'github',
        id: 'github',
        label: 'GitHub',
        brand: 'github',
        clientId: 'Iv23li-github',
        clientSecret: 'github-secret',
        webUrl: 'https://github.com',
        apiUrl: 'https://api.github.com',
        organization: null,
      },
      {
        kind: 'oidc',
        id: 'okta',
        label: 'okta',
        brand: 'oidc',
        clientId: 'okta-id',
        clientSecret: 'okta-secret',
        issuer: 'https://equisafe.okta.com',
        scopes: ['openid', 'email', 'profile'],
        authorizationParams: {},
        hostedDomain: null,
      },
    ],
    page: { title: 'Sign in to coffre', note: null },
    browserSessionHours: 12,
    cliSessionDays: 30,
  });
});

test('every optional variable is read, and values are trimmed', () => {
  const config = loadSigninConfig({
    COFFRE_PUBLIC_URL: ' https://secrets.equisafe.io/ ',
    COFFRE_SIGNIN_PROVIDERS: ' corp-github  google\tentra ',
    COFFRE_SIGNIN_CORP_GITHUB_TYPE: 'github',
    COFFRE_SIGNIN_CORP_GITHUB_CLIENT_ID: 'gh-id',
    COFFRE_SIGNIN_CORP_GITHUB_CLIENT_SECRET: 'gh-secret',
    COFFRE_SIGNIN_CORP_GITHUB_LABEL: 'GitHub Enterprise',
    COFFRE_SIGNIN_CORP_GITHUB_ORGANIZATION: ' equisafe ',
    COFFRE_SIGNIN_CORP_GITHUB_WEB_URL: 'https://git.equisafe.io/',
    COFFRE_SIGNIN_CORP_GITHUB_API_URL: 'https://git.equisafe.io/api/v3/',
    COFFRE_SIGNIN_GOOGLE_CLIENT_ID: 'g-id',
    COFFRE_SIGNIN_GOOGLE_CLIENT_SECRET: 'g-secret',
    COFFRE_SIGNIN_GOOGLE_DOMAIN: 'Equisafe.IO',
    COFFRE_SIGNIN_ENTRA_TYPE: 'microsoft',
    COFFRE_SIGNIN_ENTRA_CLIENT_ID: 'm-id',
    COFFRE_SIGNIN_ENTRA_CLIENT_SECRET: 'm-secret',
    COFFRE_SIGNIN_ENTRA_TENANT: TENANT.toUpperCase(),
    COFFRE_SIGNIN_TITLE: 'Equisafe secrets',
    COFFRE_SIGNIN_NOTE: 'Use your equisafe.io account.',
    COFFRE_SESSION_HOURS: '8',
    COFFRE_CLI_SESSION_DAYS: '7.5',
  });

  assert.equal(config.publicUrl, 'https://secrets.equisafe.io');
  assert.deepEqual(config.page, { title: 'Equisafe secrets', note: 'Use your equisafe.io account.' });
  assert.equal(config.browserSessionHours, 8);
  assert.equal(config.cliSessionDays, 7.5);
  assert.deepEqual(config.providers.map((p) => p.id), ['corp-github', 'google', 'entra']);

  const [gh, goog, entra] = config.providers;
  assert.equal(gh.kind, 'github');
  if (gh.kind !== 'github') return;
  assert.equal(gh.label, 'GitHub Enterprise');
  assert.equal(gh.organization, 'equisafe');
  assert.equal(gh.webUrl, 'https://git.equisafe.io');
  assert.equal(gh.apiUrl, 'https://git.equisafe.io/api/v3');

  assert.equal(goog.kind, 'oidc');
  if (goog.kind !== 'oidc') return;
  assert.equal(goog.brand, 'google');
  assert.equal(goog.issuer, 'https://accounts.google.com');
  assert.equal(goog.hostedDomain, 'equisafe.io');
  assert.deepEqual(goog.authorizationParams, { hd: 'equisafe.io', prompt: 'select_account' });

  assert.equal(entra.kind, 'oidc');
  if (entra.kind !== 'oidc') return;
  assert.equal(entra.brand, 'microsoft');
  assert.equal(entra.label, 'Microsoft');
  assert.equal(entra.issuer, `https://login.microsoftonline.com/${TENANT}/v2.0`);
});

test('custom OIDC scopes split on commas and whitespace', () => {
  const config = loadSigninConfig({
    ...base,
    COFFRE_SIGNIN_PROVIDERS: 'kc',
    COFFRE_SIGNIN_KC_TYPE: 'oidc',
    COFFRE_SIGNIN_KC_LABEL: 'Keycloak',
    COFFRE_SIGNIN_KC_ISSUER: 'https://sso.equisafe.io/realms/staff/',
    COFFRE_SIGNIN_KC_CLIENT_ID: 'kc-id',
    COFFRE_SIGNIN_KC_CLIENT_SECRET: 'kc-secret',
    COFFRE_SIGNIN_KC_SCOPES: 'openid, email profile,groups',
  });
  const [kc] = config.providers;
  assert.equal(kc.kind, 'oidc');
  if (kc.kind !== 'oidc') return;
  assert.equal(kc.label, 'Keycloak');
  assert.deepEqual(kc.scopes, ['openid', 'email', 'profile', 'groups']);
  assert.equal(kc.issuer, 'https://sso.equisafe.io/realms/staff', 'one trailing slash dropped');
});

test('issuers keep their exact spelling apart from a trailing slash', () => {
  // Compared byte for byte with `iss`: normalizing more would break real issuers.
  assert.equal(
    oidc({ ...CREDENTIALS, id: 'x', label: 'X', issuer: 'https://Example.com/tenant/' }).issuer,
    'https://Example.com/tenant',
  );
});

test('the public URL, the providers list and each client id and secret are required', () => {
  assert.throws(
    () => loadSigninConfig({ ...base, COFFRE_PUBLIC_URL: undefined }),
    /missing required environment variable: COFFRE_PUBLIC_URL/,
  );
  assert.throws(
    () => loadSigninConfig({ ...base, COFFRE_SIGNIN_PROVIDERS: ' ' }),
    /missing required environment variable: COFFRE_SIGNIN_PROVIDERS/,
  );
  assert.throws(
    () => loadSigninConfig({ ...base, COFFRE_SIGNIN_PROVIDERS: ',' }),
    /at least one provider/,
  );
  assert.throws(
    () => loadSigninConfig({ ...base, COFFRE_SIGNIN_GITHUB_CLIENT_ID: '' }),
    /missing required environment variable: COFFRE_SIGNIN_GITHUB_CLIENT_ID/,
  );
  assert.throws(
    () => loadSigninConfig({ ...base, COFFRE_SIGNIN_GITHUB_CLIENT_SECRET: undefined }),
    /missing required environment variable: COFFRE_SIGNIN_GITHUB_CLIENT_SECRET/,
  );
});

test('a provider named twice is refused', () => {
  assert.throws(
    () => loadSigninConfig({ ...base, COFFRE_SIGNIN_PROVIDERS: 'github github' }),
    /names a provider twice/,
  );
  assert.throws(
    () =>
      defineSignin({
        publicUrl: 'https://secrets.equisafe.io',
        providers: [github(CREDENTIALS), github({ ...CREDENTIALS, label: 'Again' })],
      }),
    /"github" is used twice/,
  );
});

test('provider ids are short lowercase slugs', () => {
  for (const id of ['GitHub', '-github', 'git_hub', 'a'.repeat(33), '']) {
    assert.throws(() => github({ ...CREDENTIALS, id }), /1-32 lowercase letters, digits or dashes/, id);
  }
  assert.equal(github({ ...CREDENTIALS, id: 'a'.repeat(32) }).id, 'a'.repeat(32));
  assert.throws(
    () => loadSigninConfig({ ...base, COFFRE_SIGNIN_PROVIDERS: 'GitHub' }),
    /"GitHub" must be 1-32/,
  );
});

test('a provider that is not a preset name needs a TYPE, and TYPE must be known', () => {
  assert.throws(
    () =>
      loadSigninConfig({
        ...base,
        COFFRE_SIGNIN_PROVIDERS: 'okta',
        COFFRE_SIGNIN_OKTA_CLIENT_ID: 'id',
        COFFRE_SIGNIN_OKTA_CLIENT_SECRET: 'secret',
      }),
    /COFFRE_SIGNIN_OKTA_TYPE is required: one of github, google, microsoft or oidc/,
  );
  assert.throws(
    () => loadSigninConfig({ ...base, COFFRE_SIGNIN_GITHUB_TYPE: 'saml' }),
    /COFFRE_SIGNIN_GITHUB_TYPE must be one of github, google, microsoft or oidc/,
  );
  // A preset name can still be given another type.
  const config = loadSigninConfig({
    ...base,
    COFFRE_SIGNIN_GITHUB_TYPE: 'oidc',
    COFFRE_SIGNIN_GITHUB_ISSUER: 'https://token.actions.githubusercontent.com',
  });
  assert.equal(config.providers[0].kind, 'oidc');
});

test('a bare `oidc` provider still needs its issuer, and Microsoft its tenant', () => {
  assert.throws(
    () =>
      loadSigninConfig({
        ...base,
        COFFRE_SIGNIN_PROVIDERS: 'oidc',
        COFFRE_SIGNIN_OIDC_CLIENT_ID: 'id',
        COFFRE_SIGNIN_OIDC_CLIENT_SECRET: 'secret',
      }),
    /missing required environment variable: COFFRE_SIGNIN_OIDC_ISSUER/,
  );
  assert.throws(
    () =>
      loadSigninConfig({
        ...base,
        COFFRE_SIGNIN_PROVIDERS: 'microsoft',
        COFFRE_SIGNIN_MICROSOFT_CLIENT_ID: 'id',
        COFFRE_SIGNIN_MICROSOFT_CLIENT_SECRET: 'secret',
      }),
    /missing required environment variable: COFFRE_SIGNIN_MICROSOFT_TENANT/,
  );
});

test('the Microsoft tenant must be a GUID, not a domain or a multi-tenant alias', () => {
  for (const tenant of ['common', 'organizations', 'equisafe.onmicrosoft.com', `${TENANT}x`]) {
    assert.throws(() => microsoft({ ...CREDENTIALS, tenant }), /must be the directory \(tenant\) ID/, tenant);
  }
  assert.equal(
    microsoft({ ...CREDENTIALS, tenant: ` ${TENANT} ` }).issuer,
    `https://login.microsoftonline.com/${TENANT}/v2.0`,
  );
});

test('google() without a domain lets any account through the picker', () => {
  const config = google(CREDENTIALS);
  assert.equal(config.id, 'google');
  assert.equal(config.hostedDomain, null);
  assert.deepEqual(config.authorizationParams, { prompt: 'select_account' });
  assert.equal(google({ ...CREDENTIALS, domain: '  ' }).hostedDomain, null);
});

test('provider URLs must be HTTPS, except on loopback', () => {
  for (const issuer of ['http://sso.equisafe.io', 'ftp://sso.equisafe.io', 'http://10.0.0.1:8080']) {
    assert.throws(
      () => oidc({ ...CREDENTIALS, id: 'sso', label: 'SSO', issuer }),
      /sign-in provider sso issuer must use HTTPS/,
      issuer,
    );
  }
  for (const issuer of ['http://127.0.0.1:8081', 'http://localhost:8081', 'http://[::1]:8081']) {
    assert.equal(oidc({ ...CREDENTIALS, id: 'dev', label: 'Dev', issuer }).issuer, issuer);
  }
  assert.throws(
    () => github({ ...CREDENTIALS, webUrl: 'http://git.equisafe.io' }),
    /sign-in provider github web URL must use HTTPS/,
  );
  assert.throws(
    () => github({ ...CREDENTIALS, apiUrl: 'http://git.equisafe.io/api/v3' }),
    /sign-in provider github API URL must use HTTPS/,
  );
  assert.throws(
    () => oidc({ ...CREDENTIALS, id: 'sso', label: 'SSO', issuer: 'sso.equisafe.io' }),
    /issuer must be an absolute URL/,
  );
});

test('provider URLs carry no credentials, query or fragment', () => {
  for (const issuer of [
    'https://user:pass@sso.equisafe.io',
    'https://sso.equisafe.io/?tenant=1',
    'https://sso.equisafe.io/#x',
  ]) {
    assert.throws(
      () => oidc({ ...CREDENTIALS, id: 'sso', label: 'SSO', issuer }),
      /must not carry credentials, a query or a fragment/,
      issuer,
    );
  }
});

test('COFFRE_PUBLIC_URL must be an HTTPS origin, or loopback HTTP', () => {
  assert.equal(publicOrigin('https://secrets.equisafe.io'), 'https://secrets.equisafe.io');
  assert.equal(publicOrigin('https://secrets.equisafe.io:8443/'), 'https://secrets.equisafe.io:8443');
  assert.equal(publicOrigin('http://127.0.0.1:3000'), 'http://127.0.0.1:3000');
  assert.equal(publicOrigin('HTTPS://Secrets.Equisafe.IO'), 'https://secrets.equisafe.io');
  assert.throws(() => publicOrigin('https://equisafe.io/secrets'), /must be an origin, with no path/);
  assert.throws(() => publicOrigin('http://secrets.equisafe.io'), /COFFRE_PUBLIC_URL must use HTTPS/);
  assert.throws(() => publicOrigin('https://secrets.equisafe.io/?a=1'), /must not carry/);
  assert.throws(() => publicOrigin('secrets.equisafe.io'), /COFFRE_PUBLIC_URL must be an absolute URL/);
  assert.throws(
    () => loadSigninConfig({ ...base, COFFRE_PUBLIC_URL: 'https://equisafe.io/coffre' }),
    /must be an origin/,
  );
  assert.throws(
    () => defineSignin({ publicUrl: 'https://equisafe.io/coffre', providers: [github(CREDENTIALS)] }),
    /must be an origin/,
  );
});

test('session lifetimes are positive and bounded', () => {
  for (const value of ['0', '-1', 'NaN', 'Infinity', 'twelve', '169']) {
    assert.throws(
      () => loadSigninConfig({ ...base, COFFRE_SESSION_HOURS: value }),
      /COFFRE_SESSION_HOURS must be a number between 0 and 168/,
      value,
    );
  }
  assert.equal(loadSigninConfig({ ...base, COFFRE_SESSION_HOURS: '168' }).browserSessionHours, 168);
  assert.throws(
    () => loadSigninConfig({ ...base, COFFRE_CLI_SESSION_DAYS: '366' }),
    /COFFRE_CLI_SESSION_DAYS must be a number between 0 and 365/,
  );
  assert.equal(loadSigninConfig({ ...base, COFFRE_CLI_SESSION_DAYS: '365' }).cliSessionDays, 365);
});

test('defineSignin needs a provider, and each needs a client id and secret', () => {
  assert.throws(
    () => defineSignin({ publicUrl: 'https://secrets.equisafe.io', providers: [] }),
    /at least one provider/,
  );
  assert.throws(
    () =>
      defineSignin({
        publicUrl: 'https://secrets.equisafe.io',
        providers: [github({ clientId: '', clientSecret: 'secret' })],
      }),
    /sign-in provider github needs a client id and a client secret/,
  );
  assert.throws(
    () =>
      defineSignin({
        publicUrl: 'https://secrets.equisafe.io',
        providers: [google({ clientId: 'id', clientSecret: '' })],
      }),
    /sign-in provider google needs a client id and a client secret/,
  );
  assert.deepEqual(
    defineSignin({
      publicUrl: 'https://secrets.equisafe.io/',
      providers: [github(CREDENTIALS)],
      page: { title: 'Equisafe secrets' },
      browserSessionHours: 4,
    }),
    {
      publicUrl: 'https://secrets.equisafe.io',
      providers: [github(CREDENTIALS)],
      page: { title: 'Equisafe secrets', note: null },
      browserSessionHours: 4,
      cliSessionDays: 30,
    },
  );
});
