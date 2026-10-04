import test from 'node:test';
import assert from 'node:assert/strict';

import {
  defineSignin,
  github,
  google,
  microsoft,
  oidc,
  publicOrigin,
} from '../src/identity/signin/config.ts';
import type { SigninProvider } from '../src/identity/signin/types.ts';

const TENANT = '6f1c2a3b-4d5e-4f60-8a9b-0c1d2e3f4a5b';
const CREDENTIALS = { clientId: 'id', clientSecret: 'secret' };

test('GitHub and Okta, as the docs write them', () => {
  const config = defineSignin({
    publicUrl: 'https://secrets.acme.example',
    providers: [
      github({ clientId: 'Iv23li-github', clientSecret: 'github-secret', organization: ' acme ' }),
      oidc({ id: 'okta', label: 'Okta', issuer: 'https://acme.okta.com/', clientId: 'okta-id', clientSecret: 'okta-secret' }),
    ],
  });
  assert.deepEqual(
    config.providers.map((provider) => ('config' in provider ? provider.config : null)),
    [
      {
        id: 'github',
        label: 'GitHub',
        brand: 'github',
        clientId: 'Iv23li-github',
        clientSecret: 'github-secret',
        webUrl: 'https://github.com',
        apiUrl: 'https://api.github.com',
        organization: 'acme',
      },
      {
        id: 'okta',
        label: 'Okta',
        brand: 'oidc',
        clientId: 'okta-id',
        clientSecret: 'okta-secret',
        issuer: 'https://acme.okta.com',
        scopes: ['openid', 'email', 'profile'],
        authorizationParams: {},
        hostedDomain: null,
      },
    ],
  );
  assert.deepEqual(
    config.providers.map(({ id, label, brand }) => ({ id, label, brand })),
    [
      { id: 'github', label: 'GitHub', brand: 'github' },
      { id: 'okta', label: 'Okta', brand: 'oidc' },
    ],
  );
  assert.deepEqual(config.page, { title: 'Sign in to coffre', note: null });
  assert.equal(config.browserSessionHours, 12);
  assert.equal(config.cliSessionDays, 30);
});

test('GitHub Enterprise and a Google domain', () => {
  const gh = github({
    ...CREDENTIALS,
    id: 'corp-github',
    label: 'GitHub Enterprise',
    webUrl: 'https://git.acme.example/',
    apiUrl: 'https://git.acme.example/api/v3/',
  }).config;
  assert.equal(gh.webUrl, 'https://git.acme.example');
  assert.equal(gh.apiUrl, 'https://git.acme.example/api/v3');
  const goog = google({ ...CREDENTIALS, domain: 'Acme.EXAMPLE' }).config;
  assert.equal(goog.brand, 'google');
  assert.equal(goog.issuer, 'https://accounts.google.com');
  assert.equal(goog.hostedDomain, 'acme.example');
  assert.deepEqual(goog.authorizationParams, { hd: 'acme.example', prompt: 'select_account' });
});

test('issuers keep their exact spelling apart from a trailing slash', () => {
  // Compared byte for byte with `iss`: normalizing more would break real issuers.
  assert.equal(
    oidc({ ...CREDENTIALS, id: 'x', label: 'X', issuer: 'https://Example.com/tenant/' }).config.issuer,
    'https://Example.com/tenant',
  );
});

test('a provider named twice is refused', () => {
  assert.throws(
    () =>
      defineSignin({
        publicUrl: 'https://secrets.acme.example',
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
});

test('the Microsoft tenant must be a GUID, not a domain or a multi-tenant alias', () => {
  for (const tenant of ['common', 'organizations', 'acme.onmicrosoft.com', `${TENANT}x`]) {
    assert.throws(() => microsoft({ ...CREDENTIALS, tenant }), /must be the directory \(tenant\) ID/, tenant);
  }
  assert.equal(
    microsoft({ ...CREDENTIALS, tenant: ` ${TENANT} ` }).config.issuer,
    `https://login.microsoftonline.com/${TENANT}/v2.0`,
  );
});

test('google() without a domain lets any account through the picker', () => {
  const { config } = google(CREDENTIALS);
  assert.equal(config.id, 'google');
  assert.equal(config.hostedDomain, null);
  assert.deepEqual(config.authorizationParams, { prompt: 'select_account' });
  assert.equal(google({ ...CREDENTIALS, domain: '  ' }).config.hostedDomain, null);
});

test('provider URLs must be HTTPS, except on loopback', () => {
  for (const issuer of ['http://sso.acme.example', 'ftp://sso.acme.example', 'http://10.0.0.1:8080']) {
    assert.throws(
      () => oidc({ ...CREDENTIALS, id: 'sso', label: 'SSO', issuer }),
      /sign-in provider sso issuer must use HTTPS/,
      issuer,
    );
  }
  for (const issuer of ['http://127.0.0.1:8081', 'http://localhost:8081', 'http://[::1]:8081']) {
    assert.equal(oidc({ ...CREDENTIALS, id: 'dev', label: 'Dev', issuer }).config.issuer, issuer);
  }
  assert.throws(
    () => github({ ...CREDENTIALS, webUrl: 'http://git.acme.example' }),
    /sign-in provider github web URL must use HTTPS/,
  );
  assert.throws(
    () => github({ ...CREDENTIALS, apiUrl: 'http://git.acme.example/api/v3' }),
    /sign-in provider github API URL must use HTTPS/,
  );
  assert.throws(
    () => oidc({ ...CREDENTIALS, id: 'sso', label: 'SSO', issuer: 'sso.acme.example' }),
    /issuer must be an absolute URL/,
  );
});

test('provider URLs carry no credentials, query or fragment', () => {
  for (const issuer of [
    'https://user:pass@sso.acme.example',
    'https://sso.acme.example/?tenant=1',
    'https://sso.acme.example/#x',
  ]) {
    assert.throws(
      () => oidc({ ...CREDENTIALS, id: 'sso', label: 'SSO', issuer }),
      /must not carry credentials, a query or a fragment/,
      issuer,
    );
  }
});

test('the public URL must be an HTTPS origin, or loopback HTTP', () => {
  assert.equal(publicOrigin('https://secrets.acme.example'), 'https://secrets.acme.example');
  assert.equal(publicOrigin('https://secrets.acme.example:8443/'), 'https://secrets.acme.example:8443');
  assert.equal(publicOrigin('http://127.0.0.1:3000'), 'http://127.0.0.1:3000');
  assert.equal(publicOrigin('HTTPS://Secrets.Acme.EXAMPLE'), 'https://secrets.acme.example');
  assert.throws(() => publicOrigin('https://acme.example/secrets'), /must be an origin, with no path/);
  assert.throws(() => publicOrigin('http://secrets.acme.example'), /the public URL must use HTTPS/);
  assert.throws(() => publicOrigin('https://secrets.acme.example/?a=1'), /must not carry/);
  assert.throws(() => publicOrigin('secrets.acme.example'), /the public URL must be an absolute URL/);
  assert.throws(
    () => defineSignin({ publicUrl: 'https://acme.example/coffre', providers: [github(CREDENTIALS)] }),
    /must be an origin/,
  );
});

test('session lifetimes are positive and bounded', () => {
  const define = (lifetimes: { browserSessionHours?: number; cliSessionDays?: number }) =>
    defineSignin({ publicUrl: 'https://secrets.acme.example', providers: [github(CREDENTIALS)], ...lifetimes });
  for (const value of [0, -1, NaN, Infinity, 169]) {
    assert.throws(
      () => define({ browserSessionHours: value }),
      /browserSessionHours must be a number above 0 and at most 168/,
      String(value),
    );
  }
  assert.equal(define({ browserSessionHours: 168 }).browserSessionHours, 168);
  assert.equal(define({ cliSessionDays: 7.5 }).cliSessionDays, 7.5);
  assert.throws(() => define({ cliSessionDays: 366 }), /cliSessionDays must be a number above 0 and at most 365/);
  assert.equal(define({ cliSessionDays: 365 }).cliSessionDays, 365);
});

test('defineSignin needs a provider, and each needs a client id and secret', () => {
  assert.throws(
    () => defineSignin({ publicUrl: 'https://secrets.acme.example', providers: [] }),
    /at least one provider/,
  );
  assert.throws(
    () => github({ clientId: '', clientSecret: 'secret' }),
    /sign-in provider github needs a client id and a client secret/,
  );
  assert.throws(
    () => google({ clientId: 'id', clientSecret: '' }),
    /sign-in provider google needs a client id and a client secret/,
  );
  assert.deepEqual(
    defineSignin({
      publicUrl: 'https://secrets.acme.example/',
      providers: [github(CREDENTIALS)],
      page: { title: 'Acme secrets' },
      browserSessionHours: 4,
    }),
    {
      publicUrl: 'https://secrets.acme.example',
      providers: [github(CREDENTIALS)],
      page: { title: 'Acme secrets', note: null },
      browserSessionHours: 4,
      cliSessionDays: 30,
      workloads: null,
    },
  );
});

test("a deployment's own provider is checked like coffre's", () => {
  const own: SigninProvider = {
    id: 'acme',
    issuer: 'https://sso.acme.example',
    label: 'Acme SSO',
    brand: 'oidc',
    start: async () => ({ url: new URL('https://sso.acme.example/authorize'), pending: { state: 's', codeVerifier: 'v', nonce: null } }),
    finish: async () => ({ subject: '1', emails: ['dev@acme.example'], name: null }),
  };
  const define = (provider: SigninProvider) =>
    defineSignin({ publicUrl: 'https://secrets.acme.example', providers: [github(CREDENTIALS), provider] });
  assert.equal(define(own).providers[1], own);
  assert.throws(() => define({ ...own, id: 'Acme SSO' }), /"Acme SSO" must be 1-32 lowercase letters/);
  assert.throws(() => define({ ...own, id: 'github' }), /"github" is used twice/);
  assert.throws(() => define({ ...own, label: ' ' }), /sign-in provider acme needs a label/);
  assert.throws(() => define({ ...own, brand: 'okta' as never }), /acme's brand must be one of github, google, microsoft, oidc/);
  assert.throws(() => define({ ...own, finish: undefined as never }), /acme needs start\(\) and finish\(\)/);
});
