import test from 'node:test';
import assert from 'node:assert/strict';

import { cloudflareAccess, devIdp, signin } from '../src/identity/auth-mode.ts';
import { github } from '../src/identity/signin/config.ts';

const AUD = 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90';

test('cloudflareAccess derives the issuer and cert URL from the team domain', () => {
  const expected = {
    mode: 'cloudflare',
    access: {
      issuer: 'https://acme.cloudflareaccess.com',
      jwksUrl: 'https://acme.cloudflareaccess.com/cdn-cgi/access/certs',
      audience: AUD,
    },
  };
  for (const teamDomain of ['acme.cloudflareaccess.com', 'https://acme.cloudflareaccess.com', ' acme.cloudflareaccess.com/ ']) {
    const auth = cloudflareAccess({ teamDomain, audience: AUD });
    assert.equal(auth.mode, 'cloudflare');
    assert.deepEqual(auth.resolve('https://secrets.acme.example'), expected, teamDomain);
  }
});

test('cloudflareAccess takes only an Access team domain, with an AUD tag', () => {
  for (const teamDomain of [
    'login.example.com',
    'cloudflareaccess.com',
    'acme.cloudflareaccess.com:8443',
    'http://acme.cloudflareaccess.com',
    'https://acme.cloudflareaccess.com/cdn-cgi/access/certs',
  ]) {
    assert.throws(() => cloudflareAccess({ teamDomain, audience: AUD }), /team domain/, teamDomain);
  }
  for (const audience of ['', ' ', 'two words', 'a'.repeat(65)]) {
    assert.throws(
      () => cloudflareAccess({ teamDomain: 'acme.cloudflareaccess.com', audience }),
      /Access audience/,
      audience,
    );
  }
});

test('devIdp runs on loopback only, with the local audience by default', () => {
  assert.deepEqual(devIdp({ url: 'http://127.0.0.1:8081' }).resolve('http://127.0.0.1:3000'), {
    mode: 'dev',
    access: {
      issuer: 'http://127.0.0.1:8081',
      jwksUrl: 'http://127.0.0.1:8081/cdn-cgi/access/certs',
      audience: 'coffre-local-dev-aud',
    },
    devIdpUrl: 'http://127.0.0.1:8081',
  });
  assert.equal(devIdp({ url: 'http://localhost:8081/', audience: 'other' }).resolve('').mode, 'dev');
  for (const url of ['http://10.0.0.5:8081', 'https://127.0.0.1:8081', 'http://idp.acme.example', 'http://127.0.0.1:8081/idp']) {
    assert.throws(() => devIdp({ url }), /dev IdP/, url);
  }
});

test('signin checks its options where they are written, and resolves against the public URL', () => {
  const providers = [github({ clientId: 'id', clientSecret: 'secret' })];
  const auth = signin({ providers, title: 'Acme secrets', browserSessionHours: 8 });
  assert.equal(auth.mode, 'signin');
  const resolved = auth.resolve('https://secrets.acme.example/');
  assert.equal(resolved.mode, 'signin');
  if (resolved.mode !== 'signin') return;
  assert.equal(resolved.signin.publicUrl, 'https://secrets.acme.example');
  assert.deepEqual(resolved.signin.page, { title: 'Acme secrets', note: null });
  assert.equal(resolved.signin.browserSessionHours, 8);
  assert.equal(resolved.signin.cliSessionDays, 30);

  assert.throws(() => signin({ providers: [] }), /at least one provider/);
  assert.throws(() => signin({ providers, cliSessionDays: 400 }), /cliSessionDays must be a number above 0 and at most 365/);
  assert.throws(() => auth.resolve('http://secrets.acme.example'), /the public URL must use HTTPS/);
});
