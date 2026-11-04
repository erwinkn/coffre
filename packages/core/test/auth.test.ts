import test from 'node:test';
import assert from 'node:assert/strict';

import { cloudflareAccess, signin } from '../src/identity/auth.ts';
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

test('signin checks its options where they are written, and resolves against the public URL', () => {
  const providers = [github({ clientId: 'id', clientSecret: 'secret' })];
  const auth = signin({ providers, title: 'Acme secrets', browserSessionHours: 8 });
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

test('signin passes its passkey policy on, optional unless set (passkeys.md, section 2; review r1 of #497)', () => {
  const providers = [github({ clientId: 'id', clientSecret: 'secret' })];
  const policy = (auth: ReturnType<typeof signin>) => {
    const resolved = auth.resolve('https://secrets.acme.example');
    return resolved.mode === 'signin' ? resolved.signin.passkeys.policy : null;
  };
  assert.equal(policy(signin({ providers })), 'optional');
  assert.equal(policy(signin({ providers, passkeys: 'required' })), 'required');
  assert.equal(policy(signin({ providers, passkeys: 'off' })), 'off');
  // @ts-expect-error: what a deployment's JavaScript could pass
  assert.throws(() => signin({ providers, passkeys: 'always' }), /passkeys is one of 'off', 'optional', 'required'/);
});

test("passkeys' relying party is the public URL's host, or a parent of it; an IP address starts nothing but `off` (passkeys.md, section 7.1)", () => {
  const providers = [github({ clientId: 'id', clientSecret: 'secret' })];
  const party = (passkeys: Parameters<typeof signin>[0]['passkeys'], url = 'https://secrets.acme.example') => {
    const resolved = signin({ providers, passkeys }).resolve(url);
    return resolved.mode === 'signin' ? resolved.signin.passkeys : null;
  };
  assert.deepEqual(party(undefined), { policy: 'optional', rpId: 'secrets.acme.example', origin: 'https://secrets.acme.example' });
  assert.equal(party({ policy: 'required', rpId: 'acme.example' })?.rpId, 'acme.example');
  assert.equal(party({ rpId: 'secrets.acme.example' })?.policy, 'optional');
  assert.equal(party(undefined, 'http://localhost:3000')?.rpId, 'localhost', 'localhost is a name browsers make passkeys for');
  assert.throws(() => party({ rpId: 'example' }), /passkeys.rpId example must be the public URL's host, secrets.acme.example, or a parent of it with at least two labels/);
  assert.throws(() => party({ rpId: 'cme.example' }), /must be the public URL's host/, 'a suffix that cuts a label is no parent');
  assert.throws(() => party({ rpId: 'other.example' }), /must be the public URL's host/);
  assert.throws(() => signin({ providers, passkeys: { rpId: 'Acme.Example' } }), /passkeys.rpId is a domain name/, 'checked where the deployment wrote it');
  for (const url of ['http://127.0.0.1:3000', 'http://[::1]:3000']) {
    for (const policy of ['optional', 'required'] as const) assert.throws(() => party(policy, url), /passkeys need a public URL whose host is a name/, `${url} ${policy}`);
    assert.equal(party('off', url)?.policy, 'off', 'off needs no relying party');
  }
});
