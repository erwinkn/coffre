import test from 'node:test';
import assert from 'node:assert/strict';

import { cloudflareAccess, github, signin } from '@coffre/core/identity';

import { resolveConfig, type CoffreConfig } from '../src/config.ts';

const vault = {} as CoffreConfig['vault'];
const auditChainKey = Buffer.alloc(32, 7).toString('base64');

const base: CoffreConfig = {
  publicUrl: 'https://secrets.acme.example',
  vault,
  auth: cloudflareAccess({ teamDomain: 'acme.cloudflareaccess.com', audience: 'coffre-aud' }),
  auditChainKey,
};

test('a deployment as the docs write it resolves, with the sync defaults', () => {
  const resolved = resolveConfig(base);
  assert.equal(resolved.publicUrl, 'https://secrets.acme.example');
  assert.equal(resolved.auth.mode, 'cloudflare');
  assert.equal(resolved.auditChainKey.length, 32);
  assert.deepEqual(resolved.syncs, { driftCheckMs: 60 * 60_000, retryAfterMs: 15 * 60_000 });
});

test('sign-in callbacks are built on the public URL', () => {
  const resolved = resolveConfig({
    ...base,
    auth: signin({ providers: [github({ clientId: 'id', clientSecret: 'secret', organization: 'acme' })] }),
  });
  assert.equal(resolved.auth.mode, 'signin');
  if (resolved.auth.mode === 'signin') assert.equal(resolved.auth.signin.publicUrl, 'https://secrets.acme.example');
});

test('a bad configuration fails on start, naming what is wrong', () => {
  const cases: [Partial<CoffreConfig>, RegExp][] = [
    [{ publicUrl: 'http://secrets.acme.example' }, /HTTPS/],
    [{ publicUrl: 'https://secrets.acme.example/coffre' }, /public URL/],
    [{ auditChainKey: Buffer.alloc(16).toString('base64') }, /auditChainKey must be 32 bytes.*got 16/],
    [{ auditChainKey: undefined as never }, /auditChainKey/],
    [{ vault: undefined as never }, /vault is required/],
    [{ syncs: { driftCheckMinutes: 0 } }, /syncs\.driftCheckMinutes/],
    [{ syncs: { retryAfterMinutes: Number.NaN } }, /syncs\.retryAfterMinutes/],
  ];
  for (const [change, message] of cases) {
    assert.throws(() => resolveConfig({ ...base, ...change }), message, JSON.stringify(change));
  }
});

test('auth constructors refuse what cannot be right', () => {
  assert.throws(() => cloudflareAccess({ teamDomain: 'acme.example.com', audience: 'aud' }), /cloudflareaccess\.com/);
  assert.throws(() => signin({ providers: [] }), /provider/);
  // Loopback is the one place plain HTTP is fine.
  const local = resolveConfig({
    ...base,
    publicUrl: 'http://127.0.0.1:3080',
    auth: signin({ providers: [github({ clientId: 'id', clientSecret: 'secret' })] }),
  });
  assert.equal(local.auth.mode, 'signin');
});
