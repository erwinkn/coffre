import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';

import { jwtVerify } from 'jose';

import { r2 } from '@coffre/core/mint';

const ACCOUNT = 'a'.repeat(32);
const PARENT = { accessKeyId: 'parent-key-id', secretAccessKey: createHash('sha256').update(randomBytes(32)).digest('hex') };

test("R2 credentials are signed here, as Cloudflare derives them: under the parent's secret, for one bucket and scope, for the TTL asked", async () => {
  const minter = r2({ accountId: ACCOUNT, ...PARENT }).credentials({ bucket: 'web-assets', scope: 'object-read-write', prefixes: ['releases/'], ttlSeconds: 900 });
  assert.deepEqual(minter.fields, ['accessKeyId', 'secretAccessKey', 'sessionToken']);
  const { values, expiresAt } = await minter.mint(AbortSignal.timeout(1000));
  assert.equal(values.accessKeyId, PARENT.accessKeyId, "the parent's ID, reused");
  const jwt = Buffer.from(values.sessionToken!, 'base64').toString('utf8').replace(/^jwt\//, '');
  assert.equal(values.secretAccessKey, createHash('sha256').update(jwt).digest('hex'));
  const { payload } = await jwtVerify(jwt, new TextEncoder().encode(PARENT.secretAccessKey), {
    algorithms: ['HS256'], issuer: PARENT.accessKeyId, subject: ACCOUNT, audience: `${ACCOUNT}.r2.cloudflarestorage.com`,
  });
  assert.equal(payload.bucket, 'web-assets');
  assert.equal(payload.scope, 'object-read-write');
  assert.deepEqual(payload.paths, { prefixPaths: ['releases/'], objectPaths: [] });
  assert.equal(payload.exp! - payload.iat!, 900);
  assert.equal(Date.parse(expiresAt), payload.exp! * 1000);
  // Nothing in it is random: two mints in the same second are one credential, which a log cannot tell apart.
  // Whether R2 takes a `jti` to make each its own is an open question (docs/spikes/dynamic-secrets.md).
});

test('a scope R2 would not take stops the deployment when it is made, never at the first read', () => {
  const parent = r2({ accountId: ACCOUNT, ...PARENT });
  assert.throws(() => parent.credentials({ bucket: 'web-assets', scope: 'everything' as never, ttlSeconds: 900 }), /scope must be one of/);
  assert.throws(() => parent.credentials({ bucket: 'web-assets', scope: 'object-read-only', ttlSeconds: 30 * 24 * 3600 }), /a minute to a week/);
  assert.throws(() => r2({ accountId: 'acme', ...PARENT }), /account ID/);
});
