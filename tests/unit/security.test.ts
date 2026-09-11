import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT } from 'jose';
import { b64, random, LocalKeyProvider, open, seal, rewrap, canonical } from '../../packages/crypto/src/index';
import { AccessAuthenticator } from '../../packages/core/src/auth';
import { chainEvents, verifyChain } from '../../packages/core/src/audit';
import { invocationSchema, type SecretContext } from '../../packages/contracts/src/index';
const context: SecretContext = { instanceId: crypto.randomUUID(), projectId: crypto.randomUUID(), envId: crypto.randomUUID(), secretId: crypto.randomUUID(), version: 1 };
const root = random(32);
const provider = new LocalKeyProvider(new Map([['local:v1', root]]), 'local:v1');

test('envelopes preserve exact Unicode, whitespace, empty and multiline values', async () => {
  for (const value of ['', '  exact\nlines\t ', 'secrét 🔑', 'a'.repeat(65536)]) assert.equal(await open(await seal(value, context, provider), context, provider), value);
});
test('fresh encryption is randomized and never stores plaintext', async () => {
  const a = await seal('synthetic credential', context, provider), b = await seal('synthetic credential', context, provider);
  assert.notEqual(a.ciphertext, b.ciphertext); assert.notEqual(a.nonce, b.nonce); assert.ok(!canonical(a).includes('synthetic credential'));
});
for (const field of ['instanceId', 'projectId', 'envId', 'secretId', 'version'] as const) test(`AAD prevents relocation at ${field}`, async () => {
  const envelope = await seal('demo', context, provider);
  const other = { ...context, [field]: field === 'version' ? 2 : crypto.randomUUID() };
  await assert.rejects(open(envelope, other, provider));
});
test('payload AAD still rejects relocation when wrapping AAD is maliciously replaced', async () => {
  const envelope = await seal('demo', context, provider), other = { ...context, envId: crypto.randomUUID() };
  const dek = await provider.unwrap(envelope.wrappedKey, context);
  const forged = { ...envelope, wrappedKey: await provider.wrap(dek, other) };
  await assert.rejects(open(forged, other, provider)); dek.fill(0);
});
test('rewrap preserves payload and requires both correct providers', async () => {
  const newer = new LocalKeyProvider(new Map([['local:v2', random(32)]]), 'local:v2');
  const original = await seal('demo', context, provider), rotated = await rewrap(original, context, provider, newer);
  assert.equal(rotated.ciphertext, original.ciphertext); assert.equal(await open(rotated, context, newer), 'demo');
  await assert.rejects(open(rotated, context, provider));
});
test('corrupted ciphertext fails authenticated decryption', async () => {
  const a = await seal('demo', context, provider); a.ciphertext = b64(random(40)); await assert.rejects(open(a, context, provider));
});
test('audit chain detects modification, omission, and reordered records', async () => {
  const input = { requestId: crypto.randomUUID(), actorId: crypto.randomUUID(), action: 'secret.read_authorized', resourceId: context.secretId, projectId: context.projectId, envId: context.envId, outcome: 'allowed' as const, detail: { version: 1 } };
  const events = await chainEvents({ auditSeq: 0, auditHash: 'GENESIS' }, [input, input, input]);
  assert.equal((await verifyChain(events)).seq, 3);
  await assert.rejects(verifyChain(events.slice(1)));
  await assert.rejects(verifyChain([...events].reverse()));
  await assert.rejects(verifyChain([{ ...events[0]!, detail: { version: 2 } }, ...events.slice(1)]));
});
test('request schemas reject unexpected fields and NUL without modifying values', () => {
  const request = { requestId: crypto.randomUUID(), command: { type: 'secret.write', id: context.secretId, expectedVersion: 1, value: ' a\n ' } };
  assert.equal(invocationSchema.parse(request).command.type, 'secret.write');
  assert.throws(() => invocationSchema.parse({ ...request, actorId: 'forged' }));
  assert.throws(() => invocationSchema.parse({ ...request, command: { ...request.command, value: 'x\0y' } }));
});
test('Access verification rejects forged, expired, wrong-audience and identity-less tokens', async t => {
  const pair = await generateKeyPair('RS256'), publicJwk = await exportJWK(pair.publicKey);
  const issuer = 'https://test.cloudflareaccess.com';
  const auth = new AccessAuthenticator(issuer, 'vault-audience', createLocalJWKSet({ keys: [{ ...publicJwk, kid: 'test' }] }));
  const sign = (claims: Record<string, unknown> = {}, overrides: { issuer?: string; aud?: string; exp?: number } = {}) => new SignJWT({ sub: 'owner', ...claims }).setProtectedHeader({ alg: 'RS256', kid: 'test' }).setIssuer(overrides.issuer ?? issuer).setAudience(overrides.aud ?? 'vault-audience').setIssuedAt().setExpirationTime(overrides.exp ?? Math.floor(Date.now() / 1000) + 600).sign(pair.privateKey);
  await t.test('valid subject, not email, establishes identity', async () => { assert.deepEqual(await auth.verify({ accessJwt: await sign({ email: 'spoof@example.com' }) }), { kind: 'human', subject: 'owner' }); });
  await t.test('machine tokens have common_name and no email', async () => { assert.deepEqual(await auth.verify({ accessJwt: await sign({ sub: '', common_name: 'machine-id' }) }), { kind: 'access-service', subject: 'machine-id' }); });
  for (const [name, token] of [['audience', await sign({}, { aud: 'other' })], ['issuer', await sign({}, { issuer: 'https://evil.cloudflareaccess.com' })], ['expiry', await sign({}, { exp: 1 })], ['identity', await sign({ sub: '' })], ['signature', (await sign()).slice(0, -8) + 'tampered'], ['none', 'eyJhbGciOiJub25lIn0.e30.']] as const) await t.test(`reject ${name}`, async () => { await assert.rejects(auth.verify({ accessJwt: token })); });
  await t.test('ambiguous credentials fail', async () => { await assert.rejects(auth.verify({ accessJwt: await sign(), bearer: 'coffre_bad' })); });
});
