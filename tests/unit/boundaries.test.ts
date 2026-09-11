import { test } from 'node:test';
import assert from 'node:assert/strict';
import { KeyBroker } from '../../apps/kms/src/broker';
import { LocalKeyProvider, ServiceKeyProvider, random, b64, unb64, canonical } from '../../packages/crypto/src/index';
import { ScalewayKeyProvider } from '../../packages/crypto/src/scaleway';
import { HttpKmsBinding } from '../../packages/crypto/src/remote';
import { createKeyProvider } from '../../packages/crypto/src/factory';
import { commandSchema } from '../../packages/contracts/src/index';
import { credentialsFrom, failure, limitedJson, validateOrigin } from '../../packages/core/src/http';
const context = { instanceId: crypto.randomUUID(), projectId: crypto.randomUUID(), envId: crypto.randomUUID(), secretId: crypto.randomUUID(), version: 1 };
const local = () => new LocalKeyProvider(new Map([['test:v1', random(32)]]), 'test:v1');
test('separate KMS service releases a key only after its independent journal commits', async () => {
  const journal: string[] = []; let fail = false;
  const broker = new KeyBroker(local(), { async putIfAbsent(_key, body) { if (fail) throw new Error('audit unavailable'); journal.push(body); } }, context.instanceId);
  const remote = new ServiceKeyProvider(broker); const dek = random(32), wrapped = await remote.wrap(dek, context);
  assert.deepEqual(await remote.unwrap(wrapped, context), dek); assert.equal(journal.length, 2); assert.ok(!journal.join().includes(b64(dek)));
  fail = true; await assert.rejects(remote.unwrap(wrapped, context), /audit unavailable/); await assert.rejects(remote.wrap(dek, context), /audit unavailable/);
});
test('KMS service rejects other installations and extra protocol fields', async () => {
  const broker = new KeyBroker(local(), { async putIfAbsent() {} }, context.instanceId);
  await assert.rejects(broker.wrap({ data: b64(random(32)), context: { ...context, instanceId: crypto.randomUUID() }, requestId: crypto.randomUUID() }));
  await assert.rejects(broker.invoke({ operation: 'wrap', data: b64(random(32)), context, requestId: crypto.randomUUID(), bypass: true }, 'test'));
});
test('key provider selection has no implicit downgrade or missing-binding fallback', () => {
  assert.throws(() => createKeyProvider({ KEY_PROVIDER: 'service' })); assert.throws(() => createKeyProvider({ KEY_PROVIDER: 'unknown' as never }));
  assert.throws(() => new HttpKmsBinding('http://localhost', 'id', 'secret'));
});
test('Scaleway adapter uses encrypt/decrypt with base64 AAD strings and allowed key references', async () => {
  const id = crypto.randomUUID(), ref = `scaleway:fr-par:${id}`, dek = random(32), calls: unknown[] = [];
  const fetcher: typeof fetch = async (input, init) => { const body = JSON.parse(String(init?.body)); calls.push(body); assert.equal(typeof body.associated_data, 'string'); assert.equal(init?.redirect, 'error'); assert.equal((init?.headers as Record<string, string>)['X-Auth-Token'], 'synthetic-only'); return Response.json({ key_id: id, [String(input).endsWith('/encrypt') ? 'ciphertext' : 'plaintext']: btoa(String.fromCharCode(...dek)) }); };
  const provider = new ScalewayKeyProvider(ref, [ref], 'synthetic-only', fetcher);
  const wrapped = await provider.wrap(dek, context); assert.deepEqual(await provider.unwrap(wrapped, context), dek); assert.equal(calls.length, 2);
  await assert.rejects(provider.unwrap({ ...wrapped, keyRef: `scaleway:fr-par:${crypto.randomUUID()}` }, context));
  const broken = new ScalewayKeyProvider(ref, [ref], 'synthetic-only', async () => new Response('do-not-echo-this-secret', { status: 500 }));
  await assert.rejects(broken.wrap(dek, context), e => !String(e).includes('do-not-echo'));
});
test('request origin, method, and custom header checks reject browser cross-site requests', () => {
  const url = 'https://coffre.example.invalid';
  const request = (headers: Record<string, string>, method = 'POST') => new Request(url, { method, headers });
  validateOrigin(request({ Origin: url, 'X-Coffre-Request': '1', 'Sec-Fetch-Site': 'same-origin' }), url);
  for (const req of [request({}, 'GET'), request({ Origin: 'https://attacker.invalid', 'X-Coffre-Request': '1' }), request({ 'X-Coffre-Request': '1', 'Sec-Fetch-Site': 'same-site' }), request({ Origin: url })]) assert.throws(() => validateOrigin(req, url));
  assert.deepEqual(credentialsFrom(request({ 'Cf-Access-Jwt-Assertion': 'assertion' })), { accessJwt: 'assertion', bearer: undefined });
});
test('streaming body size checks do not trust Content-Length', async () => {
  const stream = new ReadableStream({ start(controller) { controller.enqueue(new TextEncoder().encode('x'.repeat(200))); controller.close(); } });
  await assert.rejects(limitedJson(new Request('https://example.invalid', { method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': '1' }, body: stream, duplex: 'half' } as RequestInit), 100));
  await assert.rejects(limitedJson(new Request('https://example.invalid', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{bad' })));
});
test('unexpected database/provider exceptions never echo secrets in RPC errors', () => { const message = JSON.stringify(failure(new Error('postgres://private:password@host'), crypto.randomUUID())); assert.ok(!message.includes('password')); assert.ok(message.includes('UNAVAILABLE')); });
test('Unicode value size is bounded in bytes, and large binary conversion does not overflow the stack', () => {
  assert.equal(commandSchema.safeParse({ type: 'secret.write', id: crypto.randomUUID(), expectedVersion: 1, value: '🌍'.repeat(20000) }).success, false);
  const data = new Uint8Array(300000).fill(150); assert.deepEqual(unb64(b64(data)), data);
});
