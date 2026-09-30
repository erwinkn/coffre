import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';

import type { SecretContext } from '../src/context.ts';
import { awsKms, AwsKmsKekProvider, type AwsKmsOptions } from '../src/kek/aws-kms.ts';
import { signV4 } from '../src/kek/sigv4.ts';
import { KekUnavailableError } from '../src/kek/types.ts';

const ARN = 'arn:aws:kms:eu-west-3:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab';
const CREDENTIALS = { accessKeyId: 'AKIAEXAMPLE123', secretAccessKey: 'abc/def+ghi' };

test('requests are signed as AWS signs them', () => {
  // AWS's own worked example: IAM ListUsers, in "Create a signed AWS API request".
  const listUsers = signV4({
    method: 'GET',
    url: new URL('https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08'),
    headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8' },
    body: '',
    region: 'us-east-1',
    service: 'iam',
    credentials: { accessKeyId: 'AKIDEXAMPLE', secretAccessKey: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY' },
    date: new Date('2015-08-30T12:36:00Z'),
  });
  assert.equal(
    listUsers.authorization,
    'AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, ' +
      'SignedHeaders=content-type;host;x-amz-date, Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7',
  );

  // A KMS call with a session token, as @smithy/signature-v4 5.7.3 (the AWS
  // SDK's signer, with applyChecksum off) signs the same request.
  const encrypt = signV4({
    method: 'POST',
    url: new URL('https://kms.eu-west-3.amazonaws.com/'),
    headers: { 'content-type': 'application/x-amz-json-1.1', 'x-amz-target': 'TrentService.Encrypt' },
    body: JSON.stringify({ KeyId: ARN, Plaintext: 'AAAA', EncryptionContext: { 'coffre:secret': 'x' } }),
    region: 'eu-west-3',
    service: 'kms',
    credentials: { ...CREDENTIALS, sessionToken: 'FwoGZXIvYXdzEB  token' },
    date: new Date('2026-09-30T08:15:42.123Z'),
  });
  assert.equal(encrypt['x-amz-security-token'], 'FwoGZXIvYXdzEB  token');
  assert.equal(
    encrypt.authorization,
    'AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE123/20260930/eu-west-3/kms/aws4_request, ' +
      'SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-amz-target, ' +
      'Signature=66a91fa726ce7ebeaa0cd4f3291636e516bf62861a882a08e66026dfac414b24',
  );
});

// --- a KMS of our own --------------------------------------------------------

type Call = { target: string; context: unknown; authorization: string; token: string | null };
type Canned = Response | Error;

const kmsError = (type: string, status = 400) => Response.json({ __type: type, message: `${type} (fake)` }, { status });

/**
 * KMS's Encrypt and Decrypt as the API documents them: a ciphertext opens
 * only under the key and the exact context it was made with. `canned` answers
 * first, in order, for the failures.
 */
function fakeKms(canned: Canned[] = []) {
  const blobs = new Map<string, { plaintext: string; keyId: string; context: string }>();
  const calls: Call[] = [];
  let inFlight = 0;
  let mostInFlight = 0;
  const fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    assert.equal(String(input), 'https://kms.eu-west-3.amazonaws.com/');
    assert.equal(init?.method, 'POST');
    const headers = new Headers(init?.headers);
    assert.equal(headers.get('content-type'), 'application/x-amz-json-1.1');
    const body = JSON.parse(String(init?.body)) as Record<string, any>;
    calls.push({
      target: headers.get('x-amz-target') ?? '',
      context: body.EncryptionContext,
      authorization: headers.get('authorization') ?? '',
      token: headers.get('x-amz-security-token'),
    });
    inFlight++;
    mostInFlight = Math.max(mostInFlight, inFlight);
    await new Promise((resolve) => setTimeout(resolve, 2));
    inFlight--;
    const next = canned.shift();
    if (next instanceof Error) throw next;
    if (next !== undefined) return next;
    if (body.KeyId !== ARN) return kmsError('NotFoundException');
    const context = JSON.stringify(body.EncryptionContext);
    if (headers.get('x-amz-target') === 'TrentService.Encrypt') {
      const blob = randomBytes(48).toString('base64');
      blobs.set(blob, { plaintext: body.Plaintext, keyId: body.KeyId, context });
      return Response.json({ CiphertextBlob: blob, KeyId: ARN, EncryptionAlgorithm: 'SYMMETRIC_DEFAULT' });
    }
    const stored = blobs.get(body.CiphertextBlob);
    if (stored === undefined || stored.context !== context) return kmsError('InvalidCiphertextException');
    if (stored.keyId !== body.KeyId) return kmsError('IncorrectKeyException');
    return Response.json({ Plaintext: stored.plaintext, KeyId: ARN, EncryptionAlgorithm: 'SYMMETRIC_DEFAULT' });
  };
  return { fetch: fetch as typeof globalThis.fetch, calls, mostInFlight: () => mostInFlight };
}

function context(): SecretContext {
  return { projectId: randomUUID(), environmentId: randomUUID(), secretId: randomUUID() };
}

function kms(fake: ReturnType<typeof fakeKms>, options: Partial<AwsKmsOptions> = {}) {
  return awsKms({ keyArn: ARN, credentials: CREDENTIALS, fetch: fake.fetch, ...options });
}

test('a data key goes to KMS with the secret as its context, and comes back only as that secret', async () => {
  const fake = fakeKms();
  const kek = kms(fake);
  const ctx = context();
  const dek = randomBytes(32);
  const wrapped = await kek.wrap(dek, ctx);
  assert.deepEqual([wrapped.kekProvider, wrapped.kekId, wrapped.kekVersion], ['aws-kms', ARN, '1']);
  assert.deepEqual(await kek.unwrap(wrapped, ctx), dek);

  // What CloudTrail shows for each call: the secret, by its ids.
  const logged = { 'coffre:project': ctx.projectId, 'coffre:environment': ctx.environmentId, 'coffre:secret': ctx.secretId };
  assert.deepEqual(
    fake.calls.map(({ target, context }) => [target, context]),
    [
      ['TrentService.Encrypt', logged],
      ['TrentService.Decrypt', logged],
    ],
  );
  assert.match(fake.calls[0]!.authorization, /^AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE123\/\d{8}\/eu-west-3\/kms\/aws4_request, /);

  // Presented as another secret, or as another key's, it does not open; and
  // that is a verdict on the claim, not an outage.
  for (const [claim, as] of [
    [wrapped, { ...ctx, secretId: randomUUID() }],
    [{ ...wrapped, kekId: `${ARN}0` }, ctx],
  ] as const) {
    const refused = await kek.unwrap(claim, as).then(
      () => null,
      (error: unknown) => error,
    );
    assert.ok(refused instanceof Error && !(refused instanceof KekUnavailableError), String(refused));
  }
  await assert.rejects(kek.unwrap(wrapped, { ...ctx, secretId: 'not-a-uuid' }), /must be a lowercase UUID/);
  assert.equal(fake.calls.length, 3, 'a malformed context never reaches KMS');
});

test('KMS throttling, failing or out of reach is retried, then an outage', async () => {
  const dek = randomBytes(32);
  const ctx = context();

  const flaky = fakeKms([new TypeError('fetch failed'), kmsError('ThrottlingException')]);
  const wrapped = await kms(flaky).wrap(dek, ctx);
  assert.equal(flaky.calls.length, 3, 'two failures, then the call that went through');
  assert.equal(wrapped.kekId, ARN);

  const down = fakeKms([500, 503, 500].map((status) => kmsError('KMSInternalException', status)));
  await assert.rejects(kms(down).unwrap(wrapped, ctx), (error: unknown) => {
    assert.ok(error instanceof KekUnavailableError);
    assert.equal(error.message, 'KMS Decrypt failed 3 times: KMSInternalException, KMSInternalException (fake)');
    return true;
  });

  // KMS refusing coffre itself is no verdict on the key, and no use retrying.
  const denied = fakeKms([kmsError('AccessDeniedException')]);
  await assert.rejects(kms(denied).wrap(dek, ctx), (error: unknown) => {
    assert.ok(error instanceof KekUnavailableError);
    assert.match(error.message, /^KMS Encrypt failed: AccessDeniedException/);
    return true;
  });
  assert.equal(denied.calls.length, 1);
});

test('credentials may be a function, asked before each call, and may carry a session token', async () => {
  const fake = fakeKms();
  let asked = 0;
  const kek = kms(fake, {
    credentials: async () => (asked++, { ...CREDENTIALS, sessionToken: `session-${asked}` }),
  });
  const ctx = context();
  await kek.unwrap(await kek.wrap(randomBytes(32), ctx), ctx);
  assert.deepEqual(fake.calls.map(({ token }) => token), ['session-1', 'session-2']);

  const broken = kms(fake, { credentials: async () => Promise.reject(new Error('no instance role')) });
  await assert.rejects(broken.wrap(randomBytes(32), ctx), (error: unknown) => {
    assert.ok(error instanceof KekUnavailableError);
    assert.equal(error.message, 'no AWS credentials for KMS: no instance role');
    return true;
  });
});

test('at most eight calls are in flight at once', async () => {
  const fake = fakeKms();
  const kek = kms(fake);
  await Promise.all(Array.from({ length: 30 }, () => kek.wrap(randomBytes(32), context())));
  assert.equal(fake.calls.length, 30);
  assert.equal(fake.mostInFlight(), 8);
});

test('the key is named by its ARN, whose region is where coffre calls', async () => {
  for (const keyArn of [
    'alias/coffre',
    'arn:aws:kms:eu-west-3:123456789012:alias/coffre',
    '1234abcd-12ab-34cd-56ef-1234567890ab',
    'arn:aws:kms:eu-west-3:1234:key/1234abcd',
  ]) {
    assert.throws(() => awsKms({ keyArn, credentials: CREDENTIALS }), /must be a key ARN/, keyArn);
  }
  const urls: string[] = [];
  const record = (async (input: RequestInfo | URL) => (urls.push(String(input)), kmsError('AccessDeniedException'))) as typeof fetch;
  for (const keyArn of [
    'arn:aws:kms:us-east-1:123456789012:key/mrk-1234abcd12ab34cd56ef1234567890ab',
    'arn:aws-cn:kms:cn-north-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab',
  ]) {
    const kek = new AwsKmsKekProvider({ keyArn, credentials: CREDENTIALS, fetch: record });
    assert.equal(kek.keyId, keyArn);
    await assert.rejects(kek.wrap(randomBytes(32), context()), KekUnavailableError);
  }
  assert.deepEqual(urls, ['https://kms.us-east-1.amazonaws.com/', 'https://kms.cn-north-1.amazonaws.com.cn/']);
});
