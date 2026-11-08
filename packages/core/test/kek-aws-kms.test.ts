import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';

import type { SecretContext } from '../src/context.ts';
import { awsKms, AwsKmsKekProvider, KMS_ATTEMPT_MS, KMS_ATTEMPTS, KMS_REQUEST_MAX_MS, type AwsKmsOptions } from '../src/kek/aws-kms.ts';
import { operationSignal } from '../src/kek/cancellation.ts';
import { signV4 } from '../src/kek/sigv4.ts';
import { KekCancelledError, KekUnavailableError } from '../src/kek/types.ts';

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

test("a personal config's owner is in the KMS context: under another, or none, KMS refuses", async () => {
  const fake = fakeKms();
  const kek = kms(fake);
  const ctx = { ...context(), owner: 'a'.repeat(64) };
  const dek = randomBytes(32);
  const wrapped = await kek.wrap(dek, ctx);
  assert.equal((fake.calls[0]!.context as Record<string, string>)['coffre:owner'], 'a'.repeat(64));
  assert.deepEqual(await kek.unwrap(wrapped, ctx), dek);
  const { owner: _, ...without } = ctx;
  await assert.rejects(kek.unwrap(wrapped, without));
  await assert.rejects(kek.unwrap(wrapped, { ...ctx, owner: 'b'.repeat(64) }));
});

test("a sensitive value's key is sensitive in the KMS context: as anything else, KMS refuses", async () => {
  const fake = fakeKms();
  const kek = kms(fake);
  const ctx = { ...context(), sensitive: true as const };
  const dek = randomBytes(32);
  const wrapped = await kek.wrap(dek, ctx);
  assert.equal((fake.calls[0]!.context as Record<string, string>)['coffre:sensitive'], 'true');
  assert.deepEqual(await kek.unwrap(wrapped, ctx), dek);
  const { sensitive: _, ...secret } = ctx;
  await assert.rejects(kek.unwrap(wrapped, secret));
});

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

test("at most six of one operation's requests are in flight at once, and calls apart each have their own", async () => {
  const fake = fakeKms();
  const kek = kms(fake);
  const operation = { deadline: Date.now() + 10_000, signal: new AbortController().signal };
  await Promise.all(Array.from({ length: 30 }, () => kek.wrap(randomBytes(32), context(), operation)));
  assert.equal(fake.calls.length, 30);
  assert.equal(fake.mostInFlight(), 6, "Workers' simultaneous open connections of one invocation");
  // Thirty calls, each its own (as many requests of an isolate are): none waits for another's slot.
  const apart = fakeKms();
  const kek2 = kms(apart);
  await Promise.all(Array.from({ length: 30 }, () => kek2.wrap(randomBytes(32), context(), { deadline: Date.now() + 10_000, signal: new AbortController().signal })));
  assert.equal(apart.mostInFlight(), 30);
});

test("one call's keys under two KEKs (a rotation's batch) take turns in the same six (review r2 of #549)", async () => {
  let inFlight = 0;
  let most = 0;
  const answering = (arn: string): typeof fetch => async (_input, init) => {
    inFlight++;
    most = Math.max(most, inFlight);
    await new Promise((resolve) => setTimeout(resolve, 5));
    inFlight--;
    const body = JSON.parse(String(init?.body)) as { Plaintext?: string };
    return Response.json({ CiphertextBlob: randomBytes(48).toString('base64'), KeyId: arn, Plaintext: body.Plaintext });
  };
  const other = 'arn:aws:kms:eu-west-3:123456789012:key/previous';
  const current = awsKms({ keyArn: ARN, credentials: CREDENTIALS, fetch: answering(ARN) });
  const previous = awsKms({ keyArn: other, credentials: CREDENTIALS, fetch: answering(other) });
  const operation = { deadline: Date.now() + 10_000, signal: new AbortController().signal };
  await Promise.all(Array.from({ length: 24 }, (_, i) => (i % 2 === 0 ? current : previous).wrap(randomBytes(32), context(), operation)));
  assert.equal(most, 6);
});

test("a call never waits behind another call's hung requests: a use's key opens while a read's six hang (formal/KeyService.tla)", async () => {
  const fake = fakeKms();
  let hang = 6;
  const kek = awsKms({ keyArn: ARN, credentials: CREDENTIALS, fetch: async (input, init) => {
    if (hang > 0 && --hang >= 0) return new Promise((_, reject) => init?.signal?.addEventListener('abort', () => reject(new Error('aborted')), { once: true }));
    return fake.fetch(input, init);
  } });
  const read = { deadline: Date.now() + 5_000, signal: new AbortController().signal };
  const hung = Array.from({ length: 6 }, () => kek.wrap(randomBytes(32), context(), read).catch(() => 'cancelled'));
  const started = Date.now();
  const ctx = context();
  const wrapped = await kek.wrap(randomBytes(32), ctx, { deadline: Date.now() + 5_000, signal: new AbortController().signal });
  assert.ok(Date.now() - started < 1_000, `the use's request waited ${Date.now() - started} ms behind the read's`);
  assert.equal(wrapped.kekId, ARN);
  const alive = setInterval(() => {}, 1000);
  await Promise.all(hung).finally(() => clearInterval(alive));
});

test('an attempt KMS does not answer is cut at KMS_ATTEMPT_MS and tried again; with no deadline, the request ends within KMS_REQUEST_MAX_MS', async () => {
  assert.equal(KMS_ATTEMPT_MS, 830);
  assert.equal(KMS_REQUEST_MAX_MS, 3_490);
  let sent = 0;
  const kek = awsKms({ keyArn: ARN, credentials: CREDENTIALS, fetch: async (_input, init) => {
    sent++;
    return new Promise((_, reject) => init?.signal?.addEventListener('abort', () => reject(new Error('aborted')), { once: true }));
  } });
  const alive = setInterval(() => {}, 1000);
  const random = Math.random;
  Math.random = () => 0; // the pauses at their least, 100 and 400 ms
  const started = Date.now();
  await assert.rejects(kek.wrap(randomBytes(32), context()), (error: unknown) => error instanceof KekUnavailableError && /3 times/.test((error as Error).message))
    .finally(() => { clearInterval(alive); Math.random = random; });
  const took = Date.now() - started;
  assert.equal(sent, KMS_ATTEMPTS);
  // Three attempts of 830 ms and pauses of 100 and 400 ms: 2,990 ms at least; the upper bound a watchdog for a hang.
  assert.ok(took >= KMS_ATTEMPTS * KMS_ATTEMPT_MS + 500 - 5, `it took ${took} ms`);
  assert.ok(took < KMS_REQUEST_MAX_MS + 30_000, `it took ${took} ms`);
});

test("a hung KMS answers by its operation's deadline: each attempt cut at what is left of it, no attempt nor pause started past it", async () => {
  const attempts: { started: number; ended?: number }[] = [];
  const kek = awsKms({ keyArn: ARN, credentials: CREDENTIALS, fetch: async (_input, init) => {
    const attempt: { started: number; ended?: number } = { started: Date.now() };
    attempts.push(attempt);
    return new Promise((_, reject) => init?.signal?.addEventListener('abort', () => { attempt.ended = Date.now(); reject(new Error('aborted')); }, { once: true }));
  } });
  const alive = setInterval(() => {}, 1000);
  const random = Math.random;
  Math.random = () => 0; // pauses of 100 and 400 ms: the third attempt starts at 2,160 ms at the earliest
  // A deadline the third attempt cannot finish before (2,300 < 2,160 + 830): it must be cut at it, at 2,300 ms, where
  // an attempt left its own 830 ms would end at 2,990 ms at the earliest.
  const started = Date.now();
  const deadline = started + 2_300;
  await assert.rejects(kek.unwrap({ kekProvider: 'aws-kms', kekId: ARN, kekVersion: '1', bytes: randomBytes(48) }, context(), { deadline, signal: new AbortController().signal }),
    KekCancelledError).finally(() => { clearInterval(alive); Math.random = random; });
  const ended = Date.now();
  // However the host schedules it (a stall in a pause leaves no time for the third attempt, which then never starts):
  // every attempt that could not finish before the deadline was cut at it, never let run its own 830 ms past it.
  assert.ok(attempts.length >= 2 && attempts.length <= 3, `${attempts.length} attempts`);
  const late = attempts.filter((attempt) => attempt.started + KMS_ATTEMPT_MS > deadline);
  for (const attempt of late) {
    assert.ok(attempt.ended !== undefined && attempt.ended - attempt.started < KMS_ATTEMPT_MS, `an attempt ran ${attempt.ended! - attempt.started} ms past the deadline: not cut at it`);
  }
  assert.ok(ended < deadline + 30_000, 'a watchdog for a hang');
});

test('no pause before another try starts when it would end past the deadline: the call is cancelled at once', async () => {
  let sent = 0;
  const kek = awsKms({ keyArn: ARN, credentials: CREDENTIALS, fetch: async () => (sent++, kmsError('ThrottlingException')) });
  // Every timer started meanwhile: a pause is one of at least 100 ms (`backoffMs`). The deadline is under it from the
  // start, so none may start, however the host schedules this (a stall before the first try cancels it unsent).
  const started: number[] = [];
  const real = globalThis.setTimeout;
  globalThis.setTimeout = ((handler: () => void, ms?: number, ...rest: unknown[]) => (started.push(ms ?? 0), real(handler, ms, ...rest))) as typeof setTimeout;
  try {
    await assert.rejects(kek.wrap(randomBytes(32), context(), { deadline: Date.now() + 99, signal: new AbortController().signal }), KekCancelledError);
  } finally {
    globalThis.setTimeout = real;
  }
  assert.ok(sent <= 1, `${sent} requests`);
  assert.deepEqual(started.filter((ms) => ms >= 100), [], 'no pause started');
});

test('every call of one operation shares its deadline, so the deadline cancels them all at once', async () => {
  const operation = { deadline: Date.now() + 50, signal: new AbortController().signal };
  const first = operationSignal(operation);
  await new Promise((resolve) => setTimeout(resolve, 5));
  // A call made later gets the same signal, not a timer of its own that fires a moment after the first's.
  assert.equal(operationSignal(operation), first);
});

test('no key queued behind a batch at the deadline is ever sent', async () => {
  let sent = 0;
  const kek = awsKms({ keyArn: ARN, credentials: CREDENTIALS, fetch: async (_input, init) => {
    sent++;
    // KMS never answers in time: each call waits for the deadline to cancel it.
    await new Promise((resolve) => init?.signal?.addEventListener('abort', resolve, { once: true }));
    throw new Error('aborted');
  } });
  // Only the deadline cancels: nobody aborts the operation's own signal.
  const operation = { deadline: Date.now() + 50, signal: new AbortController().signal };
  const calls = Array.from({ length: 7 }, () => kek.wrap(randomBytes(32), context(), operation));
  // The deadline's timer is AbortSignal.timeout's, which does not keep Node running: this one does,
  // or a loaded runner can find nothing left to wait for and cancel the file.
  const alive = setInterval(() => {}, 1000);
  const outcomes = await Promise.allSettled(calls).finally(() => clearInterval(alive));
  assert.ok(outcomes.every((outcome) => outcome.status === 'rejected' && outcome.reason instanceof KekUnavailableError));
  assert.equal(sent, 6, 'the seventh key waited for a slot of its operation, and was cancelled, not sent');
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

test('an expired operation never starts a KMS request', async () => {
  const fake = fakeKms();
  const operation = { deadline: Date.now() - 1, signal: new AbortController().signal };
  await assert.rejects(kms(fake).wrap(randomBytes(32), context(), operation), KekUnavailableError);
  assert.equal(fake.calls.length, 0);
});

test('cancellation interrupts a retry delay without starting the next request', async () => {
  const controller = new AbortController();
  let calls = 0;
  const kek = awsKms({ keyArn: ARN, credentials: CREDENTIALS, fetch: async () => {
    calls++;
    setTimeout(() => controller.abort(), 10);
    return kmsError('ThrottlingException');
  } });
  await assert.rejects(kek.wrap(randomBytes(32), context(), { deadline: Date.now() + 1000, signal: controller.signal }), KekUnavailableError);
  assert.equal(calls, 1);
});

test('cancellation while credentials resolve never sends the request', async () => {
  const fake = fakeKms();
  const controller = new AbortController();
  let resolveCredentials!: (value: typeof CREDENTIALS) => void;
  let started!: () => void;
  const credentials = new Promise<typeof CREDENTIALS>((resolve) => { resolveCredentials = resolve; });
  const waiting = new Promise<void>((resolve) => { started = resolve; });
  const kek = kms(fake, { credentials: () => (started(), credentials) });
  const call = kek.wrap(randomBytes(32), context(), { deadline: Date.now() + 1000, signal: controller.signal });
  await waiting;
  controller.abort();
  resolveCredentials(CREDENTIALS);
  await assert.rejects(call, KekUnavailableError);
  assert.equal(fake.calls.length, 0);
});
