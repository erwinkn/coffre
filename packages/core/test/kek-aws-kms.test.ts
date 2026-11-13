import test, { type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';

import type { SecretContext } from '../src/context.ts';
import { awsKms, AwsKmsKekProvider, KMS_ATTEMPT_MS, KMS_ATTEMPTS, KMS_REQUEST_MAX_MS, type AwsKmsOptions } from '../src/kek/aws-kms.ts';
import { operationSignal } from '../src/kek/cancellation.ts';
import { signV4 } from '../src/kek/sigv4.ts';
import { KekCancelledError, KekThrottledError, KekUnavailableError } from '../src/kek/types.ts';

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

test("a call KMS throttled to its last try is turned away for load, a KekThrottledError; credentials refused, a key disabled or KMS's own failures are not (T250)", async () => {
  const dek = randomBytes(32);
  const ctx = context();
  const wrapped = await kms(fakeKms()).wrap(dek, ctx);
  const ended = async (canned: Canned[], options: Partial<AwsKmsOptions> = {}) => {
    const fake = fakeKms(canned);
    const error = await kms(fake, options).unwrap(wrapped, ctx).then(() => assert.fail('KMS answered'), (thrown: unknown) => thrown);
    assert.ok(error instanceof KekUnavailableError, String(error));
    return { error, sent: fake.calls.length };
  };

  // Past the account's quota: each try throttled, by name or by status; the message as any outage's.
  for (const canned of [
    [kmsError('ThrottlingException'), kmsError('ThrottlingException'), kmsError('ThrottlingException')],
    [kmsError('KMSInternalException', 500), kmsError('TooManyRequests', 429), kmsError('ThrottlingException')],
  ]) {
    const { error, sent } = await ended(canned);
    assert.ok(error instanceof KekThrottledError, error.message);
    assert.equal(sent, KMS_ATTEMPTS);
    assert.match(error.message, /^KMS Decrypt failed 3 times: ThrottlingException, ThrottlingException \(fake\)$/);
    assert.equal(error.uncertain, false);
  }

  // Not for load: what the call ends on is a failure of another kind, whatever came before it.
  const notLoad: [string, Canned[], Partial<AwsKmsOptions>?][] = [
    ['credentials refused', [kmsError('AccessDeniedException', 403)]],
    ['an unknown access key', [kmsError('UnrecognizedClientException', 403)]],
    ['the key disabled', [kmsError('DisabledException')]],
    ['the key not found', [kmsError('NotFoundException')]],
    ['throttled, then refused', [kmsError('ThrottlingException'), kmsError('AccessDeniedException', 403)]],
    ['KMS failing on its side', [500, 503, 500].map((status) => kmsError('KMSInternalException', status))],
    ['throttled, then failing', [kmsError('ThrottlingException'), kmsError('ThrottlingException'), kmsError('ServiceUnavailable', 503)]],
    ['a resource quota', [kmsError('LimitExceededException')]],
    ['no credentials', [], { credentials: async () => Promise.reject(new Error('no instance role')) }],
  ];
  for (const [what, canned, options] of notLoad) {
    const { error } = await ended(canned, options);
    assert.ok(!(error instanceof KekThrottledError), `${what}: ${error.message}`);
  }
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

// The adapter's timing, on a clock the test drives (`mock.timers`: `setTimeout`, `Date` and `AbortSignal.timeout`): the
// host's scheduling cannot stall it, so each attempt's start and end is held to the millisecond, and an attempt the
// deadline must cut always exists when the rule says it does. Math.random is 0: each pause at its
// least, 100 × 4^(attempt-1) ms.
// The clock's timers: Node 26 mocks `AbortSignal.timeout` beside them, which @types/node 26.1.1 does not list yet.
const CLOCK = ['setTimeout', 'Date', 'AbortSignal.timeout'] as unknown as ('setTimeout' | 'Date')[];
type Attempt = { started: number; ended?: number };

/** A KMS that never answers, recording when each attempt starts and when its signal ends it, on the mocked clock. */
function hungKms(attempts: Attempt[], at: () => number) {
  return awsKms({ keyArn: ARN, credentials: CREDENTIALS, fetch: async (_input, init) => {
    const attempt: Attempt = { started: at() };
    attempts.push(attempt);
    return new Promise((_, reject) => init?.signal?.addEventListener('abort', () => { attempt.ended = at(); reject(new Error('aborted')); }, { once: true }));
  } });
}

/** Drive the mocked clock a millisecond at a time, every promise settled between ticks, until `work` settles. */
async function settleOnClock(t: TestContext, work: Promise<unknown>, at: () => number): Promise<{ error: unknown; at: number }> {
  let outcome: { error: unknown; at: number } | undefined;
  work.then(() => (outcome = { error: undefined, at: at() }), (error: unknown) => (outcome = { error, at: at() }));
  for (let ms = 0; ms <= 60_000; ms++) {
    await new Promise((resolve) => setImmediate(resolve));
    if (outcome !== undefined) return outcome;
    t.mock.timers.tick(1);
  }
  throw new Error('still pending after 60 s on the clock');
}

/**
 * What the rule says a hung KMS's attempts are, for a deadline `deadline` ms from the start: each cut at the sooner of
 * `KMS_ATTEMPT_MS` and the deadline; no attempt, nor a pause that would end at the deadline or past it, starts.
 */
function expectedAttempts(deadline: number): Attempt[] {
  const attempts: Attempt[] = [];
  let at = 0;
  for (let attempt = 1; attempt <= KMS_ATTEMPTS && at < deadline; attempt++) {
    const ended = Math.min(at + KMS_ATTEMPT_MS, deadline);
    attempts.push({ started: at, ended });
    const pause = 100 * 4 ** (attempt - 1);
    if (ended >= deadline || ended + pause >= deadline) break;
    at = ended + pause;
  }
  return attempts;
}

test('an attempt KMS does not answer is cut at KMS_ATTEMPT_MS and tried again; with no deadline, the request ends within KMS_REQUEST_MAX_MS', async (t) => {
  assert.equal(KMS_ATTEMPT_MS, 878);
  assert.equal(KMS_REQUEST_MAX_MS, 3_634);
  t.mock.timers.enable({ apis: CLOCK, now: 0 });
  t.mock.method(Math, 'random', () => 0);
  const attempts: Attempt[] = [];
  const { error, at } = await settleOnClock(t, hungKms(attempts, Date.now).wrap(randomBytes(32), context()), Date.now);
  assert.ok(error instanceof KekUnavailableError && /3 times/.test(error.message), String(error));
  // Three attempts of 878 ms, pauses of 100 and 400 ms between: 3,134 ms, the least of KMS_REQUEST_MAX_MS's pauses.
  assert.deepEqual(attempts, [{ started: 0, ended: 878 }, { started: 978, ended: 1_856 }, { started: 2_256, ended: 3_134 }]);
  assert.equal(at, 3_134);
  assert.ok(at <= KMS_REQUEST_MAX_MS);
});

test("a hung KMS answers by its operation's deadline: each attempt cut at what is left of it, no attempt nor pause started past it", async (t) => {
  // Deadlines in each attempt and each pause, and at their edges: 439 (the first attempt, under KMS_ATTEMPT_MS from the
  // start, with no timer of its own), 878 and 900 (a pause that would end past it), 1,400 (the second attempt), 2,200
  // (the second pause would end past it), 2,256 (the third attempt would start at it), 2,300 and 2,695 (the third,
  // cut), 3,134 (it ends as the deadline comes), and 60,000 (the attempts' own timers alone, then an outage).
  for (const deadline of [439, 878, 900, 1_400, 2_200, 2_256, 2_300, 2_695, 3_134, 60_000]) {
    await t.test(`a deadline at ${deadline} ms`, async (t) => {
      t.mock.timers.enable({ apis: CLOCK, now: 0 });
      t.mock.method(Math, 'random', () => 0);
      const attempts: Attempt[] = [];
      const work = hungKms(attempts, Date.now).unwrap({ kekProvider: 'aws-kms', kekId: ARN, kekVersion: '1', bytes: randomBytes(48) }, context(),
        { deadline, signal: new AbortController().signal });
      const { error, at } = await settleOnClock(t, work, Date.now);
      const expected = expectedAttempts(deadline);
      assert.deepEqual(attempts, expected);
      const last = expected.at(-1)!;
      if (last.ended! >= deadline || expected.length < KMS_ATTEMPTS) {
        // Cut by the deadline, or no time left for a pause and another attempt: cancelled, at the deadline or before it.
        assert.ok(error instanceof KekCancelledError, String(error));
        assert.ok(at <= deadline, `answered at ${at} ms`);
      } else {
        assert.ok(error instanceof KekUnavailableError, String(error));
      }
      assert.equal(at, last.ended);
    });
  }
});

test('no pause before another try starts when it would end past the deadline: the call is cancelled at once', async (t) => {
  t.mock.timers.enable({ apis: CLOCK, now: 0 });
  let sent = 0;
  const kek = awsKms({ keyArn: ARN, credentials: CREDENTIALS, fetch: async () => (sent++, kmsError('ThrottlingException')) });
  // A pause is at least 100 ms (`backoffMs`), and the deadline 99 ms off: the throttled try's pause may not start.
  const { error, at } = await settleOnClock(t, kek.wrap(randomBytes(32), context(), { deadline: 99, signal: new AbortController().signal }), Date.now);
  assert.ok(error instanceof KekCancelledError, String(error));
  assert.equal(sent, 1);
  assert.equal(at, 0, 'cancelled at once, not at its deadline');
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
