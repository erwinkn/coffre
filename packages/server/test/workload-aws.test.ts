// The app's half of an `aws` proof (src/workloads/aws.ts), as 0.14.7 tested it
// (test/workload-aws.test.ts at v0.14.7): the checks on the signed
// GetCallerIdentity before STS is asked (its host, body, headers, what the
// signature covers, the audience, the key and the time), STS's answer read
// (a refusal is the proof's; a redirect, a 5xx, throttling or a garbled
// answer is STS unavailable), and `stsFetch`, which follows no redirect,
// under a deadline. Whose identity it is (a role's, not a root's or a
// user's) is core's (`assumedRole`, packages/core/test/workload-proofs.test.ts);
// the sign-in around it, test/workload-signin.test.ts's. No database here.
import assert from 'node:assert/strict';
import { createHash, createHmac, type Hash, type Hmac } from 'node:crypto';
import { test } from 'node:test';

import { SignatureV4 } from '@smithy/signature-v4';

import { checkAwsRequest, GET_CALLER_IDENTITY, readStsAnswer, stsFetch, StsUnavailable, type AwsProofInput, type AwsRefusal, type CheckedAwsRequest } from '../src/workloads/aws.ts';
import { FETCH_DEADLINE_MS, MAX_BODY_BYTES } from '../src/workloads/transport.ts';

const ORIGIN = 'https://secrets.acme.example';
/** The session's key, as the DPoP proof names it. */
const JKT = 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs';
const ROLE = { accessKeyId: 'ASIAROLEEXAMPLE00001', secretAccessKey: 'role-secret', sessionToken: 'role-session-token' };
const ARN = 'arn:aws:sts::671742253563:assumed-role/ingest-task/i-0b5f3c2a9d8e7f601';
const USER_ID = 'AROAZ3EXAMPLE7QXYZAB:i-0b5f3c2a9d8e7f601';

type SourceData = string | ArrayBuffer | ArrayBufferView;
const bytes = (data: SourceData) => (typeof data === 'string' ? data : ArrayBuffer.isView(data) ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength) : new Uint8Array(data));
class Sha256 {
  readonly #hash: Hash | Hmac;
  constructor(secret?: SourceData) {
    this.#hash = secret === undefined ? createHash('sha256') : createHmac('sha256', bytes(secret));
  }
  update(data: SourceData): void {
    this.#hash.update(bytes(data));
  }
  async digest(): Promise<Uint8Array> {
    return new Uint8Array(this.#hash.digest());
  }
}

/**
 * A role's `GetCallerIdentity` as the SDK signs one for eu-west-3, naming this instance and the key, unsent: with
 * `headers` signed beside them, `unsigned` sent but left out of the signature, another `region`, `body` or time.
 */
async function signed(options: { headers?: Record<string, string>; unsigned?: string[]; region?: string; body?: string; at?: Date; checksum?: boolean } = {}): Promise<AwsProofInput> {
  const region = options.region ?? 'eu-west-3';
  const hostname = `sts.${region}.amazonaws.com`;
  const all: Record<string, string> = { host: hostname, 'content-type': 'application/x-www-form-urlencoded; charset=utf-8', 'x-coffre-audience': ORIGIN, 'x-coffre-key': JKT, ...options.headers };
  const unsigned = options.unsigned ?? [];
  const toSign = Object.fromEntries(Object.entries(all).filter(([name]) => !unsigned.includes(name)));
  const signer = new SignatureV4({ credentials: ROLE, region, service: 'sts', sha256: Sha256, applyChecksum: options.checksum ?? false });
  const made = await signer.sign(
    { method: 'POST', protocol: 'https:', hostname, path: '/', query: {}, headers: toSign, body: options.body ?? GET_CALLER_IDENTITY },
    { signingDate: options.at ?? new Date(), unsignableHeaders: new Set(), signableHeaders: new Set(Object.keys(toSign)) },
  );
  const { host: _, ...sent } = made.headers;
  for (const name of unsigned) sent[name] = all[name]!;
  return { url: `https://${hostname}/`, headers: sent, body: options.body ?? GET_CALLER_IDENTITY };
}

const check = (input: unknown, jkt = JKT, now = Date.now()) => checkAwsRequest(input, { publicUrl: ORIGIN, jkt, now });

/** `input` refused for `reason`, its message matching `message` if given. */
function refused(input: unknown, reason: AwsRefusal['refused'], message?: RegExp, jkt = JKT): void {
  const outcome = check(input, jkt);
  assert.ok('refused' in outcome, `refused with ${reason}, not checked: ${JSON.stringify(input).slice(0, 200)}`);
  assert.equal(outcome.refused, reason, outcome.message);
  if (message !== undefined) assert.match(outcome.message, message);
}

test('a role\'s signed GetCallerIdentity is forwarded as signed: its headers lower-cased, host and length left to the fetch', async () => {
  const proof = await signed({ headers: { 'content-length': String(GET_CALLER_IDENTITY.length) } });
  const checked = check(proof) as CheckedAwsRequest;
  assert.ok(!('refused' in checked));
  assert.deepEqual([checked.url, checked.region, checked.body], ['https://sts.eu-west-3.amazonaws.com/', 'eu-west-3', GET_CALLER_IDENTITY]);
  assert.deepEqual(Object.keys(checked.headers).sort(), ['authorization', 'content-type', 'x-amz-date', 'x-amz-security-token', 'x-coffre-audience', 'x-coffre-key']);
  // The global host is us-east-1's.
  assert.equal((check(await signed({ region: 'us-east-1' }).then((made) => ({ ...made, url: 'https://sts.amazonaws.com/' }))) as CheckedAwsRequest).region, 'us-east-1');
});

test('a proof whose signature leaves out the key, the audience or the content type is refused; so is one that sends a header unsigned', async () => {
  refused(await signed({ unsigned: ['x-coffre-key'] }), 'signature', /does not cover x-coffre-key/);
  refused(await signed({ unsigned: ['x-coffre-audience'] }), 'signature', /does not cover x-coffre-audience/);
  // Without a signed content-type, the fetch would send its own, and STS would not read the form.
  refused(await signed({ unsigned: ['content-type'] }), 'signature', /does not cover content-type/);
  const good = await signed();
  const { 'content-type': _, ...untyped } = good.headers;
  refused({ ...good, headers: untyped }, 'malformed', /signs content-type, and does not send it/);
  // Every header sent is signed, or coffre would forward what no key signed.
  refused(await signed({ headers: { 'x-amz-content-sha256': createHash('sha256').update(GET_CALLER_IDENTITY).digest('hex') }, unsigned: ['x-amz-content-sha256'] }), 'malformed', /sends x-amz-content-sha256 unsigned/);
});

test('a proof for another host, URL or body, or with another header, is refused before anything is sent', async () => {
  const good = await signed();
  for (const url of [
    'https://sts.us-east-1.amazonaws.com/', // signed for eu-west-3
    'https://sts.us-gov-west-1.amazonaws.com/',
    'https://sts-fips.us-east-1.amazonaws.com/',
    'https://sts.cn-north-1.amazonaws.com.cn/',
    'https://sts.eu-west-3.amazonaws.com',
    'https://sts.eu-west-3.amazonaws.com/?Action=GetCallerIdentity',
    'https://sts.eu-west-3.amazonaws.com:443/',
    'https://user@sts.eu-west-3.amazonaws.com/',
    'http://sts.eu-west-3.amazonaws.com/',
    'https://sts.eu-west-3.amazonaws.com.evil.example/',
    'https://evil.example/',
    'https://169.254.169.254/',
  ]) {
    refused({ ...good, url }, 'malformed', undefined);
  }
  refused(await signed({ region: 'us-gov-west-1' }), 'malformed', /commercial partition/);
  for (const body of [`${GET_CALLER_IDENTITY}&X=1`, 'Action=AssumeRole&Version=2011-06-15', '']) {
    refused({ ...good, body }, 'malformed', /signs a POST of Action=GetCallerIdentity/);
    refused(await signed({ body }), 'malformed', /signs a POST of Action=GetCallerIdentity/);
  }
  // A header outside the allowlist, signed or not.
  refused(await signed({ headers: { 'x-forwarded-for': '10.0.0.1' } }), 'malformed', /does not forward: "x-forwarded-for"/);
  refused({ ...good, headers: { ...good.headers, 'x-evil\nforged: 1': 'x' } }, 'malformed', /does not forward: "x-evil\\nforged: 1"/);
  refused({ ...good, headers: { ...good.headers, 'x-amz-target': 'AWSSecurityTokenServiceV20110615.AssumeRole' } }, 'malformed', /does not forward/);
  refused({ ...good, headers: { ...good.headers, 'X-Coffre-Key': JKT } }, 'malformed', /names x-coffre-key twice/);
  refused(await signed({ headers: { 'content-length': '7' } }), 'malformed', /says content-length 7/);
  refused({ ...good, headers: { ...good.headers, 'x-amz-date': `${good.headers['x-amz-date']}\r\nx-evil: 1` } }, 'malformed', /no header value/);
  refused(await signed({ headers: { 'content-type': 'application/json' } }), 'malformed', /content-type/);
  // A value SigV4 would sign, and a fetch send, is printable ASCII: anything else is the proof's fault, never STS unavailable.
  for (const value of ['abc€', 'tab\there', '', 'x'.repeat(8 * 1024 + 1)]) {
    refused({ ...good, headers: { ...good.headers, 'x-amz-security-token': value } }, 'malformed', /no header value/);
  }
  // The scope's day is x-amz-date's and its region the host's; SignedHeaders are listed once each, sorted; each one signed is sent.
  const authorization = good.headers.authorization!;
  const day = /\/(\d{8})\//.exec(authorization)![1]!;
  refused({ ...good, headers: { ...good.headers, authorization: authorization.replace(`/${day}/`, '/20200101/') } }, 'malformed', /another day than its credential's scope/);
  refused({ ...good, headers: { ...good.headers, authorization: authorization.replace('/eu-west-3/', '/eu-west-1/') } }, 'malformed', /signed for eu-west-1, and sent to eu-west-3/);
  for (const list of ['host;content-type;x-amz-date;x-amz-security-token;x-coffre-audience;x-coffre-key', 'content-type;host;host;x-amz-date;x-amz-security-token;x-coffre-audience;x-coffre-key']) {
    refused({ ...good, headers: { ...good.headers, authorization: authorization.replace(/SignedHeaders=[^,]+/, `SignedHeaders=${list}`) } }, 'malformed', /twice or out of order/);
  }
  const { 'x-amz-security-token': _token, ...tokenless } = good.headers;
  refused({ ...good, headers: tokenless }, 'malformed', /signs x-amz-security-token, and does not send it/);
  refused(await signed({ checksum: true, headers: { 'x-amz-content-sha256': 'e'.repeat(64) } }), 'malformed', /x-amz-content-sha256/);
  for (const input of [null, 'proof', [], { ...good, method: 'GET' }, { url: good.url, headers: good.headers }, { ...good, headers: [] }]) {
    refused(input, 'malformed');
  }
  const { authorization: _, ...unauthorized } = good.headers;
  refused({ ...good, headers: unauthorized }, 'malformed', /no authorization of SigV4/);
});

test('a proof for another instance or key, or signed more than five minutes either side of now, is refused', async () => {
  refused(await signed(), 'audience', /names another key/, 'Ab3dLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9X');
  refused(await signed({ headers: { 'x-coffre-audience': 'https://secrets.other.example' } }), 'audience', /not https:\/\/secrets\.acme\.example/);
  refused(await signed({ at: new Date(Date.now() - 6 * 60_000) }), 'too_old', /more than 5 minutes ago/);
  // 0.14.7 said not_yet_valid; 0.16's sign-in names the one reason.
  refused(await signed({ at: new Date(Date.now() + 6 * 60_000) }), 'too_old', /in the future/);
  for (const minutes of [-4, 4]) assert.ok(!('refused' in check(await signed({ at: new Date(Date.now() + minutes * 60_000) }))), `${minutes} minutes`);
});

const RESULT = `<GetCallerIdentityResult><Arn>${ARN}</Arn><UserId>${USER_ID}</UserId><Account>671742253563</Account></GetCallerIdentityResult>`;

test("STS's answer: a 200's one result read, a refusal the proof's by its code, and a redirect, a 5xx, throttling or a garbled answer STS unavailable", () => {
  const answer = `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">\n  ${RESULT.replace('<Arn>', '\n    <Arn>')}\n  <ResponseMetadata><RequestId>01234567-89ab-cdef-0123-456789abcdef</RequestId></ResponseMetadata>\n</GetCallerIdentityResponse>\n`;
  assert.deepEqual(readStsAnswer({ status: 200, body: answer }), { account: '671742253563', arn: ARN, userId: USER_ID });

  const error = (code: string) => `<ErrorResponse><Error><Type>Sender</Type><Code>${code}</Code><Message>…</Message></Error></ErrorResponse>`;
  assert.deepEqual(readStsAnswer({ status: 403, body: error('SignatureDoesNotMatch') }), { refused: 'signature', message: 'STS refused the aws proof (403: SignatureDoesNotMatch)' });
  assert.deepEqual(readStsAnswer({ status: 403, body: error('InvalidClientTokenId') }), { refused: 'signature', message: 'STS refused the aws proof (403: InvalidClientTokenId)' });
  // A code that is no code is not repeated.
  assert.deepEqual(readStsAnswer({ status: 400, body: error('<script>') }), { refused: 'signature', message: 'STS refused the aws proof (400)' });
  assert.deepEqual(readStsAnswer({ status: 400, body: 'not xml' }), { refused: 'signature', message: 'STS refused the aws proof (400)' });

  const unavailable = (answered: { status: number; body: string }, why: RegExp) => assert.throws(() => readStsAnswer(answered), (thrown: unknown) => thrown instanceof StsUnavailable && why.test(thrown.message));
  unavailable({ status: 307, body: '' }, /answered 307/);
  unavailable({ status: 302, body: '<x/>' }, /answered 302/);
  unavailable({ status: 500, body: '<ErrorResponse/>' }, /answered 500/);
  unavailable({ status: 503, body: error('ServiceUnavailable') }, /answered 503/);
  // Throttling is STS's 400, or a 429: try again, not a refused proof.
  for (const [status, code] of [[400, 'Throttling'], [400, 'ThrottlingException'], [400, 'RequestLimitExceeded'], [429, 'TooManyRequestsException']] as const) {
    unavailable({ status, body: error(code) }, /is throttling/);
  }
  unavailable({ status: 429, body: '' }, /is throttling \(429\)/);
  // A 200 with no result, two, one missing a field, or a field holding markup or an entity, is no answer to read.
  const garbled = (body: string) => unavailable({ status: 200, body }, /without one GetCallerIdentityResult/);
  garbled('<GetCallerIdentityResponse></GetCallerIdentityResponse>');
  garbled('');
  garbled(`<R>${RESULT}${RESULT}</R>`);
  garbled(`<R>${RESULT.replace(/<UserId>.*<\/UserId>/, '')}</R>`);
  garbled(`<R>${RESULT.replace('</Arn>', '&amp;</Arn>')}</R>`);
  garbled(`<R>${RESULT.replace('</Account>', '<x/></Account>')}</R>`);
  garbled(`<R>${RESULT.replace('<Arn>', '<Arn><Arn>')}</R>`);
});

const CHECKED: CheckedAwsRequest = { url: 'https://sts.amazonaws.com/', region: 'us-east-1', headers: { authorization: 'a' }, body: GET_CALLER_IDENTITY };

test('stsFetch follows no redirect, hands one back as the status it is, and sends what was checked to the URL checked', async () => {
  const sent: [string, RequestInit][] = [];
  const transport = stsFetch(async (url, init) => {
    sent.push([String(url), init!]);
    return new Response('<x/>', { status: 302, headers: { location: 'https://evil.example/' } });
  });
  assert.deepEqual(await transport(CHECKED), { status: 302, body: '<x/>' });
  const [[url, init]] = sent as [[string, RequestInit]];
  assert.deepEqual([url, init.method, init.redirect, init.body], [CHECKED.url, 'POST', 'manual', GET_CALLER_IDENTITY]);
  assert.equal((init.headers as Record<string, string>).authorization, 'a');
});

test("stsFetch gives up at its deadline, and a fetch that fails or an answer past a proof's size is STS unavailable", { timeout: 10_000 }, async (t) => {
  // The deadline is the fetch's signal, which aborts it from DNS to the last byte: here, aborted as the deadline would.
  const deadline = new AbortController();
  const asked: number[] = [];
  t.mock.method(AbortSignal, 'timeout', (ms: number) => (asked.push(ms), deadline.signal));
  const hanging = stsFetch((_, init) => new Promise<Response>((_resolve, reject) => init!.signal!.addEventListener('abort', () => reject(init!.signal!.reason))));
  const waiting = hanging(CHECKED);
  deadline.abort(new DOMException('The operation timed out.', 'TimeoutError'));
  await assert.rejects(waiting, (thrown: unknown) => thrown instanceof StsUnavailable && /could not be reached/.test(thrown.message));
  assert.deepEqual(asked, [FETCH_DEADLINE_MS]);

  await assert.rejects(stsFetch(async () => Promise.reject(new TypeError('fetch failed')))(CHECKED), (thrown: unknown) => thrown instanceof StsUnavailable && /could not be reached/.test(thrown.message));
  await assert.rejects(stsFetch(async () => new Response('x'.repeat(MAX_BODY_BYTES + 1), { status: 200 }))(CHECKED), (thrown: unknown) => thrown instanceof StsUnavailable && /more than a proof's answer/.test(thrown.message));
  assert.deepEqual(await stsFetch(async () => new Response('x'.repeat(MAX_BODY_BYTES), { status: 200 }))(CHECKED), { status: 200, body: 'x'.repeat(MAX_BODY_BYTES) });
});
