// SigV4 against the AWS SDK's own signer (`@smithy/signature-v4`), on
// random requests: what coffre signs is what the SDK signs for the same
// request, as it goes on the wire, byte for byte. AWS's rules
// (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html):
// S3 signs each path segment encoded once, as sent, never normalized; every
// other service normalizes the path and encodes it again, `%20` as `%2520`.
// The SDK is the reference here, as AWS's services verify what it signs.
import assert from 'node:assert/strict';
import test, { mock } from 'node:test';
import { createHash, createHmac, type Hash, type Hmac } from 'node:crypto';
import * as hegel from '@hegeldev/hegel';
import * as gs from '@hegeldev/hegel/generators';
import { SignatureV4 } from '@smithy/signature-v4';
import { awsKms } from '@coffre/core/kek';

import { propertySettings } from '../../../scripts/property-settings.ts';
import { presignV4, signV4, type AwsKeys } from '../src/plugins/sigv4.ts';

type SourceData = string | ArrayBuffer | ArrayBufferView;
const bytes = (data: SourceData) => (typeof data === 'string' ? data : ArrayBuffer.isView(data) ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength) : new Uint8Array(data));

/** SHA-256 and its HMAC, as the SDK's signer takes a hash. */
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

/** RFC 3986's encoding, as the SDK's S3 client writes an object key's segments: every byte but A-Z a-z 0-9 - . _ ~ as %XX. */
const rfc3986 = (text: string) => [...new TextEncoder().encode(text)]
  .map((byte) => (/[A-Za-z0-9\-._~]/.test(String.fromCharCode(byte)) ? String.fromCharCode(byte) : `%${byte.toString(16).toUpperCase().padStart(2, '0')}`))
  .join('');

/** A piece of a key, a path or a query: what URLs and AWS's encoding treat each its own way. */
const piece = gs.oneOf(
  gs.sampledFrom(['a', 'Z', '0', '-', '_', '.', '~', ' ', '+', '%', '!', "'", '(', ')', '*', '@', ':', ';', '=', '&', '$', ',', '[', ']', '"', '<', '>', '`', '{', '}', '|', '^']),
  gs.sampledFrom(['é', '日', '😀', 'ﬁ', ' ']),
  gs.sampledFrom(['%20', '%2F', '%2f', '%41', '%7e', '%7E', '%25', '%252F', '%252e', '%2B', '%C3%A9', '%c3%a9']),
  gs.text({ maxSize: 4, excludeCategories: ['Cs'] }),
);
const word = gs.arrays(piece, { maxSize: 4 }).map((parts) => parts.join(''));

/** An S3 object key, as the SDK sends it: each segment encoded once, `//` and a trailing slash kept. URLs resolve `.` and `..`, which S3 keys therefore cannot be through the proxy. */
const s3Path = gs.record({
  bucket: gs.fromRegex('[a-z0-9][a-z0-9.-]{2,20}', { fullmatch: true }).filter((bucket) => !/\.\.|^\.|\.$/.test(bucket)),
  key: gs.arrays(word.filter((segment) => segment !== '.' && segment !== '..'), { maxSize: 5 }),
}).map(({ bucket, key }) => `/${bucket}/${key.map(rfc3986).join('/')}`);

/** Any other service's path, as an app writes it: dot segments, `%2e`, `//`, a trailing slash, backslashes, already-encoded bytes. */
const otherPath = gs.arrays(gs.oneOf(word, gs.sampledFrom(['', '.', '..', '%2e', '%2E%2e', '.%2e', '\\', 'a\\b'])), { maxSize: 6 })
  .map((segments) => `/${segments.join('/').replace(/[?#]/g, '')}`);

/** A query as written: repeated names, empty values, names with no `=`, and everything encoded or not. */
const queryString = gs.arrays(gs.record({
  name: word,
  value: gs.optional(word),
  encode: gs.sampledFrom(['raw', 'component', 'form'] as const),
}), { maxSize: 6 }).map((params) => {
  if (params.length === 0) return '';
  const encode = (text: string, how: 'raw' | 'component' | 'form') =>
    how === 'raw' ? text.replace(/[&=#%+]/g, (char) => encodeURIComponent(char)) : how === 'component' ? encodeURIComponent(text) : new URLSearchParams({ v: text }).toString().slice(2);
  return `?${params.map(({ name, value, encode: how }) => (value === null ? encode(name, how) : `${encode(name, how)}=${encode(value, how)}`)).join('&')}`;
});

/** What AWS reads of a query: names and values decoded, `+` a space, repeated names kept. */
function queryOf(url: URL): Record<string, string | string[]> {
  const query: Record<string, string | string[]> = {};
  for (const [name, value] of url.searchParams) {
    const held = query[name];
    query[name] = held === undefined ? value : Array.isArray(held) ? [...held, value] : [held, value];
  }
  return query;
}

/** Header values as `Headers` keeps them: Latin-1, no CR, LF or NUL; runs of spaces and tabs, commas, and repeats. */
const headerValue = gs.arrays(gs.oneOf(gs.sampledFrom([' ', '  ', '\t', ' \t ', ',', ', ', '"', 'é', ' ', '\u000b']), gs.text({ codec: 'latin-1', maxSize: 6 }).map((text) => text.replace(/[\0\r\n]/g, ''))), { maxSize: 5 }).map((parts) => parts.join(''));
const headerName = gs.oneOf(
  gs.sampledFrom(['X-Amz-Meta-Name', 'x-amz-meta-name', 'X-AMZ-TAGGING', 'x-amz-acl', 'Content-Type', 'content-md5', 'Accept', 'User-Agent', 'x-amz-date', 'X-Amz-Security-Token', 'Host', 'authorization', 'x-amz-content-sha256']),
  gs.fromRegex('x-amz-[a-z0-9-]{1,12}', { fullmatch: true }),
  gs.fromRegex("[A-Za-z0-9!#$&'*+.^_`|~-]{1,12}", { fullmatch: true }),
);

const keys = gs.record({
  accessKeyId: gs.fromRegex('(AKIA|ASIA)[A-Z0-9]{16}', { fullmatch: true }),
  secretAccessKey: gs.oneOf(gs.fromRegex('[A-Za-z0-9/+]{40}', { fullmatch: true }), gs.text({ minSize: 1, maxSize: 40, excludeCategories: ['Cs'] })),
  sessionToken: gs.optional(gs.fromRegex('[A-Za-z0-9/+=]{1,80}( [A-Za-z0-9/+=]{1,8})?', { fullmatch: true })),
}).map(({ sessionToken, ...rest }): AwsKeys => (sessionToken === null ? rest : { ...rest, sessionToken }));

const region = gs.fromRegex('[a-z]{2}(-gov)?-[a-z]{4,9}-[1-9]', { fullmatch: true });
const otherService = gs.oneOf(gs.sampledFrom(['execute-api', 'sqs', 'lambda', 'kms', 'sts', 'es', 'iam']), gs.fromRegex('[a-z0-9-]{1,32}', { fullmatch: true })).filter((service) => service !== 's3');
/** Between 1970 and 2100, to the millisecond, which AWS drops. */
const instant = gs.integers({ minValue: 0, maxValue: 4_102_444_800_000 }).map((ms) => new Date(ms));
const host = gs.oneOf(gs.sampledFrom(['s3.eu-west-3.amazonaws.com', 'bucket.s3.amazonaws.com', '127.0.0.1:9000', 'abc.execute-api.eu-west-3.amazonaws.com', 'xn--bcher-kva.example:8443']), gs.domains());
const method = gs.oneOf(gs.sampledFrom(['GET', 'PUT', 'POST', 'DELETE', 'HEAD', 'PATCH']), gs.fromRegex('[A-Z]{3,8}', { fullmatch: true }));
const payloadHash = gs.oneOf(gs.just('UNSIGNED-PAYLOAD'), gs.binary({ maxSize: 64 }).map((body) => createHash('sha256').update(body).digest('hex')));

/** The SDK's signer, as the S3 client sets it (paths as sent) or as any other service's (normalized and encoded again). */
const signer = (service: string, region: string, credentials: AwsKeys) =>
  new SignatureV4({ credentials, region, service, sha256: Sha256, uriEscapePath: service !== 's3', applyChecksum: false });

const settings = propertySettings(64);

test(`a request coffre signs carries the SDK's own signature for it, S3's and every other service's, seed ${settings.seed}`, () => hegel.testAsync(async (tc) => {
  const service = tc.draw(gs.oneOf(gs.just('s3'), otherService));
  const path = tc.draw(service === 's3' ? s3Path : otherPath);
  const url = new URL(`https://${tc.draw(host)}${path}${tc.draw(queryString)}`);
  // As the SDK wrote it: a URL keeps an S3 path's encoding as it is.
  if (service === 's3') assert.equal(url.pathname, path);
  // AWS's own query auth is never part of a request signed in its headers: the proxy refuses it first.
  for (const name of [...url.searchParams.keys()]) if (name.toLowerCase() === 'x-amz-signature') url.searchParams.delete(name);
  const sent = new Headers();
  for (const [name, value] of tc.draw(gs.arrays(gs.tuples(headerName, headerValue), { maxSize: 6 }))) sent.append(name, value);
  const hash = tc.draw(payloadHash);
  const credentials = tc.draw(keys);
  const scope = { region: tc.draw(region), service };
  const now = tc.draw(instant);
  const verb = tc.draw(method);
  tc.note(`${verb} ${url.href} ${JSON.stringify([...sent])}`);

  await signV4(verb, url, sent, hash, credentials, scope, now);
  const authorization = sent.get('authorization')!;
  const names = /SignedHeaders=([^,]+),/.exec(authorization)![1]!.split(';');
  // What AWS requires signed: the host, the date, the payload's hash, the session token and every other `x-amz-*` header sent.
  for (const name of ['host', 'x-amz-date', 'x-amz-content-sha256', ...[...sent.keys()].filter((name) => name.startsWith('x-amz-') || name === 'content-type' || name === 'content-md5')]) {
    assert.ok(names.includes(name), `${name} is signed`);
  }
  assert.equal(sent.get('x-amz-security-token'), credentials.sessionToken ?? null);
  assert.equal(sent.has('host'), false, 'fetch sends the URL\'s host');
  // The SDK signs the same headers, as they go out: their names lowercased, `Headers`' values, and the URL's host.
  const headers: Record<string, string> = { host: url.host };
  for (const name of names) if (name !== 'host') headers[name] = sent.get(name)!;
  const theirs = await signer(service, scope.region, credentials).sign(
    { method: verb, protocol: 'https:', hostname: url.hostname, path: url.pathname, query: queryOf(url), headers },
    { signingDate: now },
  );
  assert.equal(authorization, theirs.headers.authorization);
}, settings));

test(`a URL coffre presigns is the SDK's presigned URL, parameter for parameter, seed ${settings.seed}`, () => hegel.testAsync(async (tc) => {
  const service = tc.draw(gs.oneOf(gs.just('s3'), otherService));
  const path = tc.draw(service === 's3' ? s3Path : otherPath);
  const url = new URL(`https://${tc.draw(host)}${path}${tc.draw(gs.oneOf(queryString, gs.just('?X-Amz-Signature=0&x-amz-credential=x&X-Amz-Expires=1')))}`);
  const credentials = tc.draw(keys);
  const scope = { region: tc.draw(region), service };
  const expires = tc.draw(gs.integers({ minValue: 1, maxValue: 604_800 }));
  const now = tc.draw(instant);
  const verb = tc.draw(method);
  tc.note(`${verb} ${url.href}`);

  const ours = await presignV4(verb, url, credentials, scope, expires, now);
  assert.equal(ours.origin + ours.pathname, url.origin + url.pathname, 'the path goes as it was asked');
  // Whatever query auth the URL already had is the caller's, never signed again: the SDK is given the URL without it.
  const asked = new URL(url);
  for (const name of [...asked.searchParams.keys()]) if (name.toLowerCase().startsWith('x-amz-')) asked.searchParams.delete(name);
  // As the SDK's S3 presigner asks it: the payload unsigned, said in a header it does not sign. Any other service signs the empty body.
  const theirs = await signer(service, scope.region, credentials).presign(
    { method: verb, protocol: 'https:', hostname: url.hostname, path: url.pathname, query: queryOf(asked), headers: service === 's3' ? { host: url.host, 'x-amz-content-sha256': 'UNSIGNED-PAYLOAD' } : { host: url.host } },
    { signingDate: now, expiresIn: expires, ...(service === 's3' ? { unsignableHeaders: new Set(['x-amz-content-sha256']), unhoistableHeaders: new Set(['x-amz-content-sha256']) } : {}) },
  );
  const sorted = (entries: [string, string][]) => entries.map((entry) => JSON.stringify(entry)).sort();
  const theirEntries = Object.entries(theirs.query!).flatMap(([name, value]) => (Array.isArray(value) ? value.map((one): [string, string] => [name, one]) : [[name, value as string] as [string, string]]));
  assert.deepEqual(sorted([...ours.searchParams]), sorted(theirEntries));
}, settings));

test(`core's KMS calls carry the SDK's signature for them, seed ${settings.seed}`, () => hegel.testAsync(async (tc) => {
  const partition = tc.draw(gs.sampledFrom(['aws', 'aws-cn', 'aws-us-gov']));
  const where = tc.draw(region);
  const arn = `arn:${partition}:kms:${where}:${tc.draw(gs.fromRegex('[0-9]{12}', { fullmatch: true }))}:key/${tc.draw(gs.uuids())}`;
  const credentials = tc.draw(keys);
  const now = tc.draw(instant);
  const context = { projectId: tc.draw(gs.uuids()), environmentId: tc.draw(gs.uuids()), secretId: tc.draw(gs.uuids()), ...(tc.draw(gs.booleans()) ? { sensitive: true as const } : {}) };
  tc.note(`${arn} ${JSON.stringify(credentials)} ${now.toISOString()}`);
  const checked: string[] = [];
  const kms = awsKms({
    keyArn: arn,
    credentials,
    fetch: async (input, init) => {
      const url = new URL(String(input));
      assert.equal(url.href, `https://kms.${where}.amazonaws.com${partition === 'aws-cn' ? '.cn' : ''}/`);
      const sent = init!.headers as Record<string, string>;
      const names = /SignedHeaders=([^,]+),/.exec(sent.authorization!)![1]!.split(';');
      assert.deepEqual(names, ['content-type', 'host', 'x-amz-date', ...(credentials.sessionToken === undefined ? [] : ['x-amz-security-token']), 'x-amz-target']);
      const headers = Object.fromEntries(names.map((name) => [name, sent[name]!]));
      const theirs = await signer('kms', where, credentials).sign(
        { method: 'POST', protocol: 'https:', hostname: url.hostname, path: url.pathname, query: {}, headers, body: init!.body as string },
        { signingDate: now },
      );
      checked.push(sent.authorization!);
      assert.equal(sent.authorization, theirs.headers.authorization);
      return Response.json({ CiphertextBlob: Buffer.from('blob').toString('base64'), KeyId: arn });
    },
  });
  // KMS signs the time it calls at: the clock is the drawn one, for the call alone.
  mock.timers.enable({ apis: ['Date'], now });
  try {
    await kms.wrap(Buffer.alloc(32, 7), context);
  } finally {
    mock.timers.reset();
  }
  assert.equal(checked.length, 1);
}, settings));
