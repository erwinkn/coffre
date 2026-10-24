import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac, randomUUID, type Hash, type Hmac } from 'node:crypto';

import { SignatureV4 } from '@smithy/signature-v4';

import { canonicalClaims, type BindingClaims } from '@coffre/core/identity';
import type { Database } from '@coffre/db';

import { ExchangeRefused, type MatchedProof, type ProofContext } from '../src/api/workloads.ts';
import { insertBinding, memberStanding } from '../src/db/queries.ts';
import { awsProof, GET_CALLER_IDENTITY, stsFetch, type AwsProofInput, type StsTransport } from '../src/workloads/aws.ts';
import { holdSomething, openTestDatabase, resetDatabase, testDeps, type FixtureDeps } from './api-fixture.ts';

const ORIGIN = 'https://secrets.acme.example';
const ROOT = 'admin@acme.example';
const SERVICE = 'ingest';
const MEMBER = `token:${SERVICE}`;
const ACCOUNT = '671742253563';
const ROLE_ID = 'AROAZ3EXAMPLE7QXYZAB';
/** The session's key, as the DPoP proof names it. */
const JKT = 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs';
const OTHER_KEY = 'Ab3dLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9X';

/** Whose credentials signed, as STS knows them by access key. */
type Principal = { accessKeyId: string; secretAccessKey: string; sessionToken?: string; arn: string; userId: string };
const session = 'i-0b5f3c2a9d8e7f601';
const ROLE: Principal = {
  accessKeyId: 'ASIAROLEEXAMPLE00001', secretAccessKey: 'role-secret', sessionToken: 'role-session-token',
  arn: `arn:aws:sts::${ACCOUNT}:assumed-role/ingest-task/${session}`, userId: `${ROLE_ID}:${session}`,
};
/** The same role's name, deleted and made again: a new unique ID. */
const RECREATED: Principal = { ...ROLE, accessKeyId: 'ASIAROLEEXAMPLE00002', userId: `AROAZ3EXAMPLENEWROLE:${session}` };
const ROOT_KEY: Principal = { accessKeyId: 'AKIAROOTEXAMPLE00001', secretAccessKey: 'root-secret', arn: `arn:aws:iam::${ACCOUNT}:root`, userId: ACCOUNT };
const FEDERATED: Principal = {
  accessKeyId: 'ASIAFEDERATED0000001', secretAccessKey: 'federated-secret', sessionToken: 'federated-token',
  arn: `arn:aws:sts::${ACCOUNT}:federated-user/ada`, userId: `${ACCOUNT}:ada`,
};
const USER: Principal = { accessKeyId: 'AKIAUSEREXAMPLE00001', secretAccessKey: 'user-secret', arn: `arn:aws:iam::${ACCOUNT}:user/ada`, userId: 'AIDAZ3EXAMPLEUSER001' };
const PRINCIPALS = [ROLE, RECREATED, ROOT_KEY, FEDERATED, USER];

/** What the signer hands a hash: a string, or bytes in any view. */
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

type Signing = {
  /** `sts.amazonaws.com` when null, as the global endpoint. */
  region?: string | null;
  /** Where it is sent, if not where it was signed for. */
  url?: string;
  headers?: Record<string, string>;
  /** Headers left out of the signature. */
  unsigned?: string[];
  body?: string;
  at?: Date;
  /** Sign the body's digest in `x-amz-content-sha256`, as an SDK may. */
  checksum?: boolean;
};

/** A proof as the SDK makes one: `GetCallerIdentity`, signed by `by` with the audience and key among its headers, and not sent. */
async function signed(by: Principal, options: Signing = {}): Promise<AwsProofInput> {
  const region = options.region === undefined ? 'eu-west-3' : options.region;
  const hostname = region === null ? 'sts.amazonaws.com' : `sts.${region}.amazonaws.com`;
  const signer = new SignatureV4({ credentials: by, region: region ?? 'us-east-1', service: 'sts', sha256: Sha256, applyChecksum: options.checksum === true });
  const request = await signer.sign(
    {
      method: 'POST', protocol: 'https:', hostname, path: '/', query: {},
      headers: { host: hostname, 'content-type': 'application/x-www-form-urlencoded; charset=utf-8', 'x-coffre-audience': ORIGIN, 'x-coffre-key': JKT, ...options.headers },
      body: options.body ?? GET_CALLER_IDENTITY,
    },
    { signingDate: options.at ?? new Date(), unsignableHeaders: new Set(options.unsigned ?? []) },
  );
  const { host: _, ...headers } = request.headers;
  return { url: options.url ?? `https://${hostname}/`, headers, body: options.body ?? GET_CALLER_IDENTITY };
}

/** STS as AWS runs it, for these principals: the signature recomputed with the real secret over the signed headers, in the host's region. */
let sts: { calls: number; requests: { url: string; init: RequestInit }[]; answer?: () => Response };
const fakeFetch: typeof fetch = async (input, init) => {
  sts.calls++;
  sts.requests.push({ url: String(input), init: init! });
  if (sts.answer !== undefined) return sts.answer();
  const url = new URL(String(input));
  const sent = init!.headers as Record<string, string>;
  const authorization = sent.authorization ?? '';
  const [, keyId, , region] = /Credential=([^/]+)\/(\d{8})\/([^/]+)\/sts\/aws4_request/.exec(authorization) ?? [];
  const by = PRINCIPALS.find((principal) => principal.accessKeyId === keyId);
  const signedHeaders = /SignedHeaders=([^,]+)/.exec(authorization)?.[1]?.split(';') ?? [];
  const headers: Record<string, string> = {};
  // The host and the length are what the fetch sends, from the URL and the body.
  for (const name of signedHeaders) headers[name] = name === 'host' ? url.host : name === 'content-length' ? String((init!.body as string).length) : sent[name]!;
  const stamp = sent['x-amz-date'] ?? '';
  const date = new Date(`${stamp.slice(0, 4)}-${stamp.slice(4, 6)}-${stamp.slice(6, 8)}T${stamp.slice(9, 11)}:${stamp.slice(11, 13)}:${stamp.slice(13, 15)}Z`);
  const hostRegion = url.hostname === 'sts.amazonaws.com' ? 'us-east-1' : url.hostname.split('.')[1];
  if (by !== undefined && region === hostRegion) {
    const signer = new SignatureV4({ credentials: by, region, service: 'sts', sha256: Sha256, applyChecksum: false });
    const expected = await signer.sign(
      { method: init!.method!, protocol: 'https:', hostname: url.hostname, path: url.pathname, query: {}, headers, body: init!.body as string },
      { signingDate: date, unsignableHeaders: new Set(), signableHeaders: new Set(signedHeaders) },
    );
    if (expected.headers.authorization === authorization && init!.body === GET_CALLER_IDENTITY) {
      return new Response(
        '<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">\n  <GetCallerIdentityResult>\n' +
          `    <Arn>${by.arn}</Arn>\n    <UserId>${by.userId}</UserId>\n    <Account>${ACCOUNT}</Account>\n` +
          '  </GetCallerIdentityResult>\n  <ResponseMetadata>\n    <RequestId>01234567-89ab-cdef-0123-456789abcdef</RequestId>\n  </ResponseMetadata>\n</GetCallerIdentityResponse>\n',
        { status: 200, headers: { 'content-type': 'text/xml' } },
      );
    }
  }
  return new Response(
    '<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><Error><Type>Sender</Type><Code>SignatureDoesNotMatch</Code>' +
      '<Message>The request signature we calculated does not match the signature you provided.</Message></Error></ErrorResponse>',
    { status: 403, headers: { 'content-type': 'text/xml' } },
  );
};

let db: { owner: Database; runtime: Database; close: () => Promise<void> };
let deps: FixtureDeps;
const proof = awsProof({ sts: stsFetch(fakeFetch) });

before(async () => {
  db = await openTestDatabase();
});

after(async () => {
  await db.close();
});

beforeEach(async () => {
  await resetDatabase(db.owner);
  sts = { calls: 0, requests: [] };
  deps = testDeps(db.runtime, [ROOT]);
  assert.equal((await deps.vault.admit({ actor: `user:${ROOT}`, principal: MEMBER })).ok, true);
  await holdSomething(db.owner, deps.vault, MEMBER, `user:${ROOT}`);
});

/** An `aws` binding of the service, as PR 1a's binding creation will store one: its claims, and a policy. */
async function bind(claims: BindingClaims = { account: ACCOUNT, role_id: ROLE_ID }): Promise<string> {
  const standing = await memberStanding(deps.db, MEMBER);
  const id = randomUUID();
  await insertBinding(deps.db, deps.chainKey, {
    id, principal: MEMBER, generation: standing!.generation, profile: 'aws', issuer: 'urn:coffre:aws', jwksUri: '', jwks: null,
    claims: canonicalClaims(claims), scope: null, policy: '{}', label: null, createdAt: new Date(), createdBy: ROOT,
  });
  return id;
}

function context(jkt = JKT): ProofContext {
  return {
    db: deps.db, chainKey: deps.chainKey, config: undefined as never, transport: undefined as never, publicUrl: ORIGIN,
    service: MEMBER, jkt, sourceIp: '203.0.113.9', requestId: randomUUID(),
  };
}

async function verify(input: unknown, jkt = JKT): Promise<MatchedProof | ExchangeRefused> {
  return proof.verify(input, context(jkt));
}

async function refused(input: unknown, reason: ExchangeRefused['reason'], message?: RegExp, jkt = JKT): Promise<ExchangeRefused> {
  const outcome = await verify(input, jkt);
  assert.ok(outcome instanceof ExchangeRefused, `refused with ${reason}, not matched`);
  assert.equal(outcome.reason, reason, outcome.message);
  if (message !== undefined) assert.match(outcome.message, message);
  return outcome;
}

test("a role's signed GetCallerIdentity matches its binding by account and role ID, spends nothing, and makes a match each time", async () => {
  const id = await bind();
  const input = await signed(ROLE);
  for (let i = 0; i < 2; i++) {
    const matched = await verify(input);
    assert.ok(!(matched instanceof ExchangeRefused), (matched as Error).message);
    assert.equal(matched.binding.id, id);
    assert.deepEqual(matched.claims, { account: ACCOUNT, role_id: ROLE_ID, arn: ROLE.arn, session });
    // It names its key, so it is never spent, and the same request again is another session for the same key, not `replayed`.
    assert.equal(matched.spentKey, undefined);
    assert.equal(matched.notAfter, undefined);
  }
  assert.equal(sts.calls, 2);
  // Forwarded as signed, to the host it names, with nothing coffre adds under the signature.
  const { url, init } = sts.requests[0]!;
  assert.equal(url, 'https://sts.eu-west-3.amazonaws.com/');
  assert.equal(init.method, 'POST');
  assert.equal(init.redirect, 'manual');
  assert.equal(init.body, GET_CALLER_IDENTITY);
  assert.deepEqual(Object.keys(init.headers as object).sort(), ['accept', 'authorization', 'content-type', 'user-agent', 'x-amz-date', 'x-amz-security-token', 'x-coffre-audience', 'x-coffre-key']);
  assert.equal(proof.lifetimeMs, 3_600_000);
  assert.deepEqual(proof.profiles, ['aws']);

  // STS's global host; a body digest an SDK signs; header names in any case.
  assert.ok(!((await verify(await signed(ROLE, { region: null }))) instanceof ExchangeRefused));
  assert.ok(!((await verify(await signed(ROLE, { checksum: true }))) instanceof ExchangeRefused));
  // A signed content-length, as an SDK's middleware sets it, is the body's: the fetch sends that itself.
  assert.ok(!((await verify(await signed(ROLE, { headers: { 'content-length': '43' } }))) instanceof ExchangeRefused));
  assert.ok(!Object.hasOwn(sts.requests.at(-1)!.init.headers as object, 'content-length'));
  await refused(await signed(ROLE, { headers: { 'content-length': '44' } }), 'malformed', /says content-length 44, and its body is 43 bytes/);
  const shouted = await signed(ROLE);
  shouted.headers = Object.fromEntries(Object.entries(shouted.headers).map(([name, value]) => [name.replace(/^./, (c) => c.toUpperCase()), value]));
  assert.ok(!((await verify(shouted)) instanceof ExchangeRefused));
});

test('a proof whose signature leaves out the key or the audience is refused, and STS never asked', async () => {
  await bind();
  await refused(await signed(ROLE, { unsigned: ['x-coffre-key'] }), 'signature', /does not cover x-coffre-key/);
  await refused(await signed(ROLE, { unsigned: ['x-coffre-audience'] }), 'signature', /does not cover x-coffre-audience/);
  // Without a signed content-type, the fetch would send its own, and STS would not read the form.
  await refused(await signed(ROLE, { unsigned: ['content-type'] }), 'signature', /does not cover content-type/);
  const good = await signed(ROLE);
  const { 'content-type': _, ...untyped } = good.headers;
  await refused({ ...good, headers: untyped }, 'malformed', /signs content-type, and does not send it/);
  // Every header sent is signed, or coffre would forward what no key signed.
  await refused(await signed(ROLE, { headers: { 'x-amz-content-sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' }, unsigned: ['x-amz-content-sha256'] }), 'malformed', /sends x-amz-content-sha256 unsigned/);
  assert.equal(sts.calls, 0);
});

test('a proof for another host, URL or body, or with another header, is refused before anything is sent', async () => {
  await bind();
  const good = await signed(ROLE);
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
    await refused({ ...good, url }, 'malformed', undefined);
  }
  await refused(await signed(ROLE, { region: 'us-gov-west-1' }), 'malformed', /commercial partition/);
  for (const body of [`${GET_CALLER_IDENTITY}&X=1`, 'Action=AssumeRole&Version=2011-06-15', '']) {
    await refused({ ...good, body }, 'malformed', /signs a POST of Action=GetCallerIdentity/);
    await refused(await signed(ROLE, { body }), 'malformed', /signs a POST of Action=GetCallerIdentity/);
  }
  // A header outside the allowlist, signed or not.
  await refused(await signed(ROLE, { headers: { 'x-forwarded-for': '10.0.0.1' } }), 'malformed', /does not forward: x-forwarded-for/);
  await refused({ ...good, headers: { ...good.headers, 'x-amz-target': 'AWSSecurityTokenServiceV20110615.AssumeRole' } }, 'malformed', /does not forward/);
  await refused({ ...good, headers: { ...good.headers, 'X-Coffre-Key': JKT } }, 'malformed', /names x-coffre-key twice/);
  await refused({ ...good, headers: { ...good.headers, host: 'evil.example' } }, 'malformed', /says host evil.example/);
  await refused({ ...good, headers: { ...good.headers, 'x-amz-date': `${good.headers['x-amz-date']}\r\nx-evil: 1` } }, 'malformed', /no header value/);
  await refused(await signed(ROLE, { headers: { 'content-type': 'application/json' } }), 'malformed', /content-type/);
  // A value SigV4 would sign, and a fetch send, is printable ASCII: anything else is the proof's fault, never STS unavailable.
  for (const value of ['abc€', 'tab\there', '']) {
    await refused({ ...good, headers: { ...good.headers, 'x-amz-security-token': value } }, 'malformed', /no header value/);
  }
  // The scope's day is x-amz-date's; SignedHeaders are listed once each, sorted; each one signed is sent.
  const authorization = good.headers.authorization!;
  const day = /\/(\d{8})\//.exec(authorization)![1]!;
  await refused({ ...good, headers: { ...good.headers, authorization: authorization.replace(`/${day}/`, '/20200101/') } }, 'malformed', /another day than its credential's scope/);
  for (const list of ['host;content-type;x-amz-date;x-amz-security-token;x-coffre-audience;x-coffre-key', 'content-type;host;host;x-amz-date;x-amz-security-token;x-coffre-audience;x-coffre-key']) {
    await refused({ ...good, headers: { ...good.headers, authorization: authorization.replace(/SignedHeaders=[^,]+/, `SignedHeaders=${list}`) } }, 'malformed', /twice or out of order/);
  }
  const { 'x-amz-security-token': _token, ...tokenless } = good.headers;
  await refused({ ...good, headers: tokenless }, 'malformed', /signs x-amz-security-token, and does not send it/);
  await refused(await signed(ROLE, { checksum: true, headers: { 'x-amz-content-sha256': 'e'.repeat(64) } }), 'malformed', /x-amz-content-sha256/);
  for (const input of [null, 'proof', [], { ...good, method: 'GET' }, { url: good.url, headers: good.headers }, { ...good, headers: [] }]) {
    await refused(input, 'malformed');
  }
  const { authorization: _, ...unauthorized } = good.headers;
  await refused({ ...good, headers: unauthorized }, 'malformed', /no authorization of SigV4/);
  assert.equal(sts.calls, 0);
});

test('a proof for another instance or key, or signed too long ago, is refused', async () => {
  await bind();
  await refused(await signed(ROLE), 'audience', /names another key/, OTHER_KEY);
  await refused(await signed(ROLE, { headers: { 'x-coffre-audience': 'https://secrets.other.example' } }), 'audience', /not https:\/\/secrets.acme.example/);
  await refused(await signed(ROLE, { at: new Date(Date.now() - 6 * 60_000) }), 'too_old');
  await refused(await signed(ROLE, { at: new Date(Date.now() + 6 * 60_000) }), 'not_yet_valid');
  assert.ok(!((await verify(await signed(ROLE, { at: new Date(Date.now() - 4 * 60_000) }))) instanceof ExchangeRefused));
  assert.equal(sts.calls, 1);
});

test("STS's refusal is the proof's, a redirect or an outage is STS unavailable, and nothing else is read", async () => {
  await bind();
  const good = await signed(ROLE);
  const tampered = { ...good, headers: { ...good.headers, authorization: good.headers.authorization!.replace(/Signature=(.)/, (_, c: string) => `Signature=${c === '0' ? '1' : '0'}`) } };
  await refused(tampered, 'signature', /STS refused the aws proof \(403: SignatureDoesNotMatch\)/);
  // A signature under another key's secret is the same to STS.
  await refused(await signed({ ...ROLE, secretAccessKey: 'stolen-guess' }), 'signature', /SignatureDoesNotMatch/);

  const unavailable = async (answer: () => Response) => {
    sts.answer = answer;
    const outcome = await refused(good, 'issuer_unavailable');
    assert.equal(outcome.status, 503);
  };
  await unavailable(() => new Response(null, { status: 307, headers: { location: 'https://evil.example/' } }));
  await unavailable(() => new Response('<ErrorResponse/>', { status: 500 }));
  // Throttling is STS's 400, or a 429: try again, not a refused proof.
  for (const [status, code] of [[400, 'Throttling'], [400, 'RequestLimitExceeded'], [429, 'TooManyRequestsException']] as const) {
    await unavailable(() => new Response(`<ErrorResponse><Error><Type>Sender</Type><Code>${code}</Code><Message>Rate exceeded</Message></Error></ErrorResponse>`, { status }));
  }
  // An Arn, a UserId and an Account that disagree are no answer either.
  const disagreeing = `<GetCallerIdentityResult><Arn>${ROLE.arn}</Arn><UserId>${ROLE.userId}</UserId><Account>123456789012</Account></GetCallerIdentityResult>`;
  await unavailable(() => new Response(`<R>${disagreeing}</R>`, { status: 200 }));
  await unavailable(() => new Response(`<R>${disagreeing.replace(`:${session}<`, ':another-session<')}</R>`.replace('123456789012', ACCOUNT), { status: 200 }));
  await unavailable(() => new Response('<GetCallerIdentityResponse></GetCallerIdentityResponse>', { status: 200 }));
  await unavailable(() => new Response('x'.repeat(65 * 1024), { status: 200 }));
  // Two results, or a value with markup, is no answer to read.
  const result = `<GetCallerIdentityResult><Arn>${ROLE.arn}</Arn><UserId>${ROLE.userId}</UserId><Account>${ACCOUNT}</Account></GetCallerIdentityResult>`;
  await unavailable(() => new Response(`<R>${result}${result}</R>`, { status: 200 }));
  await unavailable(() => new Response(`<R>${result.replace('</Arn>', '&amp;</Arn>')}</R>`, { status: 200 }));
  await unavailable(() => {
    throw new TypeError('fetch failed');
  });
  sts.answer = undefined;
});

test("an account's root, a federated user and an IAM user are refused; so is a role made again under the same name", async () => {
  await bind();
  await refused(await signed(ROOT_KEY), 'no_match', /an account's root/);
  await refused(await signed(FEDERATED), 'no_match', /a federated user/);
  await refused(await signed(USER), 'no_match', /an IAM user/);
  await refused(await signed(RECREATED), 'no_match', /no aws binding of ingest names role ingest-task \(AROAZ3EXAMPLENEWROLE\)/);
  assert.equal(sts.calls, 4);
  // Bound by its new ID, it matches.
  await bind({ account: ACCOUNT, role_id: 'AROAZ3EXAMPLENEWROLE' });
  assert.ok(!((await verify(await signed(RECREATED))) instanceof ExchangeRefused));
});

test('a service with no aws binding refuses the proof after one read, and asks STS nothing', async () => {
  await refused(await signed(ROLE), 'no_match', /has no aws binding/);
  assert.equal(sts.calls, 0);
});

test('stsFetch follows no redirect, under a deadline, and hands a redirect back as the status it is', async () => {
  let init: RequestInit | undefined;
  const transport: StsTransport = stsFetch(async (_, given) => {
    init = given;
    return new Response('<x/>', { status: 302, headers: { location: 'https://evil.example/' } });
  });
  const answer = await transport({ url: 'https://sts.amazonaws.com/', region: 'us-east-1', headers: { authorization: 'a' }, body: GET_CALLER_IDENTITY });
  assert.equal(answer.status, 302);
  assert.equal(init!.redirect, 'manual');
  assert.ok(init!.signal instanceof AbortSignal);
});
