import { createHash } from 'node:crypto';

import { differingClaims, PROFILE_URNS } from '@coffre/core/identity';

import { ExchangeRefused, type MatchedProof, type ProofContext, type ProofKind } from '../api/workloads.ts';
import { liveBindings, memberStanding, type BindingRow } from '../db/queries.ts';
import { capped, FETCH_DEADLINE_MS, FetchRefused, USER_AGENT } from './transport.ts';

/**
 * The `aws` proof (docs/design/workload-access.md, section 4.3): a
 * `GetCallerIdentity` the workload signs with its role's own credentials,
 * and sends coffre unsent, as URL, headers and body. Coffre sends it to
 * STS, which says whose credentials signed it:
 *
 *   { "url": "https://sts.eu-west-3.amazonaws.com/",
 *     "headers": { "authorization": "AWS4-HMAC-SHA256 Credential=ASIA…/20261024/eu-west-3/sts/aws4_request,
 *                    SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-coffre-audience;x-coffre-key, Signature=…",
 *                  "content-type": "application/x-www-form-urlencoded; charset=utf-8", "x-amz-date": "20261024T013000Z",
 *                  "x-amz-security-token": "…", "x-coffre-audience": "https://secrets.acme.example", "x-coffre-key": "NzbL…" },
 *     "body": "Action=GetCallerIdentity&Version=2011-06-15" }
 *
 * The request names this instance and the session's key under its
 * signature, so it works for that key here and nowhere else: it is never
 * spent, and the same one again makes another session for the same key.
 * Coffre forwards it only to STS's commercial hosts, exactly as signed,
 * so it offers no request of coffre's to anyone else.
 */

/** What the workload sends, the one key of `{ "proof": { "aws": … } }`. */
export type AwsProofInput = { url: string; headers: Record<string, string>; body: string };

/** The one request STS answers this proof by. */
export const GET_CALLER_IDENTITY = 'Action=GetCallerIdentity&Version=2011-06-15';
/** `x-amz-date`'s distance from now, either way; STS itself refuses past 15 minutes. */
export const MAX_SKEW_MS = 5 * 60 * 1000;
/** The longest header value forwarded; a role's session token is a few kilobytes at most. */
const MAX_HEADER_BYTES = 8 * 1024;

/**
 * STS's global host, or a regional one of the commercial partition:
 * `us-east-1`, `eu-west-3`, `ap-southeast-2`. Never GovCloud's (`-gov-`),
 * China's (a `.com.cn` host) or a FIPS endpoint (`sts-fips.`).
 */
const STS_URL = /^https:\/\/sts(?:\.([a-z]{2}(?:-[a-z]+)+-\d))?\.amazonaws\.com\/$/;

/**
 * The headers coffre forwards, each signed. `host` and `content-length` are
 * the URL's and the body's, which the fetch sets, as an SDK may sign them;
 * `x-amz-content-sha256`, which an SDK may sign, must be the body's digest.
 */
const FORWARDED = ['authorization', 'content-length', 'content-type', 'host', 'x-amz-content-sha256', 'x-amz-date', 'x-amz-security-token', 'x-coffre-audience', 'x-coffre-key'] as const;
/** Those its signature must cover, whatever else it does: without `content-type`, the fetch would send its own, and STS would not read the form. */
const MUST_SIGN = ['content-type', 'host', 'x-amz-date', 'x-coffre-audience', 'x-coffre-key'] as const;
/** A header value as SigV4 signs it and a fetch sends it: printable ASCII. */
const HEADER_VALUE = /^[\x20-\x7e]+$/;

const AUTHORIZATION = /^AWS4-HMAC-SHA256 Credential=([A-Z0-9]{16,128})\/(\d{8})\/([a-z0-9-]{1,32})\/sts\/aws4_request, ?SignedHeaders=([a-z0-9;-]{1,512}), ?Signature=[0-9a-f]{64}$/;
const AMZ_DATE = /^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z$/;
const FORM = /^application\/x-www-form-urlencoded(?:; ?charset=utf-8)?$/i;
const BODY_DIGEST = createHash('sha256').update(GET_CALLER_IDENTITY).digest('hex');

/** The request as coffre will send it: checked, its headers lower-cased, `host` left to the fetch. */
export type CheckedAwsRequest = { url: string; region: string; headers: Record<string, string>; body: string };

/**
 * Check a proof against everything coffre can see without asking STS, in
 * order: its shape, the URL and body, the headers and what the signature
 * covers, the audience and key, then the time. Returns the request to
 * forward, or why not.
 */
export function checkAwsRequest(input: unknown, expected: { publicUrl: string; jkt: string; now: number }): CheckedAwsRequest | ExchangeRefused {
  const malformed = (why: string) => new ExchangeRefused('malformed', `the aws proof ${why}`);
  if (typeof input !== 'object' || input === null || Array.isArray(input)) return malformed('is { url, headers, body }');
  const { url, headers: given, body, ...rest } = input as Record<string, unknown>;
  if (Object.keys(rest).length > 0) return malformed(`holds url, headers and body, not ${Object.keys(rest).join(', ')}`);
  if (typeof url !== 'string' || typeof body !== 'string' || typeof given !== 'object' || given === null || Array.isArray(given)) {
    return malformed('is { url, headers, body }, the first and last strings');
  }
  const host = STS_URL.exec(url);
  if (host === null || url.includes('-gov-')) {
    return malformed('is sent to https://sts.amazonaws.com/ or https://sts.<region>.amazonaws.com/ of the commercial partition, exactly');
  }
  const region = host[1] ?? 'us-east-1';
  if (body !== GET_CALLER_IDENTITY) return malformed(`signs a POST of ${GET_CALLER_IDENTITY}, exactly`);

  const headers: Record<string, string> = {};
  for (const [name, value] of Object.entries(given)) {
    const lower = name.toLowerCase();
    if (!(FORWARDED as readonly string[]).includes(lower)) return malformed(`has a header coffre does not forward: ${name.slice(0, 64)}`);
    if (Object.hasOwn(headers, lower)) return malformed(`names ${lower} twice`);
    if (typeof value !== 'string' || value.length > MAX_HEADER_BYTES || !HEADER_VALUE.test(value)) {
      return malformed(`has a ${lower} that is no header value`);
    }
    headers[lower] = value;
  }
  const authorization = AUTHORIZATION.exec(headers.authorization ?? '');
  if (authorization === null) return malformed('has no authorization of SigV4 for sts: AWS4-HMAC-SHA256 Credential=…/<date>/<region>/sts/aws4_request, SignedHeaders=…, Signature=…');
  const [, , scopeDate, scopeRegion, signedList] = authorization as unknown as [string, string, string, string, string];
  if (scopeRegion !== region) return malformed(`is signed for ${scopeRegion}, and sent to ${region}'s host`);
  const signed = signedList.split(';');
  const sorted = [...new Set(signed)].sort();
  if (signed.length !== sorted.length || signed.some((name, i) => name !== sorted[i])) return malformed('lists its SignedHeaders twice or out of order');
  const unsigned = MUST_SIGN.filter((name) => !signed.includes(name));
  if (unsigned.length > 0) {
    return new ExchangeRefused('signature', `the aws proof's signature does not cover ${unsigned.join(', ')}: the SDK signs the audience and the key`);
  }
  for (const name of signed) {
    if (!(FORWARDED as readonly string[]).includes(name) || name === 'authorization') return malformed(`signs a header coffre does not forward: ${name}`);
    if (name !== 'host' && headers[name] === undefined) return malformed(`signs ${name}, and does not send it`);
  }
  for (const name of Object.keys(headers)) {
    if (name !== 'authorization' && !signed.includes(name)) return malformed(`sends ${name} unsigned: coffre forwards only what is signed`);
  }
  // The URL's host is what was signed, as the fetch sends it.
  const sentHost = url.slice('https://'.length, -1);
  if (headers.host !== undefined && headers.host !== sentHost) return malformed(`says host ${headers.host}, and is sent to ${sentHost}`);
  delete headers.host;
  if (headers['content-length'] !== undefined && headers['content-length'] !== String(GET_CALLER_IDENTITY.length)) {
    return malformed(`says content-length ${headers['content-length']}, and its body is ${GET_CALLER_IDENTITY.length} bytes`);
  }
  delete headers['content-length'];
  if (!FORM.test(headers['content-type']!)) return malformed('has a content-type other than application/x-www-form-urlencoded');
  if (headers['x-amz-content-sha256'] !== undefined && headers['x-amz-content-sha256'] !== BODY_DIGEST) return malformed("has an x-amz-content-sha256 other than its body's");

  if (headers['x-coffre-audience'] !== expected.publicUrl) {
    return new ExchangeRefused('audience', `the aws proof is for ${JSON.stringify(headers['x-coffre-audience'])}, not ${expected.publicUrl}`);
  }
  if (headers['x-coffre-key'] !== expected.jkt) return new ExchangeRefused('audience', "the aws proof names another key than the DPoP proof's");
  const date = AMZ_DATE.exec(headers['x-amz-date']!);
  if (date === null) return malformed('has an x-amz-date that is not <yyyymmdd>T<hhmmss>Z');
  if (!headers['x-amz-date']!.startsWith(scopeDate)) return malformed("has an x-amz-date of another day than its credential's scope");
  const [, y, mo, d, h, mi, s] = date.map(Number) as [number, number, number, number, number, number, number];
  const at = Date.UTC(y, mo - 1, d, h, mi, s);
  if (expected.now - at > MAX_SKEW_MS) return new ExchangeRefused('too_old', `the aws proof was signed more than ${MAX_SKEW_MS / 60_000} minutes ago`);
  if (at - expected.now > MAX_SKEW_MS) return new ExchangeRefused('not_yet_valid', 'the aws proof says it was signed in the future');
  return { url, region, headers, body };
}

/** What STS says signed it. */
export type CallerIdentity = { account: string; arn: string; userId: string };

/** How coffre asks STS: one POST, the response's status and at most `MAX_BODY_BYTES` of its body. */
export type StsTransport = (request: CheckedAwsRequest) => Promise<{ status: number; body: string }>;

/** A request to STS that could not be made or read: STS is unavailable, as an issuer can be. */
export class StsUnavailable extends Error {
  constructor(why: string, options?: { cause?: unknown }) {
    super(`STS ${why}`, options);
    this.name = 'StsUnavailable';
  }
}

/**
 * The standard `fetch`, as JWKS fetches use it: no redirects, one deadline
 * from DNS to the last byte, and a capped body. The host is one of STS's,
 * fixed by `checkAwsRequest`, so the fetch reaches nothing else.
 */
export function stsFetch(fetchImpl: typeof fetch = (input, init) => fetch(input, init)): StsTransport {
  return async (request) => {
    let response: Response;
    try {
      response = await fetchImpl(request.url, {
        method: 'POST',
        redirect: 'manual',
        signal: AbortSignal.timeout(FETCH_DEADLINE_MS),
        headers: { ...request.headers, accept: 'text/xml', 'user-agent': USER_AGENT },
        body: request.body,
      });
    } catch (error) {
      throw new StsUnavailable('could not be reached', { cause: error });
    }
    let body: Uint8Array;
    try {
      body = await capped(new URL(request.url), response.body);
    } catch (error) {
      throw new StsUnavailable(error instanceof FetchRefused ? 'answered more than a proof\'s answer, or what could not be read' : 'answered what could not be read', { cause: error });
    }
    return { status: response.status, body: Buffer.from(body).toString('utf8') };
  };
}

/** What one element holds, opened and closed exactly once; with `text`, only if that is text with no markup or entity in it. */
function element(xml: string, name: string, { text }: { text: boolean } = { text: true }): string | null {
  const [open, close] = [`<${name}>`, `</${name}>`];
  const start = xml.indexOf(open);
  const end = xml.indexOf(close);
  if (start < 0 || end < start || xml.indexOf(open, start + 1) >= 0 || xml.indexOf(close, end + 1) >= 0) return null;
  const inner = xml.slice(start + open.length, end);
  return text && /[<&]/.test(inner) ? null : inner;
}

/** What STS answers, as a 400 or a 429, when it is asked too often: STS unavailable for now, not the proof refused. */
const THROTTLED = new Set(['Throttling', 'ThrottlingException', 'RequestLimitExceeded', 'TooManyRequestsException']);

/**
 * STS's answer, read: the caller's identity from a 200, or why STS refused
 * it. A 4xx is STS saying the signature, the key or the token is wrong,
 * named by its error code, unless it is throttling; anything else is STS
 * unavailable, which the caller tries again.
 */
export function readStsAnswer(answer: { status: number; body: string }): CallerIdentity | ExchangeRefused {
  if (answer.status === 200) {
    const result = element(answer.body, 'GetCallerIdentityResult', { text: false });
    const [arn, userId, account] = result === null ? [] : [element(result, 'Arn'), element(result, 'UserId'), element(result, 'Account')];
    if (arn == null || userId == null || account == null) throw new StsUnavailable('answered 200 without one GetCallerIdentityResult');
    return { account: account.trim(), arn: arn.trim(), userId: userId.trim() };
  }
  const code = element(answer.body, 'Code');
  if (answer.status === 429 || (code !== null && THROTTLED.has(code))) throw new StsUnavailable(`is throttling (${answer.status}${code === null ? '' : `: ${code}`})`);
  if (answer.status >= 400 && answer.status < 500) {
    const named = code !== null && /^[A-Za-z.]{1,64}$/.test(code) ? `: ${code}` : '';
    return new ExchangeRefused('signature', `STS refused the aws proof (${answer.status}${named})`);
  }
  throw new StsUnavailable(`answered ${answer.status}`);
}

/** An assumed role's session, as a binding names its role: by account and the role's unique ID, which a role made again under the same name does not keep. */
export type AwsIdentity = { account: string; roleId: string; arn: string; role: string; session: string };

const ACCOUNT = /^\d{12}$/;
const ASSUMED_ROLE = /^arn:aws:sts::(\d{12}):assumed-role\/([\w+=,.@-]{1,64})\/([\w+=,.@-]{2,64})$/;
const ROLE_SESSION = /^(AROA[A-Z0-9]{8,124}):([\w+=,.@-]{2,64})$/;

/**
 * The role a caller's identity is a session of, or why none: an account's
 * root, a federated user and an IAM user are refused, since each means a
 * long-lived key on disk, which a workload does not hold. Only the
 * commercial partition's ARNs, `arn:aws:`, are roles here.
 */
export function assumedRole(identity: CallerIdentity): AwsIdentity | ExchangeRefused {
  const refused = (what: string) => new ExchangeRefused('no_match', `the aws proof is signed by ${what}, which no binding takes: sign with a role's credentials`);
  if (!ACCOUNT.test(identity.account)) throw new StsUnavailable('answered an account that is not 12 digits');
  if (/^arn:aws:iam::\d{12}:root$/.test(identity.arn)) return refused("an account's root");
  if (/^arn:aws:sts::\d{12}:federated-user\//.test(identity.arn)) return refused('a federated user');
  if (/^arn:aws:iam::\d{12}:user\//.test(identity.arn) || identity.userId.startsWith('AIDA')) return refused('an IAM user, whose access key lives on a disk');
  const role = ASSUMED_ROLE.exec(identity.arn);
  const session = ROLE_SESSION.exec(identity.userId);
  if (role === null || session === null) return refused(`${identity.arn.startsWith('arn:aws:') ? 'what is not an assumed role' : 'another partition than aws'}`);
  if (role[1] !== identity.account || session[2] !== role[3]) throw new StsUnavailable('answered an Arn, UserId and Account that disagree');
  return { account: identity.account, roleId: session[1]!, arn: identity.arn, role: role[2]!, session: role[3]! };
}

/** The claims an `aws` binding matches, as the proof makes them. */
export function awsClaims(identity: AwsIdentity): { account: string; role_id: string } {
  return { account: identity.account, role_id: identity.roleId };
}

/** The oldest of `bindings` the identity matches: an `aws` binding naming its account and role ID. */
export function matchAwsBinding(bindings: readonly BindingRow[], identity: AwsIdentity): BindingRow | null {
  const claims = awsClaims(identity);
  return bindings.find((row) => row.profile === 'aws' && differingClaims('aws', JSON.parse(row.claims), claims).length === 0) ?? null;
}

/** A service's live `aws` bindings. */
async function awsBindings(ctx: ProofContext): Promise<BindingRow[]> {
  const standing = await memberStanding(ctx.db, ctx.service);
  if (standing === null || standing.status !== 'active') return [];
  const live = await liveBindings(ctx.db, ctx.chainKey, ctx.service, standing.generation);
  return live.filter((row) => row.profile === 'aws' && row.issuer === PROFILE_URNS.aws && row.policy !== null);
}

export type AwsProofOptions = {
  /** How STS is asked; the standard `fetch` unless a test fakes STS. */
  sts?: StsTransport;
  /** Milliseconds since the epoch, for `x-amz-date`. */
  now?: () => number;
};

/**
 * The `aws` entry of `PROOFS`. Its check runs in the exchange's order:
 * the request's shape, then the service's `aws` bindings, then STS, so a
 * proof no binding could take costs one read and asks STS nothing. Nothing
 * is spent and nothing ends the session early: the request names its key.
 */
export function awsProof(options: AwsProofOptions = {}): ProofKind {
  const sts = options.sts ?? stsFetch();
  const now = options.now ?? Date.now;
  return {
    profiles: ['aws'],
    lifetimeMs: 60 * 60 * 1000,
    async verify(input: unknown, ctx: ProofContext): Promise<MatchedProof | ExchangeRefused> {
      const request = checkAwsRequest(input, { publicUrl: ctx.publicUrl, jkt: ctx.jkt, now: now() });
      if (request instanceof ExchangeRefused) return request;
      const bindings = await awsBindings(ctx);
      if (bindings.length === 0) return new ExchangeRefused('no_match', `${ctx.service.slice('token:'.length)} has no aws binding`);
      let identity: AwsIdentity | ExchangeRefused;
      try {
        const answer = readStsAnswer(await sts(request));
        identity = answer instanceof ExchangeRefused ? answer : assumedRole(answer);
      } catch (error) {
        if (!(error instanceof StsUnavailable)) throw error;
        console.error({ event: 'sts_unavailable', region: request.region, requestId: ctx.requestId, error: error.message }, 'STS could not check an aws proof');
        return new ExchangeRefused('issuer_unavailable', 'STS could not be asked about the aws proof: try again', 503);
      }
      if (identity instanceof ExchangeRefused) return identity;
      const binding = matchAwsBinding(bindings, identity);
      if (binding === null) {
        return new ExchangeRefused('no_match', `no aws binding of ${ctx.service.slice('token:'.length)} names role ${identity.role} (${identity.roleId}) of account ${identity.account}`);
      }
      return { binding, claims: { ...awsClaims(identity), arn: identity.arn, session: identity.session } };
    },
  };
}
