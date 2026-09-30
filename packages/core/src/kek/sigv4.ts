import { createHash, createHmac } from 'node:crypto';

/** An AWS access key, with `sessionToken` when it is temporary (a role's). */
export type AwsCredentials = { accessKeyId: string; secretAccessKey: string; sessionToken?: string };

export type SigningInput = {
  method: string;
  url: URL;
  /** The headers to send, but for `host`, `x-amz-date` and the session token, which signing adds. */
  headers: Record<string, string>;
  body: string;
  region: string;
  service: string;
  credentials: AwsCredentials;
  date: Date;
};

/**
 * Every header a request signed with AWS Signature Version 4 sends: those
 * given, `host`, `x-amz-date`, the session token if any, and
 * `authorization`, which signs all of them and the body. The path is used as
 * it is, which is right for the only one KMS has, `/`.
 *
 * https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html
 */
export function signV4(input: SigningInput): Record<string, string> {
  const stamp = input.date.toISOString().replace(/[-:]|\.\d{3}/g, ''); // 20260930T120000Z
  const day = stamp.slice(0, 8);
  const headers: Record<string, string> = { host: input.url.host, 'x-amz-date': stamp };
  for (const [name, value] of Object.entries(input.headers)) headers[name.toLowerCase()] = value;
  if (input.credentials.sessionToken) headers['x-amz-security-token'] = input.credentials.sessionToken;

  const names = Object.keys(headers).sort();
  const signed = names.join(';');
  const request = [
    input.method,
    input.url.pathname,
    canonicalQuery(input.url.searchParams),
    ...names.map((name) => `${name}:${headers[name]!.trim().replace(/\s+/g, ' ')}`),
    '',
    signed,
    sha256(input.body),
  ].join('\n');
  const scope = `${day}/${input.region}/${input.service}/aws4_request`;
  const toSign = ['AWS4-HMAC-SHA256', stamp, scope, sha256(request)].join('\n');

  let key = hmac(`AWS4${input.credentials.secretAccessKey}`, day);
  for (const part of [input.region, input.service, 'aws4_request']) key = hmac(key, part);
  const signature = createHmac('sha256', key).update(toSign, 'utf8').digest('hex');
  return {
    ...headers,
    authorization: `AWS4-HMAC-SHA256 Credential=${input.credentials.accessKeyId}/${scope}, SignedHeaders=${signed}, Signature=${signature}`,
  };
}

function canonicalQuery(params: URLSearchParams): string {
  return [...params]
    .map(([name, value]) => [encode(name), encode(value)])
    .sort(([a, x], [b, y]) => (a! < b! ? -1 : a! > b! ? 1 : x! < y! ? -1 : x! > y! ? 1 : 0))
    .map(([name, value]) => `${name}=${value}`)
    .join('&');
}

/** RFC 3986: everything but letters, digits and `-._~` percent-encoded. */
function encode(text: string): string {
  return encodeURIComponent(text).replace(/[!'()*]/g, (char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`);
}

function sha256(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

function hmac(key: string | Uint8Array, text: string) {
  return createHmac('sha256', key).update(text, 'utf8').digest();
}
