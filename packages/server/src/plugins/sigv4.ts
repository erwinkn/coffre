/**
 * AWS Signature Version 4 (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html),
 * for the credential proxy to sign a request again with the real keys:
 * WebCrypto only, so it runs on Workers and Node alike. A path is encoded
 * once for S3, as its rules say, and twice for every other service.
 */
export type AwsKeys = { accessKeyId: string; secretAccessKey: string; sessionToken?: string };

const encoder = new TextEncoder();
const hex = (bytes: ArrayBuffer) => [...new Uint8Array(bytes)].map((byte) => byte.toString(16).padStart(2, '0')).join('');

async function hmac(key: BufferSource, data: string): Promise<ArrayBuffer> {
  const imported = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return crypto.subtle.sign('HMAC', imported, encoder.encode(data));
}

/** RFC 3986's unreserved characters stay; every other byte is %XX, uppercase. */
function strict(text: string): string {
  return encodeURIComponent(text).replace(/[!'()*]/g, (char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`);
}

/**
 * Each segment of a path as AWS signs it: decoded, then encoded strictly,
 * once for S3, which signs the path as it is, repeated slashes and all;
 * and twice for every other service, whose canonical path is the path as
 * sent, normalized, encoded again.
 */
function canonicalPath(pathname: string, service: string): string {
  if (service === 's3') return pathname.split('/').map((segment) => strict(decodeURIComponent(segment))).join('/');
  // Any other service's path is normalized first, as AWS's signers do: no empty or `.` segment, a `..` taking one back.
  const segments: string[] = [];
  for (const segment of pathname.split('/')) {
    if (segment === '' || segment === '.') continue;
    if (segment === '..') segments.pop();
    else segments.push(segment);
  }
  const normalized = `/${segments.map((segment) => strict(strict(decodeURIComponent(segment)))).join('/')}`;
  return segments.length > 0 && pathname.endsWith('/') ? `${normalized}/` : normalized;
}

/** A header's value as AWS signs it: ASCII spaces and tabs trimmed and runs of them made one space; any other whitespace kept. */
const canonicalValue = (value: string) => value.replace(/^[ \t]+|[ \t]+$/g, '').replace(/[ \t]+/g, ' ');

function canonicalQuery(params: URLSearchParams): string {
  return [...params]
    .map(([name, value]) => [strict(name), strict(value)] as const)
    .sort(([a, x], [b, y]) => (a < b ? -1 : a > b ? 1 : x < y ? -1 : x > y ? 1 : 0))
    .map(([name, value]) => `${name}=${value}`)
    .join('&');
}

/** The headers a signature covers, with their values: the host, every `x-amz-*`, and the body's type and digest. */
function signed(headers: Headers, host: string): [string, string][] {
  const covered = [...headers].filter(([name]) => name.startsWith('x-amz-') || name === 'content-type' || name === 'content-md5');
  return [['host', host] as [string, string], ...covered].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
}

/**
 * Sign `headers` for `method` on `url`, in place: `x-amz-date`, the
 * session token if the keys carry one, and `authorization`. The host it
 * signs is the URL's, which `fetch` sends: it sets no `host` header.
 * `payloadHash` is the body's SHA-256, hex, or `UNSIGNED-PAYLOAD`, as
 * `x-amz-content-sha256` says it.
 */
export async function signV4(
  method: string,
  url: URL,
  headers: Headers,
  payloadHash: string,
  keys: AwsKeys,
  scope: { region: string; service: string },
  now: Date = new Date(),
): Promise<void> {
  const stamp = now.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, '');
  const day = stamp.slice(0, 8);
  headers.delete('host');
  headers.set('x-amz-date', stamp);
  headers.set('x-amz-content-sha256', payloadHash);
  if (keys.sessionToken !== undefined) headers.set('x-amz-security-token', keys.sessionToken);
  else headers.delete('x-amz-security-token');
  const covered = signed(headers, url.host);
  const names = covered.map(([name]) => name);
  const canonical = [
    method,
    canonicalPath(url.pathname, scope.service),
    canonicalQuery(url.searchParams),
    ...covered.map(([name, value]) => `${name}:${canonicalValue(value)}`),
    '',
    names.join(';'),
    payloadHash,
  ].join('\n');
  const credentialScope = `${day}/${scope.region}/${scope.service}/aws4_request`;
  const toSign = ['AWS4-HMAC-SHA256', stamp, credentialScope, hex(await crypto.subtle.digest('SHA-256', encoder.encode(canonical)))].join('\n');
  let key = await hmac(encoder.encode(`AWS4${keys.secretAccessKey}`), day);
  for (const part of [scope.region, scope.service, 'aws4_request']) key = await hmac(key, part);
  const signature = hex(await hmac(key, toSign));
  headers.set('authorization', `AWS4-HMAC-SHA256 Credential=${keys.accessKeyId}/${credentialScope}, SignedHeaders=${names.join(';')}, Signature=${signature}`);
}
