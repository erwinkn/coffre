/**
 * How a workload proves who it is, once per session (docs/design/workload-access.md,
 * section 4): each platform's own proof, asked for afresh at each exchange,
 * and bound to the session's key wherever the platform lets the caller say
 * so. `workload({ proof })` takes one of these:
 *
 *   kubernetes()               the projected service account token, read from its file
 *   aws()                      a GetCallerIdentity signed with the role's own credentials
 *   gcp()                      the metadata server's ID token, its audience naming the key
 *   azure({ audience })        the managed identity's token for coffre's Entra application
 *   fly()                      the machine's OIDC token, its audience naming the key
 *   vercel()                   the function's OIDC token, exchanged for one naming the key
 *   github()                   the Actions runner's ID token, its audience naming the key
 *   oidc(token)                any other ID token: GitLab's `id_tokens`, a custom issuer's
 *   enrollment(code)           a code CI minted for this deploy, on a platform that signs nothing
 *
 * A proof reads only its platform's own variables and endpoints (AWS's,
 * GitHub's runner's, Azure's identity endpoint), never one of coffre's, and
 * nothing here writes anything anywhere. No dependency: `fetch`, WebCrypto,
 * and Node's `fs` and `http` loaded only by the proofs that read a file or
 * a socket.
 */

/** What the exchange is sent as `proof`: an ID token, a signed `GetCallerIdentity`, or an enrollment code. */
export type PlatformProof = { oidc: string } | { aws: { url: string; headers: Record<string, string>; body: string } } | { enrollment: string };

type Fetch = (input: string, init?: RequestInit) => Promise<Response>;

/** What a proof is given at each exchange: the instance and the key to name, and how to reach its platform. */
export type ProofContext = {
  /** The instance's URL as its audience: `https://secrets.acme.example`. */
  audience: string;
  /** The session key's thumbprint, which a key-naming audience carries: `<audience>#jkt=<jkt>`. */
  jkt: string;
  fetch: Fetch;
  /** Where the SDK says what it waits for: stderr unless the app said otherwise. */
  log: (line: string) => void;
  /** Aborted when the session closes: a proof that waits (a spent token's next) stops waiting, and one that asks a socket (Fly's) stops asking. `fetch` ends with it already. */
  signal?: AbortSignal;
};

export interface Proof {
  /** Which platform, as messages name it. */
  readonly name: string;
  /** An enrollment session's expiry is its liveness: it renews every 30 seconds, and can never re-prove past its code's end. */
  readonly kind: 'oidc' | 'aws' | 'enrollment';
  /** A fresh proof, for this key at this instance. */
  prove(context: ProofContext): Promise<PlatformProof>;
  /**
   * After the exchange said the proof was spent (`replayed`): wait until a
   * fresh one exists, as the kubelet writes a projected token's next, and
   * say whether one does. Only a proof whose platform hands out new ones
   * has it.
   */
  spent?(context: ProofContext): Promise<boolean>;
}

/** `<audience>#jkt=<thumbprint>`: an audience only this key can use (section 4.2). */
export function keyAudience(context: ProofContext): string {
  return `${context.audience}#jkt=${context.jkt}`;
}

type Env = Record<string, string | undefined>;
const env = (): Env => (globalThis as { process?: { env: Env } }).process?.env ?? {};

async function json(response: Response, what: string): Promise<Record<string, unknown>> {
  const body = (await response.json().catch(() => null)) as Record<string, unknown> | null;
  if (!response.ok || body === null || typeof body !== 'object') throw new Error(`${what} answered ${response.status}`);
  return body;
}

/** The token a platform answered, or why not. */
function tokenOf(body: Record<string, unknown>, field: string, what: string): string {
  const token = body[field];
  if (typeof token !== 'string' || token === '') throw new Error(`${what} gave no token`);
  return token;
}

/** The default projected token's path, as docs/workloads.md mounts it. */
export const KUBERNETES_TOKEN = '/var/run/secrets/coffre/token';

/**
 * A Kubernetes projected service account token, read from its file before
 * each exchange: the pod spec's `serviceAccountToken` with coffre's URL as
 * its `audience`. Such a token is spent once used. If the exchange finds it
 * spent (a restarted process reading the file again), this waits for the
 * kubelet's next, which it writes at 80% of the token's life, watching the
 * file for up to 10 minutes.
 */
export function kubernetes(path: string = KUBERNETES_TOKEN): Proof {
  let last: string | null = null;
  const read = async () => (await (await import('node:fs/promises')).readFile(path, 'utf8')).trim();
  return {
    name: 'kubernetes',
    kind: 'oidc',
    prove: async () => {
      last = await read().catch((error: Error & { code?: string }) => {
        throw new Error(`no projected service account token at ${path} (${error.code ?? error.message}): mount one whose audience is coffre's URL`);
      });
      return { oidc: last };
    },
    spent: async ({ log, signal }) => {
      log(`coffre: the projected token at ${path} was spent already, by an earlier start; waiting for the kubelet to write its next, up to 10 minutes`);
      for (const end = Date.now() + 10 * 60_000; Date.now() < end; ) {
        await sleep(1000);
        signal?.throwIfAborted();
        const now = await read().catch(() => last);
        if (now !== last) return true;
      }
      return false;
    },
  };
}

/** AWS credentials, as the AWS SDK's providers give them. */
export type AwsCredentials = { accessKeyId: string; secretAccessKey: string; sessionToken?: string };

/** A region as STS's regional hosts name one, in the commercial partition: the exchange takes no other. */
const REGION = /^[a-z]{2}(-[a-z]+)+-\d$/;

/**
 * A `GetCallerIdentity` request, signed with the workload's own role
 * credentials, for coffre to send STS (section 4.3). The credentials never
 * leave: coffre gets the URL, the headers and the body, and the signature
 * covers `x-coffre-key`, so the proof works with this session's key only.
 *
 * The credentials are the given ones, an AWS SDK provider's
 * (`aws({ credentials: fromNodeProviderChain() })`), or else, in order, the
 * environment's, the ECS container endpoint's, or EC2's instance metadata
 * (IMDSv2). The region is `AWS_REGION`'s, for its regional STS host, unless
 * given; without one, the global host.
 */
export function aws(options: { credentials?: AwsCredentials | (() => Promise<AwsCredentials>); region?: string } = {}): Proof {
  return {
    name: 'aws',
    kind: 'aws',
    prove: async (context) => {
      const given = options.credentials;
      const credentials = given === undefined ? await awsCredentials(context.fetch) : typeof given === 'function' ? await given() : given;
      const region = options.region ?? env().AWS_REGION ?? env().AWS_DEFAULT_REGION;
      if (region !== undefined && (!REGION.test(region) || region.includes('-gov-'))) throw new Error(`aws(): ${region} is no commercial AWS region`);
      const url = region === undefined ? 'https://sts.amazonaws.com/' : `https://sts.${region}.amazonaws.com/`;
      const body = 'Action=GetCallerIdentity&Version=2011-06-15';
      const headers: Record<string, string> = {
        'content-type': 'application/x-www-form-urlencoded; charset=utf-8',
        host: new URL(url).host,
        'x-amz-date': amzDate(new Date()),
        'x-coffre-audience': context.audience,
        'x-coffre-key': context.jkt,
      };
      if (credentials.sessionToken) headers['x-amz-security-token'] = credentials.sessionToken;
      headers.authorization = await sigv4({ method: 'POST', url, headers, body, region: region ?? 'us-east-1', service: 'sts', credentials });
      return { aws: { url, headers, body } };
    },
  };
}

/** The environment's, the ECS container endpoint's, or IMDSv2's role credentials, as the AWS SDK's default chain finds them. */
async function awsCredentials(fetchImpl: Fetch): Promise<AwsCredentials> {
  const vars = env();
  if (vars.AWS_ACCESS_KEY_ID && vars.AWS_SECRET_ACCESS_KEY) {
    return { accessKeyId: vars.AWS_ACCESS_KEY_ID, secretAccessKey: vars.AWS_SECRET_ACCESS_KEY, sessionToken: vars.AWS_SESSION_TOKEN || undefined };
  }
  const container = vars.AWS_CONTAINER_CREDENTIALS_FULL_URI ?? (vars.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI ? `http://169.254.170.2${vars.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI}` : undefined);
  if (container !== undefined) {
    const file = vars.AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE;
    const authorization = file ? (await (await import('node:fs/promises')).readFile(file, 'utf8')).trim() : vars.AWS_CONTAINER_AUTHORIZATION_TOKEN;
    const body = await json(await fetchImpl(container, { headers: authorization ? { authorization } : {} }), 'the ECS credentials endpoint');
    return { accessKeyId: tokenOf(body, 'AccessKeyId', 'ECS'), secretAccessKey: tokenOf(body, 'SecretAccessKey', 'ECS'), sessionToken: body.Token as string | undefined };
  }
  const imds = 'http://169.254.169.254/latest';
  const session = await fetchImpl(`${imds}/api/token`, { method: 'PUT', headers: { 'x-aws-ec2-metadata-token-ttl-seconds': '300' }, signal: AbortSignal.timeout(2000) }).catch(() => null);
  if (session === null || !session.ok) {
    throw new Error('aws(): no role credentials here: none in the environment, no ECS credentials endpoint, and no EC2 instance metadata');
  }
  const headers = { 'x-aws-ec2-metadata-token': await session.text() };
  const role = (await (await fetchImpl(`${imds}/meta-data/iam/security-credentials/`, { headers })).text()).trim().split('\n')[0];
  if (!role) throw new Error('aws(): this instance has no instance profile: give it a role');
  const body = await json(await fetchImpl(`${imds}/meta-data/iam/security-credentials/${role}`, { headers }), 'EC2 instance metadata');
  return { accessKeyId: tokenOf(body, 'AccessKeyId', 'IMDS'), secretAccessKey: tokenOf(body, 'SecretAccessKey', 'IMDS'), sessionToken: body.Token as string | undefined };
}

/** `20261024T013000Z`, SigV4's time. */
function amzDate(date: Date): string {
  return date.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, '');
}

const ENCODER = new TextEncoder();

async function hmac(key: Uint8Array, data: string): Promise<Uint8Array> {
  const imported = await crypto.subtle.importKey('raw', key as Uint8Array<ArrayBuffer>, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', imported, ENCODER.encode(data)));
}

async function sha256Hex(data: string): Promise<string> {
  return hex(new Uint8Array(await crypto.subtle.digest('SHA-256', ENCODER.encode(data))));
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

/** RFC 3986's encoding, as SigV4 writes a query: everything but the unreserved characters escaped. */
const awsEncode = (text: string) => encodeURIComponent(text).replace(/[!'()*]/g, (char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`);

/**
 * The `authorization` header AWS Signature Version 4 gives a request, every
 * header given signed (`host` and `x-amz-date` among them). Exported for its
 * test, against AWS's own documented example.
 */
export async function sigv4(request: {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: string;
  region: string;
  service: string;
  credentials: AwsCredentials;
}): Promise<string> {
  const url = new URL(request.url);
  const names = Object.keys(request.headers).map((name) => name.toLowerCase()).sort();
  const value = (name: string) => Object.entries(request.headers).find(([given]) => given.toLowerCase() === name)![1].trim().replace(/\s+/g, ' ');
  const query = [...url.searchParams].map(([name, v]) => `${awsEncode(name)}=${awsEncode(v)}`).sort().join('&');
  const canonical = [request.method, url.pathname, query, ...names.map((name) => `${name}:${value(name)}`), '', names.join(';'), await sha256Hex(request.body)].join('\n');
  const time = value('x-amz-date');
  const scope = `${time.slice(0, 8)}/${request.region}/${request.service}/aws4_request`;
  const toSign = ['AWS4-HMAC-SHA256', time, scope, await sha256Hex(canonical)].join('\n');
  let key: Uint8Array = ENCODER.encode(`AWS4${request.credentials.secretAccessKey}`);
  for (const part of [time.slice(0, 8), request.region, request.service, 'aws4_request']) key = await hmac(key, part);
  return `AWS4-HMAC-SHA256 Credential=${request.credentials.accessKeyId}/${scope}, SignedHeaders=${names.join(';')}, Signature=${hex(await hmac(key, toSign))}`;
}

/** Google Cloud's metadata server's ID token for the default service account, its audience naming the key: Cloud Run, GKE, GCE. */
export function gcp(): Proof {
  return {
    name: 'gcp',
    kind: 'oidc',
    prove: async (context) => {
      const url = new URL('http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity');
      url.searchParams.set('audience', keyAudience(context));
      url.searchParams.set('format', 'full');
      const response = await context.fetch(url.href, { headers: { 'metadata-flavor': 'Google' } });
      if (!response.ok) throw new Error(`Google's metadata server gave no ID token (status ${response.status})`);
      return { oidc: (await response.text()).trim() };
    },
  };
}

/**
 * An Azure managed identity's token for coffre's Entra application, its
 * `audience` (`api://coffre-acme`): from App Service's and Functions'
 * identity endpoint, or else IMDS. `clientId` picks a user-assigned
 * identity. Entra mints only for a registered audience, so the token cannot
 * name the key, and repeats until it expires (section 4.2).
 */
export function azure(options: { audience: string; clientId?: string }): Proof {
  return {
    name: 'azure',
    kind: 'oidc',
    prove: async ({ fetch: fetchImpl }) => {
      const vars = env();
      const service = vars.IDENTITY_ENDPOINT && vars.IDENTITY_HEADER;
      const url = new URL(service ? vars.IDENTITY_ENDPOINT! : 'http://169.254.169.254/metadata/identity/oauth2/token');
      url.searchParams.set('api-version', service ? '2019-08-01' : '2018-02-01');
      url.searchParams.set('resource', options.audience);
      if (options.clientId !== undefined) url.searchParams.set('client_id', options.clientId);
      const headers: Record<string, string> = service ? { 'x-identity-header': vars.IDENTITY_HEADER! } : { metadata: 'true' };
      return { oidc: tokenOf(await json(await fetchImpl(url.href, { headers }), 'Azure\'s identity endpoint'), 'access_token', 'Azure') };
    },
  };
}

/** A Fly Machine's OIDC token, from its `/.fly/api` socket, its audience naming the key. */
export function fly(socketPath = '/.fly/api'): Proof {
  return {
    name: 'fly',
    kind: 'oidc',
    prove: async (context) => {
      const { request } = await import('node:http');
      const body = JSON.stringify({ aud: keyAudience(context) });
      const token = await new Promise<string>((resolve, reject) => {
        const asked = request({ socketPath, path: '/v1/tokens/oidc', method: 'POST', signal: context.signal, headers: { 'content-type': 'application/json', 'content-length': ENCODER.encode(body).length } }, (answer) => {
          let text = '';
          answer.setEncoding('utf8');
          answer.on('data', (chunk: string) => (text += chunk));
          answer.on('end', () => (answer.statusCode === 200 ? resolve(text.trim()) : reject(new Error(`Fly's API gave no OIDC token (status ${answer.statusCode})`))));
        });
        asked.on('error', (error) => reject(new Error(`no Fly API at ${socketPath}: ${error.message}`)));
        asked.end(body);
      });
      return { oidc: token };
    },
  };
}

/**
 * A Vercel function's OIDC token, exchanged at Vercel for one whose audience
 * names the key, as `@vercel/oidc` does, asked afresh for each proof. The
 * function's own token is the file `VERCEL_OIDC_TOKEN_FILE` names, or else
 * `VERCEL_OIDC_TOKEN`, unless given: per request, from the
 * `x-vercel-oidc-token` header, as `vercel(() => headers.get(…))`.
 */
export function vercel(token?: string | (() => string | Promise<string>)): Proof {
  return {
    name: 'vercel',
    kind: 'oidc',
    prove: async (context) => {
      const file = env().VERCEL_OIDC_TOKEN_FILE;
      const own = typeof token === 'function' ? await token() : (token ?? (file ? (await (await import('node:fs/promises')).readFile(file, 'utf8')).trim() : env().VERCEL_OIDC_TOKEN));
      if (!own) throw new Error('vercel(): no OIDC token: turn on OIDC federation for the project, or pass the request\'s x-vercel-oidc-token');
      const response = await context.fetch('https://oidc.vercel.com/~token', {
        method: 'POST',
        headers: { 'content-type': 'application/json', accept: 'application/json' },
        body: JSON.stringify({ token: own, aud: keyAudience(context) }),
      });
      return { oidc: tokenOf(await json(response, 'Vercel\'s token exchange'), 'token', 'Vercel') };
    },
  };
}

/** A GitHub Actions job's ID token, from its runner, its audience naming the key: the job needs `permissions: id-token: write`. */
export function github(): Proof {
  return {
    name: 'github',
    kind: 'oidc',
    prove: async (context) => {
      const vars = env();
      const [url, bearer] = [vars.ACTIONS_ID_TOKEN_REQUEST_URL?.trim(), vars.ACTIONS_ID_TOKEN_REQUEST_TOKEN?.trim()];
      if (!url || !bearer) throw new Error('github(): this job has no ID token: give it `permissions: id-token: write`');
      const request = new URL(url);
      request.searchParams.set('audience', keyAudience(context));
      const response = await context.fetch(request.href, { headers: { authorization: `bearer ${bearer}`, accept: 'application/json' } });
      return { oidc: tokenOf(await json(response, 'GitHub\'s runner'), 'value', 'GitHub') };
    },
  };
}

/**
 * Any other ID token, as given, or asked for at each exchange: GitLab's
 * `id_tokens` entry, whose `aud` is coffre's URL, or a custom issuer's. A
 * token is spent once used, so a given string proves one session.
 */
export function oidc(token: string | (() => string | Promise<string>), name = 'oidc'): Proof {
  return { name, kind: 'oidc', prove: async () => ({ oidc: typeof token === 'function' ? await token() : token }) };
}

/**
 * An enrollment code (section 4.4), on a platform that signs nothing:
 * Railway, Render, a VM. Once given, the code leaves `process.env`, under
 * whatever name held it, so the app's own dumps of its environment no
 * longer show it; the platform's store still holds it.
 */
export function enrollment(code: string | undefined): Proof {
  if (code === undefined || !code.startsWith('coffre_enr_')) throw new Error('enrollment(): no enrollment code: CI sets one each deploy, from `coffre enroll <service>`');
  const vars = (globalThis as { process?: { env: Env } }).process?.env;
  for (const [name, value] of Object.entries(vars ?? {})) if (value === code) delete vars![name];
  return { name: 'enrollment', kind: 'enrollment', prove: async () => ({ enrollment: code }) };
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
