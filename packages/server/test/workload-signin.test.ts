// A workload signing in with a key, POST /api/auth/workload, renewing its
// session, /api/auth/workload/renew, and signing out, POST /api/auth/logout
// with its key's proof (docs/design/0.16.md, "A workload signing in"). What
// the vault decides is its own suite's (packages/vault/test/workloads.test.ts);
// here, the app's part: the DPoP proof, the issuer's keys or STS, what each
// refusal tells the workload and what it costs, and the gate's nonce.
import assert from 'node:assert/strict';
import { createHash, createHmac, generateKeyPairSync, sign, type Hash, type Hmac, type KeyObject } from 'node:crypto';
import { after, beforeEach, test } from 'node:test';

import { createProof, generateProofKey, thumbprint, type ProofKey } from '@coffre/client/dpop';
import { canonicalClaims, generateToken, github, signin, type WorkloadAlert } from '@coffre/core/identity';
import { binding, emptyDatabase, environment, grant, instance, principal, project, role, rows, session, write } from '@coffre/vault/testing';
import { SignatureV4 } from '@smithy/signature-v4';

import { processGates } from '../src/gate.ts';
import { GET_CALLER_IDENTITY, stsFetch, type AwsProofInput } from '../src/workloads/aws.ts';
import { forgetKeys } from '../src/workloads/keys.ts';
import { processLimits } from '../src/workloads/limits.ts';
import { FetchRefused, type WorkloadTransport } from '../src/workloads/transport.ts';
import { openApp, PUBLIC_URL } from './app-fixture.ts';

const DEPLOY = 'token:deploy';
const GITHUB = 'https://token.actions.githubusercontent.com';
const KEYS = `${GITHUB}/.well-known/jwks`;
const KUBE = 'https://kubernetes.acme.example';
const MAIN = { repository_owner_id: '9919', repository_id: '41532', ref: 'refs/heads/main', event_name: 'push' };
const ACCOUNT = '671742253563';
const ROLE_ID = 'AROAZ3EXAMPLE7QXYZAB';

// STS, as AWS runs it for one role: the signature recomputed with its secret over the signed headers.
const ROLE = {
  accessKeyId: 'ASIAROLEEXAMPLE00001', secretAccessKey: 'role-secret', sessionToken: 'role-session-token',
  arn: `arn:aws:sts::${ACCOUNT}:assumed-role/ingest-task/i-0b5f3c2a9d8e7f601`, userId: `${ROLE_ID}:i-0b5f3c2a9d8e7f601`,
};
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

/** A role's `GetCallerIdentity` as the SDK signs one, naming this instance and `jkt` under its signature, unsent. */
async function awsProof(jkt: string, headers: Record<string, string> = {}): Promise<AwsProofInput> {
  const hostname = 'sts.eu-west-3.amazonaws.com';
  const signer = new SignatureV4({ credentials: ROLE, region: 'eu-west-3', service: 'sts', sha256: Sha256, applyChecksum: false });
  const signed = await signer.sign(
    { method: 'POST', protocol: 'https:', hostname, path: '/', query: {}, headers: { host: hostname, 'content-type': 'application/x-www-form-urlencoded; charset=utf-8', 'x-coffre-audience': PUBLIC_URL, 'x-coffre-key': jkt, ...headers }, body: GET_CALLER_IDENTITY },
    { signingDate: new Date() },
  );
  const { host: _, ...sent } = signed.headers;
  return { url: `https://${hostname}/`, headers: sent, body: GET_CALLER_IDENTITY };
}

/** STS's calls; `answer` replaces its own answer. */
let sts: { calls: number; answer?: () => Response };
const fakeSts: typeof fetch = async (input, init) => {
  sts.calls++;
  if (sts.answer !== undefined) return sts.answer();
  const url = new URL(String(input));
  const sent = init!.headers as Record<string, string>;
  const signedHeaders = /SignedHeaders=([^,]+)/.exec(sent.authorization ?? '')?.[1]?.split(';') ?? [];
  const headers: Record<string, string> = {};
  for (const name of signedHeaders) headers[name] = name === 'host' ? url.host : sent[name]!;
  const stamp = sent['x-amz-date']!;
  const date = new Date(`${stamp.slice(0, 4)}-${stamp.slice(4, 6)}-${stamp.slice(6, 8)}T${stamp.slice(9, 11)}:${stamp.slice(11, 13)}:${stamp.slice(13, 15)}Z`);
  const signer = new SignatureV4({ credentials: ROLE, region: 'eu-west-3', service: 'sts', sha256: Sha256, applyChecksum: false });
  const expected = await signer.sign({ method: 'POST', protocol: 'https:', hostname: url.hostname, path: '/', query: {}, headers, body: init!.body as string }, { signingDate: date, signableHeaders: new Set(signedHeaders) });
  if (expected.headers.authorization !== sent.authorization) {
    return new Response('<ErrorResponse><Error><Type>Sender</Type><Code>SignatureDoesNotMatch</Code></Error></ErrorResponse>', { status: 403 });
  }
  return new Response(`<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>${ROLE.arn}</Arn><UserId>${ROLE.userId}</UserId><Account>${ACCOUNT}</Account></GetCallerIdentityResult></GetCallerIdentityResponse>`, { status: 200 });
};

/** What the issuers publish, by URL; and STS. */
const published = new Map<string, unknown>();
const transport: WorkloadTransport = {
  async json(url) {
    if (!published.has(url.href)) throw FetchRefused.answered(url, 503);
    return published.get(url.href);
  },
  sts: stsFetch(fakeSts),
};

let gates = processGates();
const alerts: WorkloadAlert[] = [];
const auth = signin({ providers: [github({ clientId: 'gh-id', clientSecret: 'gh-secret' })], workloads: { limits: processLimits(), alert: (alert) => void alerts.push(alert) } });
const app = await openApp({ auth, transport, workloads: {}, gates: (service) => gates(service) });
const ungated = await openApp({ auth, transport, workloads: {} });
const { world } = app;
after(async () => {
  await app.close();
  await ungated.close();
});

const pair = () => generateKeyPairSync('ec', { namedCurve: 'P-256' });
const jwk = (key: KeyObject, kid: string) => ({ ...key.export({ format: 'jwk' }), kid, alg: 'ES256', use: 'sig' });
const github1 = pair();
const kube1 = pair();
const kube2 = pair();
const KUBE_JWKS = JSON.stringify({ keys: [jwk(kube1.publicKey, 'kube-1')] });
const b64 = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
const now = () => Math.floor(Date.now() / 1000);
let drawn = 0;
/** An ID token, ES256: GitHub's for main by default. */
function idToken(claims: Record<string, unknown>, { key = github1.privateKey, kid = 'gh-1' }: { key?: KeyObject; kid?: string } = {}): string {
  drawn += 1;
  const input = `${b64({ alg: 'ES256', kid, typ: 'JWT' })}.${b64({ iss: GITHUB, sub: 'repo:acme/api:ref:refs/heads/main', aud: PUBLIC_URL, iat: now() - 10, exp: now() + 290, jti: `run-${drawn}`, ...MAIN, ...claims })}`;
  return `${input}.${sign('sha256', Buffer.from(input), { key, dsaEncoding: 'ieee-p1363' }).toString('base64url')}`;
}

const market = project('market');
const prod = environment(market, 'prod');
const VIEWER = JSON.stringify([{ projectId: market.id, environmentId: null, role: 'viewer' }]);
/** The workload's key, and its thumbprint. */
let held: ProofKey;
let jkt: string;
/** `deploy` holds Developer on market: a workload's binding for main, whose tokens name the key, and an AWS role's, each reaching market as a Viewer; and a CI run's binding. */
let keyed: ReturnType<typeof binding>;
let aws: ReturnType<typeof binding>;
let bearer: ReturnType<typeof binding>;

beforeEach(async () => {
  await emptyDatabase(world.owner);
  for (const kept of [world.memory.reads, world.memory.callers, world.memory.logged, world.memory.touched, world.refused]) kept.clear();
  forgetKeys();
  gates = processGates();
  published.clear();
  published.set(KEYS, { keys: [jwk(github1.publicKey, 'gh-1')] });
  sts = { calls: 0 };
  alerts.length = 0;
  held = await generateProofKey();
  jkt = await thumbprint(held.jwk);
  keyed = binding(DEPLOY, { claims: canonicalClaims(MAIN), scope: VIEWER, policy: '{"keyAudience":true}', label: 'main' });
  aws = binding(DEPLOY, { profile: 'aws', issuer: 'urn:coffre:aws', jwksUri: 'urn:coffre:aws', claims: canonicalClaims({ account: ACCOUNT, role_id: ROLE_ID }), scope: VIEWER, policy: '{}' });
  bearer = binding(DEPLOY, { claims: canonicalClaims({ ...MAIN, ref: 'refs/heads/release' }), scope: VIEWER });
  await write(
    world,
    ...rows('policy', instance()),
    ...rows('roles', role(true, 'owner', ['secret.read']), role(true, 'member', []), role(false, 'developer', ['secret.read', 'secret.write']), role(false, 'viewer', ['secret.read'])),
    ...rows('projects', market),
    ...rows('environments', prod),
    ...rows('principals', principal(DEPLOY)),
    ...rows('grants', grant(DEPLOY, 'developer', { project: market })),
    ...rows('bindings', keyed, aws, bearer),
  );
  for (const opened of [app, ungated]) {
    await opened.request('/livez');
    await opened.request('/api/me', { headers: { authorization: 'Bearer nobody' } });
  }
  app.calls.length = 0;
});

type Answer = { status: number; body: { token?: string; tokenType?: string; expiresAt?: string; notAfter?: string; places?: string[]; signedOut?: boolean; error?: string; reason?: string; message?: string; principal?: { id: string } }; nonce: string | null };
const read = async (got: Response): Promise<Answer> => ({ status: got.status, body: (await got.json()) as Answer['body'], nonce: got.headers.get('dpop-nonce') });
const reason = (answer: Answer) => [answer.status, answer.body.reason];

/** POST /api/auth/workload as `deploy`, with a DPoP proof of `key` for it unless told another (null for none). */
async function signIn(proof: Record<string, unknown>, options: { key?: ProofKey; dpop?: string | null; service?: string; through?: typeof app } = {}): Promise<Answer> {
  const url = `${PUBLIC_URL}/api/auth/workload`;
  const dpop = options.dpop !== undefined ? options.dpop : await createProof(options.key ?? held, { method: 'POST', url });
  const headers: Record<string, string> = { 'content-type': 'application/json', ...(dpop === null ? {} : { dpop }) };
  return read(await (options.through ?? app).request('/api/auth/workload', { method: 'POST', headers, body: JSON.stringify({ service: options.service ?? 'deploy', proof }) }));
}

/** A request as a session, `token` with a proof of `key` under the gate's current nonce: Authorization DPoP unless told the scheme. */
async function asSession(path: string, token: string, options: { method?: string; key?: ProofKey; scheme?: string; proof?: boolean } = {}): Promise<Answer> {
  const method = options.method ?? 'POST';
  const headers: Record<string, string> = { authorization: `${options.scheme ?? 'DPoP'} ${token}` };
  if (options.proof !== false) headers.dpop = await createProof(options.key ?? held, { method, url: `${PUBLIC_URL}${path}`, token, nonce: await gates(DEPLOY).nonce() });
  return read(await app.request(path, { method, headers }));
}

/** What a request cost: the vault's calls and the app's statements. */
async function cost<T>(run: () => Promise<T>): Promise<[T, string[], number]> {
  const [calls, statements] = [app.calls.length, app.statements];
  const result = await run();
  return [result, app.calls.slice(calls), app.statements - statements];
}

test("a run's token naming the key buys a session bound to it: one statement, one sign-in, one more for its places by path, and the gate's nonce for its first request", async () => {
  const naming = idToken({ aud: `${PUBLIC_URL}#jkt=${jkt}` });
  const [made, calls, statements] = await cost(() => signIn({ oidc: naming }));
  assert.equal(made.status, 200, JSON.stringify(made.body));
  assert.deepEqual([made.body.tokenType, made.body.places, calls, statements], ['DPoP', ['market/prod'], ['change'], 2]);
  assert.match(made.body.token!, /^coffre_wl_/);
  assert.equal(made.nonce, await gates(DEPLOY).nonce());
  // An hour, within the binding's day; the token names the key, so it is not spent and does not end the session.
  const [expires, notAfter] = [Date.parse(made.body.expiresAt!), Date.parse(made.body.notAfter!)];
  assert.ok(Math.abs(expires - (Date.now() + 3_600_000)) < 60_000 && notAfter - Date.now() > 23 * 3_600_000, `${made.body.expiresAt} ${made.body.notAfter}`);
  const me = await asSession('/api/me', made.body.token!, { method: 'GET' });
  assert.deepEqual([me.status, me.body.principal?.id], [200, 'deploy']);
  // The same token again, with a fresh proof, makes another session for the same key.
  assert.equal((await signIn({ oidc: naming })).status, 200);
});

test("the token is worth nothing to another key, which its audience does not name; nothing of the vault's is asked", async () => {
  const other = await generateProofKey();
  const [refused, calls] = await cost(() => signIn({ oidc: idToken({ aud: `${PUBLIC_URL}#jkt=${jkt}` }) }, { key: other }));
  assert.deepEqual([...reason(refused), calls], [401, 'audience', []]);
});

test('the sign-in takes a DPoP proof of the key, for its own URL and method, made within the minute, and before anything is read', async () => {
  const token = () => idToken({ aud: `${PUBLIC_URL}#jkt=${jkt}` });
  const wrong = [
    null,
    'not-a-proof',
    await createProof(held, { method: 'POST', url: `${PUBLIC_URL}/api/auth/oidc` }),
    await createProof(held, { method: 'GET', url: `${PUBLIC_URL}/api/auth/workload` }),
    await createProof(held, { method: 'POST', url: `${PUBLIC_URL}/api/auth/workload`, iat: now() - 120 }),
  ];
  for (const dpop of wrong) {
    const [refused, calls, statements] = await cost(() => signIn({ oidc: token() }, { dpop }));
    assert.deepEqual([...reason(refused), calls, statements], [401, 'dpop', [], 0], String(dpop));
  }
  // A proof names one kind, of those it takes.
  assert.deepEqual(reason(await signIn({ enrollment: 'code' })), [401, 'malformed']);
  assert.equal((await signIn({ oidc: token(), aws: {} })).status, 400);
  // No gate, nothing to stop a replay: no session is made, and nothing is spent.
  const [gateless, calls] = await cost(() => signIn({ oidc: token() }, { through: ungated }));
  assert.deepEqual([gateless.status, gateless.body.reason, calls], [503, 'no_gate', []]);
});

test("/api/auth/workload never takes a CI run's binding, and /api/auth/oidc never a workload's", async () => {
  // The release binding is a CI run's: a session from its token is no binding's, and the vault is not asked.
  const [refused, calls, statements] = await cost(() => signIn({ oidc: idToken({ ref: 'refs/heads/release', aud: PUBLIC_URL }) }));
  assert.deepEqual([...reason(refused), calls, statements], [401, 'audience', [], 1]);
  const exchanged = await read(await app.request('/api/auth/oidc', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ service: DEPLOY, token: idToken({ aud: PUBLIC_URL }) }) }));
  assert.deepEqual(reason(exchanged), [401, 'no_match']);
  // A service with no workload binding on the issuer costs that one read.
  const [none, noneCalls, noneStatements] = await cost(() => signIn({ oidc: idToken({ aud: `${PUBLIC_URL}#jkt=${jkt}` }) }, { service: 'api' }));
  assert.deepEqual([...reason(none), noneCalls, noneStatements], [401, 'no_match', [], 1]);
});

test("a token signed by a key its binding's uploaded keys lack alerts the deployment, and tells the workload unknown_key", async () => {
  const carried = binding(DEPLOY, { profile: 'custom', issuer: KUBE, jwksUri: `sha256:${createHash('sha256').update(KUBE_JWKS).digest('hex')}`, jwks: KUBE_JWKS, claims: canonicalClaims({ sub: 'system:serviceaccount:ci:runner' }), scope: VIEWER, policy: '{}' });
  await write(world, ...rows('bindings', carried));
  const token = (key: KeyObject, kid: string) => idToken({ iss: KUBE, sub: 'system:serviceaccount:ci:runner' }, { key, kid });
  const made = await signIn({ oidc: token(kube1.privateKey, 'kube-1') });
  assert.equal(made.status, 200, JSON.stringify(made.body));
  const refused = await signIn({ oidc: token(kube2.privateKey, 'kube-2') });
  assert.deepEqual(reason(refused), [401, 'unknown_key']);
  assert.deepEqual(alerts.map((alert) => [alert.kind, alert.service, alert.binding]), [['unknown_key', DEPLOY, carried.id]]);
});

test("a role's signed GetCallerIdentity, naming this instance and the key, buys a session: STS asked once, the request as signed", async () => {
  const [made, calls, statements] = await cost(async () => signIn({ aws: await awsProof(jkt) }));
  assert.equal(made.status, 200, JSON.stringify(made.body));
  assert.deepEqual([made.body.places, calls, statements, sts.calls], [['market/prod'], ['change'], 2, 1]);
  // Never spent: the same request makes another session for the same key.
  assert.equal((await signIn({ aws: await awsProof(jkt) })).status, 200);
});

test('an aws proof for another key or instance, or of a service with no aws binding, asks STS nothing; STS refusing or down is said', async () => {
  const other = await generateProofKey();
  assert.deepEqual(reason(await signIn({ aws: await awsProof(jkt) }, { key: other })), [401, 'audience']);
  assert.deepEqual(reason(await signIn({ aws: await awsProof(jkt, { 'x-coffre-audience': 'https://elsewhere.example' }) })), [401, 'audience']);
  assert.deepEqual(reason(await signIn({ aws: await awsProof(jkt) }, { service: 'api' })), [401, 'no_match']);
  assert.equal(sts.calls, 0);
  sts.answer = () => new Response('<ErrorResponse><Error><Code>InvalidClientTokenId</Code></Error></ErrorResponse>', { status: 403 });
  assert.deepEqual(reason(await signIn({ aws: await awsProof(jkt) })), [401, 'signature']);
  sts.answer = () => new Response('<ErrorResponse><Error><Code>Throttling</Code></Error></ErrorResponse>', { status: 400 });
  const down = await signIn({ aws: await awsProof(jkt) });
  assert.deepEqual([down.status, down.body.reason], [503, 'issuer_unavailable']);
});

/** A session of `of` written as the vault would have made it, ending `expiresIn` from now. */
async function written(of: ReturnType<typeof binding>, expiresIn: number): Promise<string> {
  const token = generateToken('workload');
  await write(world, ...rows('credentials', session(token, of, { jkt, scope: VIEWER, places: JSON.stringify([{ environmentId: prod.id }]), expiresAt: new Date(Date.now() + expiresIn), notAfter: new Date(Date.now() + 86_400_000) })));
  return token;
}

test("renewal moves a session's expiry on an hour, by its key, with the gate's nonce; a frozen one renews; one at its end does not", async () => {
  const token = await written(keyed, 600_000);
  const [renewed, calls] = await cost(() => asSession('/api/auth/workload/renew', token));
  assert.equal(renewed.status, 200, JSON.stringify(renewed.body));
  assert.ok(Math.abs(Date.parse(renewed.body.expiresAt!) - (Date.now() + 3_600_000)) < 60_000, String(renewed.body.expiresAt));
  assert.deepEqual([calls, renewed.nonce], [['change'], await gates(DEPLOY).nonce()]);
  // Without its key's proof, or as a bearer, nothing is asked.
  assert.deepEqual(reason(await asSession('/api/auth/workload/renew', token, { proof: false })), [401, 'dpop']);
  assert.equal((await asSession('/api/auth/workload/renew', token, { scheme: 'Bearer' })).status, 401);
  // A frozen binding's session renews: lifting the freeze restores it.
  const frozen = binding(DEPLOY, { claims: canonicalClaims(MAIN), scope: VIEWER, policy: '{}', frozenAt: new Date() });
  await write(world, ...rows('bindings', frozen));
  const still = await written(frozen, 600_000);
  assert.equal((await asSession('/api/auth/workload/renew', still)).status, 200);
  assert.deepEqual(reason(await asSession('/api/me', still, { method: 'GET' })), [403, 'frozen']);
  // Within five seconds of its end, a renewal revives nothing.
  const late = await written(keyed, 3_000);
  const refused = await asSession('/api/auth/workload/renew', late);
  assert.deepEqual([...reason(refused), refused.nonce !== null], [401, 'expired', true]);
});

test('logout ends the session, with its key; without the proof, or as a bearer, it ends nothing', async () => {
  const token = await written(keyed, 600_000);
  assert.deepEqual(reason(await asSession('/api/auth/logout', token, { proof: false })), [401, 'dpop']);
  assert.deepEqual(reason(await asSession('/api/auth/logout', token, { scheme: 'Bearer' })), [401, 'workload']);
  assert.equal((await asSession('/api/me', token, { method: 'GET' })).status, 200);
  const out = await asSession('/api/auth/logout', token);
  assert.deepEqual([out.status, out.body.signedOut, out.nonce !== null], [200, true, true]);
  for (const kept of [world.memory.callers]) kept.clear();
  assert.equal((await asSession('/api/me', token, { method: 'GET' })).status, 401);
});
