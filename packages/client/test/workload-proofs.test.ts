import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { workload } from '../src/workload.ts';
import { aws, azure, enrollment, gcp, github, keyAudience, kubernetes, sigv4, vercel, type ProofContext } from '../src/workload-proofs.ts';

/** The real one, for the tests that mock time: their I/O (a token's file, WebCrypto) runs on it. */
const realSetTimeout = globalThis.setTimeout;

/** A proof's context, its platform's answers given by `reply`, each request it made kept. */
function context(reply: (url: string, init: RequestInit) => Response) {
  const asked: { url: string; init: RequestInit }[] = [];
  const given: ProofContext = {
    audience: 'https://secrets.acme.example',
    jkt: 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs',
    fetch: async (url, init = {}) => (asked.push({ url, init }), reply(url, init)),
    log: () => undefined,
  };
  return { given, asked };
}

test("SigV4 signs as AWS's own documented example does", async () => {
  const authorization = await sigv4({
    method: 'GET',
    url: 'https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8', Host: 'iam.amazonaws.com', 'X-Amz-Date': '20150830T123600Z' },
    body: '',
    region: 'us-east-1',
    service: 'iam',
    credentials: { accessKeyId: 'AKIDEXAMPLE', secretAccessKey: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY' },
  });
  assert.equal(
    authorization,
    'AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7',
  );
});

test('aws() signs a GetCallerIdentity naming the instance and the key, and sends coffre no credential', async () => {
  const { given } = context(() => new Response(null, { status: 500 }));
  const proof = await aws({ credentials: { accessKeyId: 'ASIAEXAMPLE', secretAccessKey: 'secret', sessionToken: 'session' }, region: 'eu-west-3' }).prove(given);
  assert.ok('aws' in proof);
  assert.equal(proof.aws.url, 'https://sts.eu-west-3.amazonaws.com/');
  assert.equal(proof.aws.body, 'Action=GetCallerIdentity&Version=2011-06-15');
  // Exactly the headers the exchange allows; the audience and the key under the signature.
  assert.deepEqual(Object.keys(proof.aws.headers).sort(), ['authorization', 'content-type', 'host', 'x-amz-date', 'x-amz-security-token', 'x-coffre-audience', 'x-coffre-key']);
  assert.equal(proof.aws.headers['x-coffre-key'], given.jkt);
  assert.equal(proof.aws.headers['x-coffre-audience'], given.audience);
  assert.match(proof.aws.headers.authorization!, /SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-coffre-audience;x-coffre-key, /);
  assert.ok(!JSON.stringify(proof).includes('secret"'));
  await assert.rejects(aws({ credentials: { accessKeyId: 'a', secretAccessKey: 'b' }, region: 'us-gov-west-1' }).prove(given), /no commercial AWS region/);
});

test('aws() finds role credentials at the ECS container endpoint', async () => {
  const saved = { ...process.env };
  try {
    for (const name of ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_REGION', 'AWS_DEFAULT_REGION']) delete process.env[name];
    process.env.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI = '/v2/credentials/abc';
    const { given, asked } = context(() => Response.json({ AccessKeyId: 'ASIAECS', SecretAccessKey: 's', Token: 't' }));
    const proof = await aws().prove(given);
    assert.equal(asked[0]!.url, 'http://169.254.170.2/v2/credentials/abc');
    assert.ok('aws' in proof && proof.aws.url === 'https://sts.amazonaws.com/');
    assert.match((proof as { aws: { headers: Record<string, string> } }).aws.headers.authorization!, /Credential=ASIAECS\/\d{8}\/us-east-1\/sts\/aws4_request/);
  } finally {
    process.env = saved;
  }
});

test("gcp(), github() and vercel() ask for a token whose audience names the key; azure() for coffre's application", async () => {
  const audience = 'https://secrets.acme.example#jkt=NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs';
  {
    const { given, asked } = context(() => new Response('gcp-token\n'));
    assert.deepEqual(await gcp().prove(given), { oidc: 'gcp-token' });
    const url = new URL(asked[0]!.url);
    assert.equal(url.searchParams.get('audience'), audience);
    assert.equal(url.searchParams.get('format'), 'full');
    assert.deepEqual(asked[0]!.init.headers, { 'metadata-flavor': 'Google' });
  }
  const saved = { ...process.env };
  try {
    process.env.ACTIONS_ID_TOKEN_REQUEST_URL = 'https://runner.example/token?api-version=2.0';
    process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN = 'runner-bearer';
    const { given, asked } = context(() => Response.json({ value: 'gh-token' }));
    assert.deepEqual(await github().prove(given), { oidc: 'gh-token' });
    assert.equal(new URL(asked[0]!.url).searchParams.get('audience'), audience);
    assert.equal(keyAudience(given), audience);

    process.env.VERCEL_OIDC_TOKEN = 'function-token';
    const exchanged = context(() => Response.json({ token: 'vercel-token' }));
    assert.deepEqual(await vercel().prove(exchanged.given), { oidc: 'vercel-token' });
    assert.equal(exchanged.asked[0]!.url, 'https://oidc.vercel.com/~token');
    assert.deepEqual(JSON.parse(String(exchanged.asked[0]!.init.body)), { token: 'function-token', aud: audience });

    delete process.env.IDENTITY_ENDPOINT;
    const imds = context(() => Response.json({ access_token: 'azure-token' }));
    assert.deepEqual(await azure({ audience: 'api://coffre-acme' }).prove(imds.given), { oidc: 'azure-token' });
    assert.equal(new URL(imds.asked[0]!.url).searchParams.get('resource'), 'api://coffre-acme');
    assert.deepEqual(imds.asked[0]!.init.headers, { metadata: 'true' });
  } finally {
    process.env = saved;
  }
});

test('enrollment() takes the code out of the environment, under whatever name held it', async () => {
  const code = `coffre_enr_${'q'.repeat(43)}`;
  process.env.SOME_NAME = code;
  const proof = enrollment(process.env.SOME_NAME);
  assert.equal(process.env.SOME_NAME, undefined);
  assert.deepEqual(await proof.prove(context(() => new Response()).given), { enrollment: code });
  assert.throws(() => enrollment(undefined), /no enrollment code/);
});

/** A projected token's file, in a directory the test removes. */
function tokenFile(t: test.TestContext, token: string) {
  const dir = mkdtempSync(join(tmpdir(), 'coffre-k8s-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const file = join(dir, 'token');
  writeFileSync(file, `${token}\n`);
  return file;
}

test('kubernetes() never sends a token coffre took: it waits for the kubelet to write the next, and says so once', async (t) => {
  const file = tokenFile(t, 'token-1');
  const said: string[] = [];
  const { given } = context(() => new Response(null, { status: 500 }));
  given.log = (line) => said.push(line);
  const proof = kubernetes(file);
  assert.deepEqual(await proof.prove(given), { oidc: 'token-1' });
  // Not taken (a 503, a network failure): sent again.
  assert.deepEqual(await proof.prove(given), { oidc: 'token-1' });
  proof.accepted!();
  setTimeout(() => writeFileSync(file, 'token-2\n'), 1500);
  assert.deepEqual(await proof.prove(given), { oidc: 'token-2' });
  assert.deepEqual(said, [`coffre: the token at ${file} is already used; waiting for the next one (up to 10 minutes)`]);
  // The next is not waited for when the kubelet wrote it before the renewal.
  proof.accepted!();
  writeFileSync(file, 'token-3\n');
  assert.deepEqual(await proof.prove(given), { oidc: 'token-3' });
  assert.equal(said.length, 1);
});

test('kubernetes() stops waiting when the session closes', async (t) => {
  const file = tokenFile(t, 'token-1');
  const { given } = context(() => new Response(null, { status: 500 }));
  const closing = new AbortController();
  given.signal = closing.signal;
  const proof = kubernetes(file);
  await proof.prove(given);
  proof.accepted!();
  const waiting = proof.prove(given);
  setTimeout(() => closing.abort(), 200);
  await assert.rejects(waiting, (error: Error) => error.name === 'AbortError');
});

test('kubernetes() gives up after 10 minutes of the same token, with what to check; spent() says false', async (t) => {
  const file = tokenFile(t, 'token-1');
  const { given } = context(() => new Response(null, { status: 500 }));
  const proof = kubernetes(file);
  await proof.prove(given);
  proof.accepted!();
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: Date.now() });
  /** Time, moved on a second at a time, with the file reads in between on real I/O, until the wait ends. */
  const waitOut = async <T>(running: Promise<T>) => {
    let done = false;
    const settled = running.then(
      () => (done = true),
      () => (done = true),
    );
    for (let i = 0; i < 5000 && !done; i++) {
      t.mock.timers.tick(1000);
      for (let turn = 0; turn < 10; turn++) await new Promise((resolve) => setImmediate(resolve));
    }
    await settled;
    return running;
  };
  await assert.rejects(waitOut(proof.prove(given)), /wrote no new token at .* in 10 minutes/);
  assert.equal(await waitOut(proof.spent!(given)), false);
});

/**
 * A pod's sidecar on mocked time: `workload()` with `kubernetes()` on a
 * token file, signed in with `token-1`, against a fake coffre whose
 * sign-ins `answer` decides (200, for 100 seconds, unless it gives one).
 * The session proves again at 90% of that, 90 seconds on.
 */
async function sidecar(t: test.TestContext, answer: (token: string) => Response | undefined = () => undefined) {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: Date.now() });
  const file = tokenFile(t, 'token-1');
  const sent: string[] = [];
  const said: string[] = [];
  let end = '';
  const fetch = async (input: string | URL | Request, init: RequestInit = {}) => {
    if (new URL(String(input)).pathname !== '/api/auth/workload') return Response.json({ expiresAt: end });
    const token = (JSON.parse(String(init.body)) as { proof: { oidc: string } }).proof.oidc;
    sent.push(token);
    end = new Date(Date.now() + 100_000).toISOString();
    return answer(token) ?? Response.json({ token: `coffre_wl_${sent.length}`, tokenType: 'DPoP', expiresAt: end, notAfter: end, places: [] });
  };
  const session = await workload({ url: 'https://secrets.acme.example', service: 'api-prod', proof: kubernetes(file), fetch: fetch as typeof globalThis.fetch, log: (line) => said.push(line), sigterm: false });
  t.after(() => session.close().catch(() => undefined));
  /** Mocked time moved on a second at a time, with real time in between for the file's reads and the requests' signatures. */
  const advance = async (ms: number) => {
    for (let at = 0; at < ms; at += 1000) {
      t.mock.timers.tick(1000);
      await new Promise((resolve) => realSetTimeout(resolve, 5));
    }
    await new Promise((resolve) => realSetTimeout(resolve, 50));
  };
  return { file, sent, said, advance };
}

const unavailable = () => Response.json({ error: 'unavailable', reason: 'migrating', message: 'coffre is migrating' }, { status: 503 });
const replayed = () => Response.json({ error: 'unauthenticated', reason: 'replayed', message: 'this token was exchanged already' }, { status: 401 });
const WAITING = /is already used; waiting for the next one/;

test('a token coffre answered 503 to is sent again at the retry: the sidecar signs in again with no new token from the kubelet', async (t) => {
  const answers = [unavailable()];
  const { file, sent, said, advance } = await sidecar(t, (token) => (token === 'token-2' ? answers.shift() : undefined));
  // The kubelet's next, written before the session proves again.
  writeFileSync(file, 'token-2\n');
  await advance(90_000);
  assert.deepEqual(sent, ['token-1', 'token-2']);
  // The retry, a second or so on, sends the token coffre did not take, and coffre takes it.
  await advance(2000);
  assert.deepEqual(sent, ['token-1', 'token-2', 'token-2']);
  assert.deepEqual(said, []);
});

test('a token coffre took but answered 5xx for is refused replayed when sent again: the sidecar waits for the kubelet\'s next, as before', async (t) => {
  const answers = [unavailable(), replayed()];
  const { file, sent, said, advance } = await sidecar(t, (token) => (token === 'token-2' ? answers.shift() : undefined));
  writeFileSync(file, 'token-2\n');
  await advance(93_000);
  assert.deepEqual(sent, ['token-1', 'token-2', 'token-2']);
  assert.equal(said.length, 1);
  assert.match(said[0]!, WAITING);
  await advance(5000);
  assert.equal(sent.length, 3, 'nothing sent while the file holds the spent token');
  writeFileSync(file, 'token-3\n');
  await advance(2000);
  assert.deepEqual(sent, ['token-1', 'token-2', 'token-2', 'token-3']);
});

test('a token coffre took is never sent again: proving again, the sidecar waits for the kubelet\'s next', async (t) => {
  const { file, sent, said, advance } = await sidecar(t);
  await advance(100_000);
  assert.deepEqual(sent, ['token-1'], 'it waits, and sends nothing, while the file holds the token coffre took');
  assert.equal(said.length, 1);
  assert.match(said[0]!, WAITING);
  writeFileSync(file, 'token-2\n');
  await advance(2000);
  assert.deepEqual(sent, ['token-1', 'token-2']);
});
