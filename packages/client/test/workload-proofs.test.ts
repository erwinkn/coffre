import test from 'node:test';
import assert from 'node:assert/strict';

import { aws, azure, enrollment, gcp, github, keyAudience, sigv4, vercel, type ProofContext } from '../src/workload-proofs.ts';

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
