// Several inject rules per credential (docs/design/proxy-ui.md, section 7,
// "Several inject rules" and "Redaction"), end to end: coffre's own vault, a
// handle as `coffre run` makes one, and a fake upstream over HTTP. A header
// and a query parameter; a header and SigV4, the header among the signed
// ones and the signature verified as AWS verifies it; two fields of a form,
// one plain; the redaction of every key's forms, and what each rule made of
// them; the order rules at configuration; and a code item scoped to some
// environments (`environments`), which the others' plans and URLs lack.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac, type Hash, type Hmac } from 'node:crypto';
import { createServer, type IncomingMessage, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

import { SignatureV4 } from '@smithy/signature-v4';
import { createClient } from '@coffre/client';

import { clientFor } from './api-fixture.ts';
import { deps, DEV, ORIGIN, ROOT, route, runtime, sessionFor, useMcp } from './mcp-fixture.ts';
import { coffreRoute } from '../src/app.ts';
import { checkPlugins } from '../src/plugins.ts';
import { basic, credentialProxy, form, header, json, prefix, query, sigv4, type Credential, type CredentialProxyOptions } from '../src/plugins/credential-proxy.ts';

const STRIPE_KEY = 'sk_live_stripe_0123456789abcdef';
const STRIPE_ACCOUNT = 'acct_1Plain0123456';
const MAPS_KEY = 'AIza-maps-0123456789abcdef';
const MAPS_SIGNING = 'sig/ning+key=0123456789';
const TENANT_KEY = 'tenant-0123456789abcdef';
const AWS_ID = 'AKIAREALKEY000000001';
const AWS_SECRET = 'real/secret+access/key0123456789ABCDEFGH';
const CLIENT_ID = 'client-plain-0123456789';
const CLIENT_SECRET = 'client/secret+0123456789=';
const TWILIO_SID = 'AC0123456789abcdef';
const TWILIO_TOKEN = 'twilio-token-0123456789';
const TWILIO_EDGE = 'edge-key-0123456789abcd';
const REPLICA = 'prod-only-0123456789abcd';
const TICKET = 'ticket-0123456789abcdef';

/** The fake upstream: each request it got, and whether its SigV4 signature is the real key's. `/echo` answers with the forms given. */
let upstream: Server;
let upstreamUrl: string;
const reached: { url: string; headers: IncomingMessage['headers']; body: Buffer; verified: boolean }[] = [];
let echo = '';

/** SHA-256 and its HMAC, as the SDK's signer takes a hash. */
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

/** Whether S3 would take the request: its signature recomputed with the real secret over the headers it says it signed. */
async function verified(request: IncomingMessage, body: Buffer): Promise<boolean> {
  const authorization = request.headers.authorization ?? '';
  const signedHeaders = /SignedHeaders=([^,]+)/.exec(authorization)?.[1]?.split(';') ?? [];
  if (!authorization.includes(`Credential=${AWS_ID}/`)) return false;
  const url = new URL(request.url!, upstreamUrl);
  const headers: Record<string, string> = {};
  for (const name of signedHeaders) headers[name] = String(request.headers[name]);
  const signer = new SignatureV4({ credentials: { accessKeyId: AWS_ID, secretAccessKey: AWS_SECRET }, region: 'eu-west-3', service: 's3', sha256: Sha256, uriEscapePath: false, applyChecksum: false });
  const stamp = String(request.headers['x-amz-date']);
  const date = new Date(`${stamp.slice(0, 4)}-${stamp.slice(4, 6)}-${stamp.slice(6, 8)}T${stamp.slice(9, 11)}:${stamp.slice(11, 13)}:${stamp.slice(13, 15)}Z`);
  const query: Record<string, string> = {};
  for (const [name, value] of url.searchParams) query[name] = value;
  const expected = await signer.sign(
    { method: request.method!, protocol: 'http:', hostname: url.hostname, port: Number(url.port), path: url.pathname, query, headers, body },
    { signingDate: date, unsignableHeaders: new Set(), signableHeaders: new Set(signedHeaders) },
  );
  return expected.headers.authorization === authorization;
}

before(async () => {
  upstream = createServer((request, response) => {
    const chunks: Buffer[] = [];
    request.on('data', (chunk: Buffer) => chunks.push(chunk));
    request.on('end', async () => {
      const body = Buffer.concat(chunks);
      reached.push({ url: request.url!, headers: request.headers, body, verified: await verified(request, body) });
      if (request.url!.includes('/echo')) response.writeHead(200, { 'content-type': 'text/plain', 'x-echo': echo.split('\n')[0]! }).end(echo);
      else response.writeHead(200, { 'content-type': 'application/json' }).end('{"ok":true}');
    });
  });
  await new Promise<void>((resolve) => upstream.listen(0, '127.0.0.1', resolve));
  upstreamUrl = `http://127.0.0.1:${(upstream.address() as AddressInfo).port}`;
});

after(() => new Promise<void>((resolve) => upstream.close(() => resolve())));

function options(): CredentialProxyOptions {
  return {
    credentials: {
      // A secret in a header and a plain account id in another, which the app holds as it is.
      stripe: { upstream: `${upstreamUrl}/stripe`, inject: [header('authorization', 'Bearer {STRIPE_KEY}'), header('Stripe-Account', '{STRIPE_ACCOUNT}')], placeholder: prefix('sk_test_') },
      // Two secrets, a header and a query parameter, each read from the handle the app put there.
      maps: { upstream: `${upstreamUrl}/maps`, inject: [header('x-api-key', '{MAPS_KEY}'), query('signature', '{MAPS_SIGNING}')], allow: [{ methods: ['GET'], path: '/geocode/**' }, { path: '/echo' }] },
      // A header SigV4 then signs, and the signature over it.
      s3: { upstream: `${upstreamUrl}/s3`, inject: [header('x-tenant-key', '{TENANT_KEY}'), sigv4({ accessKeyId: '{AWS_ACCESS_KEY_ID}', secretAccessKey: '{AWS_SECRET_ACCESS_KEY}', region: 'eu-west-3', service: 's3' })] },
      // Two fields of a form, the client's id plain.
      oauth: { upstream: `${upstreamUrl}/oauth`, inject: [form('client_id', '{CLIENT_ID}'), form('client_secret', '{CLIENT_SECRET}')] },
      // Basic's pair and a header of its own.
      twilio: { upstream: `${upstreamUrl}/twilio`, inject: [basic('{TWILIO_SID}', '{TWILIO_TOKEN}'), header('x-edge-key', '{TWILIO_EDGE}')] },
      // A query parameter that holds the handle in a placeholder's shape.
      tickets: { upstream: `${upstreamUrl}/tickets`, inject: query('token', '{TICKET}'), placeholder: prefix('p_') },
      // Served in market/prod alone.
      replica: { upstream: `${upstreamUrl}/replica`, inject: header('x-replica-key', '{REPLICA_KEY}'), environments: ['market/prod'] },
    },
    insecureUpstreams: true,
  };
}

useMcp(async () => {
  runtime.plugins = checkPlugins([credentialProxy(options())]);
  reached.length = 0;
  const root = clientFor(deps, ROOT);
  await root.members.add(`user:${DEV}`);
  await root.projects.create('market');
  for (const path of ['market/dev', 'market/prod']) {
    await root.environments.create(path);
    await root.secrets.set(path, {
      STRIPE_KEY, STRIPE_ACCOUNT: { value: STRIPE_ACCOUNT, sensitivity: 'plain' }, MAPS_KEY, MAPS_SIGNING: { value: MAPS_SIGNING, sensitivity: 'sensitive' },
      TENANT_KEY, AWS_ACCESS_KEY_ID: AWS_ID, AWS_SECRET_ACCESS_KEY: AWS_SECRET, CLIENT_ID: { value: CLIENT_ID, sensitivity: 'plain' }, CLIENT_SECRET,
      TWILIO_SID: { value: TWILIO_SID, sensitivity: 'plain' }, TWILIO_TOKEN, TWILIO_EDGE, REPLICA_KEY: REPLICA, TICKET,
    });
  }
  await root.access.set(`user:${DEV}`, { market: 'developer' });
});

/** A handle for DEV on `path`, as `coffre run` makes one, and the plan it gets. */
async function run(path = 'market/dev'): Promise<{ handle: string; plan: { env: Record<string, string>; credentials: Record<string, string> } }> {
  const session = await sessionFor(DEV);
  const api = createClient({ url: ORIGIN, headers: () => ({ authorization: `Bearer ${session}` }), transport: (request) => coffreRoute(request, runtime, '203.0.113.7').then((response) => response!) });
  const { token: handle } = await api.handles.create({ label: `coffre run ${path}`, paths: [path] });
  const answer = await route(`/use/${path}`, { headers: { authorization: `Bearer ${handle}` } });
  assert.equal(answer.status, 200, await answer.clone().text());
  return { handle, plan: (await answer.json()) as { env: Record<string, string>; credentials: Record<string, string> } };
}

/** Whether a string holds the handle, as it is or URL-encoded. */
const holds = (text: string, handle: string) => text.includes(handle) || decodeURIComponent(text).includes(handle);

test('a header and a query parameter: each rule fills its own slot with its key, and the handle goes nowhere', async () => {
  const { handle, plan } = await run();
  assert.equal(plan.env.MAPS_KEY, handle);
  assert.equal(plan.env.MAPS_SIGNING, handle);
  const answer = await route(`/use/maps/geocode/json?address=Paris&signature=${plan.env.MAPS_SIGNING}`, { headers: { 'x-api-key': plan.env.MAPS_KEY! } });
  assert.equal(answer.status, 200, await answer.clone().text());
  const [sent] = reached;
  assert.equal(sent!.headers['x-api-key'], MAPS_KEY);
  const url = new URL(sent!.url, upstreamUrl);
  assert.equal(url.pathname, '/maps/geocode/json');
  assert.equal(url.searchParams.get('signature'), MAPS_SIGNING);
  assert.equal(url.searchParams.get('address'), 'Paris');
  assert.ok(!holds(sent!.url, handle) && !JSON.stringify(sent!.headers).includes(handle));
  // With x-coffre-handle alone, each rule sets its slot all the same.
  assert.equal((await route('/use/market/dev/maps/geocode', { headers: { 'x-coffre-handle': handle } })).status, 200);
  assert.equal(reached[1]!.headers['x-api-key'], MAPS_KEY);
  assert.equal(new URL(reached[1]!.url, upstreamUrl).searchParams.get('signature'), MAPS_SIGNING);
  // The allow list holds for every rule's request alike.
  assert.equal((await route('/use/maps/geocode', { method: 'POST', headers: { 'x-coffre-handle': handle } })).status, 405);
  assert.equal((await route('/use/maps/directions', { headers: { 'x-coffre-handle': handle } })).status, 403);
  assert.equal(reached.length, 2);
});

test('two different handles in one request are refused, wherever and however often each is sent, and nothing is sent', async () => {
  const { handle } = await run();
  const { handle: other } = await run();
  const answer = await route(`/use/maps/geocode?signature=${other}`, { headers: { 'x-api-key': handle } });
  assert.deepEqual([answer.status, ((await answer.json()) as { message: string }).message], [400, 'the request carries two different handles: maps takes one']);
  assert.equal((await route(`/use/maps/geocode?signature=${other}`, { headers: { 'x-coffre-handle': handle } })).status, 400);
  // Every occurrence counts: a parameter given twice, the second another handle, which the first alone would hide; a
  // header given twice, which Headers joins; two handles in x-coffre-handle.
  assert.equal((await route(`/use/maps/geocode?signature=${handle}&signature=${other}`, { headers: { 'x-api-key': handle } })).status, 400);
  const twice = new Headers([['x-api-key', handle], ['x-api-key', other]]);
  assert.equal((await route('/use/maps/geocode', { headers: twice })).status, 400);
  assert.equal((await route('/use/maps/geocode', { headers: { 'x-coffre-handle': `${handle}, ${other}` } })).status, 400);
  // Out of a placeholder's shape too: the second parameter, the second header, the bare handle beside the shaped one.
  assert.equal((await route(`/use/tickets/list?token=p_${handle}&token=${other}`)).status, 400);
  assert.equal((await route(`/use/tickets/list?token=p_${handle}&token=${handle}`)).status, 200);
  const shaped = new Headers([['authorization', `Bearer sk_test_${handle}`], ['authorization', `Bearer ${other}`], ['x-coffre-handle', handle]]);
  assert.equal((await route('/use/stripe/charges', { headers: shaped })).status, 400);
  // Basic's pair given twice, which Headers joins, and a handle in Authorization beside Basic's rule.
  const pair = (of: string) => `Basic ${btoa(`${TWILIO_SID}:${of}`)}`;
  assert.equal((await route('/use/twilio/messages', { headers: new Headers([['authorization', pair(handle)], ['authorization', pair(other)], ['x-coffre-handle', handle]]) })).status, 400);
  assert.equal((await route('/use/twilio/messages', { headers: { authorization: `Bearer ${other}`, 'x-coffre-handle': handle } })).status, 400);
  assert.equal(reached.length, 1);
  // The one that went: the shaped parameter and the bare one, the same handle, the ticket once in their place.
  assert.deepEqual(new URL(reached[0]!.url, upstreamUrl).searchParams.getAll('token'), [TICKET]);
});

test("a header and SigV4: the signature covers the header the rule before it set, and verifies with the real key", async () => {
  const { handle, plan } = await run();
  assert.equal(plan.env.AWS_ACCESS_KEY_ID, handle);
  // As the SDK signs it: the handle its access key, with any secret, which the proxy discards.
  const signer = new SignatureV4({ credentials: { accessKeyId: handle, secretAccessKey: 'placeholder' }, region: 'eu-west-3', service: 's3', sha256: Sha256, uriEscapePath: false, applyChecksum: false });
  const target = new URL(`${ORIGIN}/use/s3/bucket/report.csv`);
  const signed = await signer.sign({ method: 'GET', protocol: 'https:', hostname: target.hostname, path: target.pathname, headers: { host: target.host, 'x-amz-content-sha256': 'UNSIGNED-PAYLOAD', 'x-tenant-key': plan.env.TENANT_KEY! } });
  const answer = await route('/use/s3/bucket/report.csv', { headers: signed.headers });
  assert.equal(answer.status, 200, await answer.clone().text());
  const [sent] = reached;
  assert.equal(sent!.headers['x-tenant-key'], TENANT_KEY);
  assert.ok(sent!.verified, `S3 refuses ${sent!.headers.authorization}`);
  assert.match(String(sent!.headers.authorization), /SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-tenant-key,/);
  assert.ok(!JSON.stringify(sent!.headers).includes(handle));
});

test('two fields of a form: the plain one as the app sent it, the secret one in place of the handle; a field the handle rides in without it is refused', async () => {
  const { handle, plan } = await run();
  assert.equal(plan.env.CLIENT_ID, CLIENT_ID, 'a plain key the app holds as it is: the handle rides in client_secret');
  const body = `grant_type=client_credentials&client_id=${plan.env.CLIENT_ID}&client_secret=${plan.env.CLIENT_SECRET}`;
  const answer = await route('/use/oauth/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body });
  assert.equal(answer.status, 200, await answer.clone().text());
  const sent = new URLSearchParams(reached[0]!.body.toString());
  assert.deepEqual([sent.get('grant_type'), sent.get('client_id'), sent.get('client_secret')], ['client_credentials', CLIENT_ID, CLIENT_SECRET]);
  assert.equal(reached[0]!.body.toString(), `grant_type=client_credentials&client_id=${CLIENT_ID}&client_secret=${new URLSearchParams({ v: CLIENT_SECRET }).toString().slice(2)}`);
  // The handle in x-coffre-handle, and something else in client_secret: no value goes where the app did not put the handle.
  const refused = await route('/use/oauth/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', 'x-coffre-handle': handle }, body: 'client_id=x&client_secret=mine' });
  assert.deepEqual([refused.status, ((await refused.json()) as { message: string }).message], [400, 'the handle is not in the field where oauth takes its key']);
  // A field missing is refused before anything is opened.
  assert.equal((await route('/use/oauth/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: `client_secret=${handle}` })).status, 400);
  assert.equal(reached.length, 1);
});

test("Basic's pair and a header: Basic's user plain, its password and the header each the real value", async () => {
  const { handle, plan } = await run();
  assert.equal(plan.env.TWILIO_SID, TWILIO_SID);
  const answer = await route('/use/twilio/Accounts', { headers: { authorization: `Basic ${btoa(`${TWILIO_SID}:${handle}`)}`, 'x-edge-key': handle } });
  assert.equal(answer.status, 200, await answer.clone().text());
  assert.equal(reached[0]!.headers.authorization, `Basic ${btoa(`${TWILIO_SID}:${TWILIO_TOKEN}`)}`);
  assert.equal(reached[0]!.headers['x-edge-key'], TWILIO_EDGE);
});

/** The forms an honest upstream may quote a string in: as it is, URL-encoded both ways, as HTML's entities, as a JSON string, its slashes escaped or not. */
function forms(value: string): string[] {
  const entities = value.replace(/[&<>"']/g, (char) => `&${{ '&': 'amp', '<': 'lt', '>': 'gt', '"': 'quot', "'": '#39' }[char]};`);
  const js = JSON.stringify(value).slice(1, -1);
  return [value, encodeURIComponent(value), new URLSearchParams({ v: value }).toString().slice(2), entities, js, js.replaceAll('/', '\\/')];
}

test('redaction: every secret key of every rule, in every form, and what each rule made of them; a plain value stays', async () => {
  const { handle } = await run();
  const check = async (path: string, init: RequestInit, secrets: string[], plain: string[]) => {
    echo = [...secrets.flatMap(forms), ...plain].join('\n');
    const answer = await route(path, init);
    assert.equal(answer.status, 200, await answer.clone().text());
    const text = await answer.text();
    for (const secret of secrets) for (const form of forms(secret)) assert.ok(!text.includes(form), `${form} came back in ${text}`);
    for (const value of plain) assert.ok(text.includes(value), `${value}, plain, was redacted`);
    assert.ok(!(answer.headers.get('x-echo') ?? '').includes(secrets[0]!), 'a header is redacted too');
  };
  await check('/use/stripe/echo', { headers: { authorization: `Bearer sk_test_${handle}`, 'stripe-account': STRIPE_ACCOUNT } }, [STRIPE_KEY, `Bearer ${STRIPE_KEY}`], [STRIPE_ACCOUNT]);
  await check('/use/maps/echo', { headers: { 'x-coffre-handle': handle } }, [MAPS_KEY, MAPS_SIGNING], []);
  await check('/use/twilio/echo', { headers: { 'x-coffre-handle': handle } }, [TWILIO_TOKEN, TWILIO_EDGE, btoa(`${TWILIO_SID}:${TWILIO_TOKEN}`)], []);
  await check('/use/oauth/echo', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: `client_id=${CLIENT_ID}&client_secret=${handle}` }, [CLIENT_SECRET], [CLIENT_ID]);
});

test("a placeholder shapes the one rule the handle rides in: Stripe's key prefixed, its plain account as it is; the account a secret, the plan refuses", async () => {
  const { handle, plan } = await run();
  assert.equal(plan.env.STRIPE_KEY, `sk_test_${handle}`);
  assert.equal(plan.env.STRIPE_ACCOUNT, STRIPE_ACCOUNT);
  assert.equal((await route('/use/stripe/v1/charges', { headers: { authorization: `Bearer ${plan.env.STRIPE_KEY}`, 'stripe-account': plan.env.STRIPE_ACCOUNT! } })).status, 200);
  assert.deepEqual([reached[0]!.headers.authorization, reached[0]!.headers['stripe-account']], [`Bearer ${STRIPE_KEY}`, STRIPE_ACCOUNT]);
  // Both secret: the handle would ride in two slots, and a placeholder shapes one.
  await clientFor(deps, ROOT).secrets.set('market/dev', { STRIPE_ACCOUNT: { value: STRIPE_ACCOUNT, sensitivity: 'secret' } });
  const refused = await route('/use/market/dev', { headers: { authorization: `Bearer ${handle}` } });
  assert.equal(refused.status, 409);
  assert.match(((await refused.json()) as { message: string }).message, /stripe's placeholder shapes the one key a header, query, form, JSON or path rule carries, and market\/dev's keys that are no plain ones sit in 2 of its rules/);
});

test('a code item scoped to market/prod: absent from market/dev\'s plan and refused there by name, served in market/prod', async () => {
  const dev = await run();
  assert.equal(dev.plan.credentials.replica, undefined);
  assert.equal(dev.plan.env.REPLICA_KEY, REPLICA, 'no credential of market/dev uses it: a secret its person reads');
  const refused = await route('/use/market/dev/replica/x', { headers: { 'x-replica-key': dev.handle } });
  assert.deepEqual([refused.status, ((await refused.json()) as { message: string }).message], [404, "replica does not serve market/dev: its deployment's credentialProxy names the environments it serves"]);
  // The stable URL, for the environment the handle was made for.
  assert.equal((await route('/use/replica/x', { headers: { 'x-replica-key': dev.handle } })).status, 404);
  const prod = await run('market/prod');
  assert.equal(prod.plan.credentials.replica, `${ORIGIN}/use/market/prod/replica`);
  assert.equal((await route('/use/replica/x', { headers: { 'x-replica-key': prod.plan.env.REPLICA_KEY! } })).status, 200);
  assert.equal(reached.length, 1);
  assert.equal(reached[0]!.headers['x-replica-key'], REPLICA);
});

test('the configuration: one rule per slot, Basic and SigV4 own authorization, SigV4 last and with no field, one body type, scopes by full path', () => {
  const make = (inject: Credential['inject'], more: Partial<Credential> = {}) => () => credentialProxy({ credentials: { a: { upstream: 'https://api.example', inject, ...more } } });
  const key = (name: string) => `{${name}}`;
  const aws = sigv4({ accessKeyId: key('ID'), secretAccessKey: key('SECRET'), region: 'eu-west-3', service: 's3' });
  assert.throws(make([]), /a's inject is a rule or a list of them/);
  assert.throws(make([header('x-a', key('A')), header('X-A', key('B'))]), /a sets the header x-a twice: one rule each/);
  assert.throws(make([query('k', key('A')), query('k', key('B'))]), /a sets the parameter k twice/);
  // As some upstreams read a parameter: ASP.NET's collections fold case, so `Token` and `token` are one.
  assert.throws(make([query('Token', key('A')), query('token', key('B'))]), /a sets the parameter token twice/);
  assert.throws(make([query('api_key', key('A')), query('apiKey', key('B'))]), /a sets the parameter apiKey twice/);
  assert.throws(make([form('secret', key('A')), form('SECRET', key('B'))]), /a sets the field SECRET twice/);
  assert.throws(make([basic(key('A'), key('B')), basic(key('C'), key('D'))]), /a sets basic\(\) twice/);
  assert.throws(make([basic(key('A'), key('B')), header('authorization', key('C'))]), /a's basic\(\) sets the authorization header, which another of its rules sets too/);
  assert.throws(make([aws, header('x-a', key('A'))]), /a's sigv4\(\) comes last/);
  assert.throws(make([aws, aws]), /a sets sigv4\(\) twice/);
  assert.throws(make([header('authorization', key('A')), aws]), /a's sigv4\(\) owns the authorization header and the x-amz- headers and parameters, which its header rule authorization sets/);
  assert.throws(make([header('x-amz-meta-key', key('A')), aws]), /which its header rule x-amz-meta-key sets/);
  assert.throws(make([query('X-Amz-Credential', key('A')), aws]), /which its query rule X-Amz-Credential sets/);
  assert.throws(make([form('secret', key('A')), aws]), /a's sigv4\(\) signs the body's hash, which a form or JSON rule would change after/);
  assert.throws(make([form('a', key('A')), json('b', key('B'))]), /a fills fields of a form and of a JSON body/);
  assert.throws(make([header('x-a', key('A')), header('x-b', 'no key')]), /a's rule names no key/);
  assert.throws(make([basic(key('A'), key('B')), header('x-b', '{C}-{D}')], { placeholder: prefix('p_') }), /a's placeholder shapes the one key .*, not a basic\(\) rule or a template with several keys, or one twice/);
  assert.throws(make(header('x-a', key('A')), { environments: ['prod'] }), /credential a's environments are the paths it serves, \['market\/prod'\]/);
  assert.throws(make(header('x-a', key('A')), { environments: [] }), /environments are the paths it serves/);
  // Each of these goes: SigV4 last over a header and a query parameter, Basic beside a header, a form's two fields.
  make([header('x-a', key('A')), query('k', key('B')), aws])();
  make([basic(key('A'), key('B')), header('x-a', key('C'))])();
  make([form('a', key('A')), form('b', key('B'))], { environments: ['market/prod', 'market/dev'] })();
});
