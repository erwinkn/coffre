// Signing through the handle (docs/design/credential-proxy.md, section 5):
// a private key the app signs with stays in coffre, and the app asks coffre
// for each signature, `credential(name).sign(message)`, one use of the vault
// each. Here DFNS's own SDK signs a user action's challenge with a signer
// that calls coffre, in place of `AsymmetricKeySigner`, against a fake DFNS
// that checks the signature with `node:crypto.verify`, as DFNS does; and a
// signature from each kind of key verifies as Node's own `crypto.sign` would.
//
// 0.14.7's assertions, on 0.16 (docs/design/0.16.md, "The proxy"): each
// signature is one `use`, naming the signer as its upstream, and the vault
// logs a credential's use of a key once a minute, never the message's hash.
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes, verify, type KeyObject } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { after, before, beforeEach, test } from 'node:test';

import { DfnsApiClient, type CredentialSigner, type KeyAssertion, type UserActionChallenge } from '@dfns/sdk';
import { credential as proxied, type ProxiedCredential } from '@coffre/client/credential';
import { generateToken } from '@coffre/core/identity';
import { rowsOf } from '@coffre/db/dialect';
import { credential, emptyDatabase, environment, grant, instance, principal, project, rewrite, role, rows, secret, value, write } from '@coffre/vault/testing';
import { sql } from 'drizzle-orm';

import { credentialProxy, header, jwt, privateKey } from '../src/plugins/credential-proxy.ts';
import { signWith, SigningKeyError } from '../src/plugins/sign.ts';
import { openApp, PUBLIC_URL } from './app-fixture.ts';

const DEV = 'user:dev@acme.example';
const base64url = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
const TOKEN = `${base64url({ alg: 'EdDSA', typ: 'JWT' })}.${base64url({ 'https://custom/app_metadata': { orgId: 'or-sandbox' } })}.c2lnbmF0dXJl`;
const CRED_ID = 'Y2ktZGZucy1jcmVk';
/** One key of each kind coffre signs with, as PKCS#8 PEMs: DFNS's service account's is P-256, as Equisafe's fixtures make it. */
const keys = Object.fromEntries(
  ([['p256', 'ec', { namedCurve: 'P-256' }], ['ed25519', 'ed25519', {}], ['rsa', 'rsa', { modulusLength: 2048 }]] as const).map(([name, type, options]) => {
    const pair = generateKeyPairSync(type as 'ec', options as { namedCurve: string });
    return [name, { pem: pair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(), publicKey: pair.publicKey }];
  }),
) as Record<'p256' | 'ed25519' | 'rsa', { pem: string; publicKey: KeyObject }>;

let coffre: Server;
let coffreUrl: string;
const challenges = new Map<string, string>();
const created: string[] = [];

// The fake DFNS's user action flow: a challenge, its signature checked as DFNS checks a Key credential's, then the action.
const dfns = createServer(async (request, response) => {
  let body = '';
  for await (const chunk of request) body += String(chunk);
  const send = (status: number, value: unknown) => response.writeHead(status, { 'content-type': 'application/json' }).end(JSON.stringify(value));
  if (request.headers.authorization !== `Bearer ${TOKEN}`) return send(401, { error: { message: 'Unauthorized' } });
  if (request.url === '/auth/action/init') {
    const challenge = randomBytes(24).toString('base64url');
    challenges.set(`ch-${challenges.size}`, challenge);
    return send(200, { challenge, challengeIdentifier: `ch-${challenges.size - 1}`, allowCredentials: { key: [{ type: 'public-key', id: CRED_ID }], webauthn: [] }, supportedCredentialKinds: [{ kind: 'Key', factor: 'first', requiresSecondFactor: false }], userVerification: 'required', externalAuthenticationUrl: '' });
  }
  if (request.url === '/auth/action') {
    const { challengeIdentifier, firstFactor } = JSON.parse(body) as { challengeIdentifier: string; firstFactor: KeyAssertion };
    const clientData = Buffer.from(firstFactor.credentialAssertion.clientData, 'base64url');
    const parsed = JSON.parse(clientData.toString()) as { type: string; challenge: string };
    const valid = firstFactor.kind === 'Key' && firstFactor.credentialAssertion.credId === CRED_ID && parsed.type === 'key.get' && parsed.challenge === challenges.get(challengeIdentifier)
      && verify(undefined, clientData, keys.p256.publicKey, Buffer.from(firstFactor.credentialAssertion.signature, 'base64url'));
    return valid ? send(200, { userAction: `ua-${challengeIdentifier}` }) : send(401, { error: { message: 'User action signature is invalid' } });
  }
  if (request.method === 'POST' && request.url === '/wallets') {
    if (!String(request.headers['x-dfns-useraction'] ?? '').startsWith('ua-')) return send(401, { error: { message: 'User action signature is invalid' } });
    created.push(body);
    return send(200, { id: 'wa-new', network: 'EthereumSepolia' });
  }
  send(404, { error: { message: 'no such route' } });
});
await new Promise<void>((resolve) => dfns.listen(0, '127.0.0.1', resolve));
const dfnsUrl = `http://127.0.0.1:${(dfns.address() as AddressInfo).port}`;

const app = await openApp({
  plugins: [credentialProxy({
    credentials: { dfns: { upstream: dfnsUrl, inject: header('authorization', 'Bearer {DFNS_AUTH_TOKEN}'), placeholder: jwt({ claims: ['https://custom/app_metadata'] }) } },
    signers: { 'dfns-key': privateKey('DFNS_PRIVATE_KEY'), 'ed-key': privateKey('ED_KEY'), 'rsa-key': privateKey('RSA_KEY'), absent: privateKey('NOT_HELD') },
    // An environment the deployment generates for: a person's use of it reads their personal config.
    generate: { 'market/local': 'all' },
    insecureUpstreams: true,
  })],
});
const { world } = app;

before(async () => {
  // coffre on loopback, for DFNS's SDK, which fetches its base URL.
  coffre = createServer(async (request, response) => {
    const chunks: Buffer[] = [];
    for await (const chunk of request) chunks.push(chunk as Buffer);
    const headers = new Headers();
    for (const [name, value] of Object.entries(request.headers)) if (typeof value === 'string') headers.set(name, value);
    const answer = await app.request(request.url!, { method: request.method!, headers, ...(chunks.length === 0 ? {} : { body: Buffer.concat(chunks) }) });
    response.writeHead(answer.status, Object.fromEntries(answer.headers));
    response.end(Buffer.from(await answer.arrayBuffer()));
  });
  await new Promise<void>((resolve) => coffre.listen(0, '127.0.0.1', resolve));
  coffreUrl = `http://127.0.0.1:${(coffre.address() as AddressInfo).port}`;
});

after(async () => {
  await new Promise<void>((resolve) => dfns.close(() => resolve()));
  await new Promise<void>((resolve) => coffre.close(() => resolve()));
  await app.close();
});

const market = project('market');
const dev = environment(market, 'dev');
const local = environment(market, 'local');
/** The person's token, as `coffre login <url> --token` leaves it. */
const token = generateToken('personal');
let edKey: string;

beforeEach(async () => {
  await emptyDatabase(world.owner);
  for (const kept of [world.memory.reads, world.memory.callers, world.memory.logged, world.memory.touched, world.refused]) kept.clear();
  challenges.clear();
  created.length = 0;
  const ed = value(world, secret(dev, 'ED_KEY'), keys.ed25519.pem, { sensitive: true });
  edKey = ed.id;
  await write(
    world,
    ...rows('policy', instance()),
    ...rows('roles', role(true, 'owner', ['secret.read']), role(true, 'member', []), role(false, 'developer', ['secret.read', 'secret.use', 'secret.write'])),
    ...rows('projects', market),
    ...rows('environments', dev, local),
    ...rows('principals', principal(DEV)),
    ...rows('grants', grant(DEV, 'developer', { project: market })),
    ...rows(
      'secrets',
      value(world, secret(dev, 'DFNS_AUTH_TOKEN'), TOKEN),
      value(world, secret(dev, 'DFNS_CRED_ID'), CRED_ID),
      // Written on one line, its newlines escaped, as a dotenv file holds it.
      value(world, secret(dev, 'DFNS_PRIVATE_KEY'), keys.p256.pem.trim().replace(/\n/g, '\\n')),
      ed,
      value(world, secret(dev, 'RSA_KEY'), keys.rsa.pem, { sensitive: true }),
      value(world, secret(local, 'ED_KEY'), keys.ed25519.pem, { sensitive: true }),
    ),
    ...rows('credentials', credential(token, DEV, { kind: 'personal', scope: JSON.stringify([{ projectId: market.id, environmentId: null, role: 'developer' }]) })),
  );
  await world.owner.execute(sql`DELETE FROM log_pending`);
  app.calls.length = 0;
});

/** The person's API, with their token. */
async function api(method: string, path: string, body?: unknown): Promise<[number, Record<string, unknown>]> {
  const response = await app.request(`/api${path}`, { method, headers: { authorization: `Bearer ${token}` }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  return [response.status, (await response.json()) as Record<string, unknown>];
}

/** What reaches coffre in process, as `credential(name)` would over the network. */
const fetcher = (input: string, init?: RequestInit) => app.request(input.slice(PUBLIC_URL.length), init);

/** `credential(name)` as the app calls it, in process. */
const credentialOf = (name: string, env: Record<string, string>) => proxied(name, env, fetcher);

/** What `coffre run <path>` gives the app: its environment, and what `credential(name)` reads. */
async function run(path = 'market/dev'): Promise<{ env: Record<string, string>; handle: string }> {
  const [status, made] = await api('POST', '/handles', { label: `coffre run ${path}`, paths: [path] });
  assert.equal(status, 200, JSON.stringify(made));
  const handle = made.token as string;
  const response = await app.request(`/use/${path}`, { headers: { authorization: `Bearer ${handle}` } });
  assert.equal(response.status, 200, await response.clone().text());
  const plan = (await response.json()) as { env: Record<string, string>; credentials: Record<string, string> };
  // The app's own config names DFNS's stable URL on the proxy, on loopback for its SDK.
  return { env: { ...plan.env, DFNS_API_URL: `${coffreUrl}/use/dfns`, COFFRE_CREDENTIALS: JSON.stringify(plan.credentials), COFFRE_HANDLE: handle }, handle };
}

/** The vault's log entries not yet signed in that name `name` as their credential: each one's action, purpose and keys. */
async function loggedFor(name: string): Promise<{ action: string; purpose?: string; keys: string[] }[]> {
  const bodies = await rowsOf<{ body: string }>(world.owner, sql`SELECT body FROM log_pending ORDER BY id`);
  return bodies
    .map(({ body }) => JSON.parse(body) as { action: string; detail: { purpose?: string; credential?: string; keys?: { key: string }[] } })
    .filter((entry) => entry.detail.credential === name)
    .map((entry) => ({ action: entry.action, purpose: entry.detail.purpose, keys: (entry.detail.keys ?? []).map((key) => key.key) }));
}

/** The vault's calls `run` made. */
async function callsOf(run: () => Promise<unknown>): Promise<string[]> {
  const before = app.calls.length;
  await run();
  return app.calls.slice(before);
}

/** The signer the design doc gives Equisafe in place of `AsymmetricKeySigner`, line for line: the same assertion, its signature made by coffre. */
class CoffreKeySigner implements CredentialSigner<KeyAssertion> {
  readonly credId: string;
  readonly key: ProxiedCredential;

  constructor(credId: string, key: ProxiedCredential = proxied('dfns-key')) {
    this.credId = credId;
    this.key = key;
  }

  async sign(challenge: UserActionChallenge): Promise<KeyAssertion> {
    if (challenge.allowCredentials && !challenge.allowCredentials.key.some((allowed) => allowed.id === this.credId)) {
      throw new Error(`${this.credId} is not among the credentials DFNS allows for this action`);
    }
    const clientData = JSON.stringify({ type: 'key.get', challenge: challenge.challenge });
    const signature = await this.key.sign(clientData);
    return { kind: 'Key', credentialAssertion: { credId: this.credId, clientData: Buffer.from(clientData).toString('base64url'), signature } };
  }
}

test("DFNS's SDK signs a user action through coffre: the key stays there, the signature verifies as DFNS checks it, and each is one use", async () => {
  const { env, handle } = await run();
  assert.equal(env.DFNS_PRIVATE_KEY, handle, 'the handle where the key was: a signer covers it, though its person reads it');
  assert.equal(env.DFNS_CRED_ID, CRED_ID);
  const signer = new CoffreKeySigner(env.DFNS_CRED_ID!, credentialOf('dfns-key', env));
  const sdk = new DfnsApiClient({ baseUrl: env.DFNS_API_URL!, authToken: env.DFNS_AUTH_TOKEN!, signer });
  const wallet = await sdk.wallets.createWallet({ body: { network: 'EthereumSepolia' } });
  assert.equal(wallet.id, 'wa-new');
  assert.deepEqual(created, [JSON.stringify({ network: 'EthereumSepolia' })]);

  // Each signature one use of the vault, naming the signer, and nothing kept.
  assert.deepEqual(await callsOf(() => signer.sign({ challenge: 'second', challengeIdentifier: 'x' } as UserActionChallenge)), ['use']);
  assert.deepEqual(app.inputs.at(-1), { ...(app.inputs.at(-1) as object), keys: ['DFNS_PRIVATE_KEY'], purpose: 'use', upstream: 'dfns-key' });
  // The vault logs a credential's use of a key once a minute: both signatures, one entry, which names no message.
  assert.deepEqual(await loggedFor('dfns-key'), [{ action: 'secret.read', purpose: 'use', keys: ['DFNS_PRIVATE_KEY'] }]);
});

test('each kind of key signs as Node does: ECDSA P-256 in DER, Ed25519, RSA PKCS#1 v1.5, each verified by node:crypto.verify', async () => {
  const { env } = await run();
  for (const [name, kind] of [['dfns-key', 'p256'], ['ed-key', 'ed25519'], ['rsa-key', 'rsa']] as const) {
    for (const message of [new Uint8Array(randomBytes(37)), 'é ✓ text, as UTF-8', new Uint8Array(0)]) {
      const signature = Buffer.from(await credentialOf(name, env).sign(message), 'base64url');
      const bytes = typeof message === 'string' ? Buffer.from(message) : message;
      assert.ok(verify(undefined, bytes, keys[kind].publicKey, signature), `${name}: ${String(message)}`);
    }
  }
  // DER's edge: an r or s whose first bit is set takes a zero before it, one with leading zeros loses them.
  for (let at = 0; at < 200; at += 1) {
    const message = new Uint8Array(randomBytes(16));
    assert.ok(verify(undefined, message, keys.p256.publicKey, await signWith(keys.p256.pem, message)));
  }
});

test("in an environment the deployment generates for, a signature is by the person's own key, once their personal config holds one", async () => {
  const signed = async () => {
    const { env } = await run('market/local');
    return Buffer.from(await credentialOf('ed-key', env).sign('challenge'), 'base64url');
  };
  assert.ok(verify(undefined, Buffer.from('challenge'), keys.ed25519.publicKey, await signed()), "the environment's, while they have none");
  const own = generateKeyPairSync('ed25519');
  const [status, body] = await api('PATCH', '/secrets/market/local@me', { ED_KEY: own.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString() });
  assert.equal(status, 200, JSON.stringify(body));
  // A fresh handle, as each `coffre run` makes: the vault keeps a handle's rows two seconds.
  assert.ok(verify(undefined, Buffer.from('challenge'), own.publicKey, await signed()), 'then their own');
});

test('refused: no handle, an unknown signer, a key the environment lacks, a message that is no base64url, a key coffre does not sign with', async () => {
  const { env, handle } = await run();
  const post = (body: unknown, authorization = `Bearer ${handle}`) => app.request('/use/market/dev', { method: 'POST', headers: { authorization, 'content-type': 'application/json' }, body: JSON.stringify(body) });
  /** The status, and the vault's calls the request made. */
  const refusal = async (body: unknown, authorization?: string) => {
    const before = app.calls.length;
    const response = await post(body, authorization);
    return [response.status, app.calls.slice(before)];
  };
  assert.deepEqual(await refusal({ sign: { credential: 'dfns-key', message: 'aGk' } }, 'Bearer nope'), [401, []]);
  assert.deepEqual(await refusal({ sign: { credential: 'nope', message: 'aGk' } }), [404, []]);
  assert.deepEqual(await refusal({ sign: { credential: 'dfns', message: 'aGk' } }), [404, []], 'a credential with an upstream signs nothing');
  assert.deepEqual(await refusal({ sign: { credential: 'dfns-key', message: 'a+b/' } }), [400, []]);
  assert.deepEqual(await refusal({ sign: { credential: 'dfns-key' } }), [400, []]);
  assert.deepEqual(await refusal({ nothing: true }), [400, []]);
  // The vault is asked for a key the environment lacks, and says so.
  const absent = await post({ sign: { credential: 'absent', message: 'aGk' } });
  assert.equal(absent.status, 409);
  assert.match(((await absent.json()) as { message: string }).message, /market\/dev holds no NOT_HELD, which absent needs/);
  // The signer's URL proxies nothing: it says how to use it.
  const through = await app.request('/use/market/dev/dfns-key/x', { headers: { 'x-coffre-handle': handle } });
  assert.equal(through.status, 404);
  assert.match(await through.text(), /sign\(message\)/);
  assert.throws(() => credentialOf('absent', env), /no credential absent/, 'a signer whose key the environment lacks is not in the plan');

  // A key of another kind is refused, saying what it is and quoting nothing of it.
  const p384 = generateKeyPairSync('ec', { namedCurve: 'P-384' }).privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  await rewrite(world, { id: edKey }, p384);
  const refused = await post({ sign: { credential: 'ed-key', message: 'aGk' } });
  assert.equal(refused.status, 409);
  const text = await refused.text();
  assert.match(text, /market\/dev's ED_KEY is an EC key on a curve other than P-256/);
  assert.equal(text.includes(p384.split('\n')[1]!.slice(0, 16)), false);
  await assert.rejects(signWith('-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----', new Uint8Array(1)), SigningKeyError);
});

test('a signer is configured by the key that holds it, under a name of its own', () => {
  assert.throws(() => credentialProxy({ credentials: {}, signers: { Bad: privateKey('K') } }), /lowercase/);
  assert.throws(() => credentialProxy({ credentials: {}, signers: { a: privateKey('not a key') } }), /names the key that holds its private key/);
  assert.throws(() => credentialProxy({ credentials: { a: { upstream: 'https://api.example.com', inject: header('x', '{K}') } }, signers: { a: privateKey('K2') } }), /names a credential and a signer/);
  assert.throws(() => credentialProxy({ credentials: { a: { upstream: 'https://api.example.com', inject: header('x', '{K}'), placeholder: jwt() } }, signers: { b: privateKey('K') } }), /a and b read K with different placeholders/);
});
