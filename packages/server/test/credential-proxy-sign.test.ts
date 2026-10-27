// Signing through the handle (docs/design/credential-proxy.md, section 5):
// a private key the app signs with stays in coffre, and the app asks coffre
// for each signature, `credential(name).sign(message)`, one use in the log
// each. Here DFNS's own SDK signs a user action's challenge with a signer
// that calls coffre, in place of `AsymmetricKeySigner`, against a fake DFNS
// that checks the signature with `node:crypto.verify`, as DFNS does; and a
// signature from each kind of key verifies as Node's own `crypto.sign` would.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomBytes, verify, type KeyObject } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

import { DfnsApiClient, type CredentialSigner, type KeyAssertion, type UserActionChallenge } from '@dfns/sdk';
import { credential, type ProxiedCredential } from '@coffre/client/credential';

import { clientFor, keyIds, LOG, watchUses } from './api-fixture.ts';
import { db, deps, DEV, entries, ORIGIN, ROOT, route, runtime, sessionFor, useMcp } from './mcp-fixture.ts';
import { coffreRoute } from '../src/app.ts';
import { checkPlugins } from '../src/plugins.ts';
import { credentialProxy, header, jwt, privateKey } from '../src/plugins/credential-proxy.ts';
import { signWith, SigningKeyError } from '../src/plugins/sign.ts';

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

let dfns: Server;
let dfnsUrl: string;
let coffre: Server;
let coffreUrl: string;
const challenges = new Map<string, string>();
const created: string[] = [];

before(async () => {
  // The fake DFNS's user action flow: a challenge, its signature checked as DFNS checks a Key credential's, then the action.
  dfns = createServer(async (request, response) => {
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
  dfnsUrl = `http://127.0.0.1:${(dfns.address() as AddressInfo).port}`;
  coffre = createServer(async (request, response) => {
    const chunks: Buffer[] = [];
    for await (const chunk of request) chunks.push(chunk as Buffer);
    const headers = new Headers();
    for (const [name, value] of Object.entries(request.headers)) if (typeof value === 'string') headers.set(name, value);
    const body = chunks.length === 0 ? undefined : Buffer.concat(chunks);
    const answer = (await coffreRoute(new Request(`${ORIGIN}${request.url}`, { method: request.method, headers, body }), runtime, '127.0.0.1'))!;
    response.writeHead(answer.status, Object.fromEntries(answer.headers));
    response.end(Buffer.from(await answer.arrayBuffer()));
  });
  await new Promise<void>((resolve) => coffre.listen(0, '127.0.0.1', resolve));
  coffreUrl = `http://127.0.0.1:${(coffre.address() as AddressInfo).port}`;
});

after(async () => {
  await new Promise<void>((resolve) => dfns.close(() => resolve()));
  await new Promise<void>((resolve) => coffre.close(() => resolve()));
});

useMcp(
  async () => {
    runtime.plugins = checkPlugins([
      credentialProxy({
        credentials: { dfns: { upstream: dfnsUrl, inject: header('authorization', 'Bearer {DFNS_AUTH_TOKEN}'), placeholder: jwt({ claims: ['https://custom/app_metadata'] }) } },
        signers: { 'dfns-key': privateKey('DFNS_PRIVATE_KEY'), 'ed-key': privateKey('ED_KEY'), 'rsa-key': privateKey('RSA_KEY'), absent: privateKey('NOT_HELD') },
        insecureUpstreams: true,
      }),
    ]);
    challenges.clear();
    created.length = 0;
    const root = clientFor(deps, ROOT);
    await root.members.add(`user:${DEV}`);
    await root.projects.create('market');
    await root.environments.create('market/dev');
    await root.secrets.set('market/dev', { DFNS_AUTH_TOKEN: TOKEN, DFNS_CRED_ID: CRED_ID, DFNS_PRIVATE_KEY: keys.p256.pem.trim().replace(/\n/g, '\\n'), ED_KEY: { value: keys.ed25519.pem, sensitivity: 'sensitive' }, RSA_KEY: { value: keys.rsa.pem, sensitivity: 'sensitive' } });
    await root.access.set(`user:${DEV}`, { market: 'developer' });
  },
);

/** What `coffre run market/dev` gives the app: its environment, and what `credential(name)` reads, with coffre on loopback. */
async function run(): Promise<{ env: Record<string, string>; handle: string }> {
  const made = await route('/api/handles', { method: 'POST', headers: { authorization: `Bearer ${await sessionFor(DEV)}`, 'content-type': 'application/json' }, body: JSON.stringify({ label: 'run', paths: ['market/dev'] }) });
  const handle = ((await made.json()) as { token: string }).token;
  const plan = (await (await route('/use/market/dev', { headers: { authorization: `Bearer ${handle}` } })).json()) as { env: Record<string, string>; credentials: Record<string, string> };
  const loopback = (url: string) => url.replace(ORIGIN, coffreUrl);
  const credentials = Object.fromEntries(Object.entries(plan.credentials).map(([name, url]) => [name, loopback(url)]));
  // The app's own config names DFNS's stable URL on the proxy.
  return { env: { ...plan.env, DFNS_API_URL: `${coffreUrl}/use/dfns`, COFFRE_CREDENTIALS: JSON.stringify(credentials), COFFRE_HANDLE: handle }, handle };
}

/** The signer the design doc gives Equisafe in place of `AsymmetricKeySigner`, line for line: the same assertion, its signature made by coffre. */
class CoffreKeySigner implements CredentialSigner<KeyAssertion> {
  readonly credId: string;
  readonly key: ProxiedCredential;

  constructor(credId: string, key: ProxiedCredential = credential('dfns-key')) {
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

test("DFNS's SDK signs a user action through coffre: the key stays there, the signature verifies as DFNS checks it, and each is one use in the log", async () => {
  const watched = LOG === '0.15' ? watchUses(deps.vault) : null;
  const { env, handle } = await run();
  assert.equal(env.DFNS_PRIVATE_KEY, handle, 'the handle where the key was: a signer covers it, though its person reads it');
  assert.equal(env.DFNS_CRED_ID, CRED_ID);
  const signer = new CoffreKeySigner(env.DFNS_CRED_ID!, credential('dfns-key', env));
  const sdk = new DfnsApiClient({ baseUrl: env.DFNS_API_URL!, authToken: env.DFNS_AUTH_TOKEN!, signer });
  const wallet = await sdk.wallets.createWallet({ body: { network: 'EthereumSepolia' } });
  assert.equal(wallet.id, 'wa-new');
  assert.deepEqual(created, [JSON.stringify({ network: 'EthereumSepolia' })]);

  // Each signature one use, never from the cache, naming the message by its hash.
  await signer.sign({ challenge: 'second', challengeIdentifier: 'x' } as UserActionChallenge);
  if (watched !== null) {
    watched.stop();
    // 0.15: each signature one use of the key, never from the proxy's cache. Its row is slim (R53), naming no message,
    // and a repeat its isolate's cover rides writes none: the vault's uses are counted, not the rows.
    const key = await keyIds(db.owner, 'DFNS_PRIVATE_KEY');
    assert.equal(watched.asked.filter((use) => key.includes(use.secretId) && use.purpose === 'use').length, 2);
    return;
  }
  const signed = (await entries('credential.use')).filter((entry) => entry.metadata.credential === 'dfns-key');
  assert.equal(signed.length, 2);
  const clientData = JSON.stringify({ type: 'key.get', challenge: 'second' });
  assert.deepEqual(signed[1]!.metadata.sign, { sha256: createHash('sha256').update(clientData).digest('hex') });
  assert.deepEqual(signed[1]!.metadata.keys, ['DFNS_PRIVATE_KEY']);
});

test('each kind of key signs as Node does: ECDSA P-256 in DER, Ed25519, RSA PKCS#1 v1.5, each verified by node:crypto.verify', async () => {
  const { env } = await run();
  for (const [name, kind] of [['dfns-key', 'p256'], ['ed-key', 'ed25519'], ['rsa-key', 'rsa']] as const) {
    for (const message of [new Uint8Array(randomBytes(37)), 'é ✓ text, as UTF-8', new Uint8Array(0)]) {
      const signature = Buffer.from(await credential(name, env).sign(message), 'base64url');
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
  runtime.plugins = checkPlugins([credentialProxy({ credentials: {}, signers: { 'ed-key': privateKey('ED_KEY') }, generate: { 'market/dev': 'all' } })]);
  const signed = async () => {
    const { env } = await run();
    return Buffer.from(await credential('ed-key', env).sign('challenge'), 'base64url');
  };
  assert.ok(verify(undefined, Buffer.from('challenge'), keys.ed25519.publicKey, await signed()), "the environment's, while they have none");
  const own = generateKeyPairSync('ed25519');
  await clientFor(deps, DEV).secrets.set('market/dev@me', { ED_KEY: own.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString() });
  assert.ok(verify(undefined, Buffer.from('challenge'), own.publicKey, await signed()), 'then their own');
});

test('refused: no handle, an unknown signer, a key the environment lacks, a message that is no base64url, a key coffre does not sign with', async () => {
  const { env, handle } = await run();
  const post = (body: unknown, authorization = `Bearer ${handle}`) => route('/use/market/dev', { method: 'POST', headers: { authorization, 'content-type': 'application/json' }, body: JSON.stringify(body) });
  assert.equal((await post({ sign: { credential: 'dfns-key', message: 'aGk' } }, 'Bearer nope')).status, 401);
  assert.equal((await post({ sign: { credential: 'nope', message: 'aGk' } })).status, 404);
  assert.equal((await post({ sign: { credential: 'dfns', message: 'aGk' } })).status, 404, 'a credential with an upstream signs nothing');
  assert.equal((await post({ sign: { credential: 'absent', message: 'aGk' } })).status, 409);
  assert.equal((await post({ sign: { credential: 'dfns-key', message: 'a+b/' } })).status, 400);
  assert.equal((await post({ sign: { credential: 'dfns-key' } })).status, 400);
  assert.equal((await post({ nothing: true })).status, 400);
  // The signer's URL proxies nothing: it says how to use it.
  const proxied = await route('/use/market/dev/dfns-key/x', { headers: { 'x-coffre-handle': handle } });
  assert.equal(proxied.status, 404);
  assert.match(await proxied.text(), /sign\(message\)/);
  assert.throws(() => credential('absent', env), /no credential absent/, 'a signer whose key the environment lacks is not in the plan');

  // A key of another kind is refused, saying what it is and quoting nothing of it.
  const p384 = generateKeyPairSync('ec', { namedCurve: 'P-384' }).privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  await clientFor(deps, ROOT).secrets.set('market/dev', { ED_KEY: p384 });
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
