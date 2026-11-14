// AES-256-GCM through the handle (docs/design/credential-proxy.md, section 5): a cipher's key stays in coffre, and the
// app asks it to encrypt or decrypt, `credential(name).encrypt(plaintext, aad)`. Here both directions against Node's
// createCipheriv, Equisafe's three stored formats, each built as its backend builds it, one answer for every failed
// decrypt, the key's length checked after decoding, and no plaintext, AAD or key in the log, an error or the console.
//
// 0.14.7's assertions, on 0.16 (docs/design/0.16.md, "The proxy"): each encrypt or decrypt is one `use` of the vault,
// naming the cipher as its upstream, and the proxy keeps no key; the vault logs a credential's use of a key once a
// minute, `secret.read` with `detail.credential` the cipher's name.
import assert from 'node:assert/strict';
import { createCipheriv, createDecipheriv, createHash, hkdfSync, randomBytes } from 'node:crypto';
import { after, beforeEach, test } from 'node:test';

import { credential as proxied } from '@coffre/client/credential';
import { generateToken } from '@coffre/core/identity';
import { rowsOf } from '@coffre/db/dialect';
import { credential, emptyDatabase, environment, grant, instance, principal, project, rewrite, role, rows, secret, value, write } from '@coffre/vault/testing';
import { sql } from 'drizzle-orm';

import { aesGcm, credentialProxy, hmac, privateKey, type CredentialProxyOptions, type Encoding } from '../src/plugins/credential-proxy.ts';
import { openApp, PUBLIC_URL } from './app-fixture.ts';

const ADA = 'user:ada';

// Equisafe's two root keys, and the AES keys its backend derives from them, each stored in coffre as its 32 bytes in hex.
const ROOT_ENCRYPTION_KEY = 'equisafe-root-encryption-key-7c1f0e9a';
const POLICY_SEAL_KEY = '3f9a0c2e7b14d85a6c0e9f3b2a71d4c8e5f60a1b9c2d3e4f5a6b7c8d9e0f1a2b';
const hkdf = (key: string | Buffer, info: string) => Buffer.from(hkdfSync('sha256', key, Buffer.alloc(0), info, 32));
const KEYS = {
  // payer-session.crypto.ts: HKDF-SHA256 of the root key's UTF-8, an empty salt.
  PAYER_SESSION_KEY: hkdf(ROOT_ENCRYPTION_KEY.trim(), 'equisafe/gas-station/payer-session'),
  // billing-token.crypto.ts: the root key's SHA-256.
  BILLING_TOKEN_KEY: createHash('sha256').update(ROOT_ENCRYPTION_KEY.trim()).digest(),
  // signature-cipher.util.ts: HKDF-SHA256 of the seal key's bytes, read as hex.
  POLICY_SIGNATURE_KEY: hkdf(Buffer.from(POLICY_SEAL_KEY, 'hex'), 'equisafe/policy-engine/approval-decision-signature'),
  SMALL_KEY: Buffer.alloc(32, 0xa5),
  WIDE_KEY: Buffer.alloc(32, 0x3c),
};
const options: CredentialProxyOptions = {
  credentials: {},
  ciphers: {
    'payer-session': aesGcm('PAYER_SESSION_KEY', { keyEncoding: 'hex' }),
    'billing-tokens': aesGcm('BILLING_TOKEN_KEY', { keyEncoding: 'hex' }),
    'policy-signatures': aesGcm('POLICY_SIGNATURE_KEY', { keyEncoding: 'hex' }),
    small: aesGcm('SMALL_KEY', { keyEncoding: 'base64url', maxBytes: 32 }),
    wide: aesGcm('WIDE_KEY', { keyEncoding: 'base64' }),
  },
  signers: { 'iframe-token': hmac('IFRAME_TOKEN_SECRET', { encoding: 'base64url' }) },
  verifiers: { yousign: hmac('YOUSIGN_WEBHOOK_SECRET', { encoding: 'hex' }) },
};

const app = await openApp({ plugins: [credentialProxy(options)] });
const { world } = app;
after(() => app.close());

const market = project('market');
const dev = environment(market, 'dev');
const bad = environment(market, 'bad');

// Keys of 31 and 33 bytes, one outside its alphabet, and one a passphrase: none is AES-256's.
const BAD = {
  PAYER_SESSION_KEY: KEYS.PAYER_SESSION_KEY.subarray(0, 31).toString('hex'),
  BILLING_TOKEN_KEY: Buffer.concat([KEYS.BILLING_TOKEN_KEY, Buffer.from([7])]).toString('hex'),
  POLICY_SIGNATURE_KEY: `${KEYS.POLICY_SIGNATURE_KEY.toString('hex').slice(0, 62)}zz`,
  SMALL_KEY: ROOT_ENCRYPTION_KEY,
};

/** market/bad's SMALL_KEY, which a test writes again. */
let badSmall: { id: string };

/** What the console says while a test runs, every line of it. */
const said: string[] = [];

beforeEach(async () => {
  await emptyDatabase(world.owner);
  for (const kept of [world.memory.reads, world.memory.callers, world.memory.logged, world.memory.touched, world.refused]) kept.clear();
  said.length = 0;
  answered.length = 0;
  const badRows = Object.entries(BAD).map(([key, text]) => value(world, secret(bad, key), text));
  badSmall = badRows.find((row) => row.key === 'SMALL_KEY')!;
  await write(
    world,
    ...rows('policy', instance()),
    ...rows('roles', role(true, 'owner', ['secret.read']), role(true, 'member', []), role(false, 'developer', ['secret.read', 'secret.use', 'secret.write']), role(false, 'viewer', ['secret.read', 'secret.use'])),
    ...rows('projects', market),
    ...rows('environments', dev, bad),
    ...rows('principals', principal(ADA)),
    ...rows('grants', grant(ADA, 'developer', { project: market })),
    ...rows(
      'secrets',
      value(world, secret(dev, 'PAYER_SESSION_KEY'), KEYS.PAYER_SESSION_KEY.toString('hex')),
      value(world, secret(dev, 'BILLING_TOKEN_KEY'), KEYS.BILLING_TOKEN_KEY.toString('hex')),
      value(world, secret(dev, 'POLICY_SIGNATURE_KEY'), KEYS.POLICY_SIGNATURE_KEY.toString('hex'), { sensitive: true }),
      value(world, secret(dev, 'SMALL_KEY'), KEYS.SMALL_KEY.toString('base64url')),
      value(world, secret(dev, 'WIDE_KEY'), KEYS.WIDE_KEY.toString('base64')),
      value(world, secret(dev, 'IFRAME_TOKEN_SECRET'), 'iframe_secret_0123456789'),
      value(world, secret(dev, 'YOUSIGN_WEBHOOK_SECRET'), 'ys_whsec_0123456789'),
      ...badRows,
    ),
  );
  await world.owner.execute(sql`DELETE FROM log_pending`);
  await app.request('/livez');
  await app.request('/api/me', { headers: { authorization: 'Bearer nobody' } });
  app.calls.length = 0;
  app.inputs.length = 0;
});

/** What `coffre run` gives the app for `path`: a handle of Ada's made for it, and its plan's environment, with the handle. */
async function run(place = dev): Promise<Record<string, string>> {
  const handle = generateToken('handle');
  await write(world, ...rows('credentials', credential(handle, ADA, {
    kind: 'handle',
    scope: JSON.stringify([{ projectId: market.id, environmentId: place.id, role: 'viewer' }]),
    places: JSON.stringify([{ environmentId: place.id, personal: false }]),
    expiresAt: new Date(Date.now() + 3_600_000),
  })));
  const answer = await app.request(`/use/market/${place.slug}`, { headers: { authorization: `Bearer ${handle}` } });
  assert.equal(answer.status, 200, await answer.clone().text());
  const plan = (await answer.json()) as { env: Record<string, string>; credentials: Record<string, string> };
  return { ...plan.env, COFFRE_CREDENTIALS: JSON.stringify(plan.credentials), COFFRE_HANDLE: handle };
}

/** Every answer coffre gave, as status, headers and body. */
const answered: string[] = [];

const used = (env: Record<string, string>, name: string) =>
  proxied(name, env, async (input, init) => {
    const answer = await app.request(input.replace(PUBLIC_URL, ''), init);
    const text = await answer.text();
    answered.push(`${answer.status} ${JSON.stringify([...answer.headers])} ${text}`);
    return new Response(text, { status: answer.status, headers: answer.headers });
  });

/** The JSON endpoint as anyone holding the handle asks it: status and body as text. */
async function ask(env: Record<string, string>, body: unknown, path = '/use/market/dev'): Promise<[number, string]> {
  const answer = await app.request(path, { method: 'POST', headers: { authorization: `Bearer ${env.COFFRE_HANDLE}`, 'content-type': 'application/json' }, body: JSON.stringify(body) });
  const text = await answer.text();
  answered.push(`${answer.status} ${JSON.stringify([...answer.headers])} ${text}`);
  return [answer.status, text];
}

/** The vault's log entries not yet signed in, each its body parsed. */
const pending = async () => (await rowsOf<{ body: string }>(world.owner, sql`SELECT body FROM log_pending ORDER BY id`)).map(({ body }) => JSON.parse(body) as { action: string; credential: string; detail: { purpose?: string; credential?: string; keys?: { key: string }[] } });

const b64u = (bytes: Uint8Array | string) => Buffer.from(bytes).toString('base64url');

function nodeEncrypt(key: Buffer, plaintext: Buffer | string, aad?: string) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
  if (aad !== undefined) cipher.setAAD(Buffer.from(aad));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { iv, ciphertext, tag: cipher.getAuthTag() };
}

function nodeDecrypt(key: Buffer, sealed: { iv: Uint8Array; ciphertext: Uint8Array; tag: Uint8Array }, aad?: string): Buffer {
  const decipher = createDecipheriv('aes-256-gcm', key, sealed.iv, { authTagLength: 16 });
  if (aad !== undefined) decipher.setAAD(Buffer.from(aad));
  decipher.setAuthTag(sealed.tag);
  return Buffer.concat([decipher.update(sealed.ciphertext), decipher.final()]);
}

test("coffre encrypts as Node's createCipheriv('aes-256-gcm') does, and decrypts what it makes, with and without AAD; each IV is coffre's own", async () => {
  const env = await run();
  // The app holds the handle where each key was, and finds each cipher by name.
  for (const key of Object.keys(KEYS)) assert.equal(env[key], env.COFFRE_HANDLE, key);
  assert.deepEqual(Object.keys(JSON.parse(env.COFFRE_CREDENTIALS!) as object).sort(), ['billing-tokens', 'iframe-token', 'payer-session', 'policy-signatures', 'small', 'wide', 'yousign']);
  const payer = used(env, 'payer-session');
  const binary = Buffer.from(Array.from({ length: 3000 }, (_, at) => (at * 37) % 256));
  for (const [plaintext, aad] of [['a pimlico refresh token', 'workspace-1'], ['no aad', undefined], ['', 'empty plaintext'], [binary, 'bytes']] as const) {
    const sealed = await payer.encrypt(plaintext, aad);
    assert.deepEqual([sealed.iv.length, sealed.tag.length, sealed.ciphertext.length], [12, 16, Buffer.from(plaintext).length]);
    assert.deepEqual(nodeDecrypt(KEYS.PAYER_SESSION_KEY, sealed, aad), Buffer.from(plaintext), 'Node decrypts what coffre encrypted');
    assert.deepEqual(Buffer.from((await payer.decrypt(sealed, aad))!), Buffer.from(plaintext));
    const made = nodeEncrypt(KEYS.PAYER_SESSION_KEY, Buffer.from(plaintext), aad);
    assert.deepEqual(Buffer.from((await payer.decrypt(made, aad))!), Buffer.from(plaintext), 'coffre decrypts what Node encrypted');
    // AAD given as bytes is the same AAD.
    if (aad !== undefined) assert.deepEqual(Buffer.from((await payer.decrypt(made, Buffer.from(aad)))!), Buffer.from(plaintext));
  }
  // Two encrypts of one plaintext: two IVs, so two ciphertexts.
  const [one, two] = [await payer.encrypt('same', 'aad'), await payer.encrypt('same', 'aad')];
  assert.notDeepEqual(one.iv, two.iv);
  assert.notDeepEqual(one.ciphertext, two.ciphertext);
  // No caller gives the IV: one sent is refused, never used, and the vault is not asked.
  const before = app.calls.length;
  const [status, text] = await ask(env, { encrypt: { credential: 'payer-session', plaintext: b64u('x'), iv: b64u(Buffer.alloc(12)) } });
  assert.equal(status, 400, text);
  assert.match(text, /draws its own IV/);
  assert.deepEqual(app.calls.slice(before), []);
});

test("Equisafe's three stored formats decrypt through coffre once each derived key is stored as hex, and coffre's encrypts are theirs again", async () => {
  const env = await run();
  // payer-session.crypto.ts: `ps1:` then base64url of IV, ciphertext and tag; the AAD its row's.
  const aad = 'workspace-42:pimlico';
  const ps = nodeEncrypt(KEYS.PAYER_SESSION_KEY, 'refresh-token-abc', aad);
  const stored = `ps1:${Buffer.concat([ps.iv, ps.ciphertext, ps.tag]).toString('base64url')}`;
  const bytes = Buffer.from(stored.slice(4), 'base64url');
  const parts = { iv: bytes.subarray(0, 12), ciphertext: bytes.subarray(12, -16), tag: bytes.subarray(-16) };
  assert.equal(Buffer.from((await used(env, 'payer-session').decrypt(parts, aad))!).toString('utf8'), 'refresh-token-abc');
  // billing-token.crypto.ts: `btv1:iv:tag:ciphertext`, each base64; no AAD.
  const bt = nodeEncrypt(KEYS.BILLING_TOKEN_KEY, 'pennylane-api-token');
  const billing = ['btv1', bt.iv.toString('base64'), bt.tag.toString('base64'), bt.ciphertext.toString('base64')].join(':');
  const [, iv, tag, data] = billing.split(':');
  assert.equal(Buffer.from((await used(env, 'billing-tokens').decrypt({ iv: Buffer.from(iv!, 'base64'), ciphertext: Buffer.from(data!, 'base64'), tag: Buffer.from(tag!, 'base64') }))!).toString('utf8'), 'pennylane-api-token');
  // signature-cipher.util.ts: `v1:` then base64url of IV, ciphertext and tag; the AAD the decision's.
  const decision = 'approval-decision:7f3e';
  const sig = nodeEncrypt(KEYS.POLICY_SIGNATURE_KEY, '0xdeadbeef-signature', decision);
  const sealed = Buffer.from(`v1:${Buffer.concat([sig.iv, sig.ciphertext, sig.tag]).toString('base64url')}`.slice(3), 'base64url');
  assert.equal(Buffer.from((await used(env, 'policy-signatures').decrypt({ iv: sealed.subarray(0, 12), ciphertext: sealed.subarray(12, -16), tag: sealed.subarray(-16) }, decision))!).toString('utf8'), '0xdeadbeef-signature');
  // And the other way: coffre encrypts, the backend's own decipher reads the format it builds.
  const mine = await used(env, 'billing-tokens').encrypt('new-token');
  assert.equal(nodeDecrypt(KEYS.BILLING_TOKEN_KEY, mine).toString('utf8'), 'new-token');
  // One cipher's ciphertext under another's key decrypts to nothing.
  assert.equal(await used(env, 'billing-tokens').decrypt(ps, aad), null);
});

test('a flipped bit in the tag, the IV, the AAD or the ciphertext, or another key, answers exactly { plaintext: null }, the same bytes for each', async () => {
  const env = await run();
  const aad = Buffer.from('row-1');
  const good = nodeEncrypt(KEYS.PAYER_SESSION_KEY, 'secret plaintext', 'row-1');
  const flip = (bytes: Buffer, at = 0) => Buffer.from(bytes.map((byte, i) => (i === at ? byte ^ 1 : byte)));
  const asked = (part: { iv?: Buffer; ciphertext?: Buffer; tag?: Buffer; aad?: Buffer }, name = 'payer-session') =>
    ask(env, { decrypt: { credential: name, iv: b64u(part.iv ?? good.iv), ciphertext: b64u(part.ciphertext ?? good.ciphertext), tag: b64u(part.tag ?? good.tag), aad: b64u(part.aad ?? aad) } });
  assert.deepEqual(await asked({}), [200, JSON.stringify({ plaintext: b64u('secret plaintext') })]);
  const answers = [
    await asked({ tag: flip(good.tag) }), await asked({ tag: flip(good.tag, 15) }),
    await asked({ iv: flip(good.iv) }), await asked({ iv: flip(good.iv, 11) }),
    await asked({ aad: flip(aad) }), await asked({ aad: Buffer.alloc(0) }),
    await asked({ ciphertext: flip(good.ciphertext) }), await asked({ ciphertext: flip(good.ciphertext, good.ciphertext.length - 1) }),
    await asked({}, 'billing-tokens'), await asked({}, 'policy-signatures'),
  ];
  for (const one of answers) assert.deepEqual(one, [200, '{"plaintext":null}']);
  // And with the success's headers: only whether the body holds a plaintext tells them apart. (Each response's CSP
  // carries a nonce of its own, drawn at random, which tells nothing.)
  const headers = answered.slice(-11).map((line) => line.slice(4, line.indexOf(']] ') + 2).replace(/'nonce-[^']*'/, "'nonce'"));
  for (const one of headers) assert.equal(one, headers[0]);
  // Malformed asks are 400s, not decrypts: not base64url, an IV that is not 12 bytes, a tag that is not 16. None asks the vault.
  const before = app.calls.length;
  for (const decrypt of [
    { iv: '!!', ciphertext: b64u(good.ciphertext), tag: b64u(good.tag) },
    { iv: b64u(good.iv.subarray(1)), ciphertext: b64u(good.ciphertext), tag: b64u(good.tag) },
    { iv: b64u(Buffer.concat([good.iv, Buffer.alloc(1)])), ciphertext: b64u(good.ciphertext), tag: b64u(good.tag) },
    { iv: b64u(good.iv), ciphertext: b64u(good.ciphertext), tag: b64u(good.tag.subarray(1)) },
    { iv: b64u(good.iv), ciphertext: b64u(good.ciphertext) },
    { iv: b64u(good.iv), ciphertext: 'a', tag: b64u(good.tag) },
    { iv: b64u(good.iv), ciphertext: b64u(good.ciphertext), tag: b64u(good.tag), aad: 12 },
  ]) {
    assert.equal((await ask(env, { decrypt: { credential: 'payer-session', ...decrypt } }))[0], 400, JSON.stringify(decrypt));
  }
  assert.equal((await ask(env, { encrypt: { credential: 'payer-session', plaintext: 'not base64url!' } }))[0], 400);
  assert.deepEqual(app.calls.slice(before), []);
});

test("a cipher takes its maxBytes, the plaintext with its AAD, and no more: 413; JSON's 1 MiB is its ceiling", async () => {
  const env = await run();
  const small = used(env, 'small');
  assert.equal((await small.encrypt(Buffer.alloc(32))).ciphertext.length, 32);
  assert.equal((await small.encrypt(Buffer.alloc(20), Buffer.alloc(12))).ciphertext.length, 20);
  const before = app.calls.length;
  for (const [plaintext, aad] of [[33, 0], [20, 13]] as const) {
    const [status, text] = await ask(env, { encrypt: { credential: 'small', plaintext: b64u(Buffer.alloc(plaintext)), aad: b64u(Buffer.alloc(aad)) } });
    assert.equal(status, 413, text);
    assert.match(text, /small encrypts 32 bytes at most, with its AAD/);
  }
  const [status] = await ask(env, { decrypt: { credential: 'small', iv: b64u(Buffer.alloc(12)), ciphertext: b64u(Buffer.alloc(33)), tag: b64u(Buffer.alloc(16)) } });
  assert.equal(status, 413);
  assert.deepEqual(app.calls.slice(before), [], 'refused before the vault is asked');
  // 64 KiB unless set.
  assert.equal((await used(env, 'payer-session').encrypt(Buffer.alloc(64 * 1024))).ciphertext.length, 64 * 1024);
  assert.equal((await ask(env, { encrypt: { credential: 'payer-session', plaintext: b64u(Buffer.alloc(64 * 1024 + 1)) } }))[0], 413);
});

test('a key of 31 or 33 bytes, outside its encoding, or a passphrase is a 409 that names the key and never its value', async () => {
  const env = await run(bad);
  for (const [name, key] of [['payer-session', 'PAYER_SESSION_KEY'], ['billing-tokens', 'BILLING_TOKEN_KEY'], ['policy-signatures', 'POLICY_SIGNATURE_KEY'], ['small', 'SMALL_KEY']] as const) {
    for (const body of [{ encrypt: { credential: name, plaintext: b64u('x') } }, { decrypt: { credential: name, iv: b64u(Buffer.alloc(12)), ciphertext: '', tag: b64u(Buffer.alloc(16)) } }]) {
      const [status, text] = await ask(env, body, '/use/market/bad');
      assert.equal(status, 409, text);
      assert.match(text, new RegExp(`market/bad's ${key} is no AES-256 key, which ${name} reads as exactly 32 bytes`));
      assert.ok(!text.includes(BAD[key]) && !text.includes(BAD[key].slice(4, 20)), `${key}'s value in ${text}`);
    }
  }
  // A key the environment lacks is no key of the wrong length: the use says what is missing.
  const [missing, lacks] = await ask(env, { encrypt: { credential: 'wide', plaintext: b64u('x') } }, '/use/market/bad');
  assert.equal(missing, 409, lacks);
  assert.match(lacks, /market\/bad holds no WIDE_KEY, which wide needs/);
  // Base64 and base64url keys that decode cleanly to 31 and 33 bytes: their 409 comes from the length alone.
  let wide: ReturnType<typeof value> | null = null;
  for (const length of [31, 33]) {
    const bytes = Buffer.alloc(length, 0x5a);
    const values = { SMALL_KEY: bytes.toString('base64url'), WIDE_KEY: bytes.toString('base64') };
    await rewrite(world, badSmall, values.SMALL_KEY);
    if (wide === null) {
      wide = value(world, secret(bad, 'WIDE_KEY'), values.WIDE_KEY);
      await write(world, ...rows('secrets', wide));
    } else await rewrite(world, wide, values.WIDE_KEY);
    const fresh = await run(bad);
    for (const [name, key] of [['small', 'SMALL_KEY'], ['wide', 'WIDE_KEY']] as const) {
      const [status, text] = await ask(fresh, { encrypt: { credential: name, plaintext: b64u('x') } }, '/use/market/bad');
      assert.equal(status, 409, text);
      assert.match(text, new RegExp(`market/bad's ${key} is no AES-256 key, which ${name} reads as exactly 32 bytes`));
      assert.ok(!text.includes(values[key].slice(4, 20)), `${key}'s value in ${text}`);
    }
  }
});

test('a cipher is no signer, verifier or credential, and none of those is a cipher: a 404 that says which map holds the name', async () => {
  const env = await run();
  const msg = b64u('m');
  const before = app.calls.length;
  const expect = async (body: unknown, pattern: RegExp) => {
    const [status, text] = await ask(env, body);
    assert.equal(status, 404, text);
    assert.match(text, pattern);
  };
  await expect({ sign: { credential: 'payer-session', message: msg } }, /payer-session is a cipher, which encrypts and decrypts/);
  await expect({ verify: { credential: 'payer-session', message: msg, signature: 'x' } }, /payer-session is a cipher, which encrypts and decrypts/);
  await expect({ encrypt: { credential: 'iframe-token', plaintext: msg } }, /encrypt names a cipher.*iframe-token is a signer/);
  await expect({ decrypt: { credential: 'yousign', iv: '', ciphertext: '', tag: '' } }, /decrypt names a cipher.*yousign is a verifier/);
  await expect({ encrypt: { credential: 'nope', plaintext: msg } }, /encrypt names a cipher of this instance's/);
  await assert.rejects(used(env, 'iframe-token').encrypt('x'), /encrypt names a cipher/);
  // A cipher's URL, as a credential's would be, reaches nothing; nor does a raw sign name it.
  const path = await app.request('/use/market/dev/payer-session/x', { headers: { 'x-coffre-handle': env.COFFRE_HANDLE! } });
  assert.equal(path.status, 404);
  assert.match(await path.text(), /payer-session is a cipher, which reaches no upstream/);
  const raw = await app.request('/use/market/dev?sign=payer-session', { method: 'POST', headers: { authorization: `Bearer ${env.COFFRE_HANDLE}`, 'content-type': 'application/octet-stream', 'content-length': '1' }, body: 'x' });
  assert.equal(raw.status, 404);
  assert.match(await raw.text(), /payer-session is a cipher/);
  assert.deepEqual(app.calls.slice(before), [], 'no name of the wrong kind asks the vault');
});

test("each encrypt and decrypt is one use, the cipher named, and logged by the vault once a minute per handle and key; no plaintext, AAD, IV or key in the log, an error or the console", async () => {
  const lines = ['log', 'info', 'warn', 'error', 'debug'] as const;
  const original = Object.fromEntries(lines.map((line) => [line, console[line]]));
  for (const line of lines) console[line] = (...args: unknown[]) => void said.push(args.map((arg) => (arg instanceof Error ? `${arg.message} ${arg.stack}` : typeof arg === 'string' ? arg : JSON.stringify(arg))).join(' '));
  answered.length = 0;
  const PLAINTEXT = 'card-4242-4242-4242-4242';
  const AAD = 'workspace-aad-91c2';
  const ivs: string[] = [];
  try {
    const env = await run();
    const payer = used(env, 'payer-session');
    const before = app.calls.length;
    for (let i = 0; i < 4; i++) {
      const sealed = await payer.encrypt(PLAINTEXT, AAD);
      ivs.push(b64u(sealed.iv), Buffer.from(sealed.iv).toString('hex'));
      assert.equal(Buffer.from((await payer.decrypt(sealed, AAD))!).toString(), PLAINTEXT);
      assert.equal(await payer.decrypt({ ...sealed, tag: new Uint8Array(16) }, AAD), null);
    }
    // Nothing is kept: every request asks the vault again, each time naming the cipher.
    assert.deepEqual(app.calls.slice(before), Array.from({ length: 12 }, () => 'use'));
    const inputs = app.inputs.slice(before) as { keys: string[]; purpose: string; upstream: string }[];
    for (const input of inputs) assert.deepEqual([input.keys, input.purpose, input.upstream], [['PAYER_SESSION_KEY'], 'use', 'payer-session']);
    // Twelve uses, one entry: the vault's once a minute.
    const entries = (await pending()).filter((entry) => entry.action === 'secret.read' && entry.detail.purpose === 'use');
    assert.deepEqual(entries.map((entry) => [entry.detail.credential, entry.detail.keys!.map((key) => key.key)]), [['payer-session', ['PAYER_SESSION_KEY']]]);
    // Errors of every kind, each carrying the plaintext and AAD: none says them back.
    const broken = await run(bad);
    for (const name of ['payer-session', 'small', 'iframe-token', 'yousign', 'nope']) {
      for (const [handle, path] of [[env, '/use/market/dev'], [broken, '/use/market/bad']] as const) {
        await ask(handle, { encrypt: { credential: name, plaintext: b64u(PLAINTEXT.repeat(3)), aad: b64u(AAD) } }, path);
        await ask(handle, { encrypt: { credential: name, plaintext: b64u(PLAINTEXT), aad: b64u(AAD), iv: b64u(Buffer.alloc(12)) } }, path);
        await ask(handle, { decrypt: { credential: name, iv: b64u('short'), ciphertext: b64u(PLAINTEXT), tag: b64u(AAD), aad: b64u(AAD) } }, path);
        await ask(handle, { sign: { credential: name, message: b64u(PLAINTEXT) } }, path);
      }
    }
  } finally {
    for (const line of lines) console[line] = original[line]!;
  }
  const log = [
    ...(await rowsOf<{ body: string }>(world.owner, sql`SELECT body FROM log_pending ORDER BY id`)).map((row) => row.body),
    ...(await rowsOf<{ body: string }>(world.owner, sql`SELECT body FROM log ORDER BY seq`)).map((row) => row.body),
  ];
  assert.ok(log.length > 0, 'the log holds the uses');
  // What coffre said that is no decrypt's own answer: its errors and refusals, the log, the console.
  const errors = answered.filter((one) => !one.startsWith('200 '));
  assert.ok(errors.length > 30, `${errors.length} errors`);
  const everything = [...errors, ...log, ...said].join('\n');
  for (const [what, form] of [
    ['plaintext', PLAINTEXT], ['plaintext', b64u(PLAINTEXT)], ['plaintext', Buffer.from(PLAINTEXT).toString('base64')], ['aad', AAD], ['aad', b64u(AAD)],
    ...Object.entries(KEYS).flatMap(([key, bytes]) => [[key, bytes.toString('hex')], [key, bytes.toString('base64')], [key, bytes.toString('base64url')], [key, bytes.toString('hex').slice(8, 40)]]),
    ...Object.entries(BAD).map(([key, value]) => [key, value]),
  ]) {
    assert.ok(!everything.includes(form!), `${what} leaked as ${form}`);
  }
  for (const iv of ivs) assert.ok(!log.join('\n').includes(iv), 'an IV in the log');
});

test('the configuration refuses what is no AES-256-GCM with a key of known encoding', () => {
  const refused = (more: Partial<CredentialProxyOptions>, pattern: RegExp) => assert.throws(() => credentialProxy({ credentials: {}, ...more }), pattern);
  refused({ ciphers: { x: { kind: 'aes-gcm', key: 'KEY' } as never } }, /reads its key's 32 bytes as hex, base64 or base64url: keyEncoding/);
  refused({ ciphers: { x: aesGcm('KEY', { keyEncoding: 'utf8' as Encoding }) } }, /reads its key's 32 bytes as hex, base64 or base64url/);
  for (const option of ['derive', 'iv', 'tagLength', 'mode']) refused({ ciphers: { x: { ...aesGcm('KEY', { keyEncoding: 'hex' }), [option]: 1 } as never } }, new RegExp(`AES-256-GCM alone; got ${option}`));
  refused({ ciphers: { x: hmac('KEY', { encoding: 'hex' }) as never } }, /cipher x is aesGcm\(…\), the only kind there is/);
  refused({ signers: { x: aesGcm('KEY', { keyEncoding: 'hex' }) as never } }, /signer x is privateKey\(…\) or hmac\(…\)/);
  refused({ ciphers: { x: aesGcm('not a key', { keyEncoding: 'hex' }) } }, /names the key that holds its key, BILLING_TOKEN_KEY/);
  refused({ ciphers: { X: aesGcm('KEY', { keyEncoding: 'hex' }) } }, /a cipher's name is lowercase/);
  refused({ signers: { x: privateKey('KEY') }, ciphers: { x: aesGcm('KEY', { keyEncoding: 'hex' }) } }, /x names a signer and a cipher/);
  refused({ verifiers: { x: hmac('KEY', { encoding: 'hex' }) }, ciphers: { x: aesGcm('KEY', { keyEncoding: 'hex' }) } }, /x names a verifier and a cipher/);
  refused({ credentials: { x: { upstream: 'https://api.example', inject: { kind: 'header', name: 'x-key', template: '{KEY}' } } }, ciphers: { x: aesGcm('KEY', { keyEncoding: 'hex' }) } }, /x names a credential and a cipher/);
  refused({ ciphers: { x: aesGcm('KEY', { keyEncoding: 'hex', limit: { perMinute: 0 } }) } }, /limit is \{ perMinute\?, perDay\? \}/);
  for (const maxBytes of [0, 1.5, 1024 * 1024 + 1]) refused({ ciphers: { x: aesGcm('KEY', { keyEncoding: 'hex', maxBytes }) } }, /maxBytes is a whole number of bytes, 1 MiB at most/);
  assert.doesNotThrow(() => credentialProxy({ credentials: {}, ciphers: { x: aesGcm('KEY', { keyEncoding: 'base64', maxBytes: 1024 * 1024 }) } }));
});
