// AES-256-GCM through the handle (docs/design/credential-proxy.md, section 5): a cipher's key stays in coffre, and the
// app asks it to encrypt or decrypt, `credential(name).encrypt(plaintext, aad)`. Here both directions against Node's
// createCipheriv, Equisafe's three stored formats, each built as its backend builds it, one answer for every failed
// decrypt, the key's length checked after decoding, and no plaintext, AAD or key in the log, an error or the console.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createCipheriv, createDecipheriv, createHash, hkdfSync, randomBytes } from 'node:crypto';

import { credential } from '@coffre/client/credential';

import { auditLog } from '@coffre/db/schema';
import { clientFor } from './api-fixture.ts';
import { db, deps, DEV, entries, ORIGIN, ROOT, route, runtime, sessionFor, useMcp } from './mcp-fixture.ts';
import { checkPlugins } from '../src/plugins.ts';
import { aesGcm, credentialProxy, hmac, privateKey, type CredentialProxyOptions, type Encoding } from '../src/plugins/credential-proxy.ts';

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
};
const options: CredentialProxyOptions = {
  credentials: {},
  ciphers: {
    'payer-session': aesGcm('PAYER_SESSION_KEY', { keyEncoding: 'hex' }),
    'billing-tokens': aesGcm('BILLING_TOKEN_KEY', { keyEncoding: 'hex' }),
    'policy-signatures': aesGcm('POLICY_SIGNATURE_KEY', { keyEncoding: 'hex' }),
    small: aesGcm('SMALL_KEY', { keyEncoding: 'base64url', maxBytes: 32 }),
  },
  signers: { 'iframe-token': hmac('IFRAME_TOKEN_SECRET', { encoding: 'base64url' }) },
  verifiers: { yousign: hmac('YOUSIGN_WEBHOOK_SECRET', { encoding: 'hex' }) },
};

/** What the console says while a test runs, every line of it. */
const said: string[] = [];

useMcp(async () => {
  runtime.plugins = checkPlugins([credentialProxy(options)]);
  said.length = 0;
  const root = clientFor(deps, ROOT);
  await root.members.add(`user:${DEV}`);
  await root.projects.create('market');
  for (const env of ['dev', 'bad']) await root.environments.create(`market/${env}`);
  await root.secrets.set('market/dev', {
    PAYER_SESSION_KEY: KEYS.PAYER_SESSION_KEY.toString('hex'),
    BILLING_TOKEN_KEY: KEYS.BILLING_TOKEN_KEY.toString('hex'),
    POLICY_SIGNATURE_KEY: { value: KEYS.POLICY_SIGNATURE_KEY.toString('hex'), sensitivity: 'sensitive' },
    SMALL_KEY: KEYS.SMALL_KEY.toString('base64url'),
    IFRAME_TOKEN_SECRET: 'iframe_secret_0123456789',
    YOUSIGN_WEBHOOK_SECRET: 'ys_whsec_0123456789',
  });
  // Keys of 31 and 33 bytes, one outside its alphabet, and one a passphrase: none is AES-256's.
  await root.secrets.set('market/bad', { ...BAD });
  await root.access.set(`user:${DEV}`, { market: 'developer' });
});

const BAD = {
  PAYER_SESSION_KEY: KEYS.PAYER_SESSION_KEY.subarray(0, 31).toString('hex'),
  BILLING_TOKEN_KEY: Buffer.concat([KEYS.BILLING_TOKEN_KEY, Buffer.from([7])]).toString('hex'),
  POLICY_SIGNATURE_KEY: `${KEYS.POLICY_SIGNATURE_KEY.toString('hex').slice(0, 62)}zz`,
  SMALL_KEY: ROOT_ENCRYPTION_KEY,
};

/** What `coffre run` gives the app for `path`: its environment, with the handle. */
async function run(path = 'market/dev'): Promise<Record<string, string>> {
  const made = await route('/api/handles', { method: 'POST', headers: { authorization: `Bearer ${await sessionFor(DEV)}`, 'content-type': 'application/json' }, body: JSON.stringify({ label: 'run', paths: [path] }) });
  const handle = ((await made.json()) as { token: string }).token;
  const plan = (await (await route(`/use/${path}`, { headers: { authorization: `Bearer ${handle}` } })).json()) as { env: Record<string, string>; credentials: Record<string, string> };
  return { ...plan.env, COFFRE_CREDENTIALS: JSON.stringify(plan.credentials), COFFRE_HANDLE: handle };
}

/** Every answer coffre gave, as status, headers and body. */
const answered: string[] = [];

const used = (env: Record<string, string>, name: string) =>
  credential(name, env, async (input, init) => {
    const answer = await route(input.replace(ORIGIN, ''), init);
    const text = await answer.text();
    answered.push(`${answer.status} ${JSON.stringify([...answer.headers])} ${text}`);
    return new Response(text, { status: answer.status, headers: answer.headers });
  });

/** The JSON endpoint as anyone holding the handle asks it: status and body as text. */
async function ask(env: Record<string, string>, body: unknown, path = '/use/market/dev'): Promise<[number, string]> {
  const answer = await route(path, { method: 'POST', headers: { authorization: `Bearer ${env.COFFRE_HANDLE}`, 'content-type': 'application/json' }, body: JSON.stringify(body) });
  const text = await answer.text();
  answered.push(`${answer.status} ${JSON.stringify([...answer.headers])} ${text}`);
  return [answer.status, text];
}

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
  assert.deepEqual(Object.keys(JSON.parse(env.COFFRE_CREDENTIALS!) as object).sort(), ['billing-tokens', 'iframe-token', 'payer-session', 'policy-signatures', 'small', 'yousign']);
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
  // No caller gives the IV: one sent is refused, never used.
  const [status, text] = await ask(env, { encrypt: { credential: 'payer-session', plaintext: b64u('x'), iv: b64u(Buffer.alloc(12)) } });
  assert.equal(status, 400, text);
  assert.match(text, /draws its own IV/);
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
  // Malformed asks are 400s, not decrypts: not base64url, an IV that is not 12 bytes, a tag that is not 16.
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
});

test("a cipher takes its maxBytes, the plaintext with its AAD, and no more: 413; JSON's 1 MiB is its ceiling", async () => {
  const env = await run();
  const small = used(env, 'small');
  assert.equal((await small.encrypt(Buffer.alloc(32))).ciphertext.length, 32);
  assert.equal((await small.encrypt(Buffer.alloc(20), Buffer.alloc(12))).ciphertext.length, 20);
  for (const [plaintext, aad] of [[33, 0], [20, 13]] as const) {
    const [status, text] = await ask(env, { encrypt: { credential: 'small', plaintext: b64u(Buffer.alloc(plaintext)), aad: b64u(Buffer.alloc(aad)) } });
    assert.equal(status, 413, text);
    assert.match(text, /small encrypts 32 bytes at most, with its AAD/);
  }
  const [status] = await ask(env, { decrypt: { credential: 'small', iv: b64u(Buffer.alloc(12)), ciphertext: b64u(Buffer.alloc(33)), tag: b64u(Buffer.alloc(16)) } });
  assert.equal(status, 413);
  // 64 KiB unless set.
  assert.equal((await used(env, 'payer-session').encrypt(Buffer.alloc(64 * 1024))).ciphertext.length, 64 * 1024);
  assert.equal((await ask(env, { encrypt: { credential: 'payer-session', plaintext: b64u(Buffer.alloc(64 * 1024 + 1)) } }))[0], 413);
});

test('a key of 31 or 33 bytes, outside its encoding, or a passphrase is a 409 that names the key and never its value', async () => {
  const env = await run('market/bad');
  for (const [name, key] of [['payer-session', 'PAYER_SESSION_KEY'], ['billing-tokens', 'BILLING_TOKEN_KEY'], ['policy-signatures', 'POLICY_SIGNATURE_KEY'], ['small', 'SMALL_KEY']] as const) {
    for (const body of [{ encrypt: { credential: name, plaintext: b64u('x') } }, { decrypt: { credential: name, iv: b64u(Buffer.alloc(12)), ciphertext: '', tag: b64u(Buffer.alloc(16)) } }]) {
      const [status, text] = await ask(env, body, '/use/market/bad');
      assert.equal(status, 409, text);
      assert.match(text, new RegExp(`market/bad's ${key} is no AES-256 key, which ${name} reads as exactly 32 bytes`));
      assert.ok(!text.includes(BAD[key]) && !text.includes(BAD[key].slice(4, 20)), `${key}'s value in ${text}`);
    }
  }
});

test('a cipher is no signer, verifier or credential, and none of those is a cipher: a 404 that says which map holds the name', async () => {
  const env = await run();
  const msg = b64u('m');
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
  const path = await route('/use/market/dev/payer-session/x', { headers: { 'x-coffre-handle': env.COFFRE_HANDLE! } });
  assert.equal(path.status, 404);
  assert.match(await path.text(), /payer-session is a cipher, which reaches no upstream/);
  const raw = await route('/use/market/dev?sign=payer-session', { method: 'POST', headers: { authorization: `Bearer ${env.COFFRE_HANDLE}`, 'content-type': 'application/octet-stream', 'content-length': '1' }, body: 'x' });
  assert.equal(raw.status, 404);
  assert.match(await raw.text(), /payer-session is a cipher/);
});

test('a cipher is logged once a minute per handle and name, the vault asked once; no plaintext, AAD, IV or key in the log, an error or the console', async () => {
  const lines = ['log', 'info', 'warn', 'error', 'debug'] as const;
  const original = Object.fromEntries(lines.map((line) => [line, console[line]]));
  for (const line of lines) console[line] = (...args: unknown[]) => void said.push(args.map((arg) => (arg instanceof Error ? `${arg.message} ${arg.stack}` : typeof arg === 'string' ? arg : JSON.stringify(arg))).join(' '));
  answered.length = 0;
  const PLAINTEXT = 'card-4242-4242-4242-4242';
  const AAD = 'workspace-aad-91c2';
  const unwrap = deps.vault.unwrap.bind(deps.vault);
  let unwrapped = 0;
  deps.vault.unwrap = (async (...args: Parameters<typeof unwrap>) => {
    unwrapped++;
    return unwrap(...args);
  }) as typeof unwrap;
  const ivs: string[] = [];
  try {
    const env = await run();
    const payer = used(env, 'payer-session');
    for (let i = 0; i < 4; i++) {
      const sealed = await payer.encrypt(PLAINTEXT, AAD);
      ivs.push(b64u(sealed.iv), Buffer.from(sealed.iv).toString('hex'));
      assert.equal(Buffer.from((await payer.decrypt(sealed, AAD))!).toString(), PLAINTEXT);
      assert.equal(await payer.decrypt({ ...sealed, tag: new Uint8Array(16) }, AAD), null);
    }
    assert.equal(unwrapped, 1, 'one opening, then the cache');
    const uses = (await entries('credential.use')).filter((entry) => entry.metadata.cipher === true);
    assert.deepEqual(uses.map((entry) => [entry.metadata.credential, entry.metadata.purpose]), [['payer-session', 'use']]);
    // Errors of every kind, each carrying the plaintext and AAD: none says them back.
    const bad = await run('market/bad');
    for (const name of ['payer-session', 'small', 'iframe-token', 'yousign', 'nope']) {
      for (const [handle, path] of [[env, '/use/market/dev'], [bad, '/use/market/bad']] as const) {
        await ask(handle, { encrypt: { credential: name, plaintext: b64u(PLAINTEXT.repeat(3)), aad: b64u(AAD) } }, path);
        await ask(handle, { encrypt: { credential: name, plaintext: b64u(PLAINTEXT), aad: b64u(AAD), iv: b64u(Buffer.alloc(12)) } }, path);
        await ask(handle, { decrypt: { credential: name, iv: b64u('short'), ciphertext: b64u(PLAINTEXT), tag: b64u(AAD), aad: b64u(AAD) } }, path);
        await ask(handle, { sign: { credential: name, message: b64u(PLAINTEXT) } }, path);
      }
    }
  } finally {
    deps.vault.unwrap = unwrap;
    for (const line of lines) console[line] = original[line]!;
  }
  const log = (await db.owner.select().from(auditLog)).map((row) => JSON.stringify(row, (_, value: unknown) => (typeof value === 'bigint' ? String(value) : value)));
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
