// HMAC through the handle (docs/design/credential-proxy.md, section 5): an
// inbound webhook's secret stays in coffre, and the app asks whether a
// signature is the secret's, `credential(name).verify(body, signature)`;
// a key of the app's own signs too. Here Yousign's, DFNS's and Lemonway's
// schemes, each signed as the provider signs it with `node:crypto`, the
// app's own HS256 token, the log once a minute, and no byte of a secret in
// anything coffre answers, logs or says on the console.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac, generateKeyPairSync } from 'node:crypto';

import * as hegel from '@hegeldev/hegel';
import * as gs from '@hegeldev/hegel/generators';
import { credential } from '@coffre/client/credential';

import { propertySettings } from '../../../scripts/property-settings.ts';
import { clientFor } from './api-fixture.ts';
import { db, deps, DEV, entries, ORIGIN, ROOT, route, runtime, sessionFor, useMcp } from './mcp-fixture.ts';
import { auditLog } from '@coffre/db/schema';
import { checkPlugins, type PluginContext, type UseAsked } from '../src/plugins.ts';
import { credentialProxy, hmac, privateKey, type CredentialProxyOptions, type Encoding } from '../src/plugins/credential-proxy.ts';

const SECRETS = {
  YOUSIGN_WEBHOOK_SECRET: 'ys_whsec_0123456789abcdefABCDEF',
  DFNS_WEBHOOK_SECRET: 'dfns_whsec_9876543210zyxwvu',
  LEMONWAY_WEBHOOK_SECRET: 'lw_whsec_ab12cd34ef56gh78',
  IFRAME_TOKEN_SECRET: 'iframe_secret_5f4dcc3b5aa765d61d8327deb882cf99',
};
const options: CredentialProxyOptions = {
  credentials: {},
  verifiers: {
    yousign: hmac('YOUSIGN_WEBHOOK_SECRET', { encoding: 'hex', prefix: 'sha256=' }),
    // A deployment's own bound, for a provider whose bodies run long.
    dfns: hmac('DFNS_WEBHOOK_SECRET', { encoding: 'hex', prefix: 'sha256=', maxBytes: 512 * 1024 }),
    lemonway: hmac('LEMONWAY_WEBHOOK_SECRET', { encoding: 'hex' }),
    absent: hmac('NOT_HELD', { encoding: 'hex' }),
  },
  signers: {
    'iframe-token': hmac('IFRAME_TOKEN_SECRET', { encoding: 'base64url' }),
    'dfns-key': privateKey('DFNS_PRIVATE_KEY'),
  },
};

/** What the console says while a test runs, every line of it. */
const said: string[] = [];

useMcp(async () => {
  runtime.plugins = checkPlugins([credentialProxy(options)]);
  said.length = 0;
  const root = clientFor(deps, ROOT);
  await root.members.add(`user:${DEV}`);
  await root.projects.create('market');
  await root.environments.create('market/dev');
  await root.environments.create('market/bare');
  await root.secrets.set('market/dev', {
    YOUSIGN_WEBHOOK_SECRET: { value: SECRETS.YOUSIGN_WEBHOOK_SECRET, sensitivity: 'sensitive' },
    DFNS_WEBHOOK_SECRET: SECRETS.DFNS_WEBHOOK_SECRET,
    LEMONWAY_WEBHOOK_SECRET: SECRETS.LEMONWAY_WEBHOOK_SECRET,
    IFRAME_TOKEN_SECRET: SECRETS.IFRAME_TOKEN_SECRET,
    DFNS_PRIVATE_KEY: generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
  });
  await root.secrets.set('market/bare', { OTHER: 'x' });
  await root.access.set(`user:${DEV}`, { market: 'developer' });
});

/** What `coffre run market/dev` gives the app: its environment, and `credential(name)` over coffre's own route. */
async function run(paths = ['market/dev']): Promise<{ env: Record<string, string>; plan: { env: Record<string, string>; credentials: Record<string, string> } }> {
  const made = await route('/api/handles', { method: 'POST', headers: { authorization: `Bearer ${await sessionFor(DEV)}`, 'content-type': 'application/json' }, body: JSON.stringify({ label: 'run', paths }) });
  const handle = ((await made.json()) as { token: string }).token;
  const plan = (await (await route(`/use/${paths[0]}`, { headers: { authorization: `Bearer ${handle}` } })).json()) as { env: Record<string, string>; credentials: Record<string, string> };
  return { env: { ...plan.env, COFFRE_CREDENTIALS: JSON.stringify(plan.credentials), COFFRE_HANDLE: handle }, plan };
}

/** Every answer coffre gave the app, as text, headers and body. */
const answered: string[] = [];

/** `credential(name)` as the app holds it, each answer kept for the leak check. */
function used(env: Record<string, string>, name: string) {
  return credential(name, env, async (input, init) => {
    const answer = await route(input.replace(ORIGIN, ''), init);
    const text = await answer.text();
    answered.push(`${answer.status} ${JSON.stringify([...answer.headers])} ${text}`);
    return new Response(text, { status: answer.status, headers: answer.headers });
  });
}

const hmacOf = (secret: string, body: string | Buffer, encoding: 'hex' | 'base64url' = 'hex') => createHmac('sha256', secret).update(body).digest(encoding);

/** A Yousign event as Yousign sends it, its body raw: what its `x-yousign-signature-256` signs. */
const YOUSIGN_BODY = '{"event_id":"ev-1","event_name":"signature_request.done","event_time":"1761480000","data":{"signature_request":{"id":"sr-1","status":"done","signers":[{"id":"s-1","status":"signed"}]}}}';
/** A DFNS event, its `timestampSent` the app's to check: coffre checks the bytes alone. */
const DFNS_BODY = '{"id":"wh-1","kind":"wallet.transfer.confirmed","timestampSent":1761480000,"data":{"transferRequest":{"id":"xfr-1","status":"Confirmed"}}}';
const LEMONWAY_BODY = '{"NotifCategory":10,"IntId":"101","ExtId":"jkdc","Status":0,"Amount":"10.00"}';

test("each provider's signature verifies as the provider made it, over the raw body, and nothing else does", async () => {
  const { env, plan } = await run();
  // The app holds the handle where each secret was, never a value; each verifier and HMAC signer is named for credential(name).
  for (const key of Object.keys(SECRETS)) assert.equal(plan.env[key], env.COFFRE_HANDLE, key);
  assert.deepEqual(Object.keys(plan.credentials).sort(), ['dfns', 'dfns-key', 'iframe-token', 'lemonway', 'yousign']);
  const yousign = used(env, 'yousign');
  const header = `sha256=${hmacOf(SECRETS.YOUSIGN_WEBHOOK_SECRET, YOUSIGN_BODY)}`;
  assert.equal(await yousign.verify(YOUSIGN_BODY, header), true);
  assert.equal(await yousign.verify(new TextEncoder().encode(YOUSIGN_BODY), header), true, 'the same bytes, given as bytes');
  assert.equal(await yousign.verify(YOUSIGN_BODY, header.toUpperCase().replace('SHA256=', 'sha256=')), true, 'hex read in either case');
  // The body parsed and written again, as Equisafe's DFNS and Lemonway guards hash it today, is other bytes.
  assert.equal(await yousign.verify(JSON.stringify(JSON.parse(YOUSIGN_BODY), null, 1), header), false);
  for (const wrong of [
    hmacOf(SECRETS.YOUSIGN_WEBHOOK_SECRET, YOUSIGN_BODY),
    `sha256=${hmacOf(SECRETS.DFNS_WEBHOOK_SECRET, YOUSIGN_BODY)}`,
    `sha256=${hmacOf(SECRETS.YOUSIGN_WEBHOOK_SECRET, `${YOUSIGN_BODY} `)}`,
    `sha256=${hmacOf(SECRETS.YOUSIGN_WEBHOOK_SECRET, YOUSIGN_BODY).slice(0, 62)}`,
    `sha256=${hmacOf(SECRETS.YOUSIGN_WEBHOOK_SECRET, YOUSIGN_BODY)}00`,
    `sha256=${createHmac('sha256', SECRETS.YOUSIGN_WEBHOOK_SECRET).update(YOUSIGN_BODY).digest('base64')}`,
    'sha256=', '', 'sha256=zz', `sha256=${'0'.repeat(64)}`, `sha256=${'0'.repeat(100_000)}`,
  ]) {
    assert.equal(await yousign.verify(YOUSIGN_BODY, wrong), false, wrong.slice(0, 80));
  }
  assert.equal(await used(env, 'dfns').verify(DFNS_BODY, `sha256=${hmacOf(SECRETS.DFNS_WEBHOOK_SECRET, DFNS_BODY)}`), true);
  assert.equal(await used(env, 'dfns').verify(DFNS_BODY, `sha256=${hmacOf(SECRETS.YOUSIGN_WEBHOOK_SECRET, DFNS_BODY)}`), false);
  // Lemonway's, as Equisafe's guard checks it: the hex alone, no prefix.
  assert.equal(await used(env, 'lemonway').verify(LEMONWAY_BODY, hmacOf(SECRETS.LEMONWAY_WEBHOOK_SECRET, LEMONWAY_BODY)), true);
  assert.equal(await used(env, 'lemonway').verify(LEMONWAY_BODY, `sha256=${hmacOf(SECRETS.LEMONWAY_WEBHOOK_SECRET, LEMONWAY_BODY)}`), false);
  // A body of any bytes, not only text.
  const binary = Buffer.from(Array.from({ length: 300 }, (_, at) => (at * 37) % 256));
  assert.equal(await used(env, 'lemonway').verify(binary, hmacOf(SECRETS.LEMONWAY_WEBHOOK_SECRET, binary)), true);
});

test('an HMAC signer signs as Node does and checks its own signatures; a verifier makes none, a private key checks none', async () => {
  const { env } = await run();
  const iframe = used(env, 'iframe-token');
  // Equisafe's iframe token: the payload base64url, then its HMAC-SHA256, base64url.
  const payload = Buffer.from(JSON.stringify({ vrId: 'vr-1', personId: 'p-1', type: 'iframe', exp: 1761480600 })).toString('base64url');
  const signature = await iframe.sign(payload);
  assert.equal(signature, hmacOf(SECRETS.IFRAME_TOKEN_SECRET, payload, 'base64url'));
  assert.equal(await iframe.verify(payload, signature), true);
  assert.equal(await iframe.verify(`${payload}x`, signature), false);
  await assert.rejects(used(env, 'yousign').sign(YOUSIGN_BODY), /yousign is a verifier, which checks signatures and makes none/);
  await assert.rejects(used(env, 'dfns-key').verify('m', 'sig'), /verify names a verifier/);
  // An environment that holds no secret for it says so, and names no value.
  const bare = await run(['market/bare']);
  const absent = (await route('/use/market/bare', { method: 'POST', headers: { authorization: `Bearer ${bare.env.COFFRE_HANDLE}`, 'content-type': 'application/json' }, body: JSON.stringify({ verify: { credential: 'yousign', message: 'aGk', signature: 'sha256=00' } }) }));
  assert.equal(absent.status, 409);
  assert.match(((await absent.json()) as { message: string }).message, /market\/bare holds no YOUSIGN_WEBHOOK_SECRET, which yousign needs/);
  // Malformed asks: a message not base64url, a signature not a string.
  for (const verify of [{ credential: 'yousign', message: 'not base64!', signature: 'x' }, { credential: 'yousign', message: 'aGk', signature: 1 }, { credential: 'yousign', message: 'a', signature: 'x' }]) {
    const refused = await route('/use/market/dev', { method: 'POST', headers: { authorization: `Bearer ${env.COFFRE_HANDLE}`, 'content-type': 'application/json' }, body: JSON.stringify({ verify }) });
    assert.equal(refused.status, 400, JSON.stringify(verify));
  }
  // The URL of a verifier, as a credential's would be, reaches nothing.
  const path = await route('/use/market/dev/yousign/v3/x', { headers: { 'x-coffre-handle': env.COFFRE_HANDLE! } });
  assert.equal(path.status, 404);
});

test("a webhook body is 64 KiB at most, or its hmac()'s maxBytes; one past it is refused before anything is opened", async () => {
  const { env } = await run();
  const before = (await entries('credential.use')).length;
  const sized = (bytes: number) => Buffer.alloc(bytes, 'a');
  const check = (name: string, secret: string, body: Buffer) => used(env, name).verify(body, `sha256=${hmacOf(secret, body)}`);
  await assert.rejects(check('yousign', SECRETS.YOUSIGN_WEBHOOK_SECRET, sized(64 * 1024 + 1)), /yousign checks a message of 64 KiB at most: its hmac\(\)'s maxBytes takes a longer one/);
  await assert.rejects(check('dfns', SECRETS.DFNS_WEBHOOK_SECRET, sized(512 * 1024 + 1)), /dfns checks a message of 512 KiB at most/);
  // Past what the longest takes, the request is not read whole.
  await assert.rejects(check('dfns', SECRETS.DFNS_WEBHOOK_SECRET, sized(600 * 1024)), /a message to sign or verify is at most 512 KiB here/);
  assert.equal((await entries('credential.use')).length, before, 'nothing opened for a message past its bound');
  assert.equal(await check('yousign', SECRETS.YOUSIGN_WEBHOOK_SECRET, sized(64 * 1024)), true);
  assert.equal(await check('dfns', SECRETS.DFNS_WEBHOOK_SECRET, sized(512 * 1024)), true);
});

test("verifies and HMAC signatures are logged once a minute per handle and name, as a credential's requests are, the vault asked once", async () => {
  const { env } = await run();
  const reads = (await entries('secret.read')).length;
  const unwrap = deps.vault.unwrap.bind(deps.vault);
  let unwrapped = 0;
  deps.vault.unwrap = (async (...args: Parameters<typeof unwrap>) => {
    unwrapped++;
    return unwrap(...args);
  }) as typeof unwrap;
  try {
    const header = `sha256=${hmacOf(SECRETS.YOUSIGN_WEBHOOK_SECRET, YOUSIGN_BODY)}`;
    for (let i = 0; i < 5; i++) assert.equal(await used(env, 'yousign').verify(YOUSIGN_BODY, header), true);
    for (let i = 0; i < 3; i++) await used(env, 'iframe-token').sign(`m${i}`);
    assert.equal(unwrapped, 2, 'one opening for each name, then the cache');
  } finally {
    deps.vault.unwrap = unwrap;
  }
  const uses = (await entries('credential.use')).filter((entry) => entry.metadata.hmac === true);
  assert.deepEqual(uses.map((entry) => [entry.metadata.credential, entry.metadata.purpose]).sort(), [['iframe-token', 'use'], ['yousign', 'use']]);
  assert.equal((await entries('secret.read')).length, reads + 2);
});

test('no byte of a secret leaves coffre: not in an answer, an entry of the log, or the console, whatever is asked', async () => {
  const lines = ['log', 'info', 'warn', 'error', 'debug'] as const;
  const original = Object.fromEntries(lines.map((line) => [line, console[line]]));
  for (const line of lines) console[line] = (...args: unknown[]) => void said.push(args.map((arg) => (arg instanceof Error ? `${arg.message} ${arg.stack}` : typeof arg === 'string' ? arg : JSON.stringify(arg))).join(' '));
  answered.length = 0;
  try {
    const { env } = await run();
    const bare = await run(['market/bare']);
    // As the app asks, or anyone holding the handle: every name, held or not, every kind of signature, and a wrong one.
    const ask = async (handle: string, path: string, body: unknown) => {
      const answer = await route(path, { method: 'POST', headers: { authorization: `Bearer ${handle}`, 'content-type': 'application/json' }, body: JSON.stringify(body) });
      answered.push(`${answer.status} ${JSON.stringify([...answer.headers])} ${await answer.text()}`);
    };
    const message = Buffer.from(YOUSIGN_BODY).toString('base64url');
    for (const name of ['yousign', 'dfns', 'lemonway', 'absent', 'iframe-token', 'dfns-key', 'nope']) {
      for (const [handle, path] of [[env.COFFRE_HANDLE!, '/use/market/dev'], [bare.env.COFFRE_HANDLE!, '/use/market/bare']] as const) {
        for (const signature of ['', 'sha256=', `sha256=${'f'.repeat(64)}`, '%%%', `sha256=${hmacOf(SECRETS.YOUSIGN_WEBHOOK_SECRET, YOUSIGN_BODY)}`]) {
          await ask(handle, path, { verify: { credential: name, message, signature } });
        }
        await ask(handle, path, { sign: { credential: name, message } });
        await ask(handle, path, { verify: { credential: name, message: '!!', signature: 'x' } });
      }
    }
  } finally {
    for (const line of lines) console[line] = original[line]!;
  }
  const log = (await db.owner.select().from(auditLog)).map((row) => JSON.stringify(row, (_, value: unknown) => (typeof value === 'bigint' ? String(value) : value)));
  const everything = [...answered, ...log, ...said].join('\n');
  assert.ok(answered.length > 60, `${answered.length} answers`);
  for (const [key, secret] of Object.entries(SECRETS)) {
    if (key === 'IFRAME_TOKEN_SECRET') continue; // A signer's signatures are its answers; its secret is not.
    for (const form of [secret, Buffer.from(secret).toString('hex'), Buffer.from(secret).toString('base64'), Buffer.from(secret).toString('base64url'), secret.slice(4, 20)]) {
      assert.ok(!everything.includes(form), `${key} leaked as ${form}`);
    }
  }
  for (const form of [SECRETS.IFRAME_TOKEN_SECRET, Buffer.from(SECRETS.IFRAME_TOKEN_SECRET).toString('base64url'), SECRETS.IFRAME_TOKEN_SECRET.slice(4, 20)]) assert.ok(!everything.includes(form), 'the HMAC signer leaked its secret');
  // Nor is the signature a verify was asked about logged: the log names the use, never what was checked.
  assert.ok(!log.join('\n').includes('f'.repeat(64)));
});

test('the configuration refuses what is no HMAC-SHA256 of these schemes', () => {
  const refused = (more: Partial<CredentialProxyOptions>, pattern: RegExp) => assert.throws(() => credentialProxy({ credentials: {}, ...more }), pattern);
  refused({ verifiers: { x: privateKey('KEY') as never } }, /verifier x is hmac\(…\), the only kind there is/);
  refused({ verifiers: { x: hmac('KEY', { encoding: 'hex32' as Encoding }) } }, /hex, base64 or base64url/);
  refused({ verifiers: { x: { ...hmac('KEY', { encoding: 'hex' }), hash: 'SHA-512' } as never } }, /SHA-256 alone; got hash/);
  refused({ verifiers: { x: hmac('KEY', { encoding: 'hex', prefix: 'sha 256=' }) } }, /prefix is up to 32 printable characters/);
  refused({ verifiers: { x: hmac('not a key', { encoding: 'hex' }) } }, /names the key that holds its secret/);
  refused({ verifiers: { X: hmac('KEY', { encoding: 'hex' }) } }, /a verifier's name is lowercase/);
  refused({ signers: { x: hmac('KEY', { encoding: 'hex' }) }, verifiers: { x: hmac('KEY', { encoding: 'hex' }) } }, /x names a signer and a verifier/);
  refused({ credentials: { x: { upstream: 'https://api.example', inject: { kind: 'header', name: 'x-key', template: '{KEY}' } } }, verifiers: { x: hmac('KEY', { encoding: 'hex' }) } }, /x names a credential and a verifier/);
  refused({ verifiers: { x: hmac('KEY', { encoding: 'hex', limit: { perMinute: 0 } }) } }, /limit is \{ perMinute\?, perDay\? \}/);
  for (const maxBytes of [0, 1.5, 17 * 1024 * 1024]) refused({ verifiers: { x: hmac('KEY', { encoding: 'hex', maxBytes }) } }, /maxBytes is a whole number of bytes, 16 MiB at most/);
});

/** coffre, as a plugin sees it: the handle stands for `market/dev`, whose one value is `secret`. */
function fake(key: string, secret: string): PluginContext {
  const unused = () => {
    throw new Error('the proxy does not call this here');
  };
  const later = new Date(Date.now() + 3_600_000).toISOString();
  return {
    publicUrl: 'https://coffre.example', api: unused, exchange: unused, signOut: unused, recheck: unused,
    workload: async () => null,
    handle: async () => ({ expiresAt: later, paths: ['market/dev'] }),
    use: async (_handle: unknown, _asked: UseAsked) => ({ values: { [key]: secret }, plain: [], keys: [key], environment: { path: 'market/dev', personal: false }, expiresAt: later }),
  } as unknown as PluginContext;
}

const settings = propertySettings(100);

test(`whatever the secret, message and scheme, coffre signs as Node's createHmac does, verifies its own, and no other signature, seed ${settings.seed}`, () => hegel.testAsync(async (tc) => {
  const secret = tc.draw(gs.text({ minSize: 1, maxSize: 64, excludeCategories: ['Cs'] }));
  const message = Buffer.from(tc.draw(gs.binary({ maxSize: 300 })));
  const encoding = tc.draw(gs.sampledFrom(['hex', 'base64', 'base64url'] as const));
  const prefix = tc.draw(gs.sampledFrom(['', 'sha256=', 'v1:', 'v1=']));
  const proxy = credentialProxy({ credentials: {}, signers: { mac: hmac('SECRET', { encoding, ...(prefix === '' ? {} : { prefix }) }) } });
  const ask = async (body: unknown) => (await (await proxy.routes!.fetch(new Request('https://coffre.example/use/market/dev', { method: 'POST', headers: { authorization: `Bearer coffre_use_${'h'.repeat(43)}`, 'content-type': 'application/json' }, body: JSON.stringify(body) }), fake('SECRET', secret))).json()) as Record<string, unknown>;
  const signed = await ask({ sign: { credential: 'mac', message: message.toString('base64url') } });
  assert.equal(signed.signature, `${prefix}${createHmac('sha256', secret).update(message).digest(encoding)}`);
  const verified = await ask({ verify: { credential: 'mac', message: message.toString('base64url'), signature: signed.signature } });
  assert.deepEqual(verified, { valid: true });
  // One character of the signature changed, past its prefix and before its padding: a match only if it names the same
  // bytes, as hex in the other case does, or base64's last character in bits no byte reads.
  const text = signed.signature as string;
  const written = text.slice(prefix.length).replace(/=+$/, '');
  const at = tc.draw(gs.integers({ minValue: 0, maxValue: written.length - 1 }));
  const replaced = tc.draw(gs.sampledFrom(['A', 'B', 'a', '0', '9']));
  const other = `${written.slice(0, at)}${replaced}${written.slice(at + 1)}`;
  const same = Buffer.from(other, encoding).equals(Buffer.from(written, encoding));
  const changed = await ask({ verify: { credential: 'mac', message: message.toString('base64url'), signature: `${prefix}${other}${text.slice(prefix.length + written.length)}` } });
  assert.deepEqual(changed, { valid: same });
  // Another message: no match.
  const longer = Buffer.concat([message, Buffer.from([tc.draw(gs.integers({ minValue: 0, maxValue: 255 }))])]);
  assert.deepEqual(await ask({ verify: { credential: 'mac', message: longer.toString('base64url'), signature: text } }), { valid: false });
}, settings));
