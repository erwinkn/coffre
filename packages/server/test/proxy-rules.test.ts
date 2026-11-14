// The credential proxy's rules that carry a key elsewhere than a header
// (docs/design/credential-proxy.md, section 5): `query()`, a parameter;
// `form()` and `json()`, a field of the body; `path()`, a segment of the
// path. 0.14.7's assertions (credential-proxy-body, -path, and the query
// cases of credential-proxy.test.ts), ported to the 0.16 fixture: a handle's
// request through each, what reaches the upstream byte for byte, what is
// refused before anything goes, the redirects that come back, and the
// value in no answer, log line or log entry.
import assert from 'node:assert/strict';
import { after, beforeEach, test } from 'node:test';

import { bodyDigest, contentDigest } from '@coffre/client/dpop';
import { generateToken } from '@coffre/core/identity';
import { rowsOf } from '@coffre/db/dialect';
import { credential, emptyDatabase, environment, grant, instance, principal, project, rewrite, role, rows, secret, value, write } from '@coffre/vault/testing';
import { sql } from 'drizzle-orm';

import { credentialProxy, form, json, path, prefix, query, type Credential, type Egress } from '../src/plugins/credential-proxy.ts';
import { openApp, PUBLIC_URL } from './app-fixture.ts';

const ADA = 'user:ada';
/** A key with what a URL and a form encode: `+`, `/`, `=`. */
const MAPS = 'maps+real/key=0123456789';
const REFRESH = 'AMf-vB+real/refresh=token_0123456789';
const TURNSTILE = '0x4AAAAAAA_real_turnstile_secret_0123';
/** A bot token as BotFather writes one: the bot's id, a colon, 35 characters. */
const TOKEN = '123456789:AAEhBP0av28dGcj4Xqp-5Yv_LxQz0123456';
const AIOGRAM = '987654321:AAFzzBP0av28dGcj4Xqp-5Yv_LxQz0654321';
const ANGLED = 'foo<bar>baz';
const ACCENTED = 'fooébaz';

/** The upstream, through each credential's egress: what it was sent, the body as its bytes, and what it answers. */
const sent: { method: string; url: URL; headers: Headers; body: Buffer }[] = [];
let answer: (url: URL, body: Buffer) => Response = () => Response.json({ ok: true });
const egress: Egress = {
  async fetch(input, init) {
    const body = Buffer.from((init.body as Uint8Array | undefined) ?? new Uint8Array());
    sent.push({ method: init.method!, url: new URL(input.href), headers: new Headers(init.headers), body });
    return answer(input, body);
  },
};

const through = (upstream: string, inject: Credential['inject'], more: Partial<Credential> = {}): Credential => ({ upstream, inject, egress, ...more });
const proxy = credentialProxy({
  credentials: {
    maps: through('https://maps.example/v1', query('key', '{MAPS_KEY}'), { methods: ['GET'], paths: ['/geocode'] }),
    gather: through('https://securetoken.example/v1', form('refresh_token', '{GATHER_REFRESH}')),
    turnstile: through('https://turnstile.example/v0', json('secret', '{TURNSTILE}')),
    'turnstile-form': through('https://turnstile.example/v0', form('secret', '{TURNSTILE}')),
    // A client that checks its key's prefix holds `pk_coffre_use_…`, and the field must be that exactly.
    shaped: through('https://shaped.example', json('secret', '{PK_KEY}'), { placeholder: prefix('pk_') }),
    telegram: through('https://tg.example/tg', path('bot{TELEGRAM}'), { methods: ['GET', 'POST'] }),
    // As aiogram wants it: the bot's id, a colon, then the handle.
    aiogram: through('https://tg.example/aio', path('bot{AIOGRAM}'), { placeholder: prefix('987654321:') }),
    // A value the test rewrites, which `pathValue` encodes or refuses; and a template whose text and a value make a segment that goes as none.
    odd: through('https://tg.example/odd', path('bot{ODD}')),
    dots: through('https://tg.example/dots', path('..{ODD}')),
    // Where the stable URL's own segments would frame the slot: a name the template frames, and a key alone under a long base path.
    bots: through('https://tg.example', path('bot{TELEGRAM}')),
    bare: through('https://tg.example/a/long/base/path/for/the/bot', path('{TELEGRAM}')),
    angled: through('https://tg.example/angled', path('bot{ANGLED}')),
    accented: through('https://tg.example/accented', path('bot{ACCENTED}')),
    failing: { upstream: 'https://tg.example/tg', inject: path('bot{TELEGRAM}'), egress: { fetch: async (url) => Promise.reject(new Error(`could not reach ${url.href} (${decodeURIComponent(url.href)})`)) } },
  },
});

const app = await openApp({ plugins: [proxy] });
const { world } = app;
after(() => app.close());

const market = project('market');
const dev = environment(market, 'dev');
/** A handle's scope: a developer of market's, as `POST /handles` makes it. */
const scopeOf = (...places: { id: string; projectId: string }[]) => JSON.stringify(places.map((place) => ({ projectId: place.projectId, environmentId: place.id, role: 'developer' })));

let handle: string;
let odd: { id: string };

/** ODD's next value, past the vault's memory (two seconds), as a request a moment later is. */
async function oddIs(text: string): Promise<void> {
  await rewrite(world, odd, text);
  world.memory.reads.clear();
  world.memory.callers.clear();
}

/** A handle of ADA's for `place`, as `coffre run` makes one. */
async function handleFor(place: { id: string; projectId: string }): Promise<string> {
  const token = generateToken('handle');
  await write(world, ...rows('credentials', credential(token, ADA, { kind: 'handle', scope: scopeOf(place), places: JSON.stringify([{ environmentId: place.id, personal: false }]), expiresAt: new Date(Date.now() + 3_600_000) })));
  return token;
}

beforeEach(async () => {
  await emptyDatabase(world.owner);
  for (const kept of [world.memory.reads, world.memory.callers, world.memory.logged, world.memory.touched, world.refused]) kept.clear();
  sent.length = 0;
  answer = () => Response.json({ ok: true });
  const held = { MAPS_KEY: [MAPS], GATHER_REFRESH: [REFRESH], TURNSTILE: [TURNSTILE, true], PK_KEY: [TURNSTILE], TELEGRAM: [TOKEN, true], AIOGRAM: [AIOGRAM], ODD: ['a+b=c'], ANGLED: [ANGLED, true], ACCENTED: [ACCENTED, true] } as const;
  const made = Object.entries(held).map(([key, [text, sensitive]]) => value(world, secret(dev, key), text, { sensitive: sensitive === true }));
  odd = made.find((row) => row.key === 'ODD')!;
  await write(
    world,
    ...rows('policy', instance()),
    ...rows('roles', role(true, 'owner', ['secret.read']), role(true, 'member', []), role(false, 'developer', ['secret.read', 'secret.use', 'secret.write'])),
    ...rows('projects', market),
    ...rows('environments', dev),
    ...rows('principals', principal(ADA)),
    ...rows('grants', grant(ADA, 'developer', { project: market })),
    ...rows('secrets', ...made),
  );
  handle = await handleFor(dev);
  app.calls.length = 0;
});

const FORM = { 'content-type': 'application/x-www-form-urlencoded' };
const JSON_TYPE = { 'content-type': 'application/json' };
const post = (url: string, headers: Record<string, string>, body?: string | Uint8Array<ArrayBuffer>) => app.request(url, { method: 'POST', headers, ...(body === undefined ? {} : { body }) });
const formEncoded = (text: string) => new URLSearchParams({ v: text }).toString().slice(2);
const redirect = (location: string, status = 302) => new Response(null, { status, headers: { location } });
const message = async (response: Response) => ((await response.json()) as { message: string }).message;
/** Every form of the bot token an answer or a log line may carry it in. */
const free = (text: string, value = TOKEN) => [value, encodeURIComponent(value), value.replace(':', '%3a')].every((form) => !text.includes(form));

/** What `work` logs, every line, while it runs. */
async function logs<T>(work: () => Promise<T>): Promise<{ result: T; said: string }> {
  const said: string[] = [];
  const kept = { log: console.log, warn: console.warn, error: console.error, info: console.info, debug: console.debug };
  for (const level of Object.keys(kept) as (keyof typeof kept)[]) console[level] = (...args: unknown[]) => void said.push(args.map((arg) => (typeof arg === 'string' ? arg : JSON.stringify(arg))).join(' '));
  try {
    return { result: await work(), said: said.join('\n') };
  } finally {
    Object.assign(console, kept);
  }
}

test("a query rule puts the value in its parameter, the rest of the query as sent; methods and paths are read before anything is opened", async () => {
  for (const url of [`/use/maps/geocode?address=paris&key=${handle}`, `/use/market/dev/maps/geocode?address=paris&key=${handle}`]) {
    const got = await app.request(url);
    assert.equal(got.status, 200, await got.clone().text());
    assert.deepEqual([sent.at(-1)!.url.pathname, [...sent.at(-1)!.url.searchParams]], ['/v1/geocode', [['address', 'paris'], ['key', MAPS]]]);
  }
  app.calls.length = 0;
  assert.equal((await app.request(`/use/market/dev/maps/geocode?key=${handle}`, { method: 'POST' })).status, 405);
  assert.equal((await app.request(`/use/market/dev/maps/other?key=${handle}`)).status, 403);
  assert.deepEqual([app.calls, sent.length], [[], 2], 'nothing opened, nothing sent');
});

test("a query rule's redirect under the upstream keeps the handle in the key's parameter, and an echo of the value, encoded, is redacted", async () => {
  answer = (url) => (url.pathname.endsWith('/bare') ? redirect('/v1/geocode/', 301) : redirect(`/v1/geocode/?address=paris&key=${encodeURIComponent(MAPS)}`, 301));
  const moved = await app.request(`/use/maps/geocode/redirect?address=paris&key=${handle}`);
  assert.equal(moved.status, 301);
  const to = new URL(moved.headers.get('location')!);
  assert.deepEqual([to.origin + to.pathname, to.searchParams.get('key'), to.searchParams.get('address')], [`${PUBLIC_URL}/use/market/dev/maps/geocode/`, handle, 'paris']);
  // A parameter that stands in for no handle, beside x-coffre-handle, gets the handle; a query the redirect dropped gets it back.
  const helped = await app.request('/use/market/dev/maps/geocode/redirect?key=unused', { headers: { 'x-coffre-handle': handle } });
  assert.equal(new URL(helped.headers.get('location')!).searchParams.get('key'), handle);
  const bare = await app.request(`/use/market/dev/maps/geocode/bare?key=${handle}`);
  assert.equal(new URL(bare.headers.get('location')!).searchParams.get('key'), handle);
  answer = (url) => Response.json({ url: url.href, raw: url.search });
  const echoed = await (await app.request(`/use/maps/geocode/echo?key=${handle}`)).text();
  assert.ok([MAPS, encodeURIComponent(MAPS), formEncoded(MAPS)].every((form) => !echoed.includes(form)), echoed);
});

test("a form rule (Gather's token refresh) fills its field, form-encoded, and every other byte goes as the app sent it", async () => {
  // As Firebase's client sends it: the API key, no secret, in the query; the stable URL.
  const got = await post('/use/gather/token?key=AIzaSy-public', FORM, `grant_type=refresh_token&refresh_token=${handle}`);
  assert.equal(got.status, 200, await got.clone().text());
  assert.equal(sent[0]!.url.href, 'https://securetoken.example/v1/token?key=AIzaSy-public');
  assert.equal(sent[0]!.body.toString(), `grant_type=refresh_token&refresh_token=${formEncoded(REFRESH)}`);
  assert.equal(sent[0]!.headers.get('content-type'), 'application/x-www-form-urlencoded');
  // The environment's URL; the field's name encoded, among empty pairs and others as written.
  const written = `a=%E2%9C%93&&refresh%5Ftoken=${handle.replace('_', '%5F')}&b=x+y&c`;
  assert.equal((await post('/use/market/dev/gather/token', { 'content-type': 'application/x-www-form-urlencoded; charset=UTF-8' }, written)).status, 200);
  assert.equal(sent[1]!.body.toString(), `a=%E2%9C%93&&refresh%5Ftoken=${formEncoded(REFRESH)}&b=x+y&c`);
  // Raw bytes past ASCII in another pair, UTF-8 or not, go on byte for byte.
  const raw = Buffer.concat([Buffer.from('note=✓€'), Buffer.from([0x80, 0x9f, 0xff]), Buffer.from(`&refresh_token=${handle}`)]);
  assert.equal((await post('/use/gather/token', FORM, new Uint8Array(raw))).status, 200);
  assert.deepEqual(sent[2]!.body, Buffer.concat([raw.subarray(0, raw.length - handle.length), Buffer.from(formEncoded(REFRESH))]));
});

test("a JSON rule (Turnstile's siteverify) fills its field and keeps every other byte, spacing and a number too long for a double; a form rule fills the same key", async () => {
  const written = `{ "response" : "XXXX.DUMMY.TOKEN",\n  "secret":"${handle}", "secret_hint": "a name that begins as the field's", "n": 12345678901234567890123, "nested": { "secret": "kept" } }`;
  const got = await post('/use/turnstile/siteverify', { ...JSON_TYPE, 'content-digest': contentDigest(await bodyDigest(written)) }, written);
  assert.equal(got.status, 200, await got.clone().text());
  const expected = written.replace(handle, TURNSTILE);
  assert.equal(sent[0]!.body.toString(), expected);
  assert.equal(sent[0]!.headers.get('content-digest'), contentDigest(await bodyDigest(expected)), 'the digest that goes on is of what goes on');
  // A value JSON escapes stays as JSON writes it; a byte order mark is kept where it is.
  assert.equal((await post('/use/market/dev/turnstile/siteverify', { 'content-type': 'application/json; charset="utf-8"' }, JSON.stringify({ secret: handle, response: 'é"' }))).status, 200);
  assert.deepEqual(JSON.parse(sent[1]!.body.toString()), { secret: TURNSTILE, response: 'é"' });
  assert.equal((await post('/use/turnstile/siteverify', JSON_TYPE, `﻿{"secret":"${handle}"}`)).status, 200);
  assert.deepEqual(sent[2]!.body, Buffer.from(`﻿{"secret":"${TURNSTILE}"}`));
  assert.equal((await post('/use/turnstile-form/siteverify', FORM, `secret=${handle}&response=XXXX`)).status, 200);
  assert.equal(sent[3]!.body.toString(), `secret=${TURNSTILE}&response=XXXX`);
});

test('an upstream that echoes the body gives the app none of the value, JSON or form', async () => {
  answer = (_url, body) => Response.json({ got: body.toString() });
  const echoed = await (await post('/use/turnstile/echo', JSON_TYPE, JSON.stringify({ secret: handle }))).text();
  assert.ok(sent[0]!.body.toString().includes(TURNSTILE), 'it went out');
  assert.ok(!echoed.includes(TURNSTILE) && echoed.includes('redacted by coffre'), echoed);
  const formed = await (await post('/use/gather/echo', FORM, `refresh_token=${handle}`)).text();
  assert.ok(!formed.includes('real/refresh') && !formed.includes('real%2Frefresh'), formed);
});

test('a handle anywhere but its field, a body of another type, too large, malformed, or without the field once is refused, quoting nothing, and nothing goes', async () => {
  const cases: [string, string, Record<string, string>, string | Uint8Array<ArrayBuffer> | undefined, number][] = [
    ['gather', 'no field', FORM, 'grant_type=refresh_token', 400],
    ['gather', 'the field twice', FORM, `refresh_token=${handle}&refresh_token=${handle}`, 400],
    ['gather', 'a name PHP reads as the field', FORM, `refresh_token=${handle}&refresh.token=x`, 400],
    ['gather', 'a name qs reads as the field', FORM, `refresh_token[0]=x&refresh_token=${handle}`, 400],
    ['gather', 'the handle percent-encoded in another field', FORM, `refresh_token=${handle}&note=${handle.replace('_', '%5F')}`, 400],
    ['gather', "the handle in another field's name", FORM, `refresh_token=${handle}&${handle}=1`, 400],
    ['gather', 'the handle in another field, the field without it', FORM, `refresh_token=x&note=${handle}`, 401],
    ['gather', 'JSON to a form rule', JSON_TYPE, JSON.stringify({ refresh_token: handle }), 415],
    ['gather', 'another charset', { 'content-type': 'application/x-www-form-urlencoded; charset=iso-8859-1' }, `refresh_token=${handle}`, 415],
    ['gather', 'compressed', { ...FORM, 'content-encoding': 'gzip' }, `refresh_token=${handle}`, 415],
    ['gather', 'past 64 KiB', FORM, `refresh_token=${handle}&pad=${'x'.repeat(64 * 1024)}`, 413],
    ['gather', 'no body', FORM, undefined, 400],
    ['gather', 'more than 256 fields', FORM, `refresh_token=${handle}${'&'.repeat(300)}`, 400],
    ['turnstile', 'malformed', JSON_TYPE, `{"secret":"${handle}",}`, 400],
    ['turnstile', 'no object', JSON_TYPE, JSON.stringify([{ secret: handle }]), 400],
    ['turnstile', 'not UTF-8', JSON_TYPE, new Uint8Array([...Buffer.from(`{"secret":"${handle}","x":"`), 0xff, ...Buffer.from('"}')]), 400],
    ['turnstile', 'the field nested only', JSON_TYPE, JSON.stringify({ data: { secret: handle } }), 400],
    ['turnstile', 'the field twice, once escaped', JSON_TYPE, `{"secret":"${handle}","\\u0073ecret":"x"}`, 400],
    ['turnstile', 'the field twice, as Go folds case', JSON_TYPE, `{"Secret":"x","secret":"${handle}"}`, 400],
    ['turnstile', 'the field twice, as Go folds the long s', JSON_TYPE, `{"secret":"${handle}","ſecret":"x"}`, 400],
    ['turnstile', 'the field no string', JSON_TYPE, `{"secret":{"value":"${handle}"}}`, 400],
    ['turnstile', 'the handle escaped in another field', JSON_TYPE, `{"secret":"${handle}","response":"\\u0063${handle.slice(1)}"}`, 400],
    ['turnstile', 'the handle nested', JSON_TYPE, JSON.stringify({ secret: handle, nested: [{ deep: handle }] }), 400],
    ['turnstile', 'nested deeper than 32', JSON_TYPE, `{"secret":"${handle}","x":${'['.repeat(40)}${']'.repeat(40)}}`, 400],
    ['turnstile', 'text/plain', { 'content-type': 'text/plain' }, JSON.stringify({ secret: handle }), 415],
  ];
  for (const [name, what, headers, body, status] of cases) {
    for (const url of [`/use/${name}/x`, `/use/market/dev/${name}/x`]) {
      const refused = await post(url, headers, body);
      const text = await refused.text();
      assert.deepEqual([refused.status, refused.headers.get('coffre-proxy')], [status, 'refused'], `${what}, ${url}: ${text}`);
      assert.ok(!text.includes(handle) && !text.includes(TURNSTILE) && !text.includes(REFRESH), `${what}: nothing of the body is quoted`);
    }
  }
  // x-coffre-handle lets the request in, and the field must hold that handle.
  assert.equal((await post('/use/market/dev/gather/x', { ...FORM, 'x-coffre-handle': handle }, 'refresh_token=mine')).status, 400);
  assert.equal(sent.length, 0);
});

test("a project named like a body credential: the route the handle decides sends the body as the stable URL read it", async () => {
  const named = project('gather');
  const own = environment(named, 'dev');
  await write(world, ...rows('projects', named), ...rows('environments', own), ...rows('grants', grant(ADA, 'developer', { project: named })), ...rows('secrets', value(world, secret(own, 'TURNSTILE'), 'own-turnstile-secret-0123')));
  const ours = await handleFor(own);
  // A handle for gather/dev: the environment's route, through turnstile, though gather's stable URL refuses the body (JSON, to a form rule).
  assert.equal((await post('/use/gather/dev/turnstile/siteverify', JSON_TYPE, JSON.stringify({ secret: ours }))).status, 200);
  assert.deepEqual([sent[0]!.url.pathname, sent[0]!.body.toString()], ['/v0/siteverify', JSON.stringify({ secret: 'own-turnstile-secret-0123' })]);
  // A handle for market/dev: the stable URL of gather, /dev/turnstile/… under it, though turnstile refuses the form.
  assert.equal((await post('/use/gather/dev/turnstile/x', FORM, `refresh_token=${handle}`)).status, 200);
  assert.deepEqual([sent[1]!.url.pathname, new URLSearchParams(sent[1]!.body.toString()).get('refresh_token')], ['/v1/dev/turnstile/x', REFRESH]);
});

test("a shaped placeholder in a field must be that shape exactly; a body rule's configuration names a field and a key", async () => {
  assert.equal((await post('/use/shaped/x', JSON_TYPE, JSON.stringify({ secret: handle }))).status, 401);
  assert.equal((await post('/use/shaped/x', JSON_TYPE, JSON.stringify({ secret: `pk_${handle}` }))).status, 200);
  assert.equal(sent.at(-1)!.body.toString(), JSON.stringify({ secret: TURNSTILE }));
  const make = (inject: Credential['inject']) => () => credentialProxy({ credentials: { bad: { upstream: 'https://api.example.com', inject } } });
  assert.throws(make(form('a b', '{K}')), /no field name/);
  assert.throws(make(form('_', '{K}')), /a letter or digit among them/);
  assert.throws(make(json('secret', 'literal')), /names no key/);
});

test('a path rule puts the token in the segment the app put its handle in, a method call or a file download; a shaped one fills its shape exactly', async () => {
  // As an SDK writes it, `${apiRoot}/bot${token}/${method}`: on the stable URL and the environment's.
  assert.equal((await post(`/use/telegram/bot${handle}/sendMessage`, JSON_TYPE, '{"chat_id":1}')).status, 200);
  assert.deepEqual([sent[0]!.method, sent[0]!.url.pathname, sent[0]!.body.toString()], ['POST', `/tg/bot${TOKEN}/sendMessage`, '{"chat_id":1}']);
  answer = () => new Response(new Uint8Array([0xff, 0xd8, 0xff, 0xe0]), { headers: { 'content-type': 'image/jpeg' } });
  const file = await app.request(`/use/market/dev/telegram/file/bot${handle}/photos/file_0.jpg`);
  assert.deepEqual(new Uint8Array(await file.arrayBuffer()), new Uint8Array([0xff, 0xd8, 0xff, 0xe0]));
  assert.equal(sent[1]!.url.pathname, `/tg/file/bot${TOKEN}/photos/file_0.jpg`);
  // x-coffre-handle beside it, the same handle: the segment is filled all the same.
  assert.equal((await app.request(`/use/telegram/bot${handle}/getMe`, { headers: { 'x-coffre-handle': handle } })).status, 200);
  assert.equal(sent[2]!.url.pathname, `/tg/bot${TOKEN}/getMe`);
  assert.ok(sent.every((one) => !one.url.href.includes(handle) && ![...one.headers].some(([, text]) => text.includes(handle))));
  assert.equal((await app.request(`/use/aiogram/bot987654321:${handle}/getMe`)).status, 200);
  assert.equal(sent[3]!.url.pathname, `/aio/bot${AIOGRAM}/getMe`);
  assert.equal((await app.request(`/use/aiogram/bot${handle}/getMe`)).status, 401, 'the bare handle is out of its shape');
  // The stable URL finds the handle in the segment under each credential's own upstream.
  assert.equal((await app.request(`/use/bots/bot${handle}/getMe`)).status, 200);
  assert.equal(sent.at(-1)!.url.pathname, `/bot${TOKEN}/getMe`);
  assert.equal((await app.request(`/use/bare/${handle}/getMe`)).status, 200);
  assert.equal(sent.at(-1)!.url.pathname, `/a/long/base/path/for/the/bot/${TOKEN}/getMe`);
});

test('a path rule reads methods before the value is in, and a path with no such segment, or its handle elsewhere, is refused with nothing opened or sent', async () => {
  const other = await handleFor(dev);
  assert.equal((await app.request(`/use/telegram/bot${handle}/getMe`, { method: 'DELETE' })).status, 405);
  const none = await app.request('/use/telegram/getMe/x', { headers: { 'x-coffre-handle': handle } });
  assert.deepEqual([none.status, await message(none)], [400, 'telegram takes its key in a segment of the path, bot{TELEGRAM}, and this path has none']);
  assert.deepEqual(app.calls, [], 'nothing opened');
  // The first segment `bot…` frames holds no handle: none where telegram takes it, or, with x-coffre-handle, not there.
  assert.equal((await app.request(`/use/telegram/botx/bot${handle}`)).status, 401);
  const elsewhere = await app.request(`/use/telegram/botx/bot${handle}`, { headers: { 'x-coffre-handle': handle } });
  assert.deepEqual([elsewhere.status, await message(elsewhere)], [400, 'the handle is not in the segment of the path where telegram takes its key, bot{TELEGRAM}']);
  for (const url of [`/use/telegram/bot${handle}/bot${handle}`, `/use/telegram/bot${handle}/getMe?token=${handle}`, `/use/telegram/bot${handle}/${handle}`]) {
    const leaked = await app.request(url);
    assert.deepEqual([leaked.status, await message(leaked)], [400, 'the handle is somewhere telegram does not take its key: the URL'], url);
  }
  assert.equal((await app.request(`/use/telegram/bot${handle}/getMe`, { headers: { 'x-coffre-handle': other } })).status, 400);
  assert.equal((await app.request(`/use/telegram/bot${other}/x${handle}`)).status, 400);
  assert.equal(sent.length, 0);
});

test('a path value goes percent-encoded; one that would change the path, or that a server reads as no segment, is a 409 naming the key, never the value', async () => {
  assert.equal((await app.request(`/use/odd/bot${handle}/getMe`)).status, 200);
  assert.equal(sent[0]!.url.pathname, '/odd/bota%2Bb%3Dc/getMe');
  for (const text of ['12:ab/../../admin', '..', '12:ab?x=1', '12:ab#x', '12:%2e%2e', 'a;jsessionid=1', 'a b', '12:ab\\x']) {
    await oddIs(text);
    const { result: refused, said } = await logs(() => app.request(`/use/odd/bot${handle}/getMe`));
    assert.deepEqual([refused.status, await message(refused)], [409, "odd's ODD is no segment of a path: empty, or with a /, \\, ?, #, %, ;, .., a space or a control character in it"], text);
    assert.ok(!said.includes(text), text);
  }
  await oddIs('.');
  assert.equal((await app.request(`/use/dots/..${handle}/getMe`)).status, 409, '`..` and `.` make `...`, which goes as no segment');
  assert.equal(sent.length, 1);
});

test("a path rule's redirect under the upstream that quotes the token, as sent or encoded otherwise, gets the app's placeholder back, relative ones against the URL the app sent", async () => {
  const proxied = `${PUBLIC_URL}/use/market/dev/telegram`;
  const cases: [string, (url: URL) => string, string][] = [
    [`bot${handle}/moved`, (url) => url.pathname.replace(/moved$/, 'getMe'), `${proxied}/bot${handle}/getMe`],
    [`bot${handle}/rel`, () => 'getMe', `${proxied}/bot${handle}/getMe`],
    [`bot${handle}/offset`, () => '?offset=1', `${proxied}/bot${handle}/offset?offset=1`],
    [`bot${handle}/here`, () => '', `${proxied}/bot${handle}/here`],
    [`bot${handle}/lower`, (url) => url.pathname.replace(/lower$/, 'getMe').replace(':', '%3a'), `${proxied}/bot${handle}/getMe`],
    [`bot${handle}/spelled`, (url) => url.pathname.replace(/spelled$/, 'getMe').replace('AAE', '%41AE'), `${proxied}/bot${handle}/getMe`],
    // Relative, its first segment the token's, its colon encoded: the app's, under the same parent.
    [`x/bot${handle}`, (url) => `${url.pathname.split('/').at(-1)!.replace(':', '%3A')}/getMe`, `${proxied}/x/bot${handle}/getMe`],
    // A query that ends in a space once its fragment goes: a cursor is the upstream's to the byte.
    [`bot${handle}/spaced`, (url) => `${url.pathname.replace(/spaced$/, 'getMe')}?cursor=abc #top`, `${proxied}/bot${handle}/getMe?cursor=abc%20`],
  ];
  for (const [at, location, want] of cases) {
    answer = (url) => redirect(location(url));
    const moved = await app.request(`/use/telegram/${at}`);
    assert.deepEqual([moved.status, moved.headers.get('location')], [302, want], at);
  }
  // Absolute, the token again in its query: the segment the app's, the rest redacted.
  answer = (url) => redirect(`https://tg.example${url.pathname.replace(/absolute$/, 'getMe')}?again=${encodeURIComponent(decodeURIComponent(url.pathname))}`, 307);
  const location = (await app.request(`/use/telegram/bot${handle}/absolute`)).headers.get('location')!;
  assert.ok(location.startsWith(`${proxied}/bot${handle}/getMe?again=`) && free(location) && free(decodeURIComponent(location)), location);
  // A shaped token: `bot987654321%3a…` swapped back before the URL is read would be the scheme `bot987654321:`.
  answer = (url) => redirect(`${url.pathname.split('/').at(-1)!.replace(':', '%3a')}/getMe`);
  assert.equal((await app.request(`/use/aiogram/x/bot987654321:${handle}`)).headers.get('location'), `${PUBLIC_URL}/use/market/dev/aiogram/x/bot987654321:${handle}/getMe`);
});

test("a path rule's redirect elsewhere, or quoting the token in a form coffre does not mask, is a 502 that quotes nothing; an echo and an egress's error are redacted", async () => {
  const segment = (url: URL) => url.pathname.split('/').find((part) => part.startsWith('bot'))!;
  const cases: [string, (url: URL) => string][] = [
    ['telegram/bot{h}/away', (url) => `https://elsewhere.example${url.pathname}`],
    ['telegram/bot{h}/twice', (url) => url.pathname.replace(/twice$/, 'getMe').replace(':', '%253A')],
    ['telegram/bot{h}/twicequery', (url) => `/tg/getMe?t=${segment(url).slice(3).replace(':', '%253A')}`],
    ['telegram/bot{h}/quoted', (url) => `/tg/getMe?t=${segment(url).slice(3).replace(':', '%3a')}`],
    // A relative one whose first segment holds a raw colon reads as a scheme, not a path.
    ['telegram/x/bot{h}', (url) => `${segment(url)}/getMe`],
    // A value JSON escapes, quoted so in the path: each escape's backslash a `/` to a URL's parser.
    ['angled/bot{h}/go', () => `/angled/echo-${JSON.stringify(ANGLED).slice(1, -1).replace(/[<>&]/g, (char) => `\\u00${char.charCodeAt(0).toString(16)}`)}`],
    ['accented/bot{h}/python', () => `/accented/echo-${'foo\\u00e9baz'}`],
  ];
  for (const [at, location] of cases) {
    answer = (url) => redirect(location(url));
    const moved = await app.request(`/use/${at.replace('{h}', handle)}`);
    const said = await moved.text();
    assert.deepEqual([moved.status, moved.headers.get('location')], [502, null], at);
    for (const value of [TOKEN, ANGLED, ACCENTED]) assert.ok(free(said, value) && free(decodeURIComponent(said), value), said);
  }
  answer = (url) => new Response(`no route for ${url.pathname} (${decodeURIComponent(url.pathname)})`, { status: 404, headers: { 'content-type': 'text/plain', 'x-path': url.pathname } });
  const echoed = await app.request(`/use/telegram/bot${handle}/echo`);
  const page = await echoed.text();
  assert.ok(free(page) && free(echoed.headers.get('x-path')!) && page.includes('[redacted by coffre]'), page);
  const { result: failed, said } = await logs(() => app.request(`/use/failing/bot${handle}/getMe`));
  const text = await failed.text();
  assert.equal(failed.status, 502);
  assert.match(text, /could not reach .*\[redacted by coffre\]/);
  assert.ok(free(text) && free(said), text);
});

test('a path rule\'s token is in no log line, log entry or refusal, and the use names the credential', async () => {
  answer = (url) => (url.pathname.endsWith('/moved') ? redirect(url.pathname.replace(/moved$/, 'getMe')) : url.pathname.endsWith('/away') ? redirect('https://elsewhere.example/') : Response.json({ ok: true }));
  const { said } = await logs(async () => {
    for (const [method, at] of [['POST', 'sendMessage'], ['GET', 'moved'], ['GET', 'away'], ['DELETE', 'a/b']]) await (await app.request(`/use/telegram/bot${handle}/${at}`, { method })).text();
    await (await app.request(`/use/failing/bot${handle}/getMe`)).text();
  });
  assert.ok(free(said), said);
  const entries = (await rowsOf<{ body: string }>(world.owner, sql`SELECT body FROM log_pending ORDER BY id`)).map((row) => JSON.parse(row.body) as { action: string; detail: { credential?: string } });
  assert.ok(free(JSON.stringify(entries)) && !JSON.stringify(entries).includes(handle));
  assert.ok(entries.some((entry) => entry.detail.credential === 'telegram'));
});

test('a path rule is one segment naming one key once, and its placeholder prefix has no slash', () => {
  const make = (more: Partial<Credential>) => () => credentialProxy({ credentials: { a: { upstream: 'https://api.telegram.org', inject: path('bot{K}'), ...more } } });
  assert.doesNotThrow(make({}));
  for (const template of ['bot{K}{L}', 'bot/{K}', '{K}?', 'bot%20{K}', 'bot', 'a;{K}']) assert.throws(make({ inject: path(template) }), /a's path\(\) is one segment naming one key once/, template);
  assert.throws(make({ placeholder: prefix('a/b') }), /a's prefix\(\) has a \/, and its path\(\) rule takes the placeholder in one segment/);
});
