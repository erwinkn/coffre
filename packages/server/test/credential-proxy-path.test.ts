// A path rule (docs/design/credential-proxy.md, section 5, "A segment of the path"), end to end:
// coffre's own vault, a handle as `coffre run` makes one, and a fake Telegram Bot API over HTTP. A method call and a
// file download, each with the token in its path; the allow list read on the path as the app sent it; a value that
// would change the path's shape, refused; a redirect quoting the token, given back the app's placeholder; an echo,
// redacted; and the token in no log line, no audit row and no refusal.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type IncomingMessage, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

import { createClient } from '@coffre/client';
import { defineDeployment } from '@coffre/core/deployment';

import { clientFor, loggedEntries, usesLogged } from './api-fixture.ts';
import { db, deps, DEV, entries, ORIGIN, ROOT, route, runtime, sessionFor, useMcp } from './mcp-fixture.ts';
import { auditLog } from '@coffre/db/schema';
import { coffreRoute } from '../src/app.ts';
import { checkPlugins } from '../src/plugins.ts';
import { credentialProxy, header, path, prefix, query, sigv4, type Credential, type CredentialProxyOptions } from '../src/plugins/credential-proxy.ts';

/** A bot token as BotFather writes one: the bot's id, a colon, 35 characters. */
const TOKEN = '123456789:AAEhBP0av28dGcj4Xqp-5Yv_LxQz0123456';
const AIOGRAM = '987654321:AAFzzBP0av28dGcj4Xqp-5Yv_LxQz0654321';
const TENANT = 'tenant-0123456789abcdef';
const ACCOUNT = 'acct_1Plain0123456';
const ESCAPED = '%41%42%43%44%45%46%47%48';
/** Escapes as written and punctuation a URL's parser encodes: `'` in a query, `"` in a path. */
const PUNCTUATED = `${ESCAPED}'"`;
/** Values a JSON string escapes, each its own way: Go `<` and `>`, Python what is past ASCII, PHP `/`. */
/** A key long enough to mask that reads, as a URL's client reads it, shorter than that: `ABC"`. */
const SHORTENED = '%41%42%43"';
const ANGLED = 'foo<bar>baz';
const ACCENTED = 'foo\u00e9baz';
const SLASHED = 'foo/bar/baz';

let upstream: Server;
let upstreamUrl: string;
const reached: { method: string; url: string; headers: IncomingMessage['headers'] }[] = [];

before(async () => {
  upstream = createServer((request, response) => {
    request.resume();
    request.on('end', () => {
      const url = request.url!;
      reached.push({ method: request.method!, url, headers: request.headers });
      // A redirect quoting the path as it came, token and all; one to the token's own page elsewhere; one with the token in its query.
      if (url.endsWith('/moved')) response.writeHead(302, { location: url.replace(/moved$/, 'getMe') }).end();
      else if (url.endsWith('/absolute')) response.writeHead(307, { location: `${upstreamUrl}${url.replace(/absolute$/, 'getMe')}?again=${encodeURIComponent(decodeURIComponent(url))}` }).end();
      else if (url.endsWith('/away')) response.writeHead(302, { location: `https://elsewhere.example${url}` }).end();
      // Relative ones, which resolve against the URL the token went out in.
      else if (url.endsWith('/relative')) response.writeHead(302, { location: 'getMe' }).end();
      else if (url.endsWith('/offset')) response.writeHead(302, { location: '?offset=1' }).end();
      else if (url.endsWith('/fragment')) response.writeHead(302, { location: '#top' }).end();
      else if (url.endsWith('/here')) response.writeHead(302, { location: '' }).end();
      // The token's segment encoded otherwise than it went (`%3a`, `%41` for `A`), and the token so encoded in a query.
      else if (url.endsWith('/lower')) response.writeHead(302, { location: url.replace(/lower$/, 'getMe').replace(':', '%3a') }).end();
      else if (url.endsWith('/spelled')) response.writeHead(302, { location: url.replace(/spelled$/, 'getMe').replace('AAE', '%41AE') }).end();
      else if (url.endsWith('/quoted')) response.writeHead(302, { location: `/tg/getMe?t=${url.split('/')[2]!.slice(3).replace(':', '%3a')}` }).end();
      // A relative redirect whose first segment is the token's, `%3A` or `%3a` for its colon.
      else if (url.includes('?first=')) {
        const [segment, way] = url.split('/').at(-1)!.split('?first=') as [string, string];
        // `raw` keeps the colon: a relative Location whose first segment reads as a scheme.
        response.writeHead(302, { location: `${way === 'raw' ? segment : segment.replace(':', way === 'upper' ? '%3A' : '%3a')}/getMe` }).end();
      }
      // The token's colon encoded twice, `%253A`, in a path and in a query: after one decoding it is `%3A`, not the token.
      else if (url.endsWith('/twice')) response.writeHead(302, { location: url.replace(/twice$/, 'getMe').replace(':', '%253A') }).end();
      else if (url.endsWith('/twicequery')) response.writeHead(302, { location: `/tg/getMe?t=${url.split('/')[2]!.slice(3).replace(':', '%253A')}` }).end();
      // An absolute redirect to the path as it came, where the value is the upstream's own host and port.
      else if (url.endsWith('/loop')) response.writeHead(302, { location: `${upstreamUrl}${url.replace(/loop$/, 'getMe')}` }).end();
      // A query rule's value quoted in a redirect's query as it is, `%41%42…`, which `searchParams` would write `AB…`.
      // A field named `?api_key`, which is not the rule's.
      else if (url.includes('/echoquery') || url.includes('/echopath')) {
        const sent = new URL(url, upstreamUrl).searchParams.get('api_key')!;
        const base = url.slice(0, url.search(/\/echo(query|path)/));
        const location = url.includes('/echoquery') ? `${base}/getMe?echo=${sent}&api_key=${sent}&keep=%7e&?api_key=cursor&api_key=again` : `${base}/x${sent}/getMe`;
        response.writeHead(302, { location }).end();
      }
      // The value, the path rule's or the query rule's, quoted in a redirect's path as a JSON string writes it: Go's
      // `\u003c`, Python's `\u00e9`, PHP's `\/`, each backslash a `/` to a URL's parser.
      else if (url.includes('/jsonecho')) {
        const at = new URL(url, upstreamUrl);
        const sent = at.searchParams.get('k') ?? decodeURIComponent(at.pathname.split('/')[2]!.slice(3));
        const js = JSON.stringify(sent).slice(1, -1);
        const how = at.searchParams.get('how');
        const quoted = how === 'go' ? js.replace(/[<>&]/g, (char) => `\\u00${char.charCodeAt(0).toString(16)}`) : how === 'python' ? js.replace(/[\u0080-\uffff]/g, (char) => `\\u${char.charCodeAt(0).toString(16).padStart(4, '0')}`) : js.replaceAll('/', '\\/');
        response.writeHead(302, { location: `/${at.pathname.split('/')[1]}/echo-${quoted}` }).end();
      }
      // A query that ends in a space once its fragment goes.
      else if (url.endsWith('/spaced')) response.writeHead(302, { location: `${url.replace(/spaced$/, 'getMe')}?cursor=abc #top` }).end();
      // An error page that quotes the request, as a framework's 404 may: as it came, and decoded.
      else if (url.endsWith('/echo')) response.writeHead(404, { 'content-type': 'text/plain', 'x-path': url }).end(`no route for ${url} (${decodeURIComponent(url)})`);
      else if (url.includes('/file/')) response.writeHead(200, { 'content-type': 'image/jpeg' }).end(Buffer.from([0xff, 0xd8, 0xff, 0xe0]));
      else response.writeHead(200, { 'content-type': 'application/json' }).end('{"ok":true,"result":{}}');
    });
  });
  await new Promise<void>((resolve) => upstream.listen(0, '127.0.0.1', resolve));
  upstreamUrl = `http://127.0.0.1:${(upstream.address() as AddressInfo).port}`;
});

after(() => new Promise<void>((resolve) => upstream.close(() => resolve())));

function options(): CredentialProxyOptions {
  return {
    credentials: {
      telegram: {
        upstream: `${upstreamUrl}/tg`,
        inject: path('bot{TELEGRAM_BOT_TOKEN}'),
        allow: [{ methods: ['POST'], path: '/*/sendMessage' }, { methods: ['GET'], path: '/*/*' }, { methods: ['GET'], path: '/file/*/**' }],
      },
      // As aiogram wants it: the bot's id, a colon, then the handle.
      aiogram: { upstream: `${upstreamUrl}/aio`, inject: path('bot{AIOGRAM_TOKEN}'), placeholder: prefix('987654321:') },
      // A value of the environment's that `pathValue` encodes, or refuses: `BOT_VALUE` set per test.
      odd: { upstream: `${upstreamUrl}/odd`, inject: path('bot{BOT_VALUE}') },
      // A path rule of a plain key beside a header of a secret: the handle rides in the header, the app holds the account as it is.
      tenant: { upstream: `${upstreamUrl}/tenant`, inject: [header('x-api-key', '{TENANT_KEY}'), path('{ACCOUNT}')] },
      // Where the stable URL's own segments would frame the slot, read against the wrong base: a name
      // the template frames (`bots`, `bot{…}`), and a key alone under a long base path.
      bots: { upstream: upstreamUrl, inject: path('bot{TELEGRAM_BOT_TOKEN}') },
      bare: { upstream: `${upstreamUrl}/a/long/base/path/for/the/bot`, inject: path('{TELEGRAM_BOT_TOKEN}') },
      // A plain key that is the upstream's own authority, `127.0.0.1:<port>`, in a redirect's host as in its path.
      host: { upstream: `${upstreamUrl}/host`, inject: [header('x-api-key', '{TENANT_KEY}'), path('{AUTHORITY}')] },
      // A template whose text and a value make a segment that goes as none: `..` and `.` is `...`.
      // A query rule whose value is percent-escapes, as written: `%41` is three characters of the key, not `A`.
      keyed: { upstream: `${upstreamUrl}/keyed`, inject: query('api_key', '{ESCAPED_KEY}') },
      punctuated: { upstream: `${upstreamUrl}/punctuated`, inject: query('api_key', '{PUNCTUATED_KEY}') },
      shortened: { upstream: `${upstreamUrl}/shortened`, inject: query('api_key', '{SHORTENED_KEY}') },
      angled: { upstream: `${upstreamUrl}/angled`, inject: path('bot{ANGLED_KEY}') },
      accented: { upstream: `${upstreamUrl}/accented`, inject: path('bot{ACCENTED_KEY}') },
      angledq: { upstream: `${upstreamUrl}/angledq`, inject: query('k', '{ANGLED_KEY}') },
      slashedq: { upstream: `${upstreamUrl}/slashedq`, inject: query('k', '{SLASHED_KEY}') },
      dots: { upstream: `${upstreamUrl}/dots`, inject: path('..{BOT_VALUE}'), allow: [{ methods: ['GET'], path: '/*/getMe' }] },
    },
    insecureUpstreams: true,
  };
}

useMcp(async () => {
  runtime.plugins = checkPlugins([credentialProxy(options())]);
  runtime.deployment = defineDeployment({ proxy: { cacheValues: false } });
  reached.length = 0;
  const root = clientFor(deps, ROOT);
  await root.members.add(`user:${DEV}`);
  await root.projects.create('market');
  await root.environments.create('market/dev');
  await root.secrets.set('market/dev', { TELEGRAM_BOT_TOKEN: { value: TOKEN, sensitivity: 'sensitive' }, AIOGRAM_TOKEN: AIOGRAM, BOT_VALUE: 'a+b=c', TENANT_KEY: TENANT, ESCAPED_KEY: { value: ESCAPED, sensitivity: 'sensitive' }, PUNCTUATED_KEY: { value: PUNCTUATED, sensitivity: 'sensitive' }, SHORTENED_KEY: { value: SHORTENED, sensitivity: 'sensitive' }, ANGLED_KEY: { value: ANGLED, sensitivity: 'sensitive' }, ACCENTED_KEY: { value: ACCENTED, sensitivity: 'sensitive' }, SLASHED_KEY: { value: SLASHED, sensitivity: 'sensitive' }, ACCOUNT: { value: ACCOUNT, sensitivity: 'plain' }, AUTHORITY: { value: new URL(upstreamUrl).host, sensitivity: 'plain' } });
  await root.access.set(`user:${DEV}`, { market: 'developer' });
});

/** A handle for DEV on market/dev, as `coffre run` makes one, and the plan it gets. */
async function run(): Promise<{ handle: string; env: Record<string, string> }> {
  const session = await sessionFor(DEV);
  const api = createClient({ url: ORIGIN, headers: () => ({ authorization: `Bearer ${session}` }), transport: (request) => coffreRoute(request, runtime, '203.0.113.7').then((response) => response!) });
  const { token: handle } = await api.handles.create({ label: 'coffre run market/dev', paths: ['market/dev'] });
  const answer = await route('/use/market/dev', { headers: { authorization: `Bearer ${handle}` } });
  assert.equal(answer.status, 200, await answer.clone().text());
  return { handle, env: ((await answer.json()) as { env: Record<string, string> }).env };
}

/** Every form of the token an answer or a log line may carry it in. */
const forms = (value: string) => [value, encodeURIComponent(value), value.replace(':', '%3a')];
const free = (text: string, value = TOKEN) => forms(value).every((form) => !text.includes(form));

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

test('a method call and a file download: the token goes in the segment the app put its placeholder in, as it is', async () => {
  const { handle, env } = await run();
  assert.equal(env.TELEGRAM_BOT_TOKEN, handle);
  // As an SDK writes it: `${apiRoot}/bot${token}/${method}`, on the stable URL and on the environment's.
  const sent = await route(`/use/telegram/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"chat_id":1,"text":"hi"}' });
  assert.equal(sent.status, 200, await sent.clone().text());
  assert.deepEqual([reached[0]!.method, reached[0]!.url], ['POST', `/tg/bot${TOKEN}/sendMessage`]);
  const file = await route(`/use/market/dev/telegram/file/bot${handle}/photos/file_0.jpg`);
  assert.equal(file.status, 200, await file.clone().text());
  assert.deepEqual(new Uint8Array(await file.arrayBuffer()), new Uint8Array([0xff, 0xd8, 0xff, 0xe0]));
  assert.equal(reached[1]!.url, `/tg/file/bot${TOKEN}/photos/file_0.jpg`);
  // x-coffre-handle beside it, the same handle: let in, the segment filled all the same.
  assert.equal((await route(`/use/telegram/bot${handle}/getMe`, { headers: { 'x-coffre-handle': handle } })).status, 200);
  assert.equal(reached[2]!.url, `/tg/bot${TOKEN}/getMe`);
  assert.ok(reached.every((one) => !one.url.includes(handle) && !JSON.stringify(one.headers).includes(handle)));
});

test('a shaped placeholder shapes the segment exactly: aiogram holds `<bot id>:<handle>`', async () => {
  const { handle, env } = await run();
  assert.equal(env.AIOGRAM_TOKEN, `987654321:${handle}`);
  assert.equal((await route(`/use/aiogram/bot${env.AIOGRAM_TOKEN}/getMe`)).status, 200);
  assert.equal(reached[0]!.url, `/aio/bot${AIOGRAM}/getMe`);
  // The bare handle is out of its shape: no handle where aiogram takes it.
  assert.equal((await route(`/use/aiogram/bot${handle}/getMe`)).status, 401);
  assert.equal(reached.length, 1);
});

test('the allow list reads the path as the app sent it, before the value is in; a path with no such segment is a 400, nothing opened', async () => {
  const { handle } = await run();
  const uses = (await entries('credential.use')).length;
  assert.equal((await route(`/use/telegram/bot${handle}/getMe`, { method: 'POST' })).status, 405);
  assert.equal((await route(`/use/telegram/bot${handle}/a/b`, { method: 'POST' })).status, 403);
  const refused = await route(`/use/telegram/bot${handle}/a/b`);
  assert.equal(refused.status, 403);
  // The refusal quotes the path as the app sent it: its own handle, never the token.
  assert.ok(free(await refused.text()));
  const none = await route('/use/telegram/getMe/x', { headers: { 'x-coffre-handle': handle } });
  assert.deepEqual([none.status, ((await none.json()) as { message: string }).message], [400, 'telegram takes its key in a segment of the path, bot{TELEGRAM_BOT_TOKEN}, and this path has none']);
  assert.equal(reached.length, 0);
  assert.equal((await entries('credential.use')).length, uses, 'nothing opened');
});

test('the placeholder in another segment than the first the template frames, twice, or beside another handle: refused, nothing sent', async () => {
  const { handle } = await run();
  const { handle: other } = await run();
  // The first segment `bot…` frames holds no handle: none where telegram takes it, or, with x-coffre-handle, not there.
  assert.equal((await route(`/use/telegram/botx/bot${handle}`)).status, 401);
  const elsewhere = await route(`/use/telegram/botx/bot${handle}`, { headers: { 'x-coffre-handle': handle } });
  assert.deepEqual([elsewhere.status, ((await elsewhere.json()) as { message: string }).message], [400, 'the handle is not in the segment of the path where telegram takes its key, bot{TELEGRAM_BOT_TOKEN}']);
  // Its slot taken, the handle anywhere else in the URL, a second segment included, goes nowhere: one segment is filled.
  for (const url of [`/use/telegram/bot${handle}/bot${handle}`, `/use/telegram/bot${handle}/getMe?token=${handle}`, `/use/telegram/bot${handle}/${handle}`]) {
    const leaked = await route(url);
    assert.equal(leaked.status, 400, url);
    assert.match(((await leaked.json()) as { message: string }).message, /the handle is somewhere telegram does not take its key: the URL/);
  }
  assert.equal((await route(`/use/telegram/bot${handle}/getMe`, { headers: { 'x-coffre-handle': other } })).status, 400);
  assert.equal((await route(`/use/telegram/bot${other}/x${handle}`)).status, 400);
  assert.equal(reached.length, 0);
});

test('a value goes percent-encoded; one that would change the path is a 409 naming the key, never the value, and nothing is sent', async () => {
  const { handle } = await run();
  const root = clientFor(deps, ROOT);
  assert.equal((await route(`/use/odd/bot${handle}/getMe`)).status, 200);
  assert.equal(reached[0]!.url, '/odd/bota%2Bb%3Dc/getMe');
  for (const value of ['12:ab/../../admin', 'x/y', '..', '12:ab?x=1', '12:ab#x', '12:%2e%2e', 'a;jsessionid=1', 'a b', '12:ab\\x']) {
    await root.secrets.set('market/dev', { BOT_VALUE: value });
    const { result: refused, said } = await logs(() => route(`/use/odd/bot${handle}/getMe`));
    const { message } = (await refused.json()) as { message: string };
    assert.deepEqual([refused.status, message], [409, "odd's BOT_VALUE is no segment of a path: empty, or with a /, \\, ?, #, %, ;, .., a space or a control character in it"], value);
    assert.ok(!said.includes(value), value);
  }
  assert.equal(reached.length, 1);
});

test("a redirect under the upstream quoting the token gets the app's placeholder back; one elsewhere is a 502; an echo is redacted", async () => {
  const { handle } = await run();
  const moved = await route(`/use/telegram/bot${handle}/moved`);
  assert.equal(moved.status, 302);
  assert.equal(moved.headers.get('location'), `${ORIGIN}/use/market/dev/telegram/bot${handle}/getMe`);
  // Absolute, and the token again in its query: the segment the app's, the rest redacted.
  const absolute = await route(`/use/telegram/bot${handle}/absolute`);
  assert.equal(absolute.status, 307);
  const location = absolute.headers.get('location')!;
  assert.ok(location.startsWith(`${ORIGIN}/use/market/dev/telegram/bot${handle}/getMe?again=`), location);
  assert.ok(free(location) && free(decodeURIComponent(location)), location);
  // Followed, as a client follows it: through the proxy, with the placeholder.
  assert.equal((await route(new URL(moved.headers.get('location')!).pathname)).status, 200);
  const away = await route(`/use/telegram/bot${handle}/away`);
  assert.equal(away.status, 502);
  assert.ok(free(await away.text()));
  // An error page that quotes the path, as it came and decoded, its header too.
  const echoed = await route(`/use/telegram/bot${handle}/echo`);
  const page = await echoed.text();
  assert.equal(echoed.status, 404);
  assert.ok(free(page) && free(echoed.headers.get('x-path')!), page);
  assert.match(page, /\[redacted by coffre\]/);
});

test("a token's colon encoded twice in a redirect, in its path or its query, is a 502 with nothing of the answer: no form of it leaves", async () => {
  const { handle } = await run();
  for (const at of ['twice', 'twicequery']) {
    const moved = await route(`/use/telegram/bot${handle}/${at}`);
    assert.equal(moved.status, 502, at);
    assert.equal(moved.headers.get('location'), null, at);
    const said = await moved.text();
    assert.ok(free(said) && free(decodeURIComponent(said)), said);
    for (const form of ['%253A', '%3A', '%3a']) assert.ok(!said.includes(form), said);
  }
});

test("a relative redirect whose first segment holds a raw colon reads as a scheme, not a path: refused, never followed", async () => {
  const { handle } = await run();
  // `bot123456789:AAE…/getMe` is the scheme `bot123456789:`, nowhere under the upstream: a client would not read it as a path either.
  const moved = await route(`/use/telegram/x/bot${handle}?first=raw`);
  assert.equal(moved.status, 502);
  assert.equal(moved.headers.get('location'), null);
  assert.ok(free(await moved.text()));
});

test('a relative redirect resolves against the URL the app sent, never the one the token went out in', async () => {
  const { handle } = await run();
  for (const [at, want] of [['relative', `bot${handle}/getMe`], ['offset', `bot${handle}/offset?offset=1`], ['fragment', `bot${handle}/fragment`], ['here', `bot${handle}/here`]]) {
    const moved = await route(`/use/telegram/bot${handle}/${at}`);
    assert.equal(moved.status, 302, at);
    const location = moved.headers.get('location')!;
    assert.equal(location, `${ORIGIN}/use/market/dev/telegram/${want}`, at);
    assert.ok(free(location) && free(decodeURIComponent(location)), location);
  }
});

test("the token's segment, encoded otherwise in a redirect, gets the placeholder back; the token so encoded elsewhere is a 502", async () => {
  const { handle } = await run();
  for (const at of ['lower', 'spelled']) {
    const moved = await route(`/use/telegram/bot${handle}/${at}`);
    assert.equal(moved.status, 302, at);
    assert.equal(moved.headers.get('location'), `${ORIGIN}/use/market/dev/telegram/bot${handle}/getMe`, at);
  }
  // A relative one that starts with the token's segment: the app's, under the same parent.
  for (const way of ['upper', 'lower']) {
    const moved = await route(`/use/telegram/x/bot${handle}?first=${way}`);
    assert.equal(moved.status, 302, way);
    assert.equal(moved.headers.get('location'), `${ORIGIN}/use/market/dev/telegram/x/bot${handle}/getMe`, way);
  }
  // The same, for a shaped token: `bot987654321%3a…` swapped back before the URL is read would be the scheme
  // `bot987654321:`.
  const { env } = await run();
  const shaped = await route(`/use/aiogram/x/bot${env.AIOGRAM_TOKEN}?first=lower`);
  assert.equal(shaped.status, 302, await shaped.clone().text());
  assert.equal(shaped.headers.get('location'), `${ORIGIN}/use/market/dev/aiogram/x/bot${env.AIOGRAM_TOKEN}/getMe`);
  // In the query, a form no redaction names: decoded once it is the token, so nothing of the answer goes.
  const quoted = await route(`/use/telegram/bot${handle}/quoted`);
  assert.equal(quoted.status, 502);
  assert.equal(quoted.headers.get('location'), null);
  assert.ok(free(await quoted.text()));
});

test("a redirect's host is never swapped: only the path's segments get the app's back, the value its upstream's own host", async () => {
  const { handle } = await run();
  const host = new URL(upstreamUrl).host;
  const moved = await route('/use/host/coffre/loop', { headers: { 'x-api-key': handle } });
  assert.equal(reached.at(-1)!.url, `/host/${host}/loop`);
  assert.equal(moved.status, 302, await moved.clone().text());
  assert.equal(moved.headers.get('location'), `${ORIGIN}/use/market/dev/host/coffre/getMe`);
});

test("a redirect's query keeps the bytes the upstream wrote: a key echoed there as it is gets masked, never decoded first", async () => {
  const { handle } = await run();
  const moved = await route(`/use/keyed/echoquery?api_key=${handle}`);
  assert.equal(moved.status, 302, await moved.clone().text());
  assert.equal(reached.at(-1)!.url, `/keyed/echoquery?api_key=${encodeURIComponent(ESCAPED)}`);
  const location = moved.headers.get('location')!;
  for (const form of [ESCAPED, 'ABCDEFGH', encodeURIComponent(ESCAPED)]) assert.ok(!location.includes(form), location);
  // The rule's parameter the app's placeholder, once, where the upstream first put it; every other pair as it was written.
  // `?api_key`, another field, as it was too.
  assert.match(location, new RegExp(`^${ORIGIN}/use/market/dev/keyed/getMe\\?echo=[^&]*&api_key=${handle}&keep=%7e&\\?api_key=cursor$`));
});

test("a key of escapes and punctuation, echoed in a redirect, is masked in its query and refused in its path, never re-encoded past both", async () => {
  const { handle } = await run();
  // Every form the app could read the key back from: as it is, as the parser writes it, and either decoded once.
  const forms = [PUNCTUATED, `${ESCAPED}%27"`, `${ESCAPED}'%22`, `${ESCAPED}%27%22`, 'ABCDEFGH'];
  const moved = await route(`/use/punctuated/echoquery?api_key=${handle}`);
  assert.equal(moved.status, 302, await moved.clone().text());
  const location = moved.headers.get('location')!;
  for (const form of forms) assert.ok(!location.includes(form), location);
  assert.match(location, new RegExp(`^${ORIGIN}/use/market/dev/punctuated/getMe\\?echo=[^&]*&api_key=${handle}&keep=%7e&\\?api_key=cursor$`));
  // In a path, a parser encodes `"`, so it never stays as written: the redirect goes nowhere, its answer with it.
  const pathed = await route(`/use/punctuated/echopath?api_key=${handle}`);
  assert.equal(pathed.status, 502);
  assert.equal(pathed.headers.get('location'), null);
  const said = await pathed.text();
  for (const form of forms) assert.ok(!said.includes(form), said);
});

test("a key that reads shorter than the masking minimum, echoed in a redirect's path, is refused all the same", async () => {
  const { handle } = await run();
  const moved = await route(`/use/shortened/echopath?api_key=${handle}`);
  assert.equal(moved.status, 502, `${moved.headers.get('location')}`);
  assert.equal(moved.headers.get('location'), null);
  const said = await moved.text();
  for (const form of [SHORTENED, '%41%42%43%22', 'ABC"']) assert.ok(!said.includes(form), said);
});

test("a value a JSON string escapes, echoed so in a redirect's path, is refused: each escape's backslash a `/` hides it from no check", async () => {
  const { handle } = await run();
  const cases = [
    ['go', `/use/angled/bot${handle}/jsonecho?how=go`, ANGLED],
    ['python', `/use/accented/bot${handle}/jsonecho?how=python`, ACCENTED],
    ['go', `/use/angledq/jsonecho?k=${handle}&how=go`, ANGLED],
    ['php', `/use/slashedq/jsonecho?k=${handle}&how=php`, SLASHED],
  ] as const;
  for (const [how, url, value] of cases) {
    const moved = await route(url);
    assert.equal(moved.status, 502, `${url}: ${moved.headers.get('location')}`);
    assert.equal(moved.headers.get('location'), null, how);
    const said = await moved.text();
    for (const form of [value, JSON.stringify(value).slice(1, -1), 'foo/u00', 'foo/u003c', 'foo//bar']) assert.ok(!said.includes(form), said);
  }
});

test("a redirect's query keeps a space it ends in once its fragment goes: a cursor is the upstream's to the byte", async () => {
  const { handle } = await run();
  const moved = await route(`/use/telegram/bot${handle}/spaced`);
  assert.equal(moved.status, 302, await moved.clone().text());
  const location = moved.headers.get('location')!;
  assert.equal(location, `${ORIGIN}/use/market/dev/telegram/bot${handle}/getMe?cursor=abc%20`);
  assert.equal(new URL(location).searchParams.get('cursor'), 'abc ');
});

test("the stable URL finds the handle in the segment under each credential's own upstream", async () => {
  const { handle } = await run();
  assert.equal((await route(`/use/bots/bot${handle}/getMe`)).status, 200);
  assert.equal(reached.at(-1)!.url, `/bot${TOKEN}/getMe`);
  assert.equal((await route(`/use/bare/${handle}/getMe`)).status, 200);
  assert.equal(reached.at(-1)!.url, `/a/long/base/path/for/the/bot/${TOKEN}/getMe`);
});

test('a value that makes a segment a server reads as none is a 409, though no dot segment', async () => {
  const { handle } = await run();
  await clientFor(deps, ROOT).secrets.set('market/dev', { BOT_VALUE: '.' });
  const refused = await route(`/use/dots/..${handle}/getMe`);
  assert.equal(refused.status, 409, await refused.clone().text());
  assert.equal(reached.length, 0);
});

test("the token is in no log line, no audit entry and no refusal", async () => {
  const { handle } = await run();
  const { said } = await logs(async () => {
    for (const [method, url] of [['POST', 'sendMessage'], ['GET', 'echo'], ['GET', 'moved'], ['GET', 'away'], ['POST', 'a/b']]) await (await route(`/use/telegram/bot${handle}/${url}`, { method })).text();
  });
  assert.ok(free(said), said);
  assert.ok(reached.length >= 4);
  // Every audit entry, whatever its action.
  assert.ok(free(JSON.stringify(await loggedEntries(db.owner), (_, value: unknown) => (typeof value === 'bigint' ? String(value) : value))));
  // The use row is slim: it names no host or URL at all.
  assert.ok((await usesLogged(db.owner)).length > 0);
});

test("a plain key's segment holds what the app put, the value it holds, which the rule sets again; the handle rides in the header", async () => {
  const { handle, env } = await run();
  assert.deepEqual([env.TENANT_KEY, env.ACCOUNT], [handle, ACCOUNT]);
  assert.equal((await route(`/use/tenant/${env.ACCOUNT}/items`, { headers: { 'x-api-key': env.TENANT_KEY! } })).status, 200);
  assert.deepEqual([reached[0]!.url, reached[0]!.headers['x-api-key']], [`/tenant/${ACCOUNT}/items`, TENANT]);
  // The rule decides where the value goes: whatever the app put in the segment, the account goes there.
  assert.equal((await route('/use/tenant/other/items', { headers: { 'x-api-key': handle } })).status, 200);
  assert.equal(reached[1]!.url, `/tenant/${ACCOUNT}/items`);
  // A path whose segment holds the handle rides nowhere the plan put it: the URL still carries it after, refused.
  assert.equal((await route(`/use/tenant/x/${handle}`, { headers: { 'x-api-key': handle } })).status, 400);
  assert.equal(reached.length, 2);
});

test('configuration: a path rule is one segment naming one key once, one per credential, and a placeholder prefix with no slash', () => {
  const make = (credential: Partial<Credential>) => () => credentialProxy({ credentials: { a: { upstream: 'https://api.telegram.org', inject: path('bot{K}'), ...credential } as Credential } });
  assert.doesNotThrow(make({}));
  assert.doesNotThrow(make({ inject: [path('bot{K}'), sigv4({ accessKeyId: '{ID}', secretAccessKey: '{SECRET}', region: 'eu-west-3', service: 's3' })] }));
  for (const template of ['bot{K}{L}', 'bot/{K}', '{K}?', 'bot%20{K}', 'bot', 'a;{K}']) {
    assert.throws(make({ inject: path(template) }), /a's path\(\) is one segment naming one key once/, template);
  }
  assert.throws(make({ inject: [path('bot{K}'), path('x{L}')] }), /a sets a segment of the path twice: one rule each/);
  assert.throws(make({ placeholder: prefix('a/b') }), /a's prefix\(\) has a \/, and its path\(\) rule takes the placeholder in one segment/);
});
