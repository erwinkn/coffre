// A path rule (0.15.1, T208; docs/design/credential-proxy.md, section 5, "A segment of the path"), end to end:
// coffre's own vault, a handle as `coffre run` makes one, and a fake Telegram Bot API over HTTP. A method call and a
// file download, each with the token in its path; the allow list read on the path as the app sent it; a value that
// would change the path's shape, refused; a redirect quoting the token, given back the app's placeholder; an echo,
// redacted; and the token in no log line, no audit row and no refusal.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type IncomingMessage, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

import { createClient } from '@coffre/client';

import { clientFor, LOG, usesLogged } from './api-fixture.ts';
import { db, deps, DEV, entries, ORIGIN, ROOT, route, runtime, sessionFor, useMcp } from './mcp-fixture.ts';
import { auditLog } from './db/tables.ts';
import { coffreRoute } from '../src/app.ts';
import { checkPlugins } from '../src/plugins.ts';
import { credentialProxy, header, path, prefix, sigv4, type Credential, type CredentialProxyOptions } from '../src/plugins/credential-proxy.ts';

/** A bot token as BotFather writes one: the bot's id, a colon, 35 characters. */
const TOKEN = '123456789:AAEhBP0av28dGcj4Xqp-5Yv_LxQz0123456';
const AIOGRAM = '987654321:AAFzzBP0av28dGcj4Xqp-5Yv_LxQz0654321';
const TENANT = 'tenant-0123456789abcdef';
const ACCOUNT = 'acct_1Plain0123456';

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
    },
    insecureUpstreams: true,
    cacheSeconds: 0,
  };
}

useMcp(async () => {
  runtime.plugins = checkPlugins([credentialProxy(options())]);
  reached.length = 0;
  const root = clientFor(deps, ROOT);
  await root.members.add(`user:${DEV}`);
  await root.projects.create('market');
  await root.environments.create('market/dev');
  await root.secrets.set('market/dev', { TELEGRAM_BOT_TOKEN: { value: TOKEN, sensitivity: 'sensitive' }, AIOGRAM_TOKEN: AIOGRAM, BOT_VALUE: 'a+b=c', TENANT_KEY: TENANT, ACCOUNT: { value: ACCOUNT, sensitivity: 'plain' } });
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

test("the token is in no log line, no audit entry and no refusal; 0.14's use names the host alone", async () => {
  const { handle } = await run();
  const { said } = await logs(async () => {
    for (const [method, url] of [['POST', 'sendMessage'], ['GET', 'echo'], ['GET', 'moved'], ['GET', 'away'], ['POST', 'a/b']]) await (await route(`/use/telegram/bot${handle}/${url}`, { method })).text();
  });
  assert.ok(free(said), said);
  assert.ok(reached.length >= 4);
  // Every audit entry, whatever its action.
  assert.ok(free(JSON.stringify(await db.owner.select().from(auditLog), (_, value: unknown) => (typeof value === 'bigint' ? String(value) : value))));
  // 0.15's use row is slim (R53): it names no host or URL at all. 0.14's names the host.
  if (LOG === '0.15') assert.ok((await usesLogged(db.owner)).length > 0);
  else {
    const used = (await entries('credential.use')).filter((entry) => entry.metadata.credential === 'telegram');
    assert.ok(used.length > 0);
    for (const entry of used) assert.equal(entry.metadata.host, new URL(upstreamUrl).host);
  }
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
