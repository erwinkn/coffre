// A credential whose key goes in a field of the body (docs/design/credential-proxy.md,
// section 5, "A field of the body"): `form()` and `json()`. Gather's token refresh
// sends its refresh token in a form, Turnstile's siteverify its secret in a form or
// JSON. The app puts its handle in that field; coffre puts the real value in its
// place and leaves every other byte as it was. A handle anywhere else in the body,
// however encoded, a body of another type, too large, malformed, without the field
// or with it twice, is refused, and nothing reaches the upstream; an upstream that
// echoes the body gives the app no byte of the value.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type IncomingMessage, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

import { createClient } from '@coffre/client';
import { bodyDigest, contentDigest } from '@coffre/client/dpop';

import { clientFor } from './api-fixture.ts';
import { deps, DEV, ORIGIN, ROOT, route, runtime, sessionFor, useMcp } from './mcp-fixture.ts';
import { coffreRoute } from '../src/app.ts';
import { checkPlugins } from '../src/plugins.ts';
import { credentialProxy, form, header, json, prefix, type CredentialProxyOptions } from '../src/plugins/credential-proxy.ts';

/** Turnstile's secret, and a refresh token with what a form encodes: `+`, `/`, `=`. */
const TURNSTILE = '0x4AAAAAAA_real_turnstile_secret_0123';
const REFRESH = 'AMf-vB+real/refresh=token_0123456789';

/** The fake upstream: what reached it, the body as its bytes; `/echo` answers with the body it got. */
let upstream: Server;
let upstreamUrl: string;
const reached: { url: string; headers: IncomingMessage['headers']; body: Buffer }[] = [];

before(async () => {
  upstream = createServer((request, response) => {
    const chunks: Buffer[] = [];
    request.on('data', (chunk: Buffer) => chunks.push(chunk));
    request.on('end', () => {
      const body = Buffer.concat(chunks);
      reached.push({ url: request.url!, headers: request.headers, body });
      response.writeHead(200, { 'content-type': 'application/json' }).end(request.url!.includes('/echo') ? JSON.stringify({ got: body.toString() }) : '{"success":true}');
    });
  });
  await new Promise<void>((resolve) => upstream.listen(0, '127.0.0.1', resolve));
  upstreamUrl = `http://127.0.0.1:${(upstream.address() as AddressInfo).port}`;
});

after(() => new Promise<void>((resolve) => upstream.close(() => resolve())));

function options(): CredentialProxyOptions {
  return {
    credentials: {
      gather: { upstream: `${upstreamUrl}/securetoken/v1`, inject: form('refresh_token', '{GATHER_REFRESH_TOKEN}') },
      turnstile: { upstream: `${upstreamUrl}/turnstile/v0`, inject: json('secret', '{TURNSTILE_SECRET_KEY}') },
      'turnstile-form': { upstream: `${upstreamUrl}/turnstile/v0`, inject: form('secret', '{TURNSTILE_SECRET_KEY}') },
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
  await root.environments.create('market/dev');
  await root.secrets.set('market/dev', { TURNSTILE_SECRET_KEY: { value: TURNSTILE, sensitivity: 'sensitive' }, GATHER_REFRESH_TOKEN: REFRESH });
  await root.access.set(`user:${DEV}`, { market: 'developer' });
});

/** A handle for DEV on `path`, market/dev unless given, as `coffre run` makes one, and the plan it gets. */
async function run(path = 'market/dev'): Promise<{ handle: string; env: Record<string, string> }> {
  const session = await sessionFor(DEV);
  const api = createClient({ url: ORIGIN, headers: () => ({ authorization: `Bearer ${session}` }), transport: (request) => coffreRoute(request, runtime, '203.0.113.7').then((response) => response!) });
  const { token: handle } = await api.handles.create({ label: `coffre run ${path}`, paths: [path] });
  const plan = (await (await route(`/use/${path}`, { headers: { authorization: `Bearer ${handle}` } })).json()) as { env: Record<string, string> };
  return { handle, env: plan.env };
}

const FORM = { 'content-type': 'application/x-www-form-urlencoded' };
const JSON_TYPE = { 'content-type': 'application/json' };

test("Gather's token refresh, a form, reaches the upstream with the real refresh token in its field, form-encoded, and every other byte as the app sent it", async () => {
  const { handle, env } = await run();
  assert.equal(env.GATHER_REFRESH_TOKEN, handle, 'the app holds the handle');
  // As Firebase's client sends it: the API key, no secret, in the query; the stable URL.
  const answer = await route('/use/gather/token?key=AIzaSy-public', { method: 'POST', headers: FORM, body: `grant_type=refresh_token&refresh_token=${env.GATHER_REFRESH_TOKEN}` });
  assert.equal(answer.status, 200, await answer.clone().text());
  const [sent] = reached;
  assert.equal(sent!.url, '/securetoken/v1/token?key=AIzaSy-public');
  assert.equal(sent!.body.toString(), `grant_type=refresh_token&refresh_token=${new URLSearchParams({ v: REFRESH }).toString().slice(2)}`);
  assert.equal(new URLSearchParams(sent!.body.toString()).get('refresh_token'), REFRESH);
  assert.equal(sent!.headers['content-length'], String(sent!.body.length), 'the length of what went out');
  assert.equal(sent!.headers['content-type'], 'application/x-www-form-urlencoded');

  // The environment's URL, the field anywhere among the pairs, its name and the other pairs as written, empty ones included.
  const written = `a=%E2%9C%93&&refresh%5Ftoken=${handle.replace('_', '%5F')}&b=x+y&c`;
  assert.equal((await route('/use/market/dev/gather/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded; charset=UTF-8' }, body: written })).status, 200);
  assert.equal(reached[1]!.body.toString(), `a=%E2%9C%93&&refresh%5Ftoken=${new URLSearchParams({ v: REFRESH }).toString().slice(2)}&b=x+y&c`);
  // Raw bytes past ASCII in another pair, UTF-8 or not, go on byte for byte: 0x80 to 0x9F are no windows-1252 letters here.
  const raw = Buffer.concat([Buffer.from('note=✓€'), Buffer.from([0x80, 0x9f, 0xff]), Buffer.from(`&refresh_token=${handle}`)]);
  assert.equal((await route('/use/gather/token', { method: 'POST', headers: FORM, body: new Uint8Array(raw) })).status, 200);
  assert.deepEqual(reached[2]!.body, Buffer.concat([raw.subarray(0, raw.length - handle.length), Buffer.from(new URLSearchParams({ v: REFRESH }).toString().slice(2))]));
});

test("Turnstile's siteverify, JSON or a form, gets the real secret in its field; the JSON's other bytes, spacing and a number too long for a double included, stay as they were", async () => {
  const { handle } = await run();
  const written = `{ "response" : "XXXX.DUMMY.TOKEN",\n  "secret":"${handle}", "secret_hint": "a name that merely begins as the field's", "remoteip": "203.0.113.1", "n": 12345678901234567890123, "nested": { "secret": "kept" } }`;
  const answer = await route('/use/turnstile/siteverify', { method: 'POST', headers: { ...JSON_TYPE, 'content-digest': contentDigest(await bodyDigest(written)) }, body: written });
  assert.equal(answer.status, 200, await answer.clone().text());
  const expected = written.replace(handle, TURNSTILE);
  assert.equal(reached[0]!.body.toString(), expected);
  assert.equal(reached[0]!.headers['content-digest'], contentDigest(await bodyDigest(expected)), 'the digest that goes on is of what goes on');
  // A value JSON escapes is written as JSON writes it.
  const before = JSON.stringify({ secret: handle, response: 'é"' });
  assert.equal((await route('/use/turnstile/siteverify', { method: 'POST', headers: { 'content-type': 'application/json; charset="utf-8"' }, body: before })).status, 200);
  assert.deepEqual(JSON.parse(reached[1]!.body.toString()), { secret: TURNSTILE, response: 'é"' });
  // The same upstream as a form.
  assert.equal((await route('/use/turnstile-form/siteverify', { method: 'POST', headers: FORM, body: `secret=${handle}&response=XXXX.DUMMY.TOKEN` })).status, 200);
  assert.equal(reached[2]!.body.toString(), `secret=${TURNSTILE}&response=XXXX.DUMMY.TOKEN`);
  // A byte order mark, which a parser of the web skips, is taken and kept.
  const marked = `\uFEFF{"secret":"${handle}"}`;
  assert.equal((await route('/use/turnstile/siteverify', { method: 'POST', headers: JSON_TYPE, body: marked })).status, 200);
  assert.deepEqual(reached[3]!.body, Buffer.from(`\uFEFF{"secret":"${TURNSTILE}"}`));
});

test('an upstream that echoes the body gives the app none of the value', async () => {
  const { handle } = await run();
  const echoed = await (await route('/use/turnstile/echo', { method: 'POST', headers: JSON_TYPE, body: JSON.stringify({ secret: handle }) })).text();
  assert.equal(reached[0]!.body.toString().includes(TURNSTILE), true, 'it went out');
  assert.equal(echoed.includes(TURNSTILE), false, echoed);
  assert.match(echoed, /redacted by coffre/);
  const form = await (await route('/use/gather/echo', { method: 'POST', headers: FORM, body: `refresh_token=${handle}` })).text();
  assert.equal(form.includes('real/refresh') || form.includes('real%2Frefresh'), false, form);
});

test('a handle anywhere but its field, a body of another type, too large, malformed, or without the field once, is refused, and nothing reaches the upstream', async () => {
  const { handle } = await run();
  const escaped = `\\u0063${handle.slice(1)}`;
  const cases: [string, string, Record<string, string>, string | Uint8Array<ArrayBuffer> | undefined, number][] = [
    // Forms.
    ['gather', 'no field', FORM, 'grant_type=refresh_token', 400],
    ['gather', 'the field twice', FORM, `refresh_token=${handle}&refresh_token=${handle}`, 400],
    ['gather', 'the field twice, once encoded', FORM, `refresh_token=${handle}&refresh%5Ftoken=x`, 400],
    ['gather', 'the field twice, as PHP reads a dot', FORM, `refresh_token=${handle}&refresh.token=x`, 400],
    ['gather', 'the field twice, as PHP reads a space', FORM, `refresh+token=x&refresh_token=${handle}`, 400],
    ['gather', 'the field twice, as PHP reads an array', FORM, `refresh_token=${handle}&refresh_token[]=x`, 400],
    ['gather', 'the field twice, as qs reads an index', FORM, `refresh_token[0]=x&refresh_token=${handle}`, 400],
    ['gather', 'the field twice, as PHP reads a dotted array', FORM, `refresh_token=${handle}&refresh.token[x]=y`, 400],
    ['gather', 'the field twice, in capitals', FORM, `refresh_token=${handle}&REFRESH_TOKEN=x`, 400],
    ['gather', 'the handle in another field too', FORM, `refresh_token=${handle}&note=${handle}`, 400],
    ['gather', 'the handle percent-encoded in another field', FORM, `refresh_token=${handle}&note=${handle.replace('_', '%5F')}`, 400],
    ['gather', 'the handle in another field\'s name', FORM, `refresh_token=${handle}&${handle}=1`, 400],
    ['gather', 'the handle in another field, the field without it', FORM, `refresh_token=x&note=${handle}`, 401],
    ['gather', 'JSON to a form rule', JSON_TYPE, JSON.stringify({ refresh_token: handle }), 415],
    ['gather', 'another charset', { 'content-type': 'application/x-www-form-urlencoded; charset=iso-8859-1' }, `refresh_token=${handle}`, 415],
    ['gather', 'compressed', { ...FORM, 'content-encoding': 'gzip' }, `refresh_token=${handle}`, 415],
    ['gather', 'past 64 KiB', FORM, `refresh_token=${handle}&pad=${'x'.repeat(64 * 1024)}`, 413],
    ['gather', 'no body', FORM, undefined, 400],
    ['gather', 'more than 256 fields, empty ones', FORM, `refresh_token=${handle}${'&'.repeat(300)}`, 400],
    // JSON.
    ['turnstile', 'malformed', JSON_TYPE, `{"secret":"${handle}",}`, 400],
    ['turnstile', 'no object', JSON_TYPE, JSON.stringify([{ secret: handle }]), 400],
    ['turnstile', 'not UTF-8', JSON_TYPE, new Uint8Array([...Buffer.from(`{"secret":"${handle}","x":"`), 0xff, ...Buffer.from('"}')]), 400],
    ['turnstile', 'no field', JSON_TYPE, JSON.stringify({ response: 'x' }), 400],
    ['turnstile', 'the field nested only', JSON_TYPE, JSON.stringify({ data: { secret: handle } }), 400],
    ['turnstile', 'the field twice', JSON_TYPE, `{"secret":"${handle}","secret":"x"}`, 400],
    ['turnstile', 'the field twice, once escaped', JSON_TYPE, `{"secret":"${handle}","\\u0073ecret":"x"}`, 400],
    ['turnstile', 'the field twice, as Go folds case, after it', JSON_TYPE, `{"secret":"${handle}","SECRET":"x"}`, 400],
    ['turnstile', 'the field twice, as Go folds case, before it', JSON_TYPE, `{"Secret":"x","secret":"${handle}"}`, 400],
    ['turnstile', 'the field twice, as Go folds the long s', JSON_TYPE, `{"secret":"${handle}","\u017fecret":"x"}`, 400],
    ['turnstile', 'the field no string', JSON_TYPE, `{"secret":{"value":"${handle}"}}`, 400],
    ['turnstile', 'the field a number', JSON_TYPE, '{"secret":12}', 400],
    ['turnstile', 'the handle in another field too', JSON_TYPE, JSON.stringify({ secret: handle, response: handle }), 400],
    ['turnstile', 'the handle escaped in another field', JSON_TYPE, `{"secret":"${handle}","response":"${escaped}"}`, 400],
    ['turnstile', 'the handle in a key', JSON_TYPE, JSON.stringify({ secret: handle, [handle]: 1 }), 400],
    ['turnstile', 'the handle nested', JSON_TYPE, JSON.stringify({ secret: handle, nested: [{ deep: handle }] }), 400],
    ['turnstile', 'a form to a JSON rule', FORM, `secret=${handle}`, 415],
    ['turnstile', 'nested deeper than 32', JSON_TYPE, `{"secret":"${handle}","x":${'['.repeat(40)}${']'.repeat(40)}}`, 400],
    ['turnstile', 'more than 256 fields', JSON_TYPE, JSON.stringify({ secret: handle, ...Object.fromEntries(Array.from({ length: 300 }, (_, at) => [`k${at}`, 'v'])) }), 400],
    ['turnstile', 'text/plain', { 'content-type': 'text/plain' }, JSON.stringify({ secret: handle }), 415],
  ];
  for (const [credential, what, headers, body, status] of cases) {
    for (const path of [`/use/${credential}/x`, `/use/market/dev/${credential}/x`]) {
      const refused = await route(path, { method: 'POST', headers, ...(body === undefined ? {} : { body }) });
      const text = await refused.text();
      assert.equal(refused.status, status, `${what}, ${path}: ${text}`);
      assert.equal(refused.headers.get('coffre-proxy'), 'refused', what);
      assert.equal(text.includes(handle) || text.includes(TURNSTILE) || text.includes(REFRESH), false, `${what}: nothing of the body is quoted`);
    }
  }
  // x-coffre-handle is the handle the field must hold: a field without it is refused, though the header lets the request in.
  const elsewhere = await route('/use/market/dev/gather/x', { method: 'POST', headers: { ...FORM, 'x-coffre-handle': handle }, body: 'refresh_token=mine' });
  assert.equal(elsewhere.status, 400, await elsewhere.text());
  assert.equal(reached.length, 0);
});

test('a project named like a body credential: the route the handle decides sends the body as the stable URL read it, through either credential', async () => {
  const root = clientFor(deps, ROOT);
  await root.projects.create('gather');
  await root.environments.create('gather/dev');
  const OWN = '0x4AAAAAAA_gather_dev_turnstile_0123';
  await root.secrets.set('gather/dev', { TURNSTILE_SECRET_KEY: OWN });
  await root.access.set(`user:${DEV}`, { market: 'developer', gather: 'developer' });
  // A handle for gather/dev: the environment's route, through turnstile, though gather's stable URL refuses the body (JSON, to a form rule).
  const ours = await run('gather/dev');
  assert.equal((await route('/use/gather/dev/turnstile/siteverify', { method: 'POST', headers: JSON_TYPE, body: JSON.stringify({ secret: ours.handle }) })).status, 200);
  assert.deepEqual([reached[0]!.url, reached[0]!.body.toString()], ['/turnstile/v0/siteverify', JSON.stringify({ secret: OWN })]);
  // Both form rules: gather's finds no refresh_token, turnstile-form's the handle.
  assert.equal((await route('/use/gather/dev/turnstile-form/siteverify', { method: 'POST', headers: FORM, body: `secret=${ours.handle}` })).status, 200);
  assert.equal(reached[1]!.body.toString(), `secret=${OWN}`);
  // A handle for market/dev: the stable URL of gather, /dev/turnstile/… under it, though turnstile refuses the form.
  const theirs = await run();
  assert.equal((await route('/use/gather/dev/turnstile/x', { method: 'POST', headers: FORM, body: `refresh_token=${theirs.handle}` })).status, 200);
  assert.deepEqual([reached[2]!.url, new URLSearchParams(reached[2]!.body.toString()).get('refresh_token')], ['/securetoken/v1/dev/turnstile/x', REFRESH]);
  assert.equal(reached.length, 3);
});

test('the configuration: a field name, a rule that names a key, and a shaped placeholder in a field', async () => {
  assert.throws(() => credentialProxy({ credentials: { bad: { upstream: 'https://api.example.com', inject: form('a b', '{K}') } } }), /no field name/);
  assert.throws(() => credentialProxy({ credentials: { bad: { upstream: 'https://api.example.com', inject: form('_', '{K}') } } }), /a letter or digit among them/);
  assert.throws(() => credentialProxy({ credentials: { bad: { upstream: 'https://api.example.com', inject: json('secret', 'literal') } } }), /names no key/);
  // A client that checks its key's prefix holds `pk_coffre_use_…`, and the field must be that exactly.
  runtime.plugins = checkPlugins([credentialProxy({ ...options(), credentials: { shaped: { upstream: `${upstreamUrl}/shaped`, inject: json('secret', '{TURNSTILE_SECRET_KEY}'), placeholder: prefix('pk_') }, plain: { upstream: `${upstreamUrl}/plain`, inject: header('x-api-key', '{GATHER_REFRESH_TOKEN}') } } })]);
  const { handle, env } = await run();
  assert.equal(env.TURNSTILE_SECRET_KEY, `pk_${handle}`);
  assert.equal((await route('/use/shaped/x', { method: 'POST', headers: JSON_TYPE, body: JSON.stringify({ secret: handle }) })).status, 401);
  assert.equal((await route('/use/shaped/x', { method: 'POST', headers: JSON_TYPE, body: JSON.stringify({ secret: env.TURNSTILE_SECRET_KEY }) })).status, 200);
  assert.equal(reached.at(-1)!.body.toString(), JSON.stringify({ secret: TURNSTILE }));
});
