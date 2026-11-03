// A path rule (0.16, T208; docs/design/credential-proxy.md, section 5, "A segment of the path"): its template, the
// segment it takes its key in, as the app sent the path, and the value as that segment's part, or its refusal. The
// proxy, code's startup check and the vault's save all read them here.
import test from 'node:test';
import assert from 'node:assert/strict';

import { pathSlot, pathTemplate, pathValue } from '../src/proxy-match.ts';
import { canonicalDefinition, definitionKeys, proxyDefinitionProblem } from '../src/vault.ts';

const TOKEN = '123456789:AAEhBP0av28dGcj4Xqp-5Yv_LxQz0123456';

test('a template is one segment naming one key once, the text around it as it goes out', () => {
  assert.deepEqual(pathTemplate('bot{TELEGRAM_BOT_TOKEN}'), { before: 'bot', key: 'TELEGRAM_BOT_TOKEN', after: '' });
  assert.deepEqual(pathTemplate('{TOKEN}'), { before: '', key: 'TOKEN', after: '' });
  assert.deepEqual(pathTemplate("v1:{K}@x.~!$&'()*+,=-_"), { before: 'v1:', key: 'K', after: "@x.~!$&'()*+,=-_" });
  // Two keys, the same twice, none, a slash (two segments), and what a server may read as another segment or none.
  for (const refused of ['{A}{B}', '{A}x{A}', 'bot', 'a/{K}', '{K}/b', '{K}?x', '{K}#x', '%2F{K}', 'a;v={K}', 'a {K}', 'a\\{K}', '{K}\n', '{1K}', 'é{K}']) {
    assert.equal(pathTemplate(refused), null, refused);
  }
});

test('the slot is the first segment under the upstream the template frames, read decoded once, whatever is in it', () => {
  const bot = { before: 'bot', after: '' };
  assert.equal(pathSlot(bot, '/botcoffre_use_x/sendMessage'), 1);
  assert.equal(pathSlot(bot, '/file/botcoffre_use_x/photos/file_0.jpg'), 2);
  assert.equal(pathSlot(bot, '/botA/botB'), 1);
  // Decoded once, as the allow list reads it: `b%6Ft` is `bot`.
  assert.equal(pathSlot(bot, '/b%6Ftx/getMe'), 1);
  // The key's place holds at least one character: `bot` alone frames nothing, nor does a path with no such segment.
  assert.equal(pathSlot(bot, '/bot/getMe'), -1);
  assert.equal(pathSlot(bot, '/getMe'), -1);
  assert.equal(pathSlot(bot, '/'), -1);
  // The key alone frames the first segment; text after it too.
  assert.equal(pathSlot({ before: '', after: '' }, '/abc/def'), 1);
  assert.equal(pathSlot({ before: '', after: '' }, '//def'), 2);
  assert.equal(pathSlot({ before: 'k-', after: '.json' }, '/a/k-x.json'), 2);
  assert.equal(pathSlot({ before: 'k-', after: '.json' }, '/a/k-.json'), -1);
});

test("a value goes in percent-encoded, but letters, digits, -._~ and ':'; one that could read as another path goes nowhere", () => {
  assert.equal(pathValue(TOKEN), TOKEN);
  assert.equal(pathValue('a+b=c!*\'()&$,@é'), 'a%2Bb%3Dc%21%2A%27%28%29%26%24%2C%40%C3%A9');
  assert.equal(decodeURIComponent(pathValue('a+b=c!*\'()&$,@é')!), 'a+b=c!*\'()&$,@é');
  for (const refused of ['', '/', 'a/b', 'a\\b', 'a?b', 'a#b', 'a%2Fb', '%41', 'a;b', '..', 'a..b', 'a b', ' a', 'a\n', 'a\tb', 'a\u0000b', 'a\u007fb', 'a b', 'a\ud800b']) {
    assert.equal(pathValue(refused), null, JSON.stringify(refused));
  }
  // A dot alone, or two apart, is no dot segment once the template frames it; the proxy checks the segment whole too.
  assert.equal(pathValue('.'), '.');
  assert.equal(pathValue('a.b.c'), 'a.b.c');
});

test('the vault keeps a path rule as written, beside other rules, one at most, and a prefix with no slash', () => {
  const route = { kind: 'route', name: 'telegram', upstream: 'https://api.telegram.org', inject: [{ kind: 'path', template: 'bot{TELEGRAM_BOT_TOKEN}' }] };
  const kept = canonicalDefinition(route);
  assert.deepEqual(kept, {
    kind: 'route', name: 'telegram', upstream: 'https://api.telegram.org', inject: [{ kind: 'path', template: 'bot{TELEGRAM_BOT_TOKEN}' }],
    allow: null, limit: { perMinute: null, perDay: null }, placeholder: null, egress: null,
  });
  assert.deepEqual(definitionKeys(kept), ['TELEGRAM_BOT_TOKEN']);
  // A shaped placeholder shapes it, as aiogram wants `<digits>:…`.
  assert.equal(proxyDefinitionProblem({ ...route, placeholder: { kind: 'prefix', prefix: '123456789:' } }), null);
  assert.equal(proxyDefinitionProblem({ ...route, inject: [{ kind: 'header', name: 'x-tenant', template: '{TENANT}' }, ...route.inject] }), null);
  const cases: [string, unknown, RegExp][] = [
    ['two keys', { ...route, inject: [{ kind: 'path', template: '{A}{B}' }] }, /inject\[0\]\.template is one path segment naming one key once/],
    ['a slash', { ...route, inject: [{ kind: 'path', template: 'bot/{A}' }] }, /one path segment/],
    ['a percent', { ...route, inject: [{ kind: 'path', template: 'bot%20{A}' }] }, /one path segment/],
    ['no key', { ...route, inject: [{ kind: 'path', template: 'bot' }] }, /one path segment/],
    ['a name', { ...route, inject: [{ kind: 'path', name: 'x', template: 'bot{A}' }] }, /no field "name"/],
    ['two path rules', { ...route, inject: [{ kind: 'path', template: 'bot{A}' }, { kind: 'path', template: 'x{B}' }] }, /one path rule at most/],
    ['a prefix with a slash', { ...route, placeholder: { kind: 'prefix', prefix: 'a/b' } }, /no \//],
  ];
  for (const [what, value, words] of cases) assert.match(proxyDefinitionProblem(value) ?? '', words, what);
});
