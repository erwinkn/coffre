// A route's allow list on random patterns and random encodings of random
// paths (docs/design/proxy-ui.md, section 7), through the plugin's own
// route, the proxy's path check and the matcher together, held to a model
// of section 7's rules written here: a plain path a prefix by segments, `*`
// one non-empty segment, `**` the rest, code's trailing slash what is below.
//
// - No encoding of a path the model leaves outside reaches the upstream;
//   whatever does reach it, the model takes, however many times a server
//   behind decodes it.
// - A path written once-encoded, any byte of it, reaches the upstream exactly
//   when the model takes it, byte for byte as the app wrote it.
// - Matching reads each entry's pattern once against the request: at most
//   min(pattern, path) segments per entry, never more.
import assert from 'node:assert/strict';
import test from 'node:test';
import * as hegel from '@hegeldev/hegel';
import * as gs from '@hegeldev/hegel/generators';

import { propertySettings } from '../../../scripts/property-settings.ts';
import type { PluginContext, UseAsked, WorkloadUse } from '../src/plugins.ts';
import { credentialProxy, header } from '../src/plugins/credential-proxy.ts';
import { allows, readPattern, type AllowEntry, type PathPattern } from '../src/plugins/proxy-match.ts';

const PUBLIC = 'https://coffre.example';
const HANDLE = `coffre_use_${'h'.repeat(43)}`;
const LATER = new Date(Date.now() + 3_600_000).toISOString();
const settings = propertySettings(100);
/** The matcher's cases are cheap, about 3 ms each, and a mistake in one rule shows only in a few: more of them. */
const many = propertySettings(500);

const coffre = {
  publicUrl: PUBLIC,
  workload: async () => null,
  handle: async () => ({ expiresAt: LATER, paths: ['market/dev'] }),
  use: async (_handle: string | WorkloadUse, asked: UseAsked) => ({
    values: Object.fromEntries((asked.keys as readonly string[]).map((key) => [key, 'sk_live_0123456789abcdef'])),
    plain: [],
    keys: ['KEY'],
    environment: { path: 'market/dev', personal: false },
    expiresAt: LATER,
  }),
} as unknown as PluginContext;

// The model.

/** A pattern as the model reads it: its literal segments as text (`*` as null), and what may follow them. */
type Model = { segments: (string | null)[]; tail: 'prefix' | 'below' | 'exact' | 'rest' };

/** Whether the model takes a path given as its segments, each text. */
function takes(model: Model, path: readonly string[]): boolean {
  if (path.length < model.segments.length) return false;
  if (!model.segments.every((want, at) => (want === null ? path[at] !== '' : path[at] === want))) return false;
  return model.tail === 'below' ? path.length > model.segments.length : model.tail === 'exact' ? path.length === model.segments.length : true;
}

/**
 * Literal segments a pattern or a path may hold: no `%`, so that decoding
 * again changes none of them; some that every byte of must be encoded, and
 * some past ASCII. Paths also draw `*`, which is a literal there.
 */
const LITERALS = ['a', 'b', 'ab', 'companies', 'é', 'a b', 'x;y', "it's", '~_-', '(1)', '日本', '@', 'a+b'];

/**
 * And what only a path holds: a `%` of its own, which a server that decodes
 * twice reads as another byte (`%61` as `a`), or as a slash or a dot segment.
 */
const PERCENT = ['%61', '%62%62', '50%', '%2F', '%2e%2e', '%25', ';x', '%3B', ';'];

/**
 * Whether a segment, as text, reads as no slash, backslash, control byte or
 * dot segment (its `;` parameters dropped), however many times it is
 * decoded: one that does, the proxy refuses whatever the list says.
 */
function safe(segment: string): boolean {
  for (let view = utf8(segment); ; view = decode(view)) {
    if (/[/\\\x00-\x1f\x7f]/.test(view) || /^\.{1,2}[ \t]*$/.test(view.split(';')[0]!)) return false;
    if (decode(view) === view) return true;
  }
}

/** Bytes, one character each, of `text` as UTF-8. */
const utf8 = (text: string) => String.fromCharCode(...new TextEncoder().encode(text));
/** `%XX` as its byte, one character each. */
const decode = (text: string) => text.replace(/%([0-9a-f]{2})/gi, (_, byte: string) => String.fromCharCode(parseInt(byte, 16)));

/** Whether a segment, not empty, is empty to a server that drops `;` parameters, decoded however often: refused under a list. */
function bare(segment: string): boolean {
  if (segment === '') return false;
  for (let view = utf8(segment); ; view = decode(view)) {
    if (view.split(';')[0] === '') return true;
    if (decode(view) === view) return false;
  }
}

/** A byte as a URL may write it in a path: as it is when it needs no encoding and `raw` says so, else `%XX` in either case, or `%25XX`, encoded twice. */
const writes = gs.sampledFrom(['raw', 'upper', 'lower', 'twice'] as const);
type Write = 'raw' | 'upper' | 'lower' | 'twice';
function written(byte: number, how: Write): string {
  const char = String.fromCharCode(byte);
  if (how === 'raw' && /[A-Za-z0-9\-_~!$&'()*+,;=:@]/.test(char)) return char;
  const hex = byte.toString(16).padStart(2, '0');
  const cased = how === 'lower' ? hex.toLowerCase() : hex.toUpperCase();
  return how === 'twice' ? `%25${cased}` : `%${cased}`;
}

/** A pattern as code writes it, and as the model reads it. */
const patterns = gs.composite((tc) => {
  const segments = tc.draw(gs.arrays(gs.oneOf(gs.sampledFrom(LITERALS), gs.just(null)), { maxSize: 4 }));
  const tail = tc.draw(gs.sampledFrom(['plain', 'rest', 'below'] as const));
  const text = segments.map((segment) => {
    if (segment === null) return '*';
    // A pattern's bytes, each written raw or once-encoded: it is read decoded once.
    return [...new TextEncoder().encode(segment)].map((byte) => written(byte, tc.draw(gs.sampledFrom(['raw', 'upper', 'lower'] as const)))).join('');
  });
  const path = segments.length === 0 && tail === 'plain' ? '/' : `/${text.join('/')}${tail === 'rest' ? `${text.length === 0 ? '' : '/'}**` : tail === 'below' && text.length > 0 ? '/' : ''}`;
  const glob = segments.includes(null) || tail === 'rest';
  const model: Model = {
    segments: segments.map((segment) => (segment === null ? null : utf8(segment))),
    tail: tail === 'rest' ? 'rest' : tail === 'below' && text.length > 0 ? 'below' : glob ? 'exact' : 'prefix',
  };
  return { path, model, segments };
});

test(`no encoding of a path outside the allow list reaches the upstream, and a once-encoded path inside it does, byte for byte, seed ${settings.seed}`, () => hegel.testAsync(async (tc) => {
  const allow = tc.draw(gs.arrays(patterns, { minSize: 1, maxSize: 2 }));
  // The path, as text segments: an entry's own, its `*`s some literal, so that it nearly matches, alone or with more
  // after; or literals, `%`s of its own and `*` as a literal; and now and then an empty last one, a trailing slash.
  const shape = tc.draw(gs.sampledFrom(['entry', 'entry and more', 'any'] as const));
  const entry = allow[tc.draw(gs.integers({ minValue: 0, maxValue: allow.length - 1 }))]!;
  const path = shape === 'any' ? [] : entry.segments.map((segment) => segment ?? tc.draw(gs.oneOf(gs.sampledFrom(LITERALS), gs.just(''))));
  const more = gs.oneOf(gs.sampledFrom(LITERALS), gs.sampledFrom(PERCENT), gs.just('*'), gs.text({ minSize: 1, maxSize: 3, excludeCategories: ['Cs', 'Cc'] }).map((text) => text.replace(/[%./\\]/g, 'x')));
  if (shape !== 'entry') path.push(...tc.draw(gs.arrays(more, { minSize: path.length === 0 ? 1 : 0, maxSize: 4 })));
  if (path.length === 0) path.push(tc.draw(more));
  if (tc.draw(gs.booleans())) path.push('');
  // Every byte written once, or some twice, which a server that decodes twice reads as another path.
  const how = tc.draw(gs.arrays(tc.draw(gs.booleans()) ? writes : gs.sampledFrom(['raw', 'upper', 'lower'] as const), { minSize: 64, maxSize: 64 }));
  let at = 0;
  const encoded = path.map((segment) => [...new TextEncoder().encode(segment)].map((byte) => written(byte, how[at++ % how.length]!)).join('')).join('/');
  const once = !how.slice(0, at).includes('twice');
  tc.note(`allow ${allow.map((entry) => entry.path).join(' ')}, request /${encoded}`);

  const reached: string[] = [];
  const plugin = credentialProxy({ cacheSeconds: 0, credentials: { api: { upstream: 'https://api.example/v1', inject: header('x-api-key', '{KEY}'), allow: allow.map((entry) => ({ path: entry.path })), egress: { fetch: async (url: URL) => (reached.push(url.pathname), new Response('ok')) } } } });
  const answer = await plugin.routes!.fetch(new Request(`${PUBLIC}/use/market/dev/api/${encoded}`, { headers: { 'x-coffre-handle': HANDLE } }), coffre);
  const inside = (segments: readonly string[]) => allow.some((entry) => takes(entry.model, segments));

  if (reached.length === 1) {
    assert.equal(answer.status, 200);
    // What the upstream got, as a server reads it decoded once, twice, until it no longer changes: the model takes each.
    let view = reached[0]!.slice('/v1/'.length).split('/').map(decode);
    assert.ok(!view.slice(0, -1).includes(''), `the upstream got ${reached[0]}, with an empty segment`);
    assert.ok(!reached[0]!.slice('/v1/'.length).split('/').some(bare), `the upstream got ${reached[0]}, with a segment of ; parameters alone`);
    for (let again = 0; again < 4; again++) {
      assert.ok(inside(view), `the upstream got ${reached[0]}, which reads as /${view.join('/')}, outside ${allow.map((entry) => entry.path).join(' ')}`);
      view = view.map(decode);
    }
  } else assert.notEqual(answer.status, 200);
  if (once && path.every(safe) && !path.slice(0, -1).includes('') && !path.some(bare)) {
    // Written once, with no `//` and no segment of `;` parameters alone, which a list refuses: the request is the path, which goes exactly when the model takes
    // it, as the app wrote it.
    assert.equal(reached.length === 1, inside(path.map(utf8)), `status ${answer.status}`);
    if (reached.length === 1) assert.equal(reached[0], `/v1/${encoded}`);
  }
}, many));

test(`matching reads at most min(pattern, path) segments of the request per entry, seed ${settings.seed}`, () => hegel.test((tc) => {
  const entries: AllowEntry[] = tc.draw(gs.arrays(gs.composite((inner) => {
    const segments = inner.draw(gs.arrays(gs.sampledFrom(['a', '*']), { maxSize: 30 }));
    const tail = inner.draw(gs.sampledFrom(['', '/**', '/']));
    const body = segments.join('/');
    const read = readPattern(body === '' ? (tail === '/**' ? '/**' : '/') : `/${body}${tail}`, 'code') as { pattern: PathPattern };
    return { methods: inner.draw(gs.booleans()) ? null : new Set(['POST']), path: read.pattern };
  }), { minSize: 1, maxSize: 20 }));
  const path = tc.draw(gs.arrays(gs.sampledFrom(['a', 'b', '']), { minSize: 1, maxSize: 200 }));
  let reads = 0;
  const counted = new Proxy(path, { get: (target, key, receiver) => (typeof key === 'string' && /^\d+$/.test(key) && reads++, Reflect.get(target, key, receiver)) });
  allows(entries, 'GET', counted);
  const bound = entries.reduce((sum, entry) => sum + Math.min(entry.path!.segments.length, path.length), 0);
  assert.ok(reads <= bound, `${reads} reads, past ${bound}`);
}, settings));
