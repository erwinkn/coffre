// The credential proxy's guards on random requests and answers, through the
// plugin's own routes (docs/design/credential-proxy.md, "Sent on" and
// "Back"), with a fake coffre that opens the drawn values and an egress
// that plays the upstream: where a request goes, what it carries, what of a
// redirect comes back, and what redaction leaves of an answer. Then the
// addresses the proxy holds private, a tunnel's hosts, and SASLprep.
import assert from 'node:assert/strict';
import test from 'node:test';
import * as hegel from '@hegeldev/hegel';
import * as gs from '@hegeldev/hegel/generators';

import { propertySettings } from '../../../scripts/property-settings.ts';
import type { PluginContext, UseAsked } from '../src/plugins.ts';
import { basic, credentialProxy, header, postgres, query, type CredentialProxyOptions, type Inject } from '../src/plugins/credential-proxy.ts';
import { database, saslprep } from '../src/plugins/postgres-tunnel.ts';

const PUBLIC = 'https://coffre.example';
const HANDLE = `coffre_use_${'h'.repeat(43)}`;
const LATER = new Date(Date.now() + 3_600_000).toISOString();
const MIN_REDACTED = 8;

/** coffre, as a plugin sees it: the handle stands for `market/dev`, whose values are the drawn ones. */
function coffre(values: Record<string, string>, plain: readonly string[] = []): PluginContext {
  const unused = () => {
    throw new Error('the proxy does not call this here');
  };
  return {
    publicUrl: PUBLIC,
    api: unused,
    exchange: unused,
    signOut: unused,
    handle: async () => ({ expiresAt: LATER, paths: ['market/dev'] }),
    use: async (_handle: string, asked: UseAsked) => {
      const keys = Array.isArray(asked.keys) ? asked.keys : Object.keys(values);
      return {
        values: Object.fromEntries(keys.filter((key) => key in values).map((key) => [key, values[key]!])),
        plain: plain.filter((key) => keys.includes(key)),
        keys: Object.keys(values),
        environment: { path: 'market/dev', personal: false },
        expiresAt: LATER,
      };
    },
  };
}

/** An upstream the proxy reaches through its egress: each request it got, and the answer it gives. */
function upstream(answer: (url: URL) => Response = () => new Response('ok')) {
  const calls: { url: URL; headers: Headers }[] = [];
  return { calls, egress: { fetch: async (url: URL, init: RequestInit) => {
    calls.push({ url: new URL(url), headers: new Headers(init.headers) });
    return answer(new URL(url));
  } } };
}

/** The proxy's answer to `path` (after `/use`), asked with the handle in `x-coffre-handle`. */
async function ask(options: CredentialProxyOptions, values: Record<string, string>, path: string, init: RequestInit = {}, plain: readonly string[] = []): Promise<Response> {
  const headers = new Headers(init.headers);
  headers.set('x-coffre-handle', HANDLE);
  return credentialProxy({ cacheSeconds: 0, ...options }).routes!.fetch(new Request(`${PUBLIC}/use${path}`, { ...init, headers }), coffre(values, plain));
}

/** Bytes as a string of one character each, as an answer's bytes are scanned. */
const binary = (bytes: Uint8Array) => String.fromCharCode(...bytes);
const utf8 = (text: string) => binary(new TextEncoder().encode(text));

// Where a request goes.

/** What a path segment can be: dot segments in every spelling, encoded slashes, path parameters, and the rest. */
const segment = gs.oneOf(
  gs.sampledFrom(['..', '.', '%2e%2e', '%2E%2e', '.%2E', '%2e', '%2f', '%2F', '%5c', '%5C', '\\', '..;', '..;x=1', '.;', '%2e%2e;', '..%3b', '%2e%2e%3B', '%3b', ';a=b', '%252e%252e', '%252E%252e', '%25252e%25252e', '%252f', '%255c', '..%253b', '．．', '%EF%BC%8E%EF%BC%8E', '', '@', '@evil.example', '%40evil.example', '%23', '%3F', ':', 'http:', '%00', '%0d%0a', '%e9', '%']),
  gs.sampledFrom(['v1', 'v2', 'companies', 'x', 'y', 'admin', 'a', 'b%20c']),
  gs.text({ maxSize: 4, excludeCategories: ['Cs'] }).map((text) => text.replace(/[/?#]/g, '')),
);
const BASES = ['https://api.example', 'https://api.example/v1', 'https://api.example/v1/', 'https://api.example/a/b%20c'] as const;

/**
 * The path as a server reads it: each segment percent-decoded until it no
 * longer changes, as one behind another decodes it twice, and its `;`
 * parameters dropped, as Tomcat, Jetty and Spring do (Orange Tsai,
 * "Breaking Parser Logic", Black Hat 2018: `/..;/`), then dot segments
 * resolved. Null for a segment that decodes to a slash or a backslash,
 * which some servers split on.
 */
const decode = (text: string) => text.replace(/%([0-9a-f]{2})/gi, (_, byte: string) => String.fromCharCode(parseInt(byte, 16)));
function serverView(pathname: string): string[] | null {
  const segments: string[] = [];
  for (const raw of pathname.split('/').slice(1)) {
    // As a server reads it, however many times it decodes: one behind another decodes twice.
    let decoded = raw;
    for (let again = decode(decoded); again !== decoded; again = decode(decoded)) decoded = again;
    if (/[/\\]/.test(decoded)) return null;
    const bare = decoded.split(';')[0];
    if (bare === '.') continue;
    if (bare === '..') segments.pop();
    else segments.push(raw);
  }
  return segments;
}
const startsWith = (segments: readonly string[], prefix: readonly string[]) => prefix.every((one, at) => segments[at] === one);

const settings = propertySettings(100);

test(`whatever path the app asks, the upstream is asked under the credential's upstream and paths alone, as any server reads it, seed ${settings.seed}`, () => hegel.testAsync(async (tc) => {
  const base = tc.draw(gs.sampledFrom(BASES));
  const paths = tc.draw(gs.optional(gs.sampledFrom([['/companies'], ['/companies/', '/x/y'], ['/']])));
  const rest = tc.draw(gs.arrays(segment, { maxSize: 6 })).join('/');
  const stable = tc.draw(gs.booleans());
  const search = tc.draw(gs.sampledFrom(['', '?a=1', '?next=https://evil.example/', '?a=..%2f..']));
  const path = `${stable ? '/schumann' : '/market/dev/schumann'}/${rest}${search}`;
  tc.note(`${base} ${JSON.stringify(paths)} ${path}`);
  const fake = upstream();
  const answer = await ask({ credentials: { schumann: { upstream: base, inject: header('x-api-key', '{KEY}'), ...(paths === null ? {} : { paths }), egress: fake.egress } } }, { KEY: 'sk_live_0123456789abcdef' }, path);
  assert.ok(fake.calls.length <= 1);
  // Refused, or a path that climbed to coffre's own `/use`, before the proxy saw it.
  if (fake.calls.length === 0) return assert.ok(answer.headers.get('coffre-proxy') === 'refused' || (await answer.json()).proxy === 'coffre');
  const { url } = fake.calls[0]!;
  const root = new URL(base);
  assert.equal(url.origin, root.origin);
  const view = serverView(url.pathname);
  assert.ok(view !== null, `${url.pathname} smuggles a slash`);
  const under = serverView(root.pathname.replace(/\/$/, ''))!;
  assert.ok(startsWith(view, under), `${url.pathname} reads as /${view.join('/')}, outside ${root.pathname}`);
  if (paths !== null) {
    const relative = view.slice(under.length);
    assert.ok(paths.some((prefix) => startsWith(relative, prefix.split('/').filter(Boolean))), `${url.pathname} is outside ${paths.join(', ')}`);
  }
}, settings));

// What comes back of a redirect.

const SECRET = 'sk_live_0123456789abcdef';
const location = gs.oneOf(
  gs.sampledFrom([
    'https://evil.example/x', '//evil.example/x', '/\\evil.example/x', '\\\\evil.example', 'https:evil.example', 'http://api.example/v1/x',
    'https://api.example:444/v1/x', 'https://API.EXAMPLE/v1/x', '../x', '../../x', '/v1/ok', 'ok', '/other', '/v1/%2e%2e/x', '/v1/..%2fx',
    `https://api.example/v1/ok?k=${SECRET}`, `https://user:${SECRET}@api.example/v1/ok`, `/v1/${SECRET}`, 'javascript:alert(1)', 'data:text/html,x', '', '?a=1', '#frag', '/v1',
  ]),
  gs.text({ maxSize: 12, codec: 'latin-1' }).map((text) => text.replace(/[\0\r\n]/g, '')),
);

test(`a redirect comes back as the proxy's own URL under the credential, or not at all, and quotes no secret, seed ${settings.seed}`, () => hegel.testAsync(async (tc) => {
  const status = tc.draw(gs.sampledFrom([301, 302, 303, 307, 308, 200, 201]));
  const to = tc.draw(location);
  const rule = tc.draw(gs.sampledFrom(['header', 'query'] as const));
  tc.note(`${status} ${JSON.stringify(to)} ${rule}`);
  const fake = upstream(() => new Response(null, { status, headers: { location: to } }));
  const inject = rule === 'header' ? header('x-api-key', '{KEY}') : query('key', '{KEY}');
  const answer = await ask({ credentials: { schumann: { upstream: 'https://api.example/v1', inject, egress: fake.egress } } }, { KEY: SECRET }, '/market/dev/schumann/start');
  assert.equal(fake.calls.length, 1, 'never followed');
  const back = answer.headers.get('location');
  assert.equal(back?.includes(SECRET) ?? false, false);
  if (status >= 300 && status < 400 && answer.headers.get('coffre-proxy') !== 'refused') {
    const proxied = `${PUBLIC}/use/market/dev/schumann`;
    assert.ok(back !== null);
    const moved = new URL(back);
    assert.ok(moved.origin === PUBLIC && (moved.pathname === '/use/market/dev/schumann' || moved.pathname.startsWith('/use/market/dev/schumann/')), `${back} is outside ${proxied}`);
  }
}, settings));

// What a request carries.

/** Request headers the upstream must never see: about the hop (RFC 9110, 7.6.1), coffre's caller, its cookies, and the handle. */
const NEVER_SENT = ['connection', 'keep-alive', 'proxy-connection', 'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade', 'host', 'cookie', 'content-length', 'expect', 'x-coffre-handle', 'forwarded', 'x-real-ip', 'cdn-loop', 'true-client-ip'];
const requestHeader = gs.tuples(
  gs.oneOf(
    gs.sampledFrom([...NEVER_SENT.filter((name) => name !== 'x-coffre-handle'), 'Connection', 'X-Forwarded-For', 'x-forwarded-host', 'X-FORWARDED-PROTO', 'CF-Connecting-IP', 'cf-ray', 'cf-access-jwt-assertion', 'Cookie', 'Proxy-Authorization']),
    gs.fromRegex("[A-Za-z0-9!#$&'*+.^_`|~-]{1,10}", { fullmatch: true }),
  ),
  gs.text({ codec: 'latin-1', maxSize: 10 }).map((text) => text.replace(/[\0\r\n]/g, '')),
);
const awkward = gs.arrays(gs.oneOf(gs.sampledFrom(['\r', '\n', '\r\n', '\0', ' ', '\t', 'é', '日', 'X-Injected: 1', '%0d%0a', '"', ',']), gs.fromRegex('[A-Za-z0-9_]{1,12}', { fullmatch: true })), { minSize: 1, maxSize: 6 }).map((parts) => parts.join(''));

test(`no header reaches the upstream with a line break or NUL, nor one about the hop, the caller or the handle, seed ${settings.seed}`, () => hegel.testAsync(async (tc) => {
  const rule = tc.draw(gs.sampledFrom(['header', 'bearer', 'query', 'basic'] as const));
  const values = { KEY: tc.draw(awkward), USER: tc.draw(awkward) };
  const sent = tc.draw(gs.arrays(requestHeader, { maxSize: 6 }));
  tc.note(`${rule} ${JSON.stringify(values)} ${JSON.stringify(sent)}`);
  const inject: Inject = rule === 'header' ? header('x-api-key', '{KEY}') : rule === 'bearer' ? header('authorization', 'Bearer {KEY}') : rule === 'query' ? query('key', '{KEY}') : basic('{USER}', '{KEY}');
  const fake = upstream();
  const headers = new Headers();
  for (const [name, value] of sent) headers.append(name, value);
  const answer = await ask({ credentials: { schumann: { upstream: 'https://api.example/v1', inject, egress: fake.egress } } }, values, '/market/dev/schumann/x', { headers });
  if (fake.calls.length === 0) {
    assert.equal(answer.status, 409, 'only a value no header can carry stops the request');
    assert.ok(rule !== 'query' && rule !== 'basic' && /[\0\r\n]|[^\0-ÿ]/.test(values.KEY));
    return;
  }
  const out = fake.calls[0]!;
  for (const [name, value] of out.headers) {
    assert.doesNotMatch(value, /[\0\r\n]/, name);
    assert.ok(!NEVER_SENT.includes(name) && !name.startsWith('cf-') && !name.startsWith('x-forwarded-'), `${name} reached the upstream`);
  }
  if (rule === 'query') assert.equal(out.url.searchParams.get('key'), values.KEY);
  if (rule === 'basic') assert.equal(new TextDecoder().decode(Uint8Array.from(atob(out.headers.get('authorization')!.slice('Basic '.length)), (char) => char.charCodeAt(0))), `${values.USER}:${values.KEY}`);
}, settings));

// What redaction leaves of an answer.

/**
 * Secrets over an alphabet with none of `[redacted by coffre]`'s brackets, so
 * that no secret can be made of a replacement and the text around it, and with
 * what each echoed form escapes. Drawn from one string, so that they overlap
 * and begin one another.
 */
const ALPHABET = 'ABx1é日"<&/%\\ ';
const secrets = gs.composite((tc) => {
  const source = tc.draw(gs.text({ alphabet: ALPHABET, minSize: MIN_REDACTED, maxSize: 24 }));
  const cut = (least: number) => {
    const from = tc.draw(gs.integers({ minValue: 0, maxValue: source.length - least }));
    return source.slice(from, tc.draw(gs.integers({ minValue: from + least, maxValue: source.length })));
  };
  // The first long enough to be redacted, always: what is left of it is what the property is about.
  return [cut(MIN_REDACTED), cut(1), tc.draw(gs.text({ alphabet: ALPHABET, minSize: 1, maxSize: 12 }))];
});
/** The forms an honest upstream quotes a value in (the design's closed list), and the bytes they travel as. */
const forms = (value: string) => {
  const json = JSON.stringify(value).slice(1, -1);
  const text = [value, encodeURIComponent(value), new URLSearchParams({ v: value }).toString().slice(2), json, json.replace(/[\u0080-￿]/g, (char) => `\\u${char.charCodeAt(0).toString(16).padStart(4, '0')}`), value.replace(/[&<>"']/g, (char) => `&${{ '&': 'amp', '<': 'lt', '>': 'gt', '"': 'quot', "'": '#39' }[char]};`)];
  return [...text.map(utf8), ...(/^[\0-ÿ]*$/.test(value) ? [value] : [])];
};

test(`an answer redacted as it streams, however it is split, is the whole answer redacted, and no secret's form is left in it, seed ${settings.seed}`, () => hegel.testAsync(async (tc) => {
  const [a, b, c] = tc.draw(secrets);
  // A header carries Latin-1 alone (a value past it is a 409, before anything is sent); Basic's base64 carries anything.
  const rule = /^[\0-\u00ff]*$/.test(a! + b!) ? tc.draw(gs.sampledFrom(['bearer', 'basic', 'pair'] as const)) : 'basic';
  const inject: Inject = rule === 'bearer' ? header('authorization', 'Bearer {A}') : rule === 'basic' ? basic('{B}', '{A}') : header('x-key', '{A}{B}');
  const values = { A: a!, B: b! };
  const plain = tc.draw(gs.booleans()) ? ['B'] : [];
  // What the request carried: the rule's keys' values, but a plain one, which is no secret.
  const kept = (rule === 'bearer' ? ['A'] : ['A', 'B']).filter((key) => !plain.includes(key)).map((key) => values[key as 'A' | 'B']);
  // The body: pieces of every secret's forms, whole or cut short, among filler, as bytes.
  const pieces = tc.draw(gs.arrays(gs.oneOf(
    gs.sampledFrom([a!, b!, c!]).flatMap((value) => gs.sampledFrom(forms(value))).flatMap((form) => gs.integers({ minValue: 1, maxValue: form.length }).map((end) => [form, form.slice(0, end), form.slice(-end)][end % 3]!)),
    gs.text({ alphabet: `${ALPHABET}yz`, maxSize: 6 }).map(utf8),
  ), { maxSize: 12 }));
  // One of the first secret's forms whole, somewhere among them.
  pieces.splice(tc.draw(gs.integers({ minValue: 0, maxValue: pieces.length })), 0, tc.draw(gs.sampledFrom(forms(a!))));
  const body = pieces.join('');
  const cuts = [...new Set(tc.draw(gs.arrays(gs.integers({ minValue: 0, maxValue: body.length }), { maxSize: 8 })))].sort((x, y) => x - y);
  const type = tc.draw(gs.sampledFrom(['text/plain', 'application/json; charset=utf-8', 'application/xml', 'text/event-stream']));
  tc.note(`${rule} ${JSON.stringify(values)} plain ${JSON.stringify(plain)} body ${JSON.stringify(body)} cuts ${JSON.stringify(cuts)}`);
  const bytes = (text: string) => Uint8Array.from(text, (char) => char.charCodeAt(0));
  const chunks = [0, ...cuts, body.length].slice(1).map((end, at, ends) => bytes(body.slice(at === 0 ? 0 : ends[at - 1], end)));
  const echoed = pieces.find((piece) => piece.length > 0) ?? 'none';
  const answer = (parts: Uint8Array[]) => new Response(new ReadableStream({ start(controller) {
    for (const part of parts) controller.enqueue(part);
    controller.close();
  } }), { status: 400, statusText: echoed, headers: { 'content-type': type, 'x-echo': echoed } });
  const read = async (parts: Uint8Array[]) => {
    const response = await ask({ credentials: { schumann: { upstream: 'https://api.example', inject, egress: upstream(() => answer(parts)).egress } } }, values, '/market/dev/schumann/x', {}, plain);
    assert.equal(response.status, 400);
    return { body: binary(new Uint8Array(await response.arrayBuffer())), header: response.headers.get('x-echo')!, reason: response.statusText };
  };
  const streamed = await read(chunks);
  const whole = await read([bytes(body)]);
  assert.deepEqual(streamed, whole);
  for (const secret of kept.filter((value) => value.length >= MIN_REDACTED)) {
    for (const form of forms(secret)) for (const [where, text] of Object.entries(streamed)) assert.ok(!text.includes(form), `${JSON.stringify(form)} left in the ${where}`);
  }
}, settings));

// The addresses the proxy holds private.

/** An IPv4 address as a number, and every way a URL may write it: one to four parts, each decimal, octal or hex, a dot after. */
const ipv4Spelling = (address: number) => gs.composite((tc) => {
  const parts = tc.draw(gs.integers({ minValue: 1, maxValue: 4 }));
  const numbers: number[] = [];
  for (let at = 0; at < parts - 1; at++) numbers.push((address >>> (24 - 8 * at)) & 0xff);
  numbers.push(parts === 1 ? address : address % 2 ** (32 - 8 * (parts - 1)));
  const written = numbers.map((value) => {
    const base = tc.draw(gs.sampledFrom(['dec', 'oct', 'hex', 'HEX'] as const));
    if (base === 'dec') return String(value);
    if (base === 'oct') return `0${value.toString(8)}`;
    const digits = value.toString(16).padStart(tc.draw(gs.integers({ minValue: 1, maxValue: 3 })), '0');
    return base === 'hex' ? `0x${digits}` : `0X${digits.toUpperCase()}`;
  });
  return `${written.join('.')}${tc.draw(gs.booleans()) ? '.' : ''}`;
});
const dotted = (address: number) => [24, 16, 8, 0].map((shift) => (address >>> shift) & 0xff).join('.');

/** An IPv6 address as eight groups, and the ways one is written: leading zeros, either case, a run of zeros as `::`, the last 32 bits dotted. */
const ipv6Spelling = (groups: readonly number[]) => gs.composite((tc) => {
  const hex = (group: number) => {
    const text = group.toString(16).padStart(tc.draw(gs.integers({ minValue: 1, maxValue: 4 })), '0');
    return tc.draw(gs.booleans()) ? text.toUpperCase() : text;
  };
  const tail = tc.draw(gs.booleans());
  const written = tail ? [...groups.slice(0, 6).map(hex), dotted(groups[6]! * 0x10000 + groups[7]!)] : groups.map(hex);
  const width = tail ? 7 : 8;
  // A run of zero groups, any of them, of any length, as `::`.
  const runs: [number, number][] = [];
  for (let from = 0; from < width; from++) for (let to = from + 1; to <= width && groups.slice(from, to).every((group) => group === 0) && !(tail && to > 6); to++) runs.push([from, to]);
  if (runs.length === 0 || !tc.draw(gs.booleans())) return written.join(':');
  const [from, to] = tc.draw(gs.sampledFrom(runs));
  return `${written.slice(0, from).join(':')}::${written.slice(to).join(':')}`;
});
/** RFC 5952 as the URL Standard serializes IPv6: lowercase, no leading zeros, the first longest run of two or more zero groups as `::`. */
function ipv6Text(groups: readonly number[]): string {
  let best: [number, number] = [-1, 0];
  for (let from = 0; from < 8; from++) {
    let to = from;
    while (to < 8 && groups[to] === 0) to++;
    if (to - from > 1 && to - from > best[1]) best = [from, to - from];
  }
  const hex = groups.map((group) => group.toString(16));
  return best[0] < 0 ? hex.join(':') : `${hex.slice(0, best[0]).join(':')}::${hex.slice(best[0] + best[1]).join(':')}`;
}

const inRange = (address: number, base: string, bits: number) => {
  const start = base.split('.').reduce((sum, part) => sum * 256 + Number(part), 0);
  return Math.floor(address / 2 ** (32 - bits)) === Math.floor(start / 2 ** (32 - bits));
};
/** Private, loopback, link-local, this network and shared (RFC 6890): never reachable from a deployment's own upstream config. */
const privateV4 = (address: number) => [['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.168.0.0', 16]]
  .some(([base, bits]) => inRange(address, base as string, bits as number));

type Address = { kind: 'v4'; value: number } | { kind: 'v6'; groups: number[]; private: boolean | null };
const ipv4 = gs.oneOf(
  gs.integers({ minValue: 0, maxValue: 0xffff_ffff }),
  gs.sampledFrom([['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.168.0.0', 16], ['172.32.0.0', 11], ['100.128.0.0', 9]] as const)
    .flatMap(([base, bits]) => gs.integers({ minValue: 0, maxValue: 2 ** (32 - bits) - 1 }).map((offset) => base.split('.').reduce((sum, part) => sum * 256 + Number(part), 0) + offset)),
).map((value): Address => ({ kind: 'v4', value }));
const group = gs.integers({ minValue: 0, maxValue: 0xffff });
/**
 * Loopback, unspecified, unique local (fc00::/7), link-local (fe80::/10) and
 * IPv4-mapped (::ffff:0:0/96) are private; global unicast (2000::/3) but
 * 6to4 (2002::/16) is public. The rest (multicast, IPv4-compatible,
 * NAT64's 64:ff9b::/96, which RFC 6052 3.1 keeps from private IPv4) is
 * not decided here.
 */
const ipv6 = gs.oneOf(
  gs.just({ groups: [0, 0, 0, 0, 0, 0, 0, 1], private: true }),
  gs.just({ groups: [0, 0, 0, 0, 0, 0, 0, 0], private: true }),
  gs.arrays(group, { minSize: 8, maxSize: 8 }).map((groups) => ({ groups: [0xfc00 | (groups[0]! & 0x1ff), ...groups.slice(1)], private: true })),
  gs.arrays(group, { minSize: 8, maxSize: 8 }).map((groups) => ({ groups: [0xfe80 | (groups[0]! & 0x3f), ...groups.slice(1)], private: true })),
  gs.tuples(group, group).map(([high, low]) => ({ groups: [0, 0, 0, 0, 0, 0xffff, high, low], private: true })),
  gs.arrays(group, { minSize: 8, maxSize: 8 }).map((groups) => ({ groups: [0x2000 | (groups[0]! & 0x1fff), ...groups.slice(1)], private: groups[0]! % 0x2000 === 2 ? null : false })),
  gs.arrays(gs.oneOf(group, gs.just(0)), { minSize: 8, maxSize: 8 }).map((groups) => ({ groups, private: null })),
).map((drawn): Address => ({ kind: 'v6', ...drawn }));
const spell = (address: Address) => (address.kind === 'v4' ? ipv4Spelling(address.value) : ipv6Spelling(address.groups));
const isPrivate = (address: Address) => (address.kind === 'v4' ? privateV4(address.value) : address.private);
const canonical = (address: Address) => (address.kind === 'v4' ? dotted(address.value) : ipv6Text(address.groups));
const bracketed = (address: Address, text: string) => (address.kind === 'v6' ? `[${text}]` : text);

/** Names that are loopback (RFC 6761: `localhost` and every name under it, a trailing dot or not), and names that are not. */
const LOOPBACK_NAMES = ['localhost', 'LocalHost', 'localhost.', 'a.localhost', 'A.LOCALHOST.', 'x.y.localhost'];
const PUBLIC_NAMES = ['api.example', 'example.com.', 'localhost.example', 'notlocalhost', 'localhost-1.example'];

test(`an upstream at a private address, however its URL writes it, is refused without insecureUpstreams, seed ${settings.seed}`, () => hegel.test((tc) => {
  const named = tc.draw(gs.booleans());
  const address = named ? null : tc.draw(gs.oneOf(ipv4, ipv6));
  const name = named ? tc.draw(gs.sampledFrom([...LOOPBACK_NAMES, ...PUBLIC_NAMES])) : null;
  const host = address === null ? name! : bracketed(address, tc.draw(spell(address)));
  const expected = address === null ? LOOPBACK_NAMES.includes(name!) : isPrivate(address);
  tc.note(`${host} ${address === null ? '' : canonical(address)} private: ${expected}`);
  const make = () => credentialProxy({ credentials: { schumann: { upstream: `https://${host}/v1`, inject: header('x-api-key', '{KEY}') } } });
  if (expected === true) assert.throws(make, /private address/);
  if (expected === false) assert.doesNotThrow(make);
  // As insecureUpstreams allows, for a local fake.
  assert.doesNotThrow(() => credentialProxy({ credentials: { schumann: { upstream: `http://${host}/v1`, inject: header('x-api-key', '{KEY}') } }, insecureUpstreams: true }));
}, settings));

// A tunnel's database URL.

test(`a database URL's host is the address it names, however it is written, seed ${settings.seed}`, () => hegel.test((tc) => {
  const address = tc.draw(gs.oneOf(ipv4, ipv6));
  const host = bracketed(address, tc.draw(spell(address)));
  const port = tc.draw(gs.optional(gs.integers({ minValue: 1, maxValue: 65535 })));
  const scheme = tc.draw(gs.sampledFrom(['postgres', 'postgresql']));
  const url = `${scheme}://app:p%40ss@${host}${port === null ? '' : `:${port}`}/app`;
  tc.note(url);
  const parsed = database(url);
  assert.deepEqual(parsed, { host: canonical(address), port: port ?? 5432, user: 'app', password: 'p@ss', database: 'app', tls: 'require' });
}, settings));

test(`a tunnel reaches its hosts however they and the URL write them, and nothing private unless allowed, seed ${settings.seed}`, () => hegel.testAsync(async (tc) => {
  const address = tc.draw(gs.oneOf(ipv4, ipv6));
  const other = tc.draw(gs.oneOf(ipv4, ipv6));
  const configured = tc.draw(spell(address));
  const named = tc.draw(gs.booleans()) ? address : other;
  const url = `postgres://app:pw@${bracketed(named, tc.draw(spell(named)))}:5432/app`;
  const insecure = tc.draw(gs.booleans());
  tc.note(`hosts [${configured}] url ${url} insecure ${insecure}`);
  const open = async (options: CredentialProxyOptions) => credentialProxy({ cacheSeconds: 0, ...options }).routes!.socket!(
    new Request(`${PUBLIC}/use/market/dev/db`, { headers: { authorization: `Bearer ${HANDLE}` } }),
    coffre({ DATABASE_URL: url }),
  );
  if (insecure) {
    const opened = await open({ credentials: {}, tunnels: { db: postgres('DATABASE_URL', { hosts: [tc.draw(gs.booleans()) ? bracketed(address, configured) : configured] }) }, insecureUpstreams: true });
    const same = canonical(named) === canonical(address) && named.kind === address.kind;
    assert.equal(typeof opened === 'function', same, opened instanceof Response ? await opened.clone().text() : 'opened');
    return;
  }
  const opened = await open({ credentials: {}, tunnels: { db: postgres('DATABASE_URL') } });
  const expected = isPrivate(named);
  if (expected !== null) assert.equal(typeof opened !== 'function', expected, opened instanceof Response ? await opened.clone().text() : 'opened');
}, settings));

test(`a tunnel's URL naming localhost, a trailing dot or not, is refused without insecureUpstreams, seed ${settings.seed}`, () => hegel.testAsync(async (tc) => {
  const name = tc.draw(gs.sampledFrom([...LOOPBACK_NAMES, ...PUBLIC_NAMES]));
  const opened = await credentialProxy({ cacheSeconds: 0, credentials: {}, tunnels: { db: postgres('DATABASE_URL') } }).routes!.socket!(
    new Request(`${PUBLIC}/use/market/dev/db`, { headers: { authorization: `Bearer ${HANDLE}` } }),
    coffre({ DATABASE_URL: `postgres://app:pw@${name}:5432/app` }),
  );
  assert.equal(typeof opened !== 'function', LOOPBACK_NAMES.includes(name), name);
}, settings));

// SASLprep, as Postgres runs it on a SCRAM password (RFC 4013, src/common/saslprep.c).

/** RFC 3454's prohibited tables that RFC 4013 2.3 names, but for what mapping or NFKC removes first (C.1.2's spaces, B.1, U+0340 and U+0341). */
const PROHIBITED: readonly [number, number][] = [
  [0x0000, 0x001f], [0x007f, 0x009f], [0x06dd, 0x06dd], [0x070f, 0x070f], [0x180e, 0x180e], [0x2028, 0x2029], [0x2061, 0x2063], [0x206a, 0x206f],
  [0xfff9, 0xfffd], [0x1d173, 0x1d17a], [0xe000, 0xf8ff], [0xf0000, 0xffffd], [0x100000, 0x10fffd], [0xfdd0, 0xfdef], [0xfffe, 0xffff],
  [0x1fffe, 0x1ffff], [0x10fffe, 0x10ffff], [0xd800, 0xdfff], [0x2ff0, 0x2ffb], [0x200e, 0x200f], [0x202a, 0x202e], [0xe0001, 0xe0001], [0xe0020, 0xe007f],
];
const prohibited = gs.sampledFrom(PROHIBITED).flatMap(([from, to]) => gs.integers({ minValue: from, maxValue: to })).map((code) => String.fromCodePoint(code));
/** Characters whose bidirectional category RFC 3454 tables D.1 (R and AL) and D.2 (L) give, Unicode 3.2's, and what mapping changes. */
const LEFT = ['a', 'Z', 'é', 'ß'];
const RIGHT = ['א', 'ת', 'ا', 'ب', '־', '׀', '׃', '؛', '؟', 'ـ'];
const NEUTRAL = ['0', '9', ' ', '-', '!', '٠'];
const MAPPED = [' ', '　', '­', '​', '﻿'];
const bidiText = gs.arrays(gs.sampledFrom([...LEFT, ...RIGHT, ...NEUTRAL, ...MAPPED]), { minSize: 1, maxSize: 8 }).map((chars) => chars.join(''));

/** RFC 4013 on that alphabet: spaces mapped, the rest mapped to nothing, NFKC; then RFC 3454 6's bidi rule, and the password as it is when it fails. */
function modelSaslprep(password: string): string {
  const mapped = password.replace(/[ 　​]/g, ' ').replace(/[­﻿]/g, '').normalize('NFKC');
  const chars = [...mapped];
  if (mapped === '') return password;
  const right = (char: string) => RIGHT.includes(char);
  if (chars.some(right) && (chars.some((char) => LEFT.includes(char)) || !right(chars[0]!) || !right(chars.at(-1)!))) return password;
  return mapped;
}

test(`SASLprep is idempotent, seed ${settings.seed}`, () => hegel.test((tc) => {
  const password = tc.draw(gs.oneOf(gs.text({ maxSize: 12 }), bidiText, gs.arrays(gs.sampledFrom([...MAPPED, 'ﬁ', 'Ⅳ', '①', 'K', 'Å', 'é', ' ', ' ', '͏', '᠋', '️', 'a']), { maxSize: 6 }).map((chars) => chars.join(''))));
  const prepared = saslprep(password);
  tc.note(`${JSON.stringify(password)} -> ${JSON.stringify(prepared)}`);
  assert.equal(saslprep(prepared), prepared);
}, settings));

test(`a password with a prohibited character is taken as it is, as Postgres falls back, seed ${settings.seed}`, () => hegel.test((tc) => {
  const around = gs.arrays(gs.sampledFrom([...LEFT, ...NEUTRAL, ...MAPPED, 'ﬁ']), { maxSize: 4 }).map((chars) => chars.join(''));
  const password = `${tc.draw(around)}${tc.draw(prohibited)}${tc.draw(around)}`;
  tc.note(JSON.stringify(password));
  assert.equal(saslprep(password), password);
}, settings));

test(`SASLprep keeps RFC 3454's bidi rule on right-to-left letters, punctuation and marks, seed ${settings.seed}`, () => hegel.test((tc) => {
  const password = tc.draw(bidiText);
  tc.note(JSON.stringify([...password].map((char) => char.codePointAt(0)!.toString(16))));
  assert.equal(saslprep(password), modelSaslprep(password));
}, settings));
