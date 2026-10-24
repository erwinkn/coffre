import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtempSync, rmSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import * as hegel from '@hegeldev/hegel';
import * as gs from '@hegeldev/hegel/generators';

import { githubEnvironment, githubMasks } from '../src/github-env.ts';
import { choose, emptyStore, instanceOrigin, localFor, parseRepoFile, pinFor, type Local, type Pins } from '../src/instance.ts';
import { awkwardValue, keyName, value } from '../../../scripts/properties/domain.ts';
import { propertySettings } from '../../../scripts/property-settings.ts';
import { signedInWithToken } from './fakes.ts';

const settings = propertySettings(200);

/** A lone surrogate replaced by U+FFFD, as UTF-8 encoding does (`String.prototype.toWellFormed`, past this lib's target). */
const wellFormedText = (text: string) => text.replace(/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g, '�');

/** Line separators, BOM, NBSP, NEL, and what GitHub's own grammar is made of. */
const ODD = ['\u2028', '\u2029', '\uFEFF', '\u0085', '\u00A0', '\v', '\f', '\r', '\n', '\r\n', '<<', '=', '%', '%0A', '%25', '::', '::add-mask::', 'NODE_OPTIONS=--require ./x.js', 'PATH=/tmp', 'EOF', 'ghadelimiter'];
/** Values GitHub's file and log carry as UTF-8: well-formed, as a value coffre can store is. */
const githubValue = gs.oneOf(
  value,
  awkwardValue,
  gs.arrays(gs.oneOf(gs.sampledFrom(ODD), gs.text({ maxSize: 3 }), keyName.map((key) => `\n${key}<<EOF\n`)), { maxSize: 8 }).map((parts) => parts.join('').replaceAll('\0', '')),
).map(wellFormedText);
/** Entries with distinct keys, none the runner refuses to set (NODE_OPTIONS, in any case). */
const githubEntries = gs.arrays(gs.tuples(keyName, githubValue), { maxSize: 6 })
  .map((drawn) => [...new Map(drawn.filter(([key]) => key.toUpperCase() !== 'NODE_OPTIONS')).entries()]);

/**
 * `$GITHUB_ENV` as GitHub's runner reads it after the step, transcribed from
 * `EnvFileKeyValuePairs` in actions/runner's src/Runner.Worker/FileCommandManager.cs:
 * a line splits at its first "=" or "<<", whichever comes first; a heredoc's
 * value is the text between its header's line and the first line equal to
 * the delimiter, less the newline before it. Lines end at LF, and on Windows
 * at the first CRLF if it comes before. An empty line is skipped.
 */
function runnerEnvironment(text: string, windows: boolean): [string, string][] {
  let index = 0;
  const readLine = (): { line: string; newline: string | null } | null => {
    if (index >= text.length) return null;
    const start = index;
    const lf = text.indexOf('\n', index);
    if (lf < 0) {
      index = text.length;
      return { line: text.slice(start), newline: null };
    }
    const crlf = windows ? text.indexOf('\r\n', index) : -1;
    if (crlf >= 0 && crlf < lf) {
      index = crlf + 2;
      return { line: text.slice(start, crlf), newline: '\r\n' };
    }
    index = lf + 1;
    return { line: text.slice(start, lf), newline: '\n' };
  };
  const pairs: [string, string][] = [];
  for (let read = readLine(); read !== null; read = readLine()) {
    const { line } = read;
    if (line === '') continue;
    const equals = line.indexOf('=');
    const heredoc = line.indexOf('<<');
    if (equals >= 0 && (heredoc < 0 || equals < heredoc)) {
      pairs.push([line.slice(0, equals), line.slice(equals + 1)]);
    } else if (heredoc >= 0) {
      const key = line.slice(0, heredoc);
      const delimiter = line.slice(heredoc + 2);
      assert.ok(key !== '' && delimiter !== '', `invalid format ${JSON.stringify(line)}`);
      const start = index;
      let end = index;
      for (let next = readLine(); next?.line !== delimiter; next = readLine()) {
        assert.ok(next !== null, `matching delimiter not found ${JSON.stringify(delimiter)}`);
        assert.ok(next.newline !== null, 'EOF marker missing new line');
        end = index - next.newline.length;
      }
      pairs.push([key, end > start ? text.slice(start, end) : '']);
    } else {
      assert.fail(`invalid format ${JSON.stringify(line)}`);
    }
  }
  return pairs;
}

test(`GitHub's runner reads githubEnvironment's records back as exactly the entries and nothing else, on either host's newline, seed ${settings.seed}`, () => hegel.test((tc) => {
  const entries = tc.draw(githubEntries);
  const windows = tc.draw(gs.booleans());
  // Delimiters the values hold come first, so that a clash is met and passed over; then fresh ones.
  const values = entries.map(([, text]) => text).filter((text) => text !== '');
  const clashing = values.length === 0 ? [] : tc.draw(gs.arrays(gs.composite((inner) => {
    const text = inner.draw(gs.sampledFrom(values));
    const from = inner.draw(gs.integers({ minValue: 0, maxValue: text.length - 1 }));
    return text.slice(from, inner.draw(gs.integers({ minValue: from + 1, maxValue: text.length })));
  }).filter((delimiter) => !/[\r\n]/.test(delimiter)), { maxSize: 4 }));
  let fresh = 0;
  const next = () => clashing.shift() ?? `coffre_${fresh++}`;
  const text = githubEnvironment(entries, next, windows ? '\r\n' : '\n');
  tc.note(JSON.stringify(text));
  // The CLI appends it as UTF-8, and the runner decodes the file as UTF-8.
  assert.deepEqual(runnerEnvironment(Buffer.from(text, 'utf8').toString('utf8'), windows), entries);
}, settings));

test(`GitHub's runner refuses NODE_OPTIONS from $GITHUB_ENV, and githubEnvironment refuses it in any case before writing, seed ${settings.seed}`, () => hegel.test((tc) => {
  const entries = tc.draw(githubEntries);
  const name = [...'NODE_OPTIONS'].map((character) => (tc.draw(gs.booleans()) ? character.toLowerCase() : character)).join('');
  const at = tc.draw(gs.integers({ minValue: 0, maxValue: entries.length }));
  const all = [...entries.slice(0, at), [name, tc.draw(githubValue)] as [string, string], ...entries.slice(at)];
  assert.throws(() => githubEnvironment(all), /cannot be set through GITHUB_ENV/);
}, settings));

/** .NET's char.IsWhiteSpace: Unicode's space separators, line and paragraph separators, and \t to \r, NEL and NBSP. */
const DOTNET_WHITESPACE = /^[\p{Zs}\u2028\u2029\t\n\v\f\r\u0085\u00A0]*$/u;

/**
 * What GitHub's runner masks after reading a step's output, transcribed from
 * actions/runner: each line (StreamReader's: CR, LF or CRLF) is a command
 * when, its leading whitespace trimmed, it starts with `::` and names one
 * before the next `::` (`ActionCommand.TryParseV2`); `add-mask`'s data is
 * unescaped with `%0D`, `%0A`, `%25` replaced in that order
 * (`UnescapeData`), and a mask is the whole data and each of its trimmed
 * non-empty lines, unless it is all whitespace (`AddMaskCommandExtension`).
 */
function runnerMasks(stdout: string): { commands: string[]; data: string[]; masks: Set<string> } {
  const commands: string[] = [];
  const data: string[] = [];
  const masks = new Set<string>();
  for (const line of stdout.split(/\r\n|\r|\n/)) {
    if (line === '') continue;
    const message = line.trimStart();
    const end = message.startsWith('::') ? message.indexOf('::', 2) : -1;
    if (end < 0) {
      commands.push(`text: ${line}`);
      continue;
    }
    commands.push(message.slice(2, end).split(' ')[0]!.toLowerCase());
    const unescaped = message.slice(end + 2).replaceAll('%0D', '\r').replaceAll('%0A', '\n').replaceAll('%25', '%');
    data.push(unescaped);
    if (DOTNET_WHITESPACE.test(unescaped)) continue;
    masks.add(unescaped);
    for (const part of unescaped.split(/[\r\n]/)) if (!DOTNET_WHITESPACE.test(part)) masks.add(part.replace(/^[\p{Zs}\u2028\u2029\t\n\v\f\r\u0085\u00A0]+|[\p{Zs}\u2028\u2029\t\n\v\f\r\u0085\u00A0]+$/gu, ''));
  }
  return { commands, data, masks };
}

test(`githubMasks makes GitHub mask every value and each of its lines, through add-mask commands alone, each exactly a value or a line of one, seed ${settings.seed}`, () => hegel.test((tc) => {
  const values = tc.draw(gs.arrays(githubValue, { maxSize: 5 }));
  const stdout = githubMasks(values.map((text, at) => [`K${at}`, text] as const));
  tc.note(JSON.stringify(stdout));
  const { commands, data, masks } = runnerMasks(stdout);
  assert.deepEqual(commands.filter((command) => command !== 'add-mask'), []);
  const lines = (text: string) => text.split(/\r\n|\r|\n/);
  for (const one of data) assert.ok(values.some((text) => text === one || lines(text).includes(one)), `masked ${JSON.stringify(one)}, which is no value or line of one`);
  for (const text of values) {
    for (const part of [text, ...lines(text)]) {
      if (!DOTNET_WHITESPACE.test(part)) assert.ok(masks.has(part), `${JSON.stringify(part)} is not masked`);
    }
  }
}, settings));

// --- coffre.json and the instance's origin ------------------------------------

/** On this machine, where no wire carries a plain HTTP request: `localhost`, IPv6's loopback and IPv4's 127/8. */
function loopback(hostname: string): boolean {
  if (hostname === 'localhost' || hostname === '[::1]') return true;
  const octets = hostname.split('.');
  return octets.length === 4 && octets[0] === '127' && octets.every((octet) => /^\d+$/.test(octet) && Number(octet) <= 255);
}

const typedAddress = gs.composite((tc) => [
  tc.draw(gs.sampledFrom(['', ' ', '\t', '\n'])),
  tc.draw(gs.sampledFrom(['', 'https://', 'http://', 'HTTP://', 'Https://', 'ftp://', 'javascript://', 'https:/', 'https:', '//'])),
  tc.draw(gs.sampledFrom(['', '', 'ada@', 'ada:pw@', ':@', '@'])),
  tc.draw(gs.sampledFrom([
    'coffre.example.com', 'Coffre.Example.COM', 'localhost', 'LOCALHOST', 'localhost.', '127.0.0.1', '127.1', '127.255.255.254', '2130706433', '0x7f.1',
    '[::1]', '[0:0:0:0:0:0:0:1]', '[::ffff:127.0.0.1]', '128.0.0.1', '10.0.0.1', '0.0.0.0', 'ä.example', 'xn--4ca.example', '127.0.0.1.nip.io',
    'localhost.example', 'evil.example\\@127.0.0.1', '', 'exa mple.com', 'a\tb.example',
  ])),
  tc.draw(gs.sampledFrom(['', '', ':443', ':80', ':3000', ':0', ':65536', ':'])),
  tc.draw(gs.sampledFrom(['', '', '/', '/api', '?', '?x=1', '#', '#frag', '/.', '/%2e', '//', '\\', '/..'])),
  tc.draw(gs.sampledFrom(['', ' ', '\n'])),
].join(''));

const addressSettings = propertySettings(1000);

test(`an accepted address becomes an origin, its own origin again, and plain HTTP only on this machine; nothing is stripped to get there, seed ${addressSettings.seed}`, () => hegel.test((tc) => {
  const raw = tc.draw(gs.oneOf(typedAddress, gs.text({ maxSize: 12 })));
  let origin: string;
  try {
    origin = instanceOrigin(raw);
  } catch {
    return;
  }
  tc.note(`${JSON.stringify(raw)} -> ${origin}`);
  const url = new URL(origin);
  assert.equal(url.origin, origin);
  assert.ok(url.protocol === 'https:' || (url.protocol === 'http:' && loopback(url.hostname)), origin);
  assert.equal(instanceOrigin(origin), origin);
  // What was typed had no user, password, path, query or fragment to drop.
  const typed = raw.trim();
  const as = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(typed) ? typed : `https://${typed}`);
  assert.deepEqual([as.username, as.password, as.pathname, as.search, as.hash], ['', '', '/', '', '']);
}, addressSettings));

/** An origin written as one: what `new URL` makes its origin, over HTTPS, or HTTP to this machine. */
function isOrigin(url: string): boolean {
  if (!URL.canParse(url)) return false;
  const parsed = new URL(url);
  return parsed.origin === url && (parsed.protocol === 'https:' || (parsed.protocol === 'http:' && loopback(parsed.hostname)));
}

test(`coffre.json is accepted exactly when it is one object holding only "url", an origin written as one, seed ${addressSettings.seed}`, () => hegel.test((tc) => {
  const url = tc.draw(gs.oneOf(typedAddress, gs.sampledFrom(['https://coffre.acme.example', 'http://127.0.0.1:3000', 'http://localhost:3000', 'https://[::1]', 'http://[::1]:8080'])));
  const text = tc.draw(gs.oneOf(
    gs.just(JSON.stringify({ url })),
    gs.sampledFrom(['token', '__proto__', 'URL', 'url ', 'constructor', 'origin']).map((other) => `{"url":${JSON.stringify(url)},${JSON.stringify(other)}:"coffre_cli_x"}`),
    gs.just(`{"url":"https://other.example","url":${JSON.stringify(url)}}`),
    gs.just(`\uFEFF${JSON.stringify({ url })}`),
    gs.just(`${JSON.stringify({ url })} trailing`),
    gs.sampledFrom(['[]', 'null', '{}', '"https://coffre.acme.example"', '{"url":3}', '{"url":null}', '[{"url":"https://coffre.acme.example"}]', '{"url":["https://coffre.acme.example"]}']),
  ));
  tc.note(text);
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    parsed = undefined;
  }
  const accepted = typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)
    && Object.keys(parsed).join() === 'url' && typeof (parsed as { url: unknown }).url === 'string' && isOrigin((parsed as { url: string }).url);
  let result: string | null;
  try {
    result = parseRepoFile(text);
  } catch {
    result = null;
  }
  assert.equal(result, accepted ? (parsed as { url: string }).url : null);
}, addressSettings));

/** Directories as real paths are: absolute, normalised, with siblings sharing prefixes (`/a/b`, `/a/bc`) and a home among them. */
const directory = gs.arrays(gs.sampledFrom(['a', 'b', 'bc', 'b.c', '..x', 'home', 'ada']), { maxSize: 4 }).map((parts) => `/${parts.join('/')}`);
const ORIGINS = ['https://coffre.example.com', 'https://coffre.acme.example', 'http://127.0.0.1:3000'];

/** `ancestor` is `path` or a directory above it, segment by segment: `/a/b` is not above `/a/bc`. */
function above(ancestor: string, path: string): boolean {
  return ancestor === path || ancestor === '/' || path.startsWith(`${ancestor}/`);
}
/** `path`, then each directory above it, up to the root. */
function upwards(path: string): string[] {
  const out = [path];
  while (out.at(-1) !== '/') out.push(out.at(-1)!.slice(0, out.at(-1)!.lastIndexOf('/')) || '/');
  return out;
}

test(`the longest pinned directory above wins, and a walk up reads coffre.json below the pin and your home alone, seed ${settings.seed}`, () => hegel.test((tc) => {
  const where = tc.draw(directory);
  // Mostly directories above `where`, or a sibling of one that shares its name's start (`/a/b` beside `/a/bc`).
  const near = gs.oneOf(directory, gs.sampledFrom(upwards(where)), gs.tuples(gs.sampledFrom(upwards(where)), gs.booleans()).map(([at, longer]) => (at === '/' ? '/b' : longer || /\/(?:[^/]|\.\.?.)$/.test(at) ? `${at}c` : at.slice(0, -1))));
  const pins: Pins = { version: 1, directories: Object.fromEntries(tc.draw(gs.arrays(gs.tuples(near, gs.sampledFrom(ORIGINS)), { maxSize: 4 }))) };
  const files = new Map(tc.draw(gs.arrays(gs.tuples(near, gs.sampledFrom(['valid', 'credential', 'broken'] as const)), { maxSize: 4 })));
  const home = tc.draw(near);
  const pinned = Object.keys(pins.directories).filter((pin) => above(pin, where)).sort((a, b) => b.length - a.length)[0];
  const pin = pinned === undefined ? null : { directory: pinned, origin: pins.directories[pinned]! };
  assert.deepEqual(pinFor(pins, where), pin);

  // The model's walk: from `where` up, before your home or anything above it, and before the pin's directory.
  const reads: string[] = [];
  let expected: Local | 'error' | null = pin === null ? null : { ...pin, by: 'pin' };
  for (const at of upwards(where)) {
    if (above(at, home) || (pin !== null && above(at, pin.directory))) break;
    reads.push(join(at, 'coffre.json'));
    const kind = files.get(at);
    if (kind === undefined) continue;
    expected = kind === 'valid' ? { origin: ORIGINS[at.length % ORIGINS.length]!, by: 'file', directory: at } : 'error';
    break;
  }
  const read: string[] = [];
  const contents = (path: string) => {
    read.push(path);
    const at = path.slice(0, -'/coffre.json'.length) || '/';
    const kind = files.get(at);
    if (kind === undefined) return null;
    const url = ORIGINS[at.length % ORIGINS.length]!;
    return kind === 'valid' ? JSON.stringify({ url }) : kind === 'credential' ? JSON.stringify({ url, token: 'coffre_cli_x' }) : '{';
  };
  tc.note(JSON.stringify({ pins: pins.directories, files: [...files], home, where }));
  if (expected === 'error') assert.throws(() => localFor(pins, where, home, contents), /^Error: cannot use /);
  else assert.deepEqual(localFor(pins, where, home, contents), expected);
  assert.deepEqual(read, reads);
}, settings));

test(`--url, then what the directory names, then the default: the first given decides, seed ${settings.seed}`, () => hegel.test((tc) => {
  const url = tc.draw(gs.optional(gs.sampledFrom(ORIGINS)));
  const local = tc.draw(gs.optional(gs.sampledFrom(ORIGINS).map((origin): Local => ({ origin, by: 'pin', directory: '/a' }))));
  const current = tc.draw(gs.optional(gs.sampledFrom(ORIGINS)));
  const store = { ...emptyStore(), current };
  const flags = url === null ? {} : { url };
  if (url === null && local === null && current === null) {
    assert.throws(() => choose(flags, store, local), /not signed in anywhere/);
    return;
  }
  const choice = choose(flags, store, local);
  if (url !== null) assert.deepEqual(choice, { origin: url, by: 'url' });
  else if (local !== null) assert.deepEqual(choice, local);
  else assert.deepEqual(choice, { origin: current, by: 'default' });
}, settings));

// --- the CLI's JSON export ----------------------------------------------------

const TOKEN = `coffre_cli_${'s'.repeat(43)}`;
const cliSettings = propertySettings(3, 20);

test(`coffre export --format json prints, as UTF-8, JSON that parses back to exactly the values the instance gave, seed ${cliSettings.seed}`, async (t) => {
  const home = mkdtempSync(join(tmpdir(), 'coffre-export-properties-'));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  let answer = '';
  const server = createServer((req, res) => res.writeHead(200, { 'content-type': 'application/json' }).end(answer));
  t.after(() => new Promise<void>((resolve) => (server.close(() => resolve()), server.closeAllConnections())));
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const { port } = server.address() as { port: number };
  signedInWithToken(home, `http://127.0.0.1:${port}`, TOKEN);
  const env = { ...Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('COFFRE_') && key !== 'GITHUB_ENV')), COFFRE_STATE_DIR: home, HOME: home };
  // Lone surrogates included: JSON escapes them, so this export alone carries them through UTF-8.
  const jsonValue = gs.oneOf(githubValue, gs.arrays(gs.oneOf(gs.sampledFrom(['\uD800', '\uDFFF', '\uDBFF\uDFFF']), value), { maxSize: 4 }).map((parts) => parts.join('')));
  const key = gs.oneOf(keyName, gs.sampledFrom(['__proto__', 'constructor', 'toString', 'hasOwnProperty', 'valueOf']));
  await hegel.testAsync(async (tc) => {
    const entries = [...new Map(tc.draw(gs.arrays(gs.tuples(key, jsonValue), { maxSize: 6 }))).entries()];
    // Written by hand: an object literal would take `__proto__` for its prototype.
    answer = `{"values":{${entries.map(([name, text]) => `${JSON.stringify(name)}:${JSON.stringify(text)}`).join(',')}}}`;
    const child = spawn(process.execPath, ['--conditions=coffre:source', new URL('../src/main.ts', import.meta.url).pathname, 'export', 'market/prod', '--format', 'json'], { env, stdio: ['ignore', 'pipe', 'pipe'], timeout: 10_000 });
    const stdout: Buffer[] = [];
    let stderr = '';
    child.stdout.on('data', (chunk: Buffer) => stdout.push(chunk));
    child.stderr.setEncoding('utf8').on('data', (chunk: string) => (stderr += chunk));
    const [code] = await once(child, 'close');
    assert.equal(code, 0, stderr);
    const parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(stdout))) as Record<string, string>;
    const sorted = entries.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    assert.deepEqual(Object.entries(parsed), sorted);
  }, cliSettings);
});
