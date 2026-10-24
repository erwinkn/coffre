import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import * as hegel from '@hegeldev/hegel';
import * as gs from '@hegeldev/hegel/generators';

import { assertEnvironmentEntry, formatDotenv, formatShellExports, parseDotenv } from '../src/dotenv.ts';
import { secretKey } from '../src/schemas.ts';
import { awkwardValue, keyName, nearKeyName, value } from '../../../scripts/properties/domain.ts';
import { propertySettings } from './properties.ts';

const settings = propertySettings(200);

/** A lone surrogate replaced by U+FFFD, as UTF-8 encoding does (`String.prototype.toWellFormed`, past this lib's target). */
const wellFormedText = (text: string) => text.replace(/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g, '�');

/** A key name, read from its definition rather than any validator: an ASCII letter or `_`, then up to 127 letters, digits and `_`. */
function isKeyName(text: string): boolean {
  const head = /[A-Za-z_]/;
  const tail = /[A-Za-z0-9_]/;
  return text.length >= 1 && text.length <= 128 && head.test(text[0]!) && [...text.slice(1)].every((character) => character.length === 1 && tail.test(character));
}

/**
 * Characters a line-based format trips on: what JavaScript's trim strips
 * (U+2028, U+2029, U+FEFF, NBSP, \v, \f, ideographic space), NEL, which it
 * does not, a zero-width space, and lone surrogates.
 */
const ODD = ['\u2028', '\u2029', '\uFEFF', '\u0085', '\u00A0', '\v', '\f', '\t', ' ', '\u3000', '\u200B', '\uD800', '\uDFFF', '\uDBFF\uDFFF', '\r', '\n'];
/**
 * Any value without NUL, lone surrogates included. A string function sees
 * them, so the dotenv round trip holds them too. What crosses bytes (a shell,
 * a file) cannot: a lone surrogate has no UTF-8 encoding and Node writes
 * U+FFFD for it, so those properties draw `wellFormed` values.
 */
const anyValue = gs.oneOf(
  value,
  awkwardValue,
  gs.arrays(gs.oneOf(gs.sampledFrom(ODD), gs.text({ maxSize: 3 }), gs.integers({ minValue: 1, maxValue: 0xffff }).map((unit) => String.fromCharCode(unit))), { maxSize: 10 })
    .map((parts) => parts.join('').replaceAll('\0', '')),
);
const wellFormed = anyValue.map(wellFormedText);

/** Entries with distinct keys, in a drawn order. */
const entriesOf = (values: typeof anyValue, maxSize = 8) =>
  gs.arrays(gs.tuples(keyName, values), { maxSize }).map((drawn) => [...new Map(drawn).entries()]);

test(`formatDotenv's output parses back to exactly its entries, in order and one line each, seed ${settings.seed}`, () => hegel.test((tc) => {
  const entries = tc.draw(entriesOf(anyValue));
  const text = formatDotenv(entries);
  tc.note(JSON.stringify(text));
  const parsed = parseDotenv(text);
  assert.deepEqual(parsed.problems, []);
  assert.deepEqual(parsed.entries, entries.map(([key, written], at) => ({ key, value: written, line: at + 1 })));
}, settings));

/** The POSIX shells on this machine, each `eval`ing the export as the README says: `eval "$(coffre export … --format shell)"`. */
const SHELLS = [['sh'], ['dash'], ['bash'], ['bash', '--posix'], ['busybox', 'sh']].filter(([program, ...flags]) => {
  try {
    execFileSync(program!, [...flags, '-c', ':'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
});
const shellSettings = propertySettings(25, 20);

test(`each POSIX shell's eval of formatShellExports sets exactly the values, byte for byte, and runs none of them, seed ${shellSettings.seed}`, (t) => {
  assert.ok(SHELLS.length > 0, 'no POSIX shell to run');
  const directory = mkdtempSync(join(tmpdir(), 'coffre-shell-properties-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const canary = join(directory, 'ran');
  const injection = gs.sampledFrom([
    `$(touch ${canary})`, `\`touch ${canary}\``, `'; touch ${canary}; '`, `'\\''$(touch ${canary})'`, `\${X:=$(touch ${canary})}`, `\n touch ${canary}\n`, `"; touch ${canary}; "`,
  ]);
  const shellValue = gs.oneOf(wellFormed, injection, gs.tuples(wellFormed, injection, wellFormed).map((parts) => parts.join('')));
  hegel.test((tc) => {
    // Prefixed and numbered: a value is what is under test, and a drawn `IFS`, `PATH` or bash's readonly `UID` would test the shell.
    const drawn = tc.draw(gs.arrays(gs.tuples(keyName, shellValue), { minSize: 1, maxSize: 12 }));
    const entries = drawn.map(([key, text], at) => [`V${at}_${key}`.slice(0, 128), text] as const);
    const script = `eval "$(printf '%s' "$1")"\nprintf '%s\\0' ${entries.map(([key]) => `"$${key}"`).join(' ')}\n`;
    const expected = Buffer.concat(entries.map(([, text]) => Buffer.from(`${text}\0`, 'utf8')));
    for (const [program, ...flags] of SHELLS) {
      const printed = execFileSync(program!, [...flags, '-c', script, 'coffre-properties', formatShellExports(entries)], { cwd: directory, env: { PATH: process.env.PATH, LC_ALL: 'C' }, stdio: ['ignore', 'pipe', 'pipe'] });
      assert.ok(printed.equals(expected), `${[program, ...flags].join(' ')} printed ${JSON.stringify(printed.toString('utf8'))}`);
      assert.equal(existsSync(canary), false, `${[program, ...flags].join(' ')} ran a value`);
    }
  }, shellSettings);
});

/** What a line of a .env file is made of, a pasted secret's padding and quotes included. */
const TOKENS = ['export ', 'KEY', 'key_2', '_', '9', ' ', '\t', '=', '==', '"', "'", '\\', '\\"', '\\n', '#', ' #', '$', '${A}', 'é', '\u00A0', '\uFEFF', '\u2028', '\u0085', '\v', 'export', '<<', '-'];
const LINE_BREAKS = ['\n', '\r\n', '\r'];
/** The reasons a problem may give: fixed text, so none can carry a line's. */
const REASONS = new Set([
  'no "=" on this line',
  'key must match ^[A-Za-z_][A-Za-z0-9_]{0,127}$',
  'unterminated double quote (multi-line values are not supported)',
  'unterminated single quote (multi-line values are not supported)',
  'unexpected text after the closing quote',
  'a value pasted on its own, not KEY=value: only "=" follows what would be its key',
  'no value: write KEY="" for an empty one',
  'value contains a NUL byte, which cannot be passed in an environment',
  'duplicate key in this file',
]);

test(`every line of any input is an entry, a problem, blank or a comment, and a problem never carries the line's text, seed ${settings.seed}`, () => hegel.test((tc) => {
  // A secret no token can spell, so its text in a problem can only have come from the line.
  const secret = tc.draw(gs.fromRegex('[QXZ][QXZ0-9]{7}', { fullmatch: true }));
  const line = gs.arrays(gs.oneOf(gs.sampledFrom(TOKENS), gs.just(secret), gs.text({ maxSize: 2 })), { maxSize: 8 }).map((parts) => parts.join(''));
  const lines = tc.draw(gs.arrays(line, { maxSize: 8 }));
  const breaks = lines.map(() => tc.draw(gs.sampledFrom(LINE_BREAKS)));
  const input = lines.map((text, at) => text + (at < lines.length - 1 ? breaks[at] : '')).join('');
  tc.note(JSON.stringify(input));
  const { entries, problems } = parseDotenv(input);
  // A line is what the file's line breaks separate, and a line break inside a token makes two lines.
  const all = input.split(/\r\n|\n|\r/);
  for (const [at, text] of all.entries()) {
    const number = at + 1;
    const ignored = /^\s*$/.test(text) || /^\s*#/.test(text);
    const accounted = [ignored, entries.some((entry) => entry.line === number), problems.some((problem) => problem.line === number)].filter(Boolean).length;
    assert.equal(accounted, 1, `line ${number}, ${JSON.stringify(text)}`);
  }
  assert.ok([...entries, ...problems].every((item) => item.line >= 1 && item.line <= all.length));
  for (const problem of problems) {
    assert.deepEqual(Object.keys(problem).filter((field) => !['line', 'key', 'reason'].includes(field)), []);
    assert.ok(REASONS.has(problem.reason), problem.reason);
    if (problem.key === undefined) continue;
    // A key is named only when it is the line's own, before its "=": key names are not secret (R6), values are.
    const text = all[problem.line - 1]!.trim().replace(/^export /, '').trimStart();
    assert.equal(problem.key, text.slice(0, text.indexOf('=')).trim());
    assert.ok(isKeyName(problem.key));
  }
  for (const entry of entries) assert.ok(isKeyName(entry.key));
  assert.ok(!problems.some((problem) => problem.reason.includes(secret)));
}, settings));

/**
 * The same rule is written in four places, each a pattern of its own so that
 * what loads it need not load zod: the browser's form (`@coffre/ui`), the
 * credential proxy's configuration check (`@coffre/server`), and the CLI's
 * `--generate`. Not one of them is exported, so their source text is read
 * and compiled here, flags included.
 */
function patternIn(path: string, name: string): RegExp {
  const source = readFileSync(new URL(`../../${path}`, import.meta.url), 'utf8');
  const found = new RegExp(`^const ${name} = /(.+)/([a-z]*);$`, 'm').exec(source);
  assert.ok(found, `${path} no longer defines ${name} as a pattern`);
  return new RegExp(found[1]!, found[2]);
}
const validators: [string, (text: string) => boolean][] = [
  ['the API (secretKey)', (text) => secretKey.safeParse(text).success],
  ['dotenv (assertEnvironmentEntry)', (text) => {
    try {
      assertEnvironmentEntry(text, '');
      return true;
    } catch {
      return false;
    }
  }],
  ...([['ui/src/lib/validation.ts', 'SECRET_KEY'], ['server/src/plugins/credential-proxy.ts', 'KEY'], ['cli/src/generate.ts', 'KEY_NAME']] as const).map(([path, name]): [string, (text: string) => boolean] => {
    const pattern = patternIn(path, name);
    return [`${path} (${name})`, (text) => pattern.test(text)];
  }),
];

test(`every key-name validator accepts exactly the key names, near misses and any text alike, seed ${settings.seed}`, () => hegel.test((tc) => {
  const text = tc.draw(gs.oneOf(nearKeyName, gs.text({ maxSize: 130 }), gs.text({ alphabet: 'Az_09-é\n', minSize: 126, maxSize: 130 })));
  const expected = isKeyName(text);
  for (const [name, accepts] of validators) assert.equal(accepts(text), expected, `${name} on ${JSON.stringify(text)}`);
}, settings));
