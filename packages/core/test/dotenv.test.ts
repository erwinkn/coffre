import test from 'node:test';
import assert from 'node:assert/strict';

import { formatDotenv, formatShellExports, parseDotenv } from '../src/dotenv.ts';

/**
 * The parser is the one place where attacker-influenceable text becomes
 * credential material, so the bar here is not "does it work on a tidy file".
 * It is: can any input be silently mangled into a value that differs from what
 * the author wrote? Every case below is either an exact-value assertion or a
 * demand that the input be rejected.
 */

/** Parse and assert no problems, returning key -> value. */
function values(input: string): Record<string, string> {
  const { entries, problems } = parseDotenv(input);
  assert.deepEqual(problems, [], `unexpected problems: ${JSON.stringify(problems)}`);
  return Object.fromEntries(entries.map((entry) => [entry.key, entry.value]));
}

/** Parse and assert the first problem matches. */
function rejected(input: string, reason: RegExp): void {
  const { problems } = parseDotenv(input);
  assert.ok(problems.length > 0, `expected a problem for: ${JSON.stringify(input)}`);
  assert.match(problems[0].reason, reason);
}

// --- basic shapes -----------------------------------------------------------

test('parses the shapes a real .env file contains', () => {
  assert.deepEqual(
    values(
      [
        '# a comment',
        '',
        'DATABASE_URL=db-demo://user:pw@host/db',
        'export EXPORTED=value',
        'QUOTED="hello world"',
        "SINGLE='literal $NOT_INTERPOLATED'",
        'WITH_ESCAPE="line\\nbreak"',
        'TRAILING=value # trailing comment',
        'EMPTY=',
        '  SPACED  =  padded  ',
      ].join('\n'),
    ),
    {
      DATABASE_URL: 'db-demo://user:pw@host/db',
      EXPORTED: 'value',
      QUOTED: 'hello world',
      SINGLE: 'literal $NOT_INTERPOLATED',
      WITH_ESCAPE: 'line\nbreak',
      TRAILING: 'value',
      EMPTY: '',
      SPACED: 'padded',
    },
  );
});

test('empty input and comment-only input produce nothing, not an error', () => {
  assert.deepEqual(parseDotenv(''), { entries: [], problems: [] });
  assert.deepEqual(parseDotenv('\n\n   \n'), { entries: [], problems: [] });
  assert.deepEqual(parseDotenv('# just a comment\n#another'), { entries: [], problems: [] });
});

test('a file with no trailing newline parses its last line', () => {
  assert.deepEqual(values('A=1\nB=2'), { A: '1', B: '2' });
});

// --- line endings -----------------------------------------------------------

test('all three line-ending conventions split correctly', () => {
  const expected = { A: '1', B: '2', C: '3' };

  assert.deepEqual(values('A=1\nB=2\nC=3'), expected, 'unix');
  assert.deepEqual(values('A=1\r\nB=2\r\nC=3'), expected, 'windows');
  // A lone \r is the dangerous one: splitting only on /\r?\n/ leaves it inside
  // the value, silently swallowing the next key into the preceding secret.
  assert.deepEqual(values('A=1\rB=2\rC=3'), expected, 'classic mac / stray CR');
});

test('a stray carriage return never ends up inside a value', () => {
  const parsed = values('SECRET=abc\rNEXT=def');
  assert.equal(parsed.SECRET, 'abc');
  assert.equal(parsed.SECRET.includes('\r'), false);
  assert.equal(parsed.NEXT, 'def');
});

// --- values that must survive verbatim --------------------------------------

test('a value containing = is preserved after the first separator', () => {
  assert.deepEqual(values('DSN=db-demo://u:p=q@host/db?a=b'), {
    DSN: 'db-demo://u:p=q@host/db?a=b',
  });
});

test('# inside a value is preserved, and only a spaced # starts a comment', () => {
  assert.deepEqual(values('PASSWORD=pw#123'), { PASSWORD: 'pw#123' }, 'unspaced # is data');
  assert.deepEqual(values('PASSWORD="pw # 123"'), { PASSWORD: 'pw # 123' }, 'quoted # is data');
  assert.deepEqual(values('PASSWORD=pw # note'), { PASSWORD: 'pw' }, 'spaced # is a comment');
});

test('characters common in real credentials survive verbatim', () => {
  const nasty = String.raw`aA1!@$%^&*()_+-[]{}|;:,.<>?/~\``;
  assert.deepEqual(values(`KEY="${nasty}"`), { KEY: nasty });
});

test('base64 and PEM-style values survive', () => {
  assert.deepEqual(
    values('B64=aGVsbG8gd29ybGQ=\nPEM="-----BEGIN KEY-----\\nabc+/=\\n-----END KEY-----"'),
    {
      B64: 'aGVsbG8gd29ybGQ=',
      PEM: '-----BEGIN KEY-----\nabc+/=\n-----END KEY-----',
    },
  );
});

test('a value that is only whitespace becomes empty, not whitespace', () => {
  assert.deepEqual(values('A=   \nB=""\nC="  "'), { A: '', B: '', C: '  ' });
});

test('unicode and emoji survive', () => {
  assert.deepEqual(values('A=café–naïve\nB="日本語 🔐"'), {
    A: 'café–naïve',
    B: '日本語 🔐',
  });
});

// --- quoting ----------------------------------------------------------------

test('only the necessary escapes are expanded inside double quotes', () => {
  // \n and \r exist so multi-line values (PEM keys) can be written on one line.
  assert.deepEqual(values(String.raw`A="line\nbreak"`), { A: 'line\nbreak' });
  assert.deepEqual(values(String.raw`A="cr\r"`), { A: 'cr\r' });
  // Quoting escapes.
  assert.deepEqual(values(String.raw`A="quote\"inside"`), { A: 'quote"inside' });
  assert.deepEqual(values(String.raw`A="back\\slash"`), { A: 'back\\slash' });
  // Single quotes are literal, as in a shell.
  assert.deepEqual(values(String.raw`A='no\tescape'`), { A: String.raw`no\tescape` });
});

test('an unrecognised escape is preserved verbatim, never silently eaten', () => {
  // Dropping the backslash turned "C:\path\to\file" into C:path<TAB>ofile and
  // "\d+\w" into d+w -- silent corruption of credential material.
  assert.deepEqual(values(String.raw`A="C:\path\to\file"`), {
    A: String.raw`C:\path\to\file`,
  });
  assert.deepEqual(values(String.raw`A="\d+\w"`), { A: String.raw`\d+\w` });
  assert.deepEqual(values(String.raw`A="a\qb"`), { A: String.raw`a\qb` });
});

test('an escaped quote does not terminate the value early', () => {
  const parsed = values(String.raw`TOKEN="a\"b\"c"`);
  assert.equal(parsed.TOKEN, 'a"b"c');
});

test('a backslash at the end of a quoted value is handled', () => {
  assert.deepEqual(values(String.raw`A="ends\\"`), { A: 'ends\\' });
});

test('quoted values may contain the other quote character', () => {
  assert.deepEqual(values(`A="it's fine"`), { A: "it's fine" });
  assert.deepEqual(values(`A='say "hi"'`), { A: 'say "hi"' });
});

test('a comment after a closing quote is allowed', () => {
  assert.deepEqual(values('A="value" # explanation'), { A: 'value' });
  assert.deepEqual(values("A='value'   # explanation"), { A: 'value' });
});

// --- rejections: ambiguity must never be resolved silently -------------------

test('text after a closing quote is rejected, not silently discarded', () => {
  rejected('A="value"junk', /after the closing quote/);
  rejected('A="value" junk', /after the closing quote/);
  // Single quotes cannot escape a quote, so this is trailing text, not an escape.
  rejected(String.raw`A='it\'s'`, /after the closing quote/);
});

test('an unterminated quote is rejected rather than run to end of line', () => {
  rejected('A="oh dear', /unterminated double quote/);
  rejected("A='oh dear", /unterminated single quote/);
});

test('a NUL byte in a value is rejected', () => {
  // execve truncates at the first NUL, so this would inject a silently
  // shortened secret rather than fail.
  rejected('A=before\u0000after', /NUL byte/);
  rejected('A="before\u0000after"', /NUL byte/);
});

test('a line with no separator is reported with its line number', () => {
  const { entries, problems } = parseDotenv('A=1\nthis is not a pair\nB=2');
  assert.deepEqual(entries.map((e) => e.key), ['A', 'B']);
  assert.equal(problems.length, 1);
  assert.equal(problems[0].line, 2);
  assert.match(problems[0].reason, /no "="/);
});

test('a problem names its key when the line has a valid one, and never carries the line or its value', () => {
  const secret = 'sk-live-51Habc123xyz';
  const { problems } = parseDotenv(
    [`${secret}==`, secret, `TOKEN="${secret}`, `TOKEN='${secret}`, `API_KEY="${secret}" trailing`, `9${secret}=x`, `A=${secret}`, `A=${secret}`].join('\n'),
  );
  assert.deepEqual(
    problems.map(({ line, key }) => [line, key]),
    [
      [1, undefined],
      [2, undefined],
      [3, 'TOKEN'],
      [4, 'TOKEN'],
      [5, 'API_KEY'],
      [6, undefined],
      [8, 'A'],
    ],
  );
  assert.ok(!JSON.stringify(problems).includes('51Habc123'), 'a value, or part of one, in a problem');
});

test('invalid keys are rejected', () => {
  rejected('1LEADING_DIGIT=x', /key must match/);
  rejected('has-hyphen=x', /key must match/);
  rejected('has.dot=x', /key must match/);
  rejected('has space=x', /key must match/);
  rejected('café=x', /key must match/);
  rejected('=novalue', /key must match/);
  rejected(`${'A'.repeat(200)}=x`, /key must match/);
});

test('valid keys at the edges are accepted', () => {
  assert.deepEqual(values('_LEADING_UNDERSCORE=1'), { _LEADING_UNDERSCORE: '1' });
  assert.deepEqual(values('A=1'), { A: '1' });
  assert.deepEqual(values('MiXeD_Case_123=1'), { MiXeD_Case_123: '1' });
  const maxKey = `A${'B'.repeat(127)}`;
  assert.deepEqual(values(`${maxKey}=1`), { [maxKey]: '1' });
});

test('a duplicate key is reported rather than last-one-wins', () => {
  const { entries, problems } = parseDotenv('A=first\nA=second');
  // Silently taking either one would mean the file does not describe what got
  // stored. The first is kept and the collision is surfaced.
  assert.deepEqual(entries.map((e) => [e.key, e.value]), [['A', 'first']]);
  assert.equal(problems.length, 1);
  assert.match(problems[0].reason, /duplicate/);
  assert.equal(problems[0].line, 2);
});

test('keys differing only in case are distinct, as environment variables are', () => {
  assert.deepEqual(values('PATH=a\npath=b'), { PATH: 'a', path: 'b' });
});

// --- whitespace and prefixes ------------------------------------------------

test('export prefixes and surrounding whitespace are handled', () => {
  assert.deepEqual(
    values(['export A=1', '   export B=2', 'export    C=3', '\tD\t=\t4'].join('\n')),
    { A: '1', B: '2', C: '3', D: '4' },
  );
});

test('a key literally named export is not mistaken for the prefix', () => {
  assert.deepEqual(values('export=1'), { export: '1' });
});

test('a leading byte-order mark does not corrupt the first key', () => {
  // A BOM is common in files touched by Windows editors, and would otherwise
  // make the first key invalid.
  assert.deepEqual(values('﻿DATABASE_URL=x\nB=2'), { DATABASE_URL: 'x', B: '2' });
});

// --- line numbers -----------------------------------------------------------

test('reported line numbers point at the offending line', () => {
  const { entries, problems } = parseDotenv(
    ['# comment', '', 'GOOD=1', 'broken', 'ALSO_GOOD=2', '1BAD=3'].join('\n'),
  );

  assert.deepEqual(entries.map((e) => [e.key, e.line]), [
    ['GOOD', 3],
    ['ALSO_GOOD', 5],
  ]);
  assert.deepEqual(problems.map((p) => p.line), [4, 6]);
});

// --- the property that matters ---------------------------------------------

test('every accepted value round-trips exactly through a quoted encoding', () => {
  const originals = [
    'simple',
    'with spaces',
    'with"double',
    "with'single",
    'with#hash',
    'with=equals',
    'with\\backslash',
    'with\nnewline',
    '',
    '   padded   ',
    'db-demo://u:p@h:5432/db?ssl=require',
  ];

  for (const original of originals) {
    // Encode the way a careful writer would: double-quoted with escapes.
    const encoded = `K="${original
      .replace(/\\/g, '\\\\')
      .replace(/"/g, '\\"')
      .replace(/\n/g, '\\n')
      .replace(/\r/g, '\\r')}"`;

    const parsed = values(encoded);
    assert.equal(
      parsed.K,
      original,
      `round-trip failed for ${JSON.stringify(original)} via ${encoded}`,
    );
  }
});

// --- writing ----------------------------------------------------------------

const AWKWARD = [
  'plain',
  '',
  'db-demo://u:p@h:5432/db?ssl=require',
  'with space',
  '   padded   ',
  'with#hash',
  'with #comment-lookalike',
  'with$dollar and ${BRACES}',
  "with'single",
  'with"double',
  `both ' and "`,
  'with\\backslash',
  'C:\\path\\to\\file',
  '\\n is not a newline',
  'with\nnewline',
  'with\r\nCRLF',
  '-----BEGIN KEY-----\nabc\n-----END KEY-----\n',
  'tab\there',
  'unicode: café ☕',
];

test('formatDotenv output parses back to exactly the values written', () => {
  const entries = AWKWARD.map((value, index) => [`K${index}`, value] as const);
  const parsed = values(formatDotenv(entries));
  for (const [key, value] of entries) {
    assert.equal(parsed[key], value, `round trip changed ${JSON.stringify(value)}`);
  }
});

test('formatDotenv quotes only as much as each value needs', () => {
  assert.equal(
    formatDotenv([
      ['URL', 'https://example.com/a?b=c'],
      ['SPACED', 'two words'],
      ['QUOTE', "it's"],
      ['PEM', 'a\nb'],
    ]),
    [`URL=https://example.com/a?b=c`, `SPACED='two words'`, `QUOTE="it's"`, `PEM="a\\nb"`, ''].join(
      '\n',
    ),
  );
});

test('formatDotenv refuses what no .env file can carry', () => {
  assert.throws(() => formatDotenv([['1BAD', 'x']]), /not a valid variable name/);
  assert.throws(() => formatDotenv([['K', 'a\u0000b']]), /NUL/);
});

test('formatShellExports single-quotes everything, including single quotes', () => {
  assert.equal(
    formatShellExports([
      ['A', 'plain'],
      ['B', "it's $HOME `x`"],
    ]),
    `export A='plain'\nexport B='it'\\''s $HOME \`x\`'\n`,
  );
  assert.throws(() => formatShellExports([['NOT-A-NAME', 'x']]), /not a valid variable name/);
});
