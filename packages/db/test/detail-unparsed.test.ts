// `audit_events.detail` is JSON text that no SQL parses (docs/design/state-rows.md, section 2): what the API
// returns as an entry's `metadata`, display only. A query that filtered on it, or an index on one of its keys, would make
// it a dynamic schema; a field a query needs is a column of its own (0.16's typed columns). This test fails on any SQL,
// in a migration or in the sources, that casts it to JSON, takes a key of it, matches it as text, or hands it to a JSON
// or text function.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../../..', import.meta.url));

/** Every file under `dir` whose name ends in one of `endings`, but dependencies and builds. */
async function files(dir: string, endings: readonly string[]): Promise<string[]> {
  const found: string[] = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    if (entry.name === 'node_modules' || entry.name === 'dist' || entry.name.startsWith('.')) continue;
    const path = join(dir, entry.name);
    if (entry.isDirectory()) found.push(...(await files(path, endings)));
    else if (endings.some((ending) => entry.name.endsWith(ending))) found.push(path);
  }
  return found;
}

// `detail` (bare, quoted, qualified, or a Drizzle column `${….detail}`), then a cast to JSON or a key taken, or matched
// as text (LIKE, a regular expression), after any other casts or a closing parenthesis; or handed to a JSON, a text-search
// or a Drizzle LIKE function. Matched on the file's text with its whitespace collapsed, so that a statement split over
// lines is caught too.
const COLUMN = String.raw`(?:"?detail"?|\.detail\})`;
const PARSES = [
  new RegExp(String.raw`${COLUMN} ?\)? ?(?:::\s*[a-z]+ ?)*(?:::\s*jsonb?\b|->|(?:not )?i?like\b|similar to\b|!?~)`, 'i'),
  new RegExp(String.raw`\b(?:not)?i?like ?\( ?[a-z_]+\.detail\b`, 'i'),
  new RegExp(String.raw`\b(?:jsonb?_[a-z_]+|strpos|position|substring|substr|regexp_[a-z_]+|split_part|left|right) ?\( ?(?:[a-z_]+\.)?${COLUMN}`, 'i'),
  new RegExp(String.raw`\b(?:cast ?\( ?(?:[a-z_]+\.)?${COLUMN} as jsonb?\b|position ?\([^()]* in (?:[a-z_]+\.)?${COLUMN})`, 'i'),
];
const collapsed = (text: string) => text.replace(/\s+/g, ' ');

test('no SQL parses audit_events.detail: no cast to JSON, no key taken, no JSON function of it', async () => {
  const sources = [
    ...(await files(join(root, 'packages/db/src/migrations'), ['.sql'])),
    ...(await files(join(root, 'packages'), ['.ts', '.tsx'])).filter((path) => /\/packages\/[^/]+\/src\//.test(path)),
  ];
  assert.ok(sources.length > 100, 'the sources were found');
  const found: string[] = [];
  for (const path of sources) {
    const text = collapsed(await readFile(path, 'utf8'));
    for (const parses of PARSES) {
      for (const match of text.matchAll(new RegExp(parses.source, 'gi'))) found.push(`${path.slice(root.length)}: ${text.slice(Math.max(0, match.index - 40), match.index + match[0].length + 20)}`);
    }
  }
  assert.deepEqual(found, []);
});

test('the check finds what it is for', () => {
  const parsed = [
    'SELECT detail::jsonb ->> \'path\' FROM audit_events', 'WHERE e."detail" ->> \'keys\'', "jsonb_extract_path(e.detail, 'x')", 'sql`${auditEvents.detail}::jsonb`',
    'CAST(e.detail AS jsonb)', 'CAST(\n  e.detail\n  AS jsonb)', 'e.detail\n  ::jsonb', "WHERE strpos(e.detail, '\"path\"') > 0", "e.detail LIKE '%\"keys\"%'", "e.detail ILIKE '%x%'",
    "e.detail ~ '\"path\"'", "position('\"keys\"' in e.detail)", "substring(e.detail from 3)", "regexp_match(e.detail, 'x')", 'sql`${auditEvents.detail} like ${pattern}`',
    'like(auditEvents.detail, pattern)', 'ilike(auditEvents.detail, pattern)', 'notIlike(auditEvents.detail, pattern)', '(e.detail)::jsonb', 'e.detail::text::jsonb',
  ];
  for (const line of parsed) assert.ok(PARSES.some((parses) => parses.test(collapsed(line))), line);
  for (const line of ['detail text NOT NULL', "x ->> 'detail'", 'detail: JSON.stringify(metadata)', "x ->> 'detail', decode(x ->> 'mac', 'hex')", 'detail = excluded.detail']) {
    assert.ok(!PARSES.some((parses) => parses.test(collapsed(line))), line);
  }
});
