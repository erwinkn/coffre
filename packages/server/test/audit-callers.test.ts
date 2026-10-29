// No page of coffre's own asks the audit list for what it leaves out (`hidden`): the audit page, a member's Activity,
// `coffre audit`, MCP's `read_audit_log` and conformance each ask `sealed` alone, so a page always fills with what it
// shows, and none counts. A caller that asks follows `next` through pages that may show nothing (T164, review r4).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = new URL('../../..', import.meta.url).pathname;
const SOURCES = ['packages/ui/src', 'packages/cli/src', 'packages/conformance/src', 'packages/server/src/mcp'];

function* files(dir: string): Generator<string> {
  for (const entry of readdirSync(join(ROOT, dir), { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) yield* files(path);
    else if (/\.tsx?$/.test(entry.name)) yield path;
  }
}

/** Each `audit.list(…)` call's arguments, by the parentheses that close it. */
function calls(source: string): string[] {
  const found: string[] = [];
  for (let at = source.indexOf('audit.list('); at !== -1; at = source.indexOf('audit.list(', at + 1)) {
    let depth = 0;
    let end = at + 'audit.list'.length;
    do {
      if (source[end] === '(') depth++;
      if (source[end] === ')') depth--;
      end++;
    } while (depth > 0 && end < source.length);
    found.push(source.slice(at, end));
  }
  return found;
}

test("no page of coffre's own asks the audit list to count what it hides", () => {
  const asked = SOURCES.flatMap((dir) => [...files(dir)].flatMap((path) => calls(readFileSync(join(ROOT, path), 'utf8')).map((call) => ({ path, call }))));
  assert.ok(asked.length >= 10, `the callers are found: ${asked.length}`);
  assert.deepEqual(asked.filter(({ call }) => /\bhidden\b/.test(call)), []);
});
