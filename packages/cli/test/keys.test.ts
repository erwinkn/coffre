import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { parseDotenv } from '@coffre/core/dotenv';

import { generateKeys } from '../src/keys.ts';

const main = fileURLToPath(new URL('../src/main.ts', import.meta.url));
const NAMES = ['KEK_ID', 'KEK', 'AUDIT_CHAIN_KEY'];

/** `coffre keys` as an operator runs it: in an empty directory, with no home and no instance. */
function coffreKeys(args: string[] = []): string {
  const dir = mkdtempSync(join(tmpdir(), 'coffre-keys-'));
  try {
    const out = execFileSync(process.execPath, ['--conditions=coffre:source', main, 'keys', ...args], {
      cwd: dir,
      env: { PATH: process.env.PATH, HOME: dir },
      encoding: 'utf8',
    });
    assert.deepEqual(readdirSync(dir), [], 'it writes no file');
    return out;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** What the vault and the server accept: 32 bytes, base64, and a KEK id the vault takes. */
function assertUsable(keys: Record<string, string>): void {
  assert.deepEqual(Object.keys(keys), NAMES);
  assert.match(keys.KEK_ID!, /^kek-\d{4}-\d{2}-\d{2}$/);
  assert.match(keys.KEK_ID!, /^[A-Za-z0-9._-]{1,64}$/, "the vault's rule for a KEK id");
  for (const name of ['KEK', 'AUDIT_CHAIN_KEY']) {
    const bytes = Buffer.from(keys[name]!, 'base64');
    assert.equal(bytes.length, 32, name);
    assert.equal(bytes.toString('base64'), keys[name], `${name} is canonical base64`);
  }
}

test('coffre keys prints a dotenv block that parses, with notes as comments, and writes nothing', () => {
  const out = coffreKeys();
  const { entries, problems } = parseDotenv(out);
  assert.deepEqual(problems, []);
  assertUsable(Object.fromEntries(entries.map((entry) => [entry.key, entry.value])));
  assert.match(out, /Save all three in your password manager/);
  assert.match(out, /Two keys, one for each component/);
  assert.match(out, /To rotate a deployment's KEK, take only\n# KEK_ID and KEK/);
});

test('coffre keys --json prints the same three, for scripts', () => {
  assertUsable(JSON.parse(coffreKeys(['--json'])) as Record<string, string>);
});

test('every run makes new keys, and dates the KEK id to the day', () => {
  const [a, b] = [generateKeys(), generateKeys()];
  for (const name of ['KEK', 'AUDIT_CHAIN_KEY'] as const) assert.notEqual(a[name], b[name], name);
  assert.notEqual(a.KEK, a.AUDIT_CHAIN_KEY);
  assert.equal(generateKeys(new Date('2026-10-02T23:59:00Z')).KEK_ID, 'kek-2026-10-02');
  const [first, second] = [coffreKeys(['--json']), coffreKeys(['--json'])];
  assert.notEqual(JSON.parse(first).KEK, JSON.parse(second).KEK);
});
