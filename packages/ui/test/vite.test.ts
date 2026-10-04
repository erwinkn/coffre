import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { SERVER_TABLES, serverCodeIn, versionDrift } from '../src/vite.ts';

test("the guard knows every table the schema names with an underscore", () => {
  const schema = readFileSync(new URL('../../db/src/schema.ts', import.meta.url), 'utf8');
  const tables = [...schema.matchAll(/pgTable\(\s*'([a-z_]+)'/g)].map((match) => match[1]!).filter((name) => name.includes('_'));
  assert.ok(tables.length > 0);
  assert.deepEqual([...SERVER_TABLES].sort(), tables.sort());
});

test('what the browser loads is refused when it carries the database, a driver, configuration or the dev toolbar', () => {
  assert.deepEqual(serverCodeIn([{ name: 'index.js', code: 'const page = () => fetch("/api/secrets")' }]), []);
  assert.deepEqual(
    serverCodeIn([
      { name: 'a.js', code: 'Symbol.for("drizzle:Name"); select * from secret_versions' },
      { name: 'b.js', code: 'import("cloudflare:sockets"); env.COFFRE_APP_KEY' },
    ]),
    ['a.js: drizzle-orm', 'a.js: the table secret_versions', 'b.js: pg', 'b.js: a COFFRE_ variable read'],
  );
});

test('a deployment whose React, router, Start, Query or Vite is not the one the pages were built with is told which', () => {
  const peers = (JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as { peerDependencies: Record<string, string> })
    .peerDependencies;
  const dir = mkdtempSync(join(tmpdir(), 'coffre-ui-drift-'));
  try {
    writeFileSync(join(dir, 'package.json'), '{}');
    for (const [name, version] of Object.entries(peers)) {
      mkdirSync(join(dir, 'node_modules', name), { recursive: true });
      writeFileSync(join(dir, 'node_modules', name, 'package.json'), JSON.stringify({ name, version }));
    }
    assert.deepEqual(versionDrift(dir), []);
    writeFileSync(join(dir, 'node_modules', 'react', 'package.json'), JSON.stringify({ name: 'react', version: '19.9.9' }));
    rmSync(join(dir, 'node_modules', 'vite'), { recursive: true });
    assert.deepEqual(versionDrift(dir).map((line) => line.replace(/@coffre\/ui \S+/, '@coffre/ui')), [
      `react is 19.9.9, and @coffre/ui is built for ${peers.react}`,
      `vite ${peers.vite} is not installed`,
    ]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
