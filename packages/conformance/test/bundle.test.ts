import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { clientFiles, SERVER_TABLES, serverCodeIn } from '../src/bundle.ts';

test('the check knows every table the schema names with an underscore', () => {
  const schema = readFileSync(new URL('../../db/src/schema.ts', import.meta.url), 'utf8');
  const tables = [...schema.matchAll(/pgTable\(\s*'([a-z_]+)'/g)].map((match) => match[1]!).filter((name) => name.includes('_'));
  assert.ok(tables.length > 0);
  assert.deepEqual([...SERVER_TABLES].sort(), tables.sort());
});

test('what the browser loads is refused when it carries the database, a driver or configuration', () => {
  assert.deepEqual(serverCodeIn([{ name: 'index.js', code: 'const page = () => fetch("/api/secrets")' }]), []);
  assert.deepEqual(
    serverCodeIn([
      { name: 'a.js', code: 'Symbol.for("drizzle:Name"); select * from secret_versions' },
      { name: 'b.js', code: 'import("cloudflare:sockets"); env.COFFRE_APP_KEY' },
    ]),
    ['a.js: drizzle-orm', 'a.js: the table secret_versions', 'b.js: pg', 'b.js: a COFFRE_ variable read'],
  );
});

test('server code is found in a build, whatever form Vite emits it in', async () => {
  const { build, defaultClientConditions } = await import('vite');
  const marker = 'console.log("secret_versions");';
  const cases: { name: string; files: Record<string, string> }[] = [
    { name: 'a static import', files: { 'entry.js': 'import "./leak.js";', 'leak.js': marker } },
    { name: 'a dynamic import', files: { 'entry.js': 'globalThis.load = () => import("./leak.js");', 'leak.js': marker } },
    { name: 'a stylesheet', files: { 'entry.js': 'import "./leak.css";', 'leak.css': '.x::before { content: "secret_versions"; }' } },
    { name: 'a worker', files: { 'entry.js': 'new Worker(new URL("./leak.js", import.meta.url), { type: "module" });', 'leak.js': marker } },
    { name: 'an inline worker', files: { 'entry.js': 'import Leak from "./leak.js?worker&inline"; new Leak();', 'leak.js': marker } },
    {
      name: 'a script imported by its URL, which Vite emits as an asset',
      files: { 'entry.js': 'import url from "./leak.js?url"; globalThis.run = () => import(/* @vite-ignore */ url);', 'leak.js': `${marker}${'\n// padding'.repeat(500)}` },
    },
    // The deliberate break: a page that imports coffre's database layer.
    { name: 'a page importing coffre’s server code', files: { 'entry.js': 'import * as schema from "@coffre/db/schema"; globalThis.schema = schema;' } },
  ];
  // Inside this package, where @coffre/db resolves from.
  const dir = mkdtempSync(fileURLToPath(new URL('.bundle-', import.meta.url)));
  try {
    const run = async (files: Record<string, string>) => {
      rmSync(join(dir, 'src'), { recursive: true, force: true });
      rmSync(join(dir, 'dist'), { recursive: true, force: true });
      mkdirSync(join(dir, 'src'));
      for (const [name, code] of Object.entries(files)) writeFileSync(join(dir, 'src', name), code);
      await build({
        configFile: false,
        root: fileURLToPath(new URL('..', import.meta.url)),
        publicDir: false,
        logLevel: 'silent',
        // The packages' sources, as the tests read them, built or not.
        resolve: { conditions: ['coffre:source', ...defaultClientConditions] },
        build: { outDir: join(dir, 'dist'), emptyOutDir: true, rolldownOptions: { input: join(dir, 'src', 'entry.js') } },
      });
      return serverCodeIn(clientFiles(join(dir, 'dist')));
    };
    assert.deepEqual(await run({ 'entry.js': 'globalThis.page = () => fetch("/api/secrets");' }), []);
    for (const { name, files } of cases) assert.notDeepEqual(await run(files), [], name);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
