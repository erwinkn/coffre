import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

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

test('a build whose browser files hold server code fails, whatever form Vite emits them in, bytes included', async () => {
  const { build } = await import('vite');
  const { coffre } = await import('../src/vite.ts');
  const marker = 'console.log("secret_versions");';
  const cases: { name: string; files: Record<string, string>; bytes?: true }[] = [
    { name: 'a static import', files: { 'entry.js': 'import "./leak.js";', 'leak.js': marker } },
    { name: 'a dynamic import', files: { 'entry.js': 'globalThis.load = () => import("./leak.js");', 'leak.js': marker } },
    { name: 'a stylesheet', files: { 'entry.js': 'import "./leak.css";', 'leak.css': '.x::before { content: "secret_versions"; }' } },
    { name: 'a worker', files: { 'entry.js': 'new Worker(new URL("./leak.js", import.meta.url), { type: "module" });', 'leak.js': marker } },
    { name: 'an inline worker', files: { 'entry.js': 'import Leak from "./leak.js?worker&inline"; new Leak();', 'leak.js': marker } },
    {
      name: 'a script imported by its URL, which Vite emits as bytes',
      files: { 'entry.js': 'import url from "./leak.js?url"; globalThis.run = () => import(/* @vite-ignore */ url);', 'leak.js': `${marker}${'\n// padding'.repeat(500)}` },
      bytes: true,
    },
  ];
  const dir = mkdtempSync(join(tmpdir(), 'coffre-ui-guard-'));
  try {
    const run = async (files: Record<string, string>) => {
      rmSync(join(dir, 'src'), { recursive: true, force: true });
      mkdirSync(join(dir, 'src'));
      for (const [name, code] of Object.entries(files)) writeFileSync(join(dir, 'src', name), code);
      const emitted: { fileName: string; source: unknown }[] = [];
      const inspect = {
        name: 'inspect',
        enforce: 'post' as const,
        generateBundle(_options: unknown, bundle: Record<string, { type: string; fileName: string; source?: unknown }>) {
          for (const file of Object.values(bundle)) if (file.type === 'asset') emitted.push({ fileName: file.fileName, source: file.source });
        },
      };
      // Rooted here, where the pages' own versions are installed, as a deployment's are.
      await build({
        configFile: false,
        root: fileURLToPath(new URL('..', import.meta.url)),
        publicDir: false,
        logLevel: 'silent',
        plugins: [inspect, coffre()],
        build: { write: false, rolldownOptions: { input: join(dir, 'src', 'entry.js') } },
      });
      return emitted;
    };
    await run({ 'entry.js': 'globalThis.page = () => fetch("/api/secrets");' });
    for (const { name, files, bytes } of cases) {
      await assert.rejects(
        () => run(files),
        /What the browser loads holds server code:\n {2}\S+: the table secret_versions/,
        name,
      );
      if (bytes) {
        // The form this case is for: had the guard skipped it, the build would have passed with it.
        const shown = await run({ 'entry.js': files['entry.js']!, 'leak.js': files['leak.js']!.replace('secret_versions', 'nothing') });
        assert.ok(shown.some(({ fileName, source }) => fileName.endsWith('.js') && source instanceof Uint8Array), 'the script was emitted as bytes');
      }
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
