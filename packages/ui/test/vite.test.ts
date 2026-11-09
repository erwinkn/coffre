import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { defineDeployment } from '@coffre/core/deployment';

import { coffre, signInLimitProblem, versionDrift } from '../src/vite.ts';

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

test("a Workers build fails unless app/wrangler.jsonc's SIGN_IN_PER_SOURCE counts sign-ins as deployment.ts says; without the file or the binding, nothing to check", () => {
  const dir = mkdtempSync(join(tmpdir(), 'coffre-ui-limit-'));
  // As the examples write it: comments, a URL holding `//`, and a trailing comma.
  const wrangler = (simple: string) =>
    `// The app Worker.\n{\n  "vars": { "PUBLIC_URL": "https://secrets.example.com" },\n  "ratelimits": [\n    { "name": "SIGN_IN_PER_SOURCE", "namespace_id": "1006", "simple": ${simple} },\n  ],\n}\n`;
  try {
    const byDefault = defineDeployment();
    const lowered = defineDeployment({ services: { signInsPerAddress: 600 } });
    // No wrangler.jsonc: a Node deployment's root.
    assert.equal(signInLimitProblem(dir, lowered), null);

    writeFileSync(join(dir, 'wrangler.jsonc'), wrangler('{ "limit": 10000, "period": 10 }'));
    assert.equal(signInLimitProblem(dir, byDefault), null);
    assert.match(signInLimitProblem(dir, lowered) ?? '', /SIGN_IN_PER_SOURCE binding allows 10000 sign-ins per 10 s, and deployment\.ts's services\.signInsPerAddress 600 per 10 s/);

    writeFileSync(join(dir, 'wrangler.jsonc'), wrangler('{ "limit": 600, "period": 10 }'));
    assert.equal(signInLimitProblem(dir, lowered), null);
    assert.match(signInLimitProblem(dir, byDefault) ?? '', /allows 600 sign-ins per 10 s, .* 10,000 per 10 s/);

    // Cloudflare's other window, 60 s, counts six times as long: not the same number.
    writeFileSync(join(dir, 'wrangler.jsonc'), wrangler('{ "limit": 10000, "period": 60 }'));
    assert.match(signInLimitProblem(dir, byDefault) ?? '', /allows 10000 sign-ins per 60 s, .* set its "simple" to \{ "limit": 10000, "period": 10 \}/);

    // A Worker without the binding: none to hold to the number.
    writeFileSync(join(dir, 'wrangler.jsonc'), '{ "name": "coffre", "ratelimits": [] }');
    assert.equal(signInLimitProblem(dir, lowered), null);

    // The plugin, as a build resolves it: the problem stops the build; `vite dev` and a plugin given no deployment check nothing.
    writeFileSync(join(dir, 'wrangler.jsonc'), wrangler('{ "limit": 10000, "period": 10 }'));
    const resolved = (plugin: ReturnType<typeof coffre>, command: 'build' | 'serve') =>
      (plugin.configResolved as (config: { command: string; root: string }) => void)({ command, root: dir });
    assert.throws(() => resolved(coffre({ deployment: lowered }), 'build'), /SIGN_IN_PER_SOURCE binding allows 10000/);
    assert.doesNotThrow(() => resolved(coffre({ deployment: lowered }), 'serve'));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the Workers example's and the dev deployment's wrangler.jsonc agree with their deployment.ts, as their builds check", async () => {
  for (const dir of ['examples/workers', 'dev/deployment']) {
    const root = new URL(`../../../${dir}/`, import.meta.url);
    const { deployment } = (await import(new URL('deployment.ts', root).href)) as { deployment: ReturnType<typeof defineDeployment> };
    assert.equal(signInLimitProblem(fileURLToPath(new URL('app/', root)), deployment), null, dir);
  }
});
