import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { defineDeployment } from '@coffre/core/deployment';
import { parse } from 'jsonc-parser';

import { coffre, signInLimitProblem, versionDrift, type WorkerConfig } from '../src/vite.ts';

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

test("a Workers build fails unless the built Worker's SIGN_IN_PER_SOURCE counts sign-ins as deployment.ts says; without the binding, nothing to check", () => {
  // As the Cloudflare plugin writes it beside the built Worker: the file it read, and the environment's bindings.
  const built = (simple: string) =>
    JSON.parse(`{ "configPath": "/app/wrangler.jsonc", "ratelimits": [{ "name": "SIGN_IN_PER_SOURCE", "namespace_id": "1006", "simple": ${simple} }] }`) as WorkerConfig;
  const byDefault = defineDeployment();
  const lowered = defineDeployment({ services: { signInsPerAddress: 600 } });

  assert.equal(signInLimitProblem(built('{ "limit": 10000, "period": 10 }'), byDefault), null);
  assert.match(
    signInLimitProblem(built('{ "limit": 10000, "period": 10 }'), lowered) ?? '',
    /\/app\/wrangler\.jsonc's SIGN_IN_PER_SOURCE binding, as this build resolves it, allows 10000 sign-ins per 10 s, and deployment\.ts's services\.signInsPerAddress 600 per 10 s/,
  );
  assert.equal(signInLimitProblem(built('{ "limit": 600, "period": 10 }'), lowered), null);
  assert.match(signInLimitProblem(built('{ "limit": 600, "period": 10 }'), byDefault) ?? '', /allows 600 sign-ins per 10 s, .* 10,000 per 10 s/);
  // Cloudflare's other window, 60 s, counts six times as long: not the same number.
  assert.match(signInLimitProblem(built('{ "limit": 10000, "period": 60 }'), byDefault) ?? '', /allows 10000 sign-ins per 60 s, .* set its "simple" to \{ "limit": 10000, "period": 10 \}/);
  // A Worker without the binding, or a build with no Worker config (Node): none to hold to the number.
  assert.equal(signInLimitProblem({ ratelimits: [] }, lowered), null);
  assert.equal(signInLimitProblem({}, lowered), null);
});

test("the plugin holds the Worker config the build emitted, its environment's binding included, and nothing without a deployment or a config", () => {
  // A top-level binding at 600 and `env.production` at 10,000: with CLOUDFLARE_ENV=production, the Cloudflare plugin
  // emits the production binding alone, which is what the check sees and what wrangler deploys.
  const production = { configPath: '/app/wrangler.jsonc', ratelimits: [{ name: 'SIGN_IN_PER_SOURCE', namespace_id: '1006', simple: { limit: 10_000, period: 10 } }] };
  const lowered = defineDeployment({ services: { signInsPerAddress: 600 } });
  const emitted = (plugin: ReturnType<typeof coffre>, bundle: Record<string, unknown>) => {
    const hook = plugin.generateBundle as { handler: (this: { error: (message: string) => never }, options: unknown, bundle: unknown) => void };
    hook.handler.call({ error: (message: string) => { throw new Error(message); } }, {}, bundle);
  };
  const asset = { type: 'asset', fileName: 'wrangler.json', source: JSON.stringify(production) };
  assert.throws(() => emitted(coffre({ deployment: lowered }), { 'wrangler.json': asset }), /binding, as this build resolves it, allows 10000 sign-ins per 10 s/);
  assert.doesNotThrow(() => emitted(coffre({ deployment: defineDeployment() }), { 'wrangler.json': asset }));
  assert.doesNotThrow(() => emitted(coffre(), { 'wrangler.json': asset }));
  assert.doesNotThrow(() => emitted(coffre({ deployment: lowered }), { 'index.js': { type: 'chunk' } }));
});

test("the Workers example's and the dev deployment's wrangler.jsonc agree with their deployment.ts, as their builds check", async () => {
  for (const dir of ['examples/workers', 'dev/deployment']) {
    const root = new URL(`../../../${dir}/`, import.meta.url);
    const { deployment } = (await import(new URL('deployment.ts', root).href)) as { deployment: ReturnType<typeof defineDeployment> };
    const config = parse(readFileSync(new URL('app/wrangler.jsonc', root), 'utf8'), [], { allowTrailingComma: true }) as WorkerConfig;
    assert.ok(Array.isArray(config.ratelimits) && config.ratelimits.length > 0, dir);
    assert.equal(signInLimitProblem(config, deployment), null, dir);
  }
});
