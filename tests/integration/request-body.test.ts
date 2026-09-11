import { test } from 'node:test';
import assert from 'node:assert/strict';
import { build } from 'esbuild';
import { Miniflare } from 'miniflare';

test('the bounded request guard runs in workerd, not only Node fetch', { timeout: 30000 }, async t => {
  const result = await build({ stdin: { contents: `
    import { bounded } from './packages/core/src/request-body.ts';
    export default { async fetch(request) {
      try {
        const copy = await bounded(request, 128);
        return Response.json({ body: await copy.text(), method: copy.method, redirect: copy.redirect, marker: copy.headers.get('X-Test') });
      } catch { return new Response('Request too large', {status: 413}); }
    }};`, resolveDir: process.cwd(), sourcefile: 'request-guard-fixture.ts' }, bundle: true, write: false, format: 'esm', platform: 'browser', target: 'es2022' });
  const mf = new Miniflare({ cf: false, modules: true, script: result.outputFiles[0]!.text, compatibilityDate: '2026-07-01' });
  try {
    await t.test('a valid POST keeps its exact body and headers', async () => {
      const body = '{"value":"  secrét 🌍\\n "}';
      const response = await mf.dispatchFetch('https://coffre.test/operation', { method: 'POST', headers: { 'X-Test': 'preserved' }, body });
      assert.equal(response.status, 200);
      assert.deepEqual(await response.json(), { body, method: 'POST', redirect: 'manual', marker: 'preserved' });
    });
    await t.test('oversized bodies are refused before the application parser', async () => {
      const response = await mf.dispatchFetch('https://coffre.test/operation', { method: 'POST', body: 'x'.repeat(129) });
      assert.equal(response.status, 413);
    });
    await t.test('bodyless requests still reach the application', async () => {
      const response = await mf.dispatchFetch('https://coffre.test/', { method: 'GET' });
      assert.equal(response.status, 200);
      assert.equal((await response.json() as { body: string }).body, '');
    });
  } finally { await mf.dispose(); }
});
