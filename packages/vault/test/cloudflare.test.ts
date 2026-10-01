import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import type { LogInput, UnwrapInput, Vault, WrapInput } from '@coffre/core/vault';
import { build } from 'esbuild';
import { Miniflare } from 'miniflare';

test('only the canonical vault object can open keys and count reveals', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'coffre-vault-worker-'));
  const bundle = join(dir, 'vault.mjs');
  await build({
    stdin: {
      contents: `
        import { vault } from '@coffre/vault/cloudflare';
        export { VaultObject } from '@coffre/vault/cloudflare';
        export default vault(env => ({
          kek: { id: 'test-kek', key: env.KEK },
          signingKey: env.SIGNING_KEY,
          rootAdmins: ['root@acme.example'],
          bulkLimit: { count: 1, windowMinutes: 15 },
        }));`,
      resolveDir: fileURLToPath(new URL('..', import.meta.url)),
      loader: 'ts',
    },
    outfile: bundle,
    bundle: true,
    format: 'esm',
    platform: 'neutral',
    mainFields: ['module', 'main'],
    conditions: ['coffre:source'],
    external: ['node:*', 'cloudflare:*'],
  });
  const compatibility = { compatibilityDate: '2026-08-06', compatibilityFlags: ['nodejs_compat'] };
  const worker = new Miniflare({
    rootPath: dir,
    workers: [
      {
        name: 'app',
        modules: true,
        ...compatibility,
        serviceBindings: { VAULT: 'vault' },
        // A deployment can bind the namespace directly and choose another ID.
        durableObjects: { DIRECT: { className: 'VaultObject', scriptName: 'vault', useSQLite: true } },
        script: `export default {
          async fetch(request, env) {
            const { name, method, input } = await request.json();
            const target = name ? env.DIRECT.get(env.DIRECT.idFromName(name)) : env.VAULT;
            try { return Response.json(await target[method](input)); }
            catch (error) { return Response.json({ error: String(error) }, { status: 500 }); }
          }
        };`,
      },
      {
        name: 'vault',
        modules: true,
        modulesRoot: dir,
        scriptPath: bundle,
        ...compatibility,
        durableObjects: { VAULT_OBJECT: { className: 'VaultObject', useSQLite: true } },
        bindings: { KEK: randomBytes(32).toString('base64'), SIGNING_KEY: randomBytes(32).toString('base64') },
      },
    ],
  });
  t.after(async () => {
    await worker.dispose();
    rmSync(dir, { recursive: true, force: true });
  });
  const request = (method: string, input: unknown, name?: string) => worker.dispatchFetch('http://app/', {
    method: 'POST',
    body: JSON.stringify({ method, input, name }),
  });
  async function call<M extends 'wrap' | 'unwrap' | 'log'>(method: M, input: WrapInput | UnwrapInput | LogInput) {
    const response = await request(method, input);
    assert.equal(response.status, 200);
    return await response.json() as Awaited<ReturnType<Vault[M]>>;
  }
  const principal = 'user:root@acme.example';
  const secret = { projectId: randomUUID(), environmentId: randomUUID(), secretId: randomUUID(), version: 1, path: 'p/e/KEY' };
  const key = randomBytes(32).toString('base64');
  const wrapped = await call('wrap', { principal, items: [{ secret, key }] });
  assert.ok(wrapped.ok);
  const input: UnwrapInput = { principal, purpose: 'reveal', items: [{ secret, wrapped: wrapped.wrapped[0] }] };
  const opened = await call('unwrap', input);
  assert.ok(opened.ok);
  assert.deepEqual(opened.keys, [key]);
  const limited = await call('unwrap', input);
  assert.equal(!limited.ok && limited.refusal.code, 'bulk_limit');
  const before = await call('log', { actor: principal });

  const other = await request('unwrap', input, 'another-vault');
  assert.equal(other.status, 500, 'another object must not open the same key with a fresh bulk counter');
  assert.match(await other.text(), /canonical vault object/);
  assert.deepEqual(await call('log', { actor: principal }), before);
  const stillLimited = await call('unwrap', input);
  assert.equal(!stillLimited.ok && stillLimited.refusal.code, 'bulk_limit');
});
