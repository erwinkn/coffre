import test from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';

import { ESLint } from 'eslint';

const eslint = new ESLint({
  cwd: fileURLToPath(new URL('../../../', import.meta.url)),
});

async function lintImport(source: string, filePath: string) {
  const [result] = await eslint.lintText(source, { filePath });
  return result.messages.filter((message) => message.severity === 2);
}

test('ESLint keeps server functions out of the pages', async () => {
  const source = "import { createServerFn } from '@tanstack/react-start';";
  for (const filePath of ['packages/ui/src/routes/example.tsx', 'packages/ui/src/lib/example.ts']) {
    assert.equal((await lintImport(source, filePath))[0]?.ruleId, 'no-restricted-imports');
  }
  assert.deepEqual(
    await lintImport("import { getGlobalStartContext } from '@tanstack/react-start';", 'packages/ui/src/router.tsx'),
    [],
  );
});

test('ESLint keeps drizzle queries in the server\'s and the vault\'s database layers', async () => {
  const source = "import { eq } from 'drizzle-orm';";
  for (const filePath of [
    'packages/ui/src/lib/example.ts',
    'packages/server/src/api/example.ts',
    'packages/server/src/sync/example.ts',
    'packages/core/src/example.ts',
    'packages/client/src/example.ts',
    'packages/cli/src/example.ts',
    'packages/vault/src/vault.ts',
    'packages/vault/src/cloudflare.ts',
  ]) {
    assert.equal((await lintImport(source, filePath))[0]?.ruleId, 'no-restricted-imports', filePath);
  }
  assert.deepEqual(await lintImport(source, 'packages/server/src/db/example.ts'), []);
  assert.deepEqual(await lintImport(source, 'packages/vault/src/store.ts'), []);
});

test('ESLint keeps opening a database from a URL in the vault\'s Node entry, out of the Worker', async () => {
  const source = "import { openDatabase } from '@coffre/db/connect';";
  for (const filePath of ['packages/vault/src/store.ts', 'packages/vault/src/cloudflare.ts']) {
    assert.equal((await lintImport(source, filePath))[0]?.ruleId, 'no-restricted-imports', filePath);
  }
  assert.deepEqual(await lintImport(source, 'packages/vault/src/node.ts'), []);
  const sqlite = "import { DatabaseSync } from 'node:sqlite';";
  for (const filePath of ['packages/vault/src/node.ts', 'packages/vault/src/cloudflare.ts']) {
    assert.equal((await lintImport(sqlite, filePath))[0]?.ruleId, 'no-restricted-imports', filePath);
  }
});

test('ESLint has a package import another by name, never by path', async () => {
  const across = "import { Vault } from '../../vault/src/vault.ts';";
  for (const filePath of ['packages/server/src/example.ts', 'packages/server/test/example.test.ts']) {
    assert.equal((await lintImport(across, filePath))[0]?.ruleId, 'coffre/package-imports', filePath);
  }
  assert.equal(
    (await lintImport("export * from '../../../core/src/vault.ts';", 'packages/client/src/lib/example.ts'))[0]?.ruleId,
    'coffre/package-imports',
  );
  assert.deepEqual(await lintImport("import { vault } from '@coffre/vault';", 'packages/server/src/example.ts'), []);
  assert.deepEqual(await lintImport("import { plan } from '../lib/plan.ts';", 'packages/server/src/api/example.ts'), []);

  // Tests may use the dev tooling beside the packages; what ships may not.
  const seed = "import { LOCAL_SEED_DIRECTORY } from '../../../dev/seed-config.mjs';";
  assert.deepEqual(await lintImport(seed, 'packages/server/test/example.test.ts'), []);
  assert.equal((await lintImport(seed, 'packages/server/src/example.ts'))[0]?.ruleId, 'coffre/package-imports');
});
