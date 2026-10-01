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

test('ESLint keeps drizzle queries in the server\'s database layer', async () => {
  const source = "import { eq } from 'drizzle-orm';";
  for (const filePath of [
    'packages/ui/src/lib/example.ts',
    'packages/server/src/api/example.ts',
    'packages/server/src/sync/example.ts',
    'packages/core/src/example.ts',
    'packages/client/src/example.ts',
    'packages/cli/src/example.ts',
  ]) {
    assert.equal((await lintImport(source, filePath))[0]?.ruleId, 'no-restricted-imports', filePath);
  }
  for (const filePath of ['packages/server/src/db/example.ts', 'packages/vault/src/example.ts']) {
    assert.deepEqual(await lintImport(source, filePath), [], filePath);
  }
});
