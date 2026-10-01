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

test('ESLint keeps server functions out of the web app', async () => {
  const source = "import { createServerFn } from '@tanstack/react-start';";
  for (const filePath of ['apps/web/src/routes/example.tsx', 'apps/web/src/server/example.ts']) {
    assert.equal((await lintImport(source, filePath))[0]?.ruleId, 'no-restricted-imports');
  }
  assert.deepEqual(
    await lintImport("import { createMiddleware } from '@tanstack/react-start';", 'apps/web/src/start.ts'),
    [],
  );
});

test('ESLint keeps drizzle queries in packages/db', async () => {
  assert.equal(
    (await lintImport("import { eq } from 'drizzle-orm';", 'apps/web/src/server/example.ts'))[0]
      ?.ruleId,
    'no-restricted-imports',
  );
});
