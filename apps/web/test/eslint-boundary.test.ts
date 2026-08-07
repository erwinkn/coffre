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

test('ESLint reserves raw createServerFn for the factory', async () => {
  const source = "import { createServerFn } from '@tanstack/react-start';";
  assert.equal(
    (await lintImport(source, 'apps/web/src/server-functions/example.ts'))[0]?.ruleId,
    'no-restricted-imports',
  );
  assert.deepEqual(
    await lintImport(source, 'apps/web/src/server/server-fn.ts'),
    [],
  );
});

test('ESLint reserves sessionServerFn for the reviewed boundaries', async () => {
  const source = "import { sessionServerFn } from '../server/server-fn.ts';";
  assert.equal(
    (await lintImport(source, 'apps/web/src/server-functions/projects.ts'))[0]?.ruleId,
    'no-restricted-imports',
  );
  assert.deepEqual(
    await lintImport(source, 'apps/web/src/server-functions/auth.ts'),
    [],
  );
});
