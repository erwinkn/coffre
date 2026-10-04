import test from 'node:test';
import assert from 'node:assert/strict';
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { bumpPins, coffrePins } from '../src/deployment.ts';
import { templateDir } from '../src/init.ts';
import { applyChanges, lineDiff, needsStartApp, shownChange, startAppMove, withPages } from '../src/layout.ts';

const fixtures = fileURLToPath(new URL('fixtures/0.1.18/', import.meta.url));

for (const kind of ['workers', 'node'] as const) {
  test(`a ${kind} deployment of 0.1.18, moved, is its own Start app, byte for byte as coffre init writes it`, () => {
    const dir = mkdtempSync(join(tmpdir(), `coffre-layout-${kind}-`));
    try {
      cpSync(join(fixtures, kind), dir, { recursive: true });
      assert.equal(needsStartApp(dir), true);
      const template = templateDir(kind);
      const changes = startAppMove(dir, kind, template);
      assert.ok(Array.isArray(changes), JSON.stringify(changes));
      applyChanges(dir, changes);
      // What update does next: the pins, to the release.
      bumpPins(dir, Object.values(coffrePins(template))[0]!);
      for (const path of ['app/vite.config.ts', 'app/src/router.tsx', 'package.json', '.gitignore', ...(kind === 'workers' ? ['app/src/server.ts', 'app/wrangler.jsonc'] : ['src/server.ts'])]) {
        assert.equal(readFileSync(join(dir, path), 'utf8'), readFileSync(join(template, path), 'utf8'), path);
      }
      assert.equal(existsSync(join(dir, 'app/src/worker.ts')), false);
      assert.equal(needsStartApp(dir), false);
      assert.deepEqual(startAppMove(dir, kind, template), [], 'moved once, there is nothing left to move');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
}

test("an entry whose coffre(…) is not where it can be found is left alone, and said so", () => {
  assert.equal(withPages("import { coffre } from '@coffre/server/cloudflare';\nexport default makeIt();\n", '@coffre/server/cloudflare', ['pages,']), null);
  const block = "import { coffre } from '@coffre/server/cloudflare';\nexport default coffre((env: Env) => {\n  const x = 1;\n  return {\n    publicUrl: x,\n  };\n});\n";
  assert.equal(
    withPages(block, '@coffre/server/cloudflare', ['pages,']),
    "import pages from '@tanstack/react-start/server-entry';\nimport { coffre } from '@coffre/server/cloudflare';\nexport default coffre((env: Env) => {\n  const x = 1;\n  return {\n    pages,\n    publicUrl: x,\n  };\n});\n",
  );
});

test('a change is shown by the lines that go and come, a file added or removed by its name', () => {
  assert.deepEqual(lineDiff(['a', 'b', 'c'], ['a', 'x', 'c']), ['- b', '+ x']);
  assert.deepEqual(shownChange({ path: 'app/vite.config.ts', was: null, becomes: 'x' }), ['+ app/vite.config.ts, new']);
  assert.deepEqual(shownChange({ path: 'app/src/worker.ts', was: 'x', becomes: null }), ['- app/src/worker.ts']);
  assert.deepEqual(shownChange({ path: '.gitignore', was: 'node_modules\n', becomes: 'node_modules\ndist\n' }), ['~ .gitignore', '  + dist']);
});
