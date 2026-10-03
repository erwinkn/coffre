import test from 'node:test';
import assert from 'node:assert/strict';
import { cpSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { bumpPins, coffrePins } from '../src/deployment.ts';
import { installOf, migrationsAdded } from '../src/update.ts';

const examples = fileURLToPath(new URL('../../../examples/', import.meta.url));

test('update moves every @coffre/* pin of a deployment, and nothing else', () => {
  for (const kind of ['workers', 'node']) {
    const dir = mkdtempSync(join(tmpdir(), `coffre-update-${kind}-`));
    try {
      cpSync(join(examples, kind, 'package.json'), join(dir, 'package.json'));
      const before = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8')) as Record<string, Record<string, string>>;
      bumpPins(dir, '9.9.9');
      const after = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8')) as Record<string, Record<string, string>>;
      assert.ok(Object.keys(coffrePins(dir)).length >= 3, `${kind} pins coffre's packages`);
      assert.ok(Object.values(coffrePins(dir)).every((version) => version === '9.9.9'));
      for (const field of ['dependencies', 'devDependencies']) {
        for (const [name, version] of Object.entries(before[field] ?? {})) {
          assert.equal(after[field]![name], name.startsWith('@coffre/') ? '9.9.9' : version, `${kind}: ${name}`);
        }
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
});

test('how the CLI was installed says how to update it', () => {
  const roots = { npm: '/usr/lib/node_modules', pnpm: '/home/ada/.local/share/pnpm/global/5/node_modules' };
  assert.deepEqual(installOf('/usr/lib/node_modules/@coffre/cli/dist/main.js', roots), { kind: 'npm' });
  assert.deepEqual(
    installOf('/home/ada/.local/share/pnpm/global/5/.pnpm/@coffre+cli@0.1.11/node_modules/@coffre/cli/dist/main.js', roots),
    { kind: 'pnpm' },
  );
  assert.deepEqual(installOf('/home/ada/.npm/_npx/0a1b2c/node_modules/@coffre/cli/dist/main.js', roots), { kind: 'npx' });
  assert.deepEqual(installOf('/srv/coffre-deploy/node_modules/@coffre/cli/dist/main.js', roots), {
    kind: 'project',
    dir: '/srv/coffre-deploy',
  });
  assert.deepEqual(installOf('/home/ada/coffre/packages/cli/src/update.ts', roots), { kind: 'checkout' });
  assert.deepEqual(installOf('/opt/coffre/main.js', { npm: null, pnpm: null }), { kind: 'unknown' });
});

test('update ends with what the release asks of the database', () => {
  assert.equal(
    migrationsAdded('0.1.12', ['0000_baseline'], ['0000_baseline', '0001_remove_syncs']),
    'coffre 0.1.12 adds 1 migration (0001_remove_syncs): after deploying, run `coffre migrate`.',
  );
  assert.equal(migrationsAdded('0.1.13', ['0000_baseline', '0001_remove_syncs'], ['0000_baseline', '0001_remove_syncs']), 'coffre 0.1.13 adds no migration: deploying it is all.');
});
