import test from 'node:test';
import assert from 'node:assert/strict';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { bumpPins, coffrePins, installFailure } from '../src/deployment.ts';
import { deploymentMigrations, installOf, migrationsAdded } from '../src/update.ts';

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
    migrationsAdded('0.1.11', '0.1.12', ['0000_baseline'], ['0000_baseline', '0001_remove_syncs']),
    "coffre 0.1.12 adds 1 migration to 0.1.11's (0001_remove_syncs): after deploying, run `coffre migrate`.",
  );
  assert.equal(
    migrationsAdded('0.1.12', '0.1.13', ['0000_baseline', '0001_remove_syncs'], ['0000_baseline', '0001_remove_syncs']),
    "coffre 0.1.13 adds no migration to 0.1.12's: deploying it is all.",
  );
});

test("a deployment's migrations are its installed server's, through that server's @coffre/db", () => {
  const dir = mkdtempSync(join(tmpdir(), 'coffre-update-installed-'));
  try {
    assert.equal(deploymentMigrations(dir), null, 'nothing installed yet');
    const db = join(dir, 'node_modules', '@coffre', 'db');
    mkdirSync(join(dir, 'node_modules', '@coffre', 'server'), { recursive: true });
    writeFileSync(join(dir, 'node_modules', '@coffre', 'server', 'package.json'), JSON.stringify({ name: '@coffre/server', version: '0.1.11' }));
    mkdirSync(join(db, 'dist', 'migrations', 'postgres', 'meta'), { recursive: true });
    writeFileSync(join(db, 'package.json'), JSON.stringify({ name: '@coffre/db', exports: { './package.json': './package.json' } }));
    writeFileSync(join(db, 'dist', 'migrations', 'postgres', 'meta', '_journal.json'), JSON.stringify({ entries: [{ tag: '0000_baseline' }] }));
    assert.deepEqual(deploymentMigrations(dir), ['0000_baseline']);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('an install held back by minimumReleaseAge names what, and what to do', () => {
  const output = `Error: ERR_PNPM_MINIMUM_RELEASE_AGE_VIOLATION
  ╰─▶ 2 lockfile entries failed verification:
        pg-protocol@1.16.1 was published at 2026-09-30T15:41:58.793Z, within
      the minimumReleaseAge cutoff (2026-09-26T22:25:22.210Z)
        @types/node@26.6.4 was published at 2026-10-01T22:39:22.769Z, within
      the minimumReleaseAge cutoff (2026-09-26T22:25:22.210Z)`;
  assert.equal(
    installFailure(output),
    "pnpm held back pg-protocol@1.16.1, @types/node@26.6.4: published within this deployment's minimumReleaseAge " +
      '(pnpm-workspace.yaml), a week. Install again once they are a week old, or add them to minimumReleaseAgeExclude if you trust them',
  );
  assert.match(installFailure('ERR_PNPM_FETCH_404 nope\nlast line'), /^pnpm install failed: /);
});
