import test from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  bumpPins,
  coffrePins,
  excludeUntil,
  heldBack,
  installFailure,
  minimumReleaseAge,
  pinPackageManager,
  removeCleared,
} from '../src/deployment.ts';
import { inTerminal, ptySkip } from './pty.ts';
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

const VIOLATION = `Error: ERR_PNPM_MINIMUM_RELEASE_AGE_VIOLATION
  ╰─▶ 1 lockfile entries failed verification:
        pg-protocol@1.16.1 was published at 2026-09-30T15:41:58.793Z, within
      the minimumReleaseAge cutoff (2026-09-26T22:25:22.210Z)`;

test('a held-back install says which packages, and when each was published', () => {
  assert.deepEqual(heldBack(VIOLATION), [{ spec: 'pg-protocol@1.16.1', publishedAt: new Date('2026-09-30T15:41:58.793Z') }]);
  assert.deepEqual(heldBack('ERR_PNPM_FETCH_404'), []);
  assert.equal(minimumReleaseAge(join(examples, 'workers')), 10080, 'a week, as init writes it');
});

test('a temporary exclusion is named, with its date, and goes once the date has passed', () => {
  const dir = mkdtempSync(join(tmpdir(), 'coffre-exclude-'));
  try {
    cpSync(join(examples, 'workers', 'pnpm-workspace.yaml'), join(dir, 'pnpm-workspace.yaml'));
    const before = readFileSync(join(dir, 'pnpm-workspace.yaml'), 'utf8');
    excludeUntil(
      dir,
      [
        { spec: 'pg-protocol@1.16.1', clears: new Date('2026-10-07T15:41:58Z') },
        { spec: '@types/node@26.6.4', clears: new Date('2026-10-08T22:39:22Z') },
      ],
      'for coffre 0.1.14',
    );
    const written = readFileSync(join(dir, 'pnpm-workspace.yaml'), 'utf8');
    assert.match(written, /minimumReleaseAgeExclude:\n  - '@coffre\/\*'\n  - 'pg-protocol@1\.16\.1' # coffre update: until 2026-10-07T15:41:58\.000Z, for coffre 0\.1\.14\n  - '@types\/node@26\.6\.4' # coffre update: until 2026-10-08/);

    assert.deepEqual(removeCleared(dir, new Date('2026-10-01T00:00:00Z')), [], 'not before');
    assert.deepEqual(removeCleared(dir, new Date('2026-10-08T00:00:00Z')), ['pg-protocol@1.16.1']);
    assert.deepEqual(removeCleared(dir, new Date('2026-10-09T00:00:00Z')), ['@types/node@26.6.4']);
    assert.equal(readFileSync(join(dir, 'pnpm-workspace.yaml'), 'utf8'), before, 'back as init wrote it');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a deployment pins coffre's pnpm, beside \"private\", whatever it had", () => {
  const dir = mkdtempSync(join(tmpdir(), 'coffre-pnpm-'));
  try {
    writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'secrets', private: true, type: 'module' }));
    assert.equal(pinPackageManager(dir, 'pnpm@11.8.0'), undefined);
    assert.deepEqual(Object.keys(JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8'))), ['name', 'private', 'packageManager', 'type']);
    assert.equal(pinPackageManager(dir, 'pnpm@11.8.0'), null, 'right already');
    assert.equal(pinPackageManager(dir, 'pnpm@12.0.0'), 'pnpm@11.8.0');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

/**
 * A Workers deployment at 0.0.1, a registry whose latest coffre is 9.9.9,
 * and a pnpm that holds pg-protocol back until the deployment lets it
 * through by name.
 */
async function heldDeployment() {
  const dir = mkdtempSync(join(tmpdir(), 'coffre-held-'));
  for (const file of ['package.json', 'pnpm-workspace.yaml', 'app/wrangler.jsonc', 'vault/wrangler.jsonc']) {
    mkdirSync(join(dir, file, '..'), { recursive: true });
    cpSync(join(examples, 'workers', file), join(dir, file));
  }
  bumpPins(dir, '0.0.1');
  const manifest = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8')) as Record<string, unknown>;
  delete manifest.packageManager;
  writeFileSync(join(dir, 'package.json'), `${JSON.stringify(manifest, null, 2)}\n`);
  const bin = join(dir, '.bin');
  mkdirSync(bin);
  const published = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
  writeFileSync(
    join(bin, 'pnpm'),
    `#!/bin/sh
[ "$1" = install ] || exit 1
grep -q "'pg-protocol@1.16.1' # coffre update: until" pnpm-workspace.yaml && exit 0
printf 'Error: ERR_PNPM_MINIMUM_RELEASE_AGE_VIOLATION\\n        pg-protocol@1.16.1 was published at ${published}, within\\n' >&2
exit 1
`,
  );
  chmodSync(join(bin, 'pnpm'), 0o755);
  const registry = createServer((_request, response) => {
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify({ version: '9.9.9' }));
  });
  await new Promise<void>((resolve) => registry.listen(0, '127.0.0.1', resolve));
  const env = {
    PATH: `${bin}:${process.env.PATH}`,
    HOME: dir,
    npm_config_registry: `http://127.0.0.1:${(registry.address() as { port: number }).port}/`,
  };
  return { dir, env, published: new Date(published), close: () => registry.close() };
}

const main = fileURLToPath(new URL('../src/main.ts', import.meta.url));

test('held back, update --yes waits: the deployment as it was, and when each package is old enough', async () => {
  const { dir, env, published, close } = await heldDeployment();
  try {
    const before = readFileSync(join(dir, 'package.json'), 'utf8');
    // Not spawnSync: the registry answers from this process.
    const { spawn } = await import('node:child_process');
    const child = spawn(process.execPath, ['--conditions=coffre:source', main, 'update', '--yes'], { cwd: dir, env });
    let stderr = '';
    child.stderr.setEncoding('utf8').on('data', (chunk: string) => (stderr += chunk));
    const status = await new Promise((resolve) => child.on('close', resolve));
    const run = { status, stderr };
    assert.equal(run.status, 1, run.stderr);
    const clears = new Date(published.getTime() + 7 * 24 * 60 * 60 * 1000).toISOString().slice(0, 16).replace('T', ' ');
    assert.match(run.stderr, new RegExp(`pnpm holds back 1 package younger than this deployment's minimumReleaseAge, 7 days: pg-protocol@1\\.16\\.1, old enough from ${clears} UTC`));
    assert.match(run.stderr, /Run coffre update after .* UTC, or on a terminal to exclude them until then/);
    assert.equal(readFileSync(join(dir, 'package.json'), 'utf8'), before, 'pins and pnpm as they were');
    assert.doesNotMatch(readFileSync(join(dir, 'pnpm-workspace.yaml'), 'utf8'), /coffre update: until/, 'never a silent exclusion');
  } finally {
    close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('held back, update on a terminal lets them through by name, until each is old enough', { skip: ptySkip }, async () => {
  const { dir, env, close } = await heldDeployment();
  try {
    const run = await inTerminal(
      ['update'],
      env,
      async (session) => {
        await session.waitFor('and install it?');
        session.send('y');
        await session.waitFor('Proceed: let it through');
        session.send('\x1b[B');
        session.send('\r');
      },
      { columns: 160, rows: 48 },
      dir,
    );
    assert.equal(run.code, 0, run.output);
    const pins = coffrePins(dir);
    assert.ok(Object.values(pins).every((version) => version === '9.9.9'));
    assert.equal((JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8')) as { packageManager: string }).packageManager, 'pnpm@11.8.0');
    assert.match(readFileSync(join(dir, 'pnpm-workspace.yaml'), 'utf8'), /  - 'pg-protocol@1\.16\.1' # coffre update: until \S+, for coffre 9\.9\.9/);
  } finally {
    close();
    rmSync(dir, { recursive: true, force: true });
  }
});
