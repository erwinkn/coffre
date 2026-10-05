import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
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
  HeldBack,
  install,
  pinPackageManager,
  removeCleared,
  resolveAgain,
  movePins,
  START_PACKAGES,
  startPinMoves,
} from '../src/deployment.ts';
import { templateFiles } from '../src/init.ts';
import { CLEAN_BREAK } from '../src/layout.ts';
import { registry } from './registry.ts';
import { inTerminal, ptySkip } from './pty.ts';
import { deploymentMigrations, globalCli, installOf, migrationsAdded, movedLines, notUpdated } from '../src/update.ts';

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

test('how the CLI was installed: by what npm and pnpm say their globals are, not by the shape of the path', () => {
  const none = { npm: null, pnpm: null, pnpmHome: null };
  const npm = '/usr/lib/node_modules/@coffre/cli';
  assert.deepEqual(installOf(`${npm}/dist/main.js`, { ...none, npm }), { kind: 'npm' });
  // pnpm 10, on Linux: its global, in its own virtual store.
  const ten = '/home/ada/.local/share/pnpm/global/5/.pnpm/@coffre+cli@0.1.11/node_modules/@coffre/cli';
  assert.deepEqual(installOf(`${ten}/dist/main.js`, { ...none, pnpm: ten }), { kind: 'pnpm' });
  // pnpm 11, on Erwin's Mac: its global, in the store's links/, which read as a project's dependency.
  const eleven = '/Users/erwin/Library/pnpm/store/v11/links/@coffre/cli/0.1.16/7ee22ffdfe0eadd9777d18ac111f4d8648f16c979bfc6c2d111f2f16d124454d/node_modules/@coffre/cli';
  const there = `${eleven}/dist/main.js`;
  assert.deepEqual(installOf(there, { ...none, pnpm: eleven }), { kind: 'pnpm' });
  // pnpm unable to say (its bin directory off PATH): its PNPM_HOME holds it.
  assert.deepEqual(installOf(there, { ...none, pnpmHome: '/Users/erwin/Library/pnpm' }), { kind: 'pnpm' });
  // pnpm's global is another copy, and the store's directory is no project: coffre can't tell, and says so.
  assert.deepEqual(installOf(there, { ...none, pnpm: '/elsewhere/@coffre/cli' }), { kind: 'unknown', path: there });

  assert.deepEqual(installOf('/home/ada/.npm/_npx/0a1b2c/node_modules/@coffre/cli/dist/main.js', none), { kind: 'npx' });
  // A project's, as pnpm installs it: the project is where node_modules starts, not pnpm's own directory under it.
  const project = (dir: string) => dir === '/srv/coffre-deploy';
  assert.deepEqual(installOf('/srv/coffre-deploy/node_modules/.pnpm/@coffre+cli@0.1.16/node_modules/@coffre/cli/dist/main.js', none, project), {
    kind: 'project',
    dir: '/srv/coffre-deploy',
  });
  assert.deepEqual(installOf('/srv/coffre-deploy/node_modules/@coffre/cli/dist/main.js', none, project), { kind: 'project', dir: '/srv/coffre-deploy' });
  assert.deepEqual(installOf('/home/ada/coffre/packages/cli/src/update.ts', none), { kind: 'checkout' });
  assert.deepEqual(installOf('/opt/coffre/main.js', none), { kind: 'unknown', path: '/opt/coffre/main.js' });
});

test("when coffre can't tell how its CLI was installed, it says so, where it runs from, and what each manager would run", () => {
  const said = notUpdated({ kind: 'unknown', path: '/opt/coffre/dist/main.js' }, '0.1.17', null);
  assert.equal(said.text, "Nothing updated: coffre can't tell how this CLI was installed");
  assert.deepEqual(said.details, [
    "It runs from /opt/coffre/dist/main.js, which neither npm nor pnpm lists as its global, nor is it a project's",
    'Installed with npm: npm install -g @coffre/cli@0.1.17',
    'With pnpm: pnpm add -g @coffre/cli@0.1.17',
    'In a project: its @coffre/cli pin, to 0.1.17, then its install',
  ]);
  assert.match(notUpdated({ kind: 'project', dir: '/srv/coffre-deploy' }, '0.1.17', '/srv/coffre-deploy').text, /one of the deployment's packages/);
});

test('update ends with what the release asks of the database', () => {
  assert.equal(
    migrationsAdded('0.4.0', '0.5.0', ['0000_baseline'], ['0000_baseline', '0001_tags']),
    "coffre 0.5.0 adds 1 migration to 0.4.0's (0001_tags): run `pnpm exec coffre migrate` here first, then deploy.",
  );
  assert.equal(
    migrationsAdded('0.4.0', '0.4.1', ['0000_baseline'], ['0000_baseline']),
    "coffre 0.4.1 adds no migration to 0.4.0's: deploying it is all.",
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

test("the Start app's packages update moves are @coffre/ui's peers, Vite's plugins for them, and what Cloudflare's peers on", () => {
  const { peerDependencies } = JSON.parse(readFileSync(join(examples, '..', 'packages', 'ui', 'package.json'), 'utf8')) as {
    peerDependencies: Record<string, string>;
  };
  assert.deepEqual(
    [...START_PACKAGES].sort(),
    [...Object.keys(peerDependencies), '@vitejs/plugin-react', '@cloudflare/vite-plugin', 'wrangler', '@cloudflare/workers-types'].sort(),
  );
});

test("a deployment's Start app packages move to the template's versions, and nothing else does", () => {
  const dir = mkdtempSync(join(tmpdir(), 'coffre-start-pins-'));
  try {
    const template = join(examples, 'workers');
    const manifest = JSON.parse(readFileSync(join(template, 'package.json'), 'utf8')) as Record<string, Record<string, string>>;
    manifest.dependencies!.react = '19.0.0';
    manifest.devDependencies!.typescript = '5.0.0';
    writeFileSync(join(dir, 'package.json'), JSON.stringify(manifest));
    const moves = startPinMoves(dir, template);
    assert.deepEqual(moves, [{ name: 'react', from: '19.0.0', to: JSON.parse(readFileSync(join(template, 'package.json'), 'utf8')).dependencies.react }]);
    movePins(dir, moves);
    assert.deepEqual(startPinMoves(dir, template), []);
    assert.equal((JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8')) as Record<string, Record<string, string>>).devDependencies!.typescript, '5.0.0');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('update --yes leaves a deployment from before the clean break as it was, byte for byte, and says to deploy afresh', async () => {
  const { dir, env, close } = await heldDeployment();
  try {
    bumpPins(dir, '0.3.0');
    writeFileSync(join(dir, '.bin', 'pnpm'), '#!/bin/sh\nexit 0\n');
    const before = readFileSync(join(dir, 'package.json'), 'utf8');
    const { spawn } = await import('node:child_process');
    const child = spawn(process.execPath, ['--conditions=coffre:source', main, 'update', '--yes'], { cwd: dir, env });
    let stderr = '';
    child.stderr.setEncoding('utf8').on('data', (chunk: string) => (stderr += chunk));
    await new Promise((resolve) => child.on('close', resolve));
    assert.match(stderr, /This deployment stays as it is, at 0\.3\.0: coffre 0\.4\.0 was a clean break, and moves no deployment from before it\. Nothing was changed/);
    assert.match(stderr, /Deploy coffre 9\.9\.9 afresh, with coffre init/);
    assert.equal(readFileSync(join(dir, 'package.json'), 'utf8'), before);
  } finally {
    close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('update without a terminal, and without --yes, says plainly to pass --yes, and changes nothing', async () => {
  const { dir, env, close } = await heldDeployment();
  try {
    const before = readFileSync(join(dir, 'package.json'), 'utf8');
    const { spawn } = await import('node:child_process');
    const child = spawn(process.execPath, ['--conditions=coffre:source', main, 'update'], { cwd: dir, env, stdio: ['ignore', 'pipe', 'pipe'] });
    let stderr = '';
    child.stderr.setEncoding('utf8').on('data', (chunk: string) => (stderr += chunk));
    assert.notEqual(await new Promise((resolve) => child.on('close', resolve)), 0);
    assert.match(stderr, /Not a terminal, so nothing to confirm on: pass --yes to update without asking\./);
    assert.equal(readFileSync(join(dir, 'package.json'), 'utf8'), before);
  } finally {
    close();
    rmSync(dir, { recursive: true, force: true });
  }
});

/**
 * A Workers deployment at the clean break's release, a registry whose latest coffre is 9.9.9,
 * and a pnpm that holds pg-protocol back until the deployment lets it
 * through by name.
 */
async function heldDeployment() {
  const dir = mkdtempSync(join(tmpdir(), 'coffre-held-'));
  // The template's every file, as coffre init writes them.
  for (const file of templateFiles(join(examples, 'workers'))) {
    mkdirSync(join(dir, file, '..'), { recursive: true });
    cpSync(join(examples, 'workers', file), join(dir, file));
  }
  bumpPins(dir, CLEAN_BREAK);
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

test('resolved again, every version that moved is said, the held packages first, up to a screenful', () => {
  const held = [{ spec: 'pg-protocol@1.16.1', publishedAt: new Date() }];
  const others = Array.from({ length: 9 }, (_, i) => ({ name: `dep-${i}`, from: ['1.0.0'], to: ['1.0.1'] }));
  assert.deepEqual(movedLines([...others, { name: 'pg-protocol', from: ['1.16.1'], to: ['1.16.0'] }], held), [
    '  pg-protocol 1.16.1 → 1.16.0',
    ...others.slice(0, 7).map(({ name }) => `  ${name} 1.0.0 → 1.0.1`),
    '  and 2 more, in pnpm-lock.yaml',
  ]);
  assert.deepEqual(movedLines([{ name: 'gone', from: ['1.0.0'], to: [] }], held), ['  gone 1.0.0 → none']);
});

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
    assert.match(
      run.stderr,
      new RegExp(`pnpm holds back 1 package younger than this deployment's minimumReleaseAge, 7 days, and no older version fits: pg-protocol@1\\.16\\.1, old enough from ${clears} UTC`),
    );
    assert.match(run.stderr, /Run coffre update after .* UTC, or on a terminal to let them through until then\. package\.json, pnpm-workspace\.yaml and pnpm-lock\.yaml are as they were/);
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

test('any failed install puts package.json, pnpm-workspace.yaml and pnpm-lock.yaml back, byte for byte, and says so', async () => {
  const { dir, env, close } = await heldDeployment();
  try {
    writeFileSync(join(dir, '.bin', 'pnpm'), '#!/bin/sh\necho "ERR_PNPM_FETCH_404 GET http://registry.example/@coffre/server: Not Found" >&2\nexit 1\n');
    writeFileSync(join(dir, 'pnpm-lock.yaml'), "lockfileVersion: '9.0'\n# as pnpm 10 wrote it\n");
    const before = ['package.json', 'pnpm-workspace.yaml', 'pnpm-lock.yaml'].map((name) => readFileSync(join(dir, name), 'utf8'));
    const { spawn } = await import('node:child_process');
    const child = spawn(process.execPath, ['--conditions=coffre:source', main, 'update', '--yes'], { cwd: dir, env });
    let stderr = '';
    child.stderr.setEncoding('utf8').on('data', (chunk: string) => (stderr += chunk));
    assert.equal(await new Promise((resolve) => child.on('close', resolve)), 1);
    assert.match(stderr, /ERR_PNPM_FETCH_404.*package\.json, pnpm-workspace\.yaml and pnpm-lock\.yaml are as they were; node_modules may be incomplete/s);
    assert.deepEqual(['package.json', 'pnpm-workspace.yaml', 'pnpm-lock.yaml'].map((name) => readFileSync(join(dir, name), 'utf8')), before);
  } finally {
    close();
    rmSync(dir, { recursive: true, force: true });
  }
});

// --- with pnpm itself ----------------------------------------------------------------

/** Whether pnpm runs here, at the version a project asks for: online, or from a cache. */
function pnpmAt(version: string): boolean {
  const dir = mkdtempSync(join(tmpdir(), 'coffre-pnpm-probe-'));
  try {
    writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'probe', private: true, packageManager: `pnpm@${version}` }));
    const ran = spawnSync('pnpm', ['--version'], { cwd: dir, encoding: 'utf8', env: { ...process.env, COREPACK_ENABLE_DOWNLOAD_PROMPT: '0' }, timeout: 60_000 });
    return ran.status === 0 && ran.stdout.trim() === version;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const needsPnpm = (...versions: string[]) => ({ skip: versions.every(pnpmAt) ? false : `needs pnpm ${versions.join(' and ')}` });

test('a deployment moved from pnpm 10 to 11 installs without a terminal, its node_modules purged', needsPnpm('10.15.0', '11.8.0'), async () => {
  const dir = mkdtempSync(join(tmpdir(), 'coffre-majors-'));
  try {
    mkdirSync(join(dir, 'dep'));
    writeFileSync(join(dir, 'dep', 'package.json'), JSON.stringify({ name: 'dep', version: '1.0.0' }));
    const manifest = (pnpm: string) =>
      writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'deployment', private: true, packageManager: `pnpm@${pnpm}`, dependencies: { dep: 'file:./dep' } }));
    manifest('10.15.0');
    await install(dir);
    manifest('11.8.0');
    // What erwinkn/secrets met: pnpm 11 would remove pnpm 10's node_modules, and without a terminal it stops.
    // Not as CI, where pnpm removes it unasked: CI=false says so, whatever else the environment holds.
    const ci = process.env.CI;
    process.env.CI = 'false';
    try {
      await assert.rejects(install(dir), /ABORTED_REMOVE_MODULES_DIR_NO_TTY/);
    } finally {
      if (ci === undefined) delete process.env.CI;
      else process.env.CI = ci;
    }
    await install(dir, { purge: true });
    assert.match(readFileSync(join(dir, 'node_modules', '.modules.yaml'), 'utf8'), /pnpm@11\.8\.0/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

/**
 * A deployment whose lockfile an older pnpm wrote, holding proto@1.0.1, a
 * day old: what pnpm 11 then holds back. `allowed`, the range pg-like asks
 * of proto: one 1.0.0, a month old, fits, or not.
 */
async function lockedYoung(range: string) {
  const published = await registry({
    proto: [{ version: '1.0.0', daysAgo: 30 }, { version: '1.0.1', daysAgo: 1 }],
    other: [{ version: '2.0.0', daysAgo: 40 }],
    'pg-like': [{ version: '1.0.0', daysAgo: 30, dependencies: { proto: range, other: '^2.0.0' } }],
  });
  const dir = mkdtempSync(join(tmpdir(), 'coffre-locked-'));
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'deployment', private: true, packageManager: 'pnpm@11.8.0', dependencies: { 'pg-like': '1.0.0' } }));
  writeFileSync(join(dir, '.npmrc'), `registry=${published.origin}/\n`);
  writeFileSync(join(dir, 'pnpm-workspace.yaml'), 'minimumReleaseAge: 0\n');
  await install(dir);
  writeFileSync(join(dir, 'pnpm-workspace.yaml'), 'minimumReleaseAge: 10080\n');
  return { dir, close: () => (published.close(), rmSync(dir, { recursive: true, force: true })) };
}

test('held back by an old lockfile, resolving again picks a version old enough, and nothing is let through', needsPnpm('11.8.0'), async () => {
  const { dir, close } = await lockedYoung('^1.0.0');
  try {
    await assert.rejects(install(dir), (error: unknown) => error instanceof HeldBack && error.held.map(({ spec }) => spec).join() === 'proto@1.0.1');
    assert.deepEqual(await resolveAgain(dir), [{ name: 'proto', from: ['1.0.1'], to: ['1.0.0'] }]);
    assert.doesNotMatch(readFileSync(join(dir, 'pnpm-workspace.yaml'), 'utf8'), /Exclude/);
    await install(dir);
  } finally {
    close();
  }
});

test('when no version old enough fits, resolving again says which, and puts the lockfile back', needsPnpm('11.8.0'), async () => {
  const { dir, close } = await lockedYoung('^1.0.1');
  try {
    const lockfile = readFileSync(join(dir, 'pnpm-lock.yaml'), 'utf8');
    await assert.rejects(resolveAgain(dir), (error: unknown) => error instanceof HeldBack && error.held.map(({ spec }) => spec).join() === 'proto@1.0.1');
    assert.equal(readFileSync(join(dir, 'pnpm-lock.yaml'), 'utf8'), lockfile);
  } finally {
    close();
  }
});

test("pnpm 11's own global install, as it lays it out: found by asking pnpm, though it lives in the store's links/", needsPnpm('11.8.0'), () => {
  const dir = mkdtempSync(join(tmpdir(), 'coffre-pnpm-global-'));
  try {
    // A stand-in @coffre/cli, which says where it runs from as the real one finds itself: its real path.
    mkdirSync(join(dir, 'cli', 'package', 'dist'), { recursive: true });
    writeFileSync(join(dir, 'cli', 'package', 'package.json'), JSON.stringify({ name: '@coffre/cli', version: '9.9.9', bin: { coffre: 'dist/main.js' } }));
    writeFileSync(join(dir, 'cli', 'package', 'dist', 'main.js'), "#!/usr/bin/env node\nconsole.log(require('node:fs').realpathSync(__filename));\n");
    spawnSync('tar', ['czf', join(dir, 'cli.tgz'), '-C', join(dir, 'cli'), 'package']);
    // pnpm 11, its home and data of its own, as `pnpm setup` leaves them: its bin directory on PATH.
    const home = join(dir, 'home');
    mkdirSync(home);
    writeFileSync(join(home, 'package.json'), JSON.stringify({ name: 'home', private: true, packageManager: 'pnpm@11.8.0' }));
    const pnpmHome = join(dir, 'pnpm');
    const base = { ...process.env, PNPM_HOME: pnpmHome, XDG_DATA_HOME: join(dir, 'data'), XDG_CONFIG_HOME: join(dir, 'config'), XDG_STATE_HOME: join(dir, 'state') };
    const env = { ...base, PATH: `${join(pnpmHome, 'bin')}:${process.env.PATH}` };
    const added = spawnSync('pnpm', ['add', '-g', join(dir, 'cli.tgz')], { cwd: home, env, encoding: 'utf8' });
    assert.equal(added.status, 0, added.stdout + added.stderr);
    const self = spawnSync(join(pnpmHome, 'bin', 'coffre'), [], { env, encoding: 'utf8' }).stdout.trim();
    assert.match(self, /\/store\/v11\/links\/@coffre\/cli\/9\.9\.9\/[0-9a-f]+\/node_modules\/@coffre\/cli\/dist\/main\.js$/, 'where 0.1.16 was misread');

    const pnpm = globalCli('pnpm', env, home);
    assert.ok(typeof pnpm === 'string' && self.startsWith(`${pnpm}/`), `pnpm says its global is ${pnpm}`);
    assert.deepEqual(installOf(self, { npm: null, pnpm, pnpmHome: null }), { kind: 'pnpm' });
    // With its bin directory off PATH, pnpm may not answer; its PNPM_HOME still says it is pnpm's.
    const off = globalCli('pnpm', base, home);
    assert.deepEqual(installOf(self, { npm: null, pnpm: off ?? null, pnpmHome: off === undefined ? pnpmHome : null }), { kind: 'pnpm' });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
