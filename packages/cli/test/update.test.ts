import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  bumpPins,
  coffrePins,
  excludeUntil,
  generateRouteTree,
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
import { templateDir, templateFiles } from '../src/init.ts';
import { applyChanges, CLEAN_BREAK, pageMove, ROUTE_FILES } from '../src/layout.ts';
import { registry } from './registry.ts';
import { inTerminal, ptySkip } from './pty.ts';
import { deploymentMigrations, globalCli, installOf, migrationsAdded, movedLines, notUpdated, parsePlan, type Plan } from '../src/update.ts';
import { cliVersion } from '../src/version.ts';

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
    "coffre 0.4.1 adds no migration to 0.4.0's: just deploy it.",
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
    // This CLI as npm's global, updated in step 1 to one whose migrations add one: what the tail would have said.
    const updated = join(dir, 'updated-cli');
    mkdirSync(join(updated, 'dist', 'migrations', 'postgres', 'meta'), { recursive: true });
    writeFileSync(join(updated, 'dist', 'migrations', 'postgres', 'meta', '_journal.json'), JSON.stringify({ entries: [{ tag: '0000_baseline' }, { tag: '0001_later' }] }));
    const cli = realpathSync(fileURLToPath(new URL('..', import.meta.url)));
    writeFileSync(
      join(dir, '.bin', 'npm'),
      `#!/bin/sh
[ "$1" = ls ] || exit 0
if [ -e '${dir}/npm-asked' ]; then at='${updated}'; else at='${cli}'; touch '${dir}/npm-asked'; fi
printf '{"dependencies":{"@coffre/cli":{"path":"%s"}}}' "$at"
`,
    );
    chmodSync(join(dir, '.bin', 'npm'), 0o755);
    const before = readFileSync(join(dir, 'package.json'), 'utf8');
    const { spawn } = await import('node:child_process');
    const child = spawn(process.execPath, ['--conditions=coffre:source', main, 'update', '--yes'], { cwd: dir, env });
    let stderr = '';
    child.stderr.setEncoding('utf8').on('data', (chunk: string) => (stderr += chunk));
    await new Promise((resolve) => child.on('close', resolve));
    assert.match(stderr, /This deployment stays as it is, at 0\.3\.0: coffre 0\.4\.0 was a clean break, and moves no deployment from before it\. Nothing was changed/);
    assert.match(stderr, /Deploy coffre 9\.9\.9 afresh, with coffre init/);
    assert.match(stderr, /Updated this CLI from \S+ to 9\.9\.9, with npm/);
    assert.doesNotMatch(stderr, /adds \d+ migration|coffre migrate|to deploy it|Deploy it with/, 'no migration step for a deployment deployed afresh');
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
    assert.ok(!existsSync(join(dir, 'planner-ran')) && !existsSync(join(dir, 'npm-asked')), 'nothing of the release fetched or run, unasked');
  } finally {
    close();
    rmSync(dir, { recursive: true, force: true });
  }
});

/**
 * A Workers deployment at the clean break's release, a registry whose latest coffre is `latest`,
 * a pnpm that holds pg-protocol back until the deployment lets it
 * through by name, and an npm whose coffre `latest` is this CLI.
 */
async function heldDeployment(latest = '9.9.9') {
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
  // npm installs coffre `latest` as a CLI whose command is planner.mjs: this one, from source, unless a test says otherwise.
  writeFileSync(
    join(bin, 'npm'),
    `#!/bin/sh
case "$1" in
  ls) echo '{}'; exit 0 ;;
  install) ;;
  *) exit 1 ;;
esac
echo "$@" >> '${dir}/npm-asked'
for spec; do :; done
[ "$spec" = '@coffre/cli@${latest}' ] || { echo "npm $*: not the latest coffre" >&2; exit 1; }
mkdir -p node_modules/@coffre/cli
printf '{"name":"@coffre/cli","version":"${latest}","bin":{"coffre":"planner.mjs"}}' > node_modules/@coffre/cli/package.json
cp '${bin}/planner.mjs' node_modules/@coffre/cli/
`,
  );
  chmodSync(join(bin, 'npm'), 0o755);
  planner(dir, `const ran = spawnSync(process.execPath, ['--conditions=coffre:source', ${JSON.stringify(main)}, ...process.argv.slice(2)], { stdio: 'inherit' });
process.exit(ran.status ?? 1);`);
  // update never runs npx, which would run a copy of the release another project or the global prefix has.
  writeFileSync(join(bin, 'npx'), `#!/bin/sh\necho "npx $@" >> '${dir}/planner-ran'\nexit 1\n`);
  chmodSync(join(bin, 'npx'), 0o755);
  const registry = createServer((_request, response) => {
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify({ version: latest }));
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

/** The release's own CLI, as heldDeployment's npm installs it: `body`, once it has noted that it ran, in `planner-ran`. */
function planner(dir: string, body: string): void {
  writeFileSync(
    join(dir, '.bin', 'planner.mjs'),
    `import { spawnSync } from 'node:child_process';\nimport { appendFileSync } from 'node:fs';\nappendFileSync(${JSON.stringify(join(dir, 'planner-ran'))}, process.argv.slice(2).join(' ') + '\\n');\n${body}\n`,
  );
}

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

/** `coffre update --yes` in `dir`, as a deployment's own CLI runs it. */
async function updateIn(dir: string, env: NodeJS.ProcessEnv): Promise<{ code: number | null; stderr: string }> {
  const { spawn } = await import('node:child_process');
  const child = spawn(process.execPath, ['--conditions=coffre:source', main, 'update', '--yes'], { cwd: dir, env });
  let stderr = '';
  child.stderr.setEncoding('utf8').on('data', (chunk: string) => (stderr += chunk));
  return { code: await new Promise((resolve) => child.on('close', resolve)), stderr };
}

test("an earlier release's CLI moves a deployment with the pages and pins the release's own CLI names, not its own", async () => {
  // What 0.4.6's CLI did to 0.5.0: it added the pages it knew, and not users.$user.apps.tsx.
  const { dir, env, close } = await heldDeployment();
  try {
    const later = 'app/src/routes/_coffre/later.tsx';
    assert.equal(ROUTE_FILES[later], undefined, 'a page this CLI does not know');
    writeFileSync(join(dir, '.bin', 'pnpm'), '#!/bin/sh\nexit 0\n');
    // 9.9.9's own CLI, which knows a page and a React this one does not.
    const plan = {
      pages: { changes: [{ path: later, was: null, becomes: '// a page coffre 9.9.9 adds\n' }] },
      start: [{ name: 'react', from: '19.2.7', to: '19.9.0' }],
      packageManager: 'pnpm@11.8.0',
    };
    planner(dir, `console.error('a warning first'); console.log(${JSON.stringify(JSON.stringify(plan))});`);
    const run = await updateIn(dir, env);
    assert.equal(run.code, 0, run.stderr);
    assert.equal(readFileSync(join(dir, 'npm-asked'), 'utf8'), 'install --ignore-scripts --no-audit --no-fund --no-package-lock @coffre/cli@9.9.9\n');
    assert.equal(readFileSync(join(dir, 'planner-ran'), 'utf8'), `update --plan ${dir}\n`);
    assert.equal(existsSync(join(dir, later)) && readFileSync(join(dir, later), 'utf8'), '// a page coffre 9.9.9 adds\n', run.stderr);
    assert.match(run.stderr, /Changed coffre's page files: app\/src\/routes\/_coffre\/later\.tsx/);
    const manifest = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8')) as { dependencies: Record<string, string> };
    assert.equal(manifest.dependencies.react, '19.9.0');
    assert.ok(Object.values(coffrePins(dir)).every((version) => version === '9.9.9'));
  } finally {
    close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a release's CLI names the pages a deployment gains since its pins, its Start app's pins and its pnpm, as one line of JSON", async () => {
  const dir = mkdtempSync(join(tmpdir(), 'coffre-plan-'));
  try {
    for (const file of templateFiles(join(examples, 'node'))) {
      mkdirSync(join(dir, file, '..'), { recursive: true });
      cpSync(join(examples, 'node', file), join(dir, file));
    }
    const apps = 'app/src/routes/_coffre/users.$user.apps.tsx';
    rmSync(join(dir, apps));
    const ask = () => {
      const ran = spawnSync(process.execPath, ['--conditions=coffre:source', main, 'update', '--plan', dir], { cwd: tmpdir(), encoding: 'utf8' });
      assert.equal(ran.status, 0, ran.stderr);
      assert.equal(ran.stdout.trim().split('\n').length, 1);
      return JSON.parse(ran.stdout) as Plan;
    };
    bumpPins(dir, '0.4.6');
    movePins(dir, [{ name: 'react', from: '', to: '19.0.0' }]);
    const plan = ask();
    assert.deepEqual(plan.pages, { changes: [{ path: apps, was: null, becomes: readFileSync(join(templateDir('node'), apps), 'utf8') }] });
    assert.deepEqual(plan.start.map(({ name, from }) => [name, from]), [['react', '19.0.0']]);
    assert.equal(plan.packageManager, JSON.parse(readFileSync(join(templateDir('node'), 'package.json'), 'utf8')).packageManager);
    // At 0.5.0, which first wrote it, the page is one the deployment left out.
    bumpPins(dir, '0.5.0');
    assert.deepEqual(ask().pages, { changes: [] });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("when the release's own CLI can't say what it changes, the deployment stays as it was, and update fails, saying what to run", async () => {
  const { dir, env, close } = await heldDeployment();
  try {
    writeFileSync(join(dir, '.bin', 'npm'), '#!/bin/sh\n[ "$1" = ls ] && { echo "{}"; exit 0; }\necho "npm error 404 Not Found - GET @coffre/cli@9.9.9" >&2\nexit 1\n');
    const before = ['package.json', 'pnpm-workspace.yaml'].map((name) => readFileSync(join(dir, name), 'utf8'));
    const run = await updateIn(dir, env);
    assert.equal(run.code, 1, run.stderr);
    assert.match(run.stderr, /coffre 9\.9\.9's own CLI could not say what it changes \(npm error 404 Not Found - GET @coffre\/cli@9\.9\.9\)\. Nothing was changed: run coffre 9\.9\.9's own, npx @coffre\/cli@9\.9\.9 update/);
    assert.deepEqual(['package.json', 'pnpm-workspace.yaml'].map((name) => readFileSync(join(dir, name), 'utf8')), before);
  } finally {
    close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('declined on a terminal, the move runs nothing of the release: its own CLI is never fetched', { skip: ptySkip }, async () => {
  const { dir, env, close } = await heldDeployment();
  try {
    const before = readFileSync(join(dir, 'package.json'), 'utf8');
    const run = await inTerminal(
      ['update'],
      env,
      async (session) => {
        await session.waitFor('and install it?');
        session.send('n');
      },
      { columns: 160, rows: 48 },
      dir,
    );
    assert.equal(run.code, 0, run.output);
    assert.match(run.output, /This deployment stays as it is, at 0\.4\.0/);
    assert.ok(!existsSync(join(dir, 'planner-ran')) && !existsSync(join(dir, 'npm-asked')), 'nothing of the release fetched or run');
    assert.equal(readFileSync(join(dir, 'package.json'), 'utf8'), before);
  } finally {
    close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a plan that reaches outside the routes, pins another package or names no pnpm is refused, before any file changes', async () => {
  const { dir, env, close } = await heldDeployment();
  try {
    writeFileSync(join(dir, '.bin', 'pnpm'), '#!/bin/sh\nexit 0\n');
    // An exclusion past its date, which an update that goes ahead removes first.
    excludeUntil(dir, [{ spec: 'pg-protocol@1.16.1', clears: new Date('2026-01-01T00:00:00Z') }], 'for coffre 0.4.0');
    const files = ['package.json', 'pnpm-workspace.yaml'];
    const before = files.map((name) => readFileSync(join(dir, name), 'utf8'));
    const valid = { pages: { changes: [] }, start: [], packageManager: 'pnpm@11.8.0' };
    // Beside the deployment, named after it: no other run's.
    const sentinel = `${basename(dir)}.sentinel`;
    const plans: [string, unknown][] = [
      [`"../${sentinel}" is not a file in app/src/routes/`, { ...valid, pages: { changes: [{ path: `../${sentinel}`, was: null, becomes: 'outside\n' }] } }],
      [`"app/src/routes/../../../${sentinel}" is not a file in app/src/routes/`, { ...valid, pages: { changes: [{ path: `app/src/routes/../../../${sentinel}`, was: null, becomes: 'outside\n' }] } }],
      ["typescript is not one of the Start app's packages", { ...valid, start: [{ name: 'typescript', from: '5.9.3', to: '999.0.0' }] }],
      ['packageManager 42 is not an exact pnpm', { ...valid, packageManager: 42 }],
    ];
    for (const [refused, plan] of plans) {
      planner(dir, `console.log(${JSON.stringify(JSON.stringify(plan))});`);
      const run = await updateIn(dir, env);
      assert.equal(run.code, 1, run.stderr);
      assert.ok(run.stderr.includes(`coffre 9.9.9's own CLI could not say what it changes (${refused}). Nothing was changed`), run.stderr);
      assert.deepEqual(files.map((name) => readFileSync(join(dir, name), 'utf8')), before);
      assert.ok(!existsSync(join(dir, '..', sentinel)), `${sentinel} written outside the deployment`);
    }
  } finally {
    close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a plan is taken as this release knows it: fields it does not know left out, those it knows held to their shape', () => {
  const dir = mkdtempSync(join(tmpdir(), 'coffre-plan-'));
  try {
    const page = 'app/src/routes/_coffre/page.tsx';
    mkdirSync(join(dir, 'app/src/routes/_coffre'), { recursive: true });
    writeFileSync(join(dir, page), 'as coffre wrote it\n');
    const valid = {
      pages: { changes: [{ path: page, was: 'as coffre wrote it\n', becomes: null, later: true }] },
      start: [{ name: 'react', from: '19.0.0', to: '19.2.7-rc.1', why: 'later' }],
      packageManager: 'pnpm@11.8.0+sha512.0a1b',
      later: { anything: 1 },
    };
    assert.deepEqual(parsePlan(valid, dir), {
      pages: { changes: [{ path: page, was: 'as coffre wrote it\n', becomes: null }] },
      start: [{ name: 'react', from: '19.0.0', to: '19.2.7-rc.1' }],
      packageManager: 'pnpm@11.8.0+sha512.0a1b',
    });
    assert.deepEqual(parsePlan({ ...valid, pages: { problems: ['moved'] }, packageManager: null }, dir).pages, { problems: ['moved'] });
    const refused = (plan: unknown, why: RegExp) => assert.throws(() => parsePlan(plan, dir), why);
    refused(null, /not a plan/);
    refused({ ...valid, packageManager: 'npm@11.0.0' }, /not an exact pnpm/);
    refused({ ...valid, packageManager: 'pnpm@^11' }, /not an exact pnpm/);
    refused({ ...valid, start: [{ name: 'react', from: '19.0.0', to: '^19.0.0' }] }, /not an exact version/);
    refused({ ...valid, start: {} }, /start is not a list/);
    refused({ ...valid, pages: {} }, /neither changes nor problems/);
    refused({ ...valid, pages: { problems: [1] } }, /not a line/);
    for (const path of ['/etc/passwd', 'app/src/routes/', 'app/src/routes/./a.tsx', 'app/src/routes//a.tsx', 'app/src/routes\\..\\a.tsx', 'app/src/routeTree.gen.ts']) {
      refused({ ...valid, pages: { changes: [{ path, was: null, becomes: '' }] } }, /is not a file in app\/src\/routes\//);
    }
    refused({ ...valid, pages: { changes: [{ path: page, was: 'another text\n', becomes: null }] } }, /is not as it says it was/);
    refused({ ...valid, pages: { changes: [{ path: page, was: null, becomes: 1 }] } }, /not a path, was and becomes/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the release's own CLI is the registry's, as the deployment's .npmrc names it: never a copy of the same version a project or npm's global prefix has", async () => {
  const work = mkdtempSync(join(tmpdir(), 'coffre-provenance-'));
  const plan = (pnpm: string, ran: string) =>
    `import { writeFileSync } from 'node:fs';\nwriteFileSync(${JSON.stringify(join(work, ran))}, '');\nconsole.log(JSON.stringify({ pages: { changes: [] }, start: [], packageManager: '${pnpm}' }));\n`;
  const cli = (version: string, main: string) => ({ version, files: { 'package.json': JSON.stringify({ name: '@coffre/cli', version, bin: { coffre: 'main.mjs' } }), 'main.mjs': main } });
  const published = await registry({ '@coffre/cli': [{ version: '9.9.9', daysAgo: 0, files: cli('9.9.9', plan('pnpm@9.9.9', 'registry-ran')).files }] });
  try {
    const home = join(work, 'home');
    const deployment = join(work, 'deployment');
    // A home that is a project with its own @coffre/cli@9.9.9, and a global prefix with another: npx would run either.
    for (const [root, ran] of [[join(home, 'node_modules', '@coffre', 'cli'), 'home-ran'], [join(work, 'global', 'lib', 'node_modules', '@coffre', 'cli'), 'global-ran']] as const) {
      mkdirSync(root, { recursive: true });
      for (const [name, text] of Object.entries(cli('9.9.9', `#!/usr/bin/env node\n${plan('pnpm@6.6.6', ran)}`).files)) writeFileSync(join(root, name), text, { mode: 0o755 });
    }
    writeFileSync(join(home, 'package.json'), JSON.stringify({ dependencies: { '@coffre/cli': '9.9.9' } }));
    mkdirSync(join(home, 'node_modules', '.bin'));
    symlinkSync(join(home, 'node_modules', '@coffre', 'cli', 'main.mjs'), join(home, 'node_modules', '.bin', 'coffre'));
    mkdirSync(join(work, 'global', 'bin'), { recursive: true });
    symlinkSync(join(work, 'global', 'lib', 'node_modules', '@coffre', 'cli', 'main.mjs'), join(work, 'global', 'bin', 'coffre'));
    // The user's own registry answers nothing; the deployment's is coffre's.
    writeFileSync(join(home, '.npmrc'), 'registry=http://127.0.0.1:9/\n');
    mkdirSync(deployment);
    writeFileSync(join(deployment, '.npmrc'), `registry=${published.origin}/\n`);
    const env = { PATH: process.env.PATH, HOME: home, npm_config_prefix: join(work, 'global'), npm_config_cache: join(work, 'cache'), npm_config_update_notifier: 'false' };
    const update = fileURLToPath(new URL('../src/update.ts', import.meta.url));
    const { spawn } = await import('node:child_process');
    const child = spawn(
      process.execPath,
      ['--conditions=coffre:source', '--input-type=module', '-e', `import { planOf } from ${JSON.stringify(update)}; console.log(JSON.stringify(await planOf('9.9.9', ${JSON.stringify(deployment)}, process.env)));`],
      { cwd: home, env },
    );
    let [stdout, stderr] = ['', ''];
    child.stdout.setEncoding('utf8').on('data', (chunk: string) => (stdout += chunk));
    child.stderr.setEncoding('utf8').on('data', (chunk: string) => (stderr += chunk));
    assert.equal(await new Promise((resolve) => child.on('close', resolve)), 0, stderr);
    assert.equal((JSON.parse(stdout) as Plan).packageManager, 'pnpm@9.9.9');
    assert.ok(existsSync(join(work, 'registry-ran')));
    assert.ok(!existsSync(join(work, 'home-ran')) && !existsSync(join(work, 'global-ran')));
  } finally {
    published.close();
    rmSync(work, { recursive: true, force: true });
  }
});

test('the release itself moves a deployment by its own template, asking no other CLI', async () => {
  const { dir, env, close } = await heldDeployment(cliVersion());
  try {
    writeFileSync(join(dir, '.bin', 'pnpm'), '#!/bin/sh\nexit 0\n');
    const run = await updateIn(dir, env);
    assert.equal(run.code, 0, run.stderr);
    assert.ok(!existsSync(join(dir, 'npm-asked')) && !existsSync(join(dir, 'planner-ran')), 'no other CLI was asked');
    assert.ok(Object.values(coffrePins(dir)).every((version) => version === cliVersion()));
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

test("a deployment that gains route files gets the route tree its build writes, and none is left stale", { skip: !existsSync(join(examples, 'node', 'node_modules', 'vite')) }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'coffre-update-tree-'));
  // Vite's config reads @coffre/ui's sources, as the workspace's own tests do; published, the condition is inert.
  const options = process.env.NODE_OPTIONS;
  process.env.NODE_OPTIONS = `${options ?? ''} --conditions=coffre:source`.trim();
  try {
    const template = templateDir('node');
    for (const file of templateFiles(template)) {
      mkdirSync(join(dir, file, '..'), { recursive: true });
      cpSync(join(template, file), join(dir, file));
    }
    symlinkSync(join(examples, 'node', 'node_modules'), join(dir, 'node_modules'));
    const tree = join(dir, 'app', 'src', 'routeTree.gen.ts');
    const built = readFileSync(tree, 'utf8');

    // A deployment from before the account page's tabs, its tree as its build wrote it then.
    const tabs = ['index', 'sessions', 'apps', 'appearance'].map((tab) => `app/src/routes/_coffre/account.${tab}.tsx`);
    for (const path of tabs) rmSync(join(dir, path));
    assert.equal(await generateRouteTree(dir), true);
    assert.ok(!readFileSync(tree, 'utf8').includes('account.sessions'), 'the tree before the tabs has none');
    assert.equal(await generateRouteTree(dir), false, 'a tree up to date is left alone');

    // update adds the files and regenerates, and the tree is what the template's build wrote.
    const move = pageMove(dir, template, '0.4.1');
    assert.ok('changes' in move && move.changes.length === tabs.length);
    applyChanges(dir, move.changes);
    assert.equal(readFileSync(tree, 'utf8').includes('account.sessions'), false, 'stale until regenerated');
    assert.equal(await generateRouteTree(dir), true);
    assert.equal(readFileSync(tree, 'utf8'), built);

    // And one removed: the tree loses it again.
    rmSync(join(dir, tabs[1]!));
    assert.equal(await generateRouteTree(dir), true);
    assert.ok(!readFileSync(tree, 'utf8').includes('account.sessions'));
  } finally {
    if (options === undefined) delete process.env.NODE_OPTIONS;
    else process.env.NODE_OPTIONS = options;
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a directory with no Start app has no route tree to regenerate', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'coffre-update-notree-'));
  try {
    assert.equal(await generateRouteTree(dir), false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
