// `pnpm dev` runs dev/deployment, which is examples/workers' app with what
// only development adds: its files are the example's but for those named
// here, each with its reason. A shared file that drifts fails this test,
// so a change to the example's routes, router or Start setup reaches dev too.
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));

/** What dev/deployment/app means to differ by, from examples/workers/app. */
export const INTENDED = {
  // Its own configuration: the dev IdP, the seed's settings, loopback issuers.
  'src/coffre.ts': 'differs',
  // The Agentation toolbar, for annotating pages in development.
  'src/agentation.tsx': 'dev only',
  'src/routes/__root.tsx': 'differs',
  // Every @coffre/* import resolved to its sources, and the vault as an auxiliary Worker.
  'vite.config.ts': 'differs',
  // The dev stack's names, ports and bindings.
  'wrangler.jsonc': 'differs',
};

/** An app's files, as git sees them: tracked, or new and not ignored, relative to `dir`. */
function files(dir) {
  const listed = execFileSync('git', ['-C', dir, 'ls-files', '--cached', '--others', '--exclude-standard', '.'], { encoding: 'utf8' });
  return listed.split('\n').filter((line) => line !== '').sort();
}

/** How `dev` differs from `example`, file by file, beyond what is intended: empty when only as intended. */
export function drift(dev, example, intended = INTENDED) {
  const [ours, theirs] = [files(dev), files(example)];
  const problems = [];
  for (const file of new Set([...ours, ...theirs])) {
    const want = intended[file];
    const inDev = ours.includes(file);
    const inExample = theirs.includes(file);
    if (want === 'dev only') {
      if (!inDev || inExample) problems.push(`${file}: meant to be dev/deployment's only`);
    } else if (!inDev || !inExample) {
      problems.push(`${file}: in ${inDev ? 'dev/deployment' : 'examples/workers'} only`);
    } else if (want !== 'differs' && readFileSync(join(dev, file), 'utf8') !== readFileSync(join(example, file), 'utf8')) {
      problems.push(`${file}: differs from examples/workers/app/${file}`);
    }
  }
  for (const [file, want] of Object.entries(intended)) {
    if (want === 'differs' && files(dev).includes(file) && readFileSync(join(dev, file), 'utf8') === readFileSync(join(example, file), 'utf8')) {
      problems.push(`${file}: listed as differing, but is the same: take it off the list`);
    }
  }
  return problems.sort();
}

test("dev/deployment's app is examples/workers' but for what development adds", () => {
  assert.deepEqual(drift(join(root, 'dev/deployment/app'), join(root, 'examples/workers/app')), []);
});

test('a shared file that drifts, or one added on one side only, is named', () => {
  const work = mkdtempSync(join(tmpdir(), 'coffre-dev-drift-'));
  try {
    for (const side of ['dev', 'example']) {
      cpSync(join(root, side === 'dev' ? 'dev/deployment/app' : 'examples/workers/app'), join(work, side), {
        recursive: true,
        filter: (path) => !/[/\\](node_modules|dist|\.wrangler)([/\\]|$)/.test(path),
      });
    }
    execFileSync('git', ['init', '-q', work]);
    assert.deepEqual(drift(join(work, 'dev'), join(work, 'example')), []);
    writeFileSync(join(work, 'dev', 'src/router.tsx'), `${readFileSync(join(work, 'dev', 'src/router.tsx'), 'utf8')}// drifted\n`);
    writeFileSync(join(work, 'example', 'src/routes/_coffre/new.tsx'), 'export {};\n');
    assert.deepEqual(drift(join(work, 'dev'), join(work, 'example')), [
      'src/router.tsx: differs from examples/workers/app/src/router.tsx',
      'src/routes/_coffre/new.tsx: in examples/workers only',
    ]);
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
});
