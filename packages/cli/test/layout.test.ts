import test from 'node:test';
import assert from 'node:assert/strict';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { templateDir, templateFiles, type Kind } from '../src/init.ts';
import { after, applyChanges, blob, CLEAN_BREAK, lineDiff, pageMove, ROUTE_FILES, shownChange, type Move } from '../src/layout.ts';

/** A deployment as `coffre init` writes it, in a directory of its own. */
function deployment(kind: Kind): string {
  const dir = mkdtempSync(join(tmpdir(), `coffre-layout-${kind}-`));
  for (const file of templateFiles(templateDir(kind))) {
    mkdirSync(join(dir, file, '..'), { recursive: true });
    cpSync(join(templateDir(kind), file), join(dir, file));
  }
  return dir;
}

const changesOf = (move: Move) => {
  assert.ok('changes' in move, JSON.stringify(move));
  return move.changes;
};

const problemsOf = (move: Move) => {
  assert.ok('problems' in move, `moved, though it should not have: ${JSON.stringify(move)}`);
  return move.problems.join('\n');
};

test('every route file the template has is known by the release that first wrote it', () => {
  for (const kind of ['workers', 'node'] as const) {
    const routes = templateFiles(templateDir(kind)).filter((path) => path.startsWith('app/src/routes/'));
    assert.deepEqual(routes.sort(), Object.keys(ROUTE_FILES).sort(), kind);
  }
});

test('a deployment at the template\'s release gains and loses no page: one it left out stays out', () => {
  const dir = deployment('workers');
  try {
    assert.deepEqual(pageMove(dir, templateDir('workers'), CLEAN_BREAK), { changes: [] });
    rmSync(join(dir, 'app/src/routes/_coffre/audit.tsx'));
    assert.deepEqual(pageMove(dir, templateDir('workers'), CLEAN_BREAK), { changes: [] });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a page a later release adds is a file the deployment gains; one it had left out stays out; one retired goes only as coffre wrote it", () => {
  const dir = deployment('workers');
  try {
    const template = templateDir('workers');
    const added = 'app/src/routes/_coffre/projects.index.tsx';
    const retired = 'app/src/routes/_coffre/audit.tsx';
    rmSync(join(dir, added));
    const files = (since: string) => ({
      added: { [added]: since },
      retired: { [retired]: { since: '0.6.0', blobs: [blob(readFileSync(join(template, retired), 'utf8'))] } },
    });
    // Moving from 0.4.0 to a release that added the page in 0.5.0, and retired another in 0.6.0.
    const move = changesOf(pageMove(dir, template, '0.4.0', files('0.5.0')));
    assert.deepEqual(move.map(({ path, becomes }) => [path, becomes === null ? 'removed' : 'added']), [[added, 'added'], [retired, 'removed']]);
    applyChanges(dir, move);
    assert.equal(readFileSync(join(dir, added), 'utf8'), readFileSync(join(template, added), 'utf8'));
    // From 0.5.0, the page was there to be had: its file missing is the deployment's choice.
    writeFileSync(join(dir, retired), readFileSync(join(template, retired), 'utf8'));
    rmSync(join(dir, added));
    assert.deepEqual(changesOf(pageMove(dir, template, '0.5.0', files('0.5.0'))).map(({ path }) => path), [retired]);
    // A retired page the deployment changed is its own.
    writeFileSync(join(dir, retired), '// ours\n');
    assert.match(problemsOf(pageMove(dir, template, '0.5.0', files('0.5.0'))), /audit\.tsx is a page coffre 0\.6\.0 no longer has, and is not as coffre wrote it/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a 0.4.0 deployment loses /access, which only sent old links to /users, but not one it changed', () => {
  const dir = deployment('workers');
  try {
    const access = 'app/src/routes/_coffre/access.tsx';
    // The file as 0.4.0 wrote it.
    const written = "import { createFileRoute } from '@tanstack/react-router';\nimport { access } from '@coffre/ui';\n\nexport const Route = createFileRoute('/_coffre/access')({ ...access });\n";
    writeFileSync(join(dir, access), written);
    const move = changesOf(pageMove(dir, templateDir('workers'), CLEAN_BREAK));
    assert.deepEqual(move, [{ path: access, was: written, becomes: null }]);
    writeFileSync(join(dir, access), '// ours\n');
    assert.match(problemsOf(pageMove(dir, templateDir('workers'), CLEAN_BREAK)), /access\.tsx is a page coffre 0\.4\.1 no longer has/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a deployment without coffre's layouts as file routes is refused, not given pages", () => {
  const dir = deployment('workers');
  try {
    rmSync(join(dir, 'app/src/routes'), { recursive: true });
    assert.match(problemsOf(pageMove(dir, templateDir('workers'), CLEAN_BREAK)), /_coffre\.tsx and app\/src\/routes\/_solo\.tsx, coffre's layouts as file routes, are both missing/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('releases are ordered as semver orders them, a prerelease before its release', () => {
  assert.ok(after('0.2.1', '0.2.0'));
  assert.ok(after('0.10.0', '0.9.9'));
  assert.ok(after('0.2.1', '0.2.1-beta.1'));
  assert.ok(!after('0.2.1-beta.1', '0.2.1'));
  assert.ok(after('0.2.1-beta.2', '0.2.1-beta.1'));
  assert.ok(after('0.2.1-beta.10', '0.2.1-beta.9'));
  assert.ok(after('0.2.1-beta', '0.2.1-alpha'));
  assert.ok(!after('0.2.0', '0.2.0'));
});

test('a change is shown by the lines that go and come, a file added or removed by its name', () => {
  assert.deepEqual(lineDiff(['a', 'b', 'c'], ['a', 'x', 'c']), ['- b', '+ x']);
  assert.deepEqual(shownChange({ path: 'app/vite.config.ts', was: null, becomes: 'x' }), ['+ app/vite.config.ts, new']);
  assert.deepEqual(shownChange({ path: 'app/src/old.ts', was: 'x', becomes: null }), ['- app/src/old.ts']);
  assert.deepEqual(shownChange({ path: '.gitignore', was: 'node_modules\n', becomes: 'node_modules\ndist\n' }), ['~ .gitignore', '  + dist']);
});
