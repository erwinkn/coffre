import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { KINDS } from '../src/init.ts';

const root = fileURLToPath(new URL('../../../', import.meta.url));
const main = join(root, 'packages/cli/src/main.ts');
const { version } = JSON.parse(readFileSync(join(root, 'packages/cli/package.json'), 'utf8')) as { version: string };

/** An example's files, as git sees them: tracked, or new and not ignored. */
function exampleFiles(kind: string): string[] {
  const listed = execFileSync('git', ['-C', root, 'ls-files', '--cached', '--others', '--exclude-standard', `examples/${kind}`], {
    encoding: 'utf8',
  });
  const prefix = `examples/${kind}/`;
  return listed
    .split('\n')
    .filter((line) => line !== '')
    .map((line) => line.slice(prefix.length))
    .sort();
}

function coffre(args: string[], cwd: string, home: string): string {
  return execFileSync(process.execPath, ['--conditions=coffre:source', main, ...args], {
    cwd,
    encoding: 'utf8',
    env: { ...process.env, HOME: home },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

for (const kind of KINDS) {
  test(`coffre init --${kind} writes examples/${kind}, file for file`, (t) => {
    const scratch = mkdtempSync(join(tmpdir(), 'coffre-init-'));
    t.after(() => rmSync(scratch, { recursive: true, force: true }));
    // Named as the example is, so package.json's name matches too.
    const project = join(scratch, `coffre-${kind}`);
    const output = coffre(['init', `--${kind}`, project], scratch, scratch);

    const expected = exampleFiles(kind);
    assert.ok(expected.includes('package.json') && expected.includes('.gitignore'));
    // The files come first, up to a blank line; the next steps follow it.
    const written = output
      .slice(0, output.indexOf('\n\n'))
      .split('\n')
      .map((line) => line.trim())
      .sort();
    assert.deepEqual(written, expected);
    for (const file of expected) {
      assert.equal(
        readFileSync(join(project, file), 'utf8'),
        readFileSync(join(root, 'examples', kind, file), 'utf8'),
        `${file} differs from examples/${kind}/${file}`,
      );
    }
  });
}

test('coffre init names the project after its directory and pins coffre at its own version', (t) => {
  const scratch = mkdtempSync(join(tmpdir(), 'coffre-init-'));
  t.after(() => rmSync(scratch, { recursive: true, force: true }));
  coffre(['init', '--node', 'Acme Secrets'], scratch, scratch);
  const pkg = JSON.parse(readFileSync(join(scratch, 'Acme Secrets', 'package.json'), 'utf8')) as {
    name: string;
    dependencies: Record<string, string>;
  };
  assert.equal(pkg.name, 'acme-secrets');
  assert.deepEqual(pkg.dependencies, { '@coffre/server': version, '@coffre/vault': version });
});

test('coffre init refuses a directory that is not empty, and needs one kind', (t) => {
  const scratch = mkdtempSync(join(tmpdir(), 'coffre-init-'));
  t.after(() => rmSync(scratch, { recursive: true, force: true }));
  writeFileSync(join(scratch, 'notes.txt'), 'mine\n');
  assert.throws(() => coffre(['init', '--workers', '.'], scratch, scratch), /is not empty/);
  assert.equal(readFileSync(join(scratch, 'notes.txt'), 'utf8'), 'mine\n');
  assert.throws(() => coffre(['init', '--workers', '--node', 'x'], scratch, scratch), /usage: coffre init/);
  assert.throws(() => coffre(['init', 'x'], scratch, scratch), /usage: coffre init/);
});
