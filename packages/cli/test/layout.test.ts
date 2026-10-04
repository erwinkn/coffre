import test from 'node:test';
import assert from 'node:assert/strict';
import { cpSync, existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

import { bumpPins, coffrePins } from '../src/deployment.ts';
import { templateDir, templateFiles, type Kind } from '../src/init.ts';
import { applyChanges, blob, lineDiff, NODE_ENTRIES, shownChange, startAppMove, undo, WORKERS_ENTRIES, type Move } from '../src/layout.ts';

const fixtures = fileURLToPath(new URL('fixtures/', import.meta.url));
const ENTRY: Record<Kind, string> = { workers: 'app/src/worker.ts', node: 'src/server.ts' };
const CONFIG: Record<Kind, string> = { workers: 'app/src/coffre.ts', node: 'src/server.ts' };

/** A deployment of 0.1.18, as its init wrote it, in a directory of its own. */
function deployment(kind: Kind): string {
  const dir = mkdtempSync(join(tmpdir(), `coffre-layout-${kind}-`));
  cpSync(join(fixtures, '0.1.18', kind), dir, { recursive: true });
  return dir;
}

/** Every file under `dir`, and its text. */
function snapshot(dir: string): Record<string, string> {
  const files: Record<string, string> = {};
  const walk = (at: string) => {
    for (const entry of readdirSync(at, { withFileTypes: true })) {
      const path = join(at, entry.name);
      if (entry.isDirectory()) walk(path);
      else files[relative(dir, path)] = readFileSync(path, 'utf8');
    }
  };
  walk(dir);
  return files;
}

const changesOf = (move: Move) => {
  assert.ok('changes' in move, JSON.stringify(move));
  return move.changes;
};

const problemsOf = (move: Move) => {
  assert.ok('problems' in move, `moved, though it should not have: ${JSON.stringify(move)}`);
  return move.problems.join('\n');
};

for (const kind of ['workers', 'node'] as const) {
  test(`a ${kind} deployment of 0.1.18, moved, is its own Start app, byte for byte as coffre init writes it`, () => {
    const dir = deployment(kind);
    try {
      const template = templateDir(kind);
      applyChanges(dir, changesOf(startAppMove(dir, kind, template)));
      // What update does next: the pins, to the release.
      bumpPins(dir, Object.values(coffrePins(template))[0]!);
      for (const path of templateFiles(template)) {
        assert.equal(readFileSync(join(dir, path), 'utf8'), readFileSync(join(template, path), 'utf8'), path);
      }
      assert.equal(existsSync(join(dir, 'app/src/worker.ts')), false);
      assert.deepEqual(startAppMove(dir, kind, template), { changes: [], notes: [] }, 'moved once, there is nothing left to move');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test(`a ${kind} move cut short after any of its writes is finished by the next, to the same files`, () => {
    const template = templateDir(kind);
    const whole = deployment(kind);
    try {
      const changes = changesOf(startAppMove(whole, kind, template));
      applyChanges(whole, changes);
      assert.equal(changes.at(-1)!.path, ENTRY[kind], "the entry, coffre's configuration, goes last");
      for (let done = 1; done < changes.length; done++) {
        const dir = deployment(kind);
        try {
          applyChanges(dir, changes.slice(0, done));
          applyChanges(dir, changesOf(startAppMove(dir, kind, template)));
          assert.deepEqual(snapshot(dir), snapshot(whole), `cut short after ${changes[done - 1]!.path}`);
        } finally {
          rmSync(dir, { recursive: true, force: true });
        }
      }
    } finally {
      rmSync(whole, { recursive: true, force: true });
    }
  });
}

test("each entry 0.1 wrote is known by its blob, and what it differs by from 0.1.18's is all it differs by", () => {
  const releases = [
    ...WORKERS_ENTRIES.map((known) => ({ kind: 'workers' as const, known })),
    ...NODE_ENTRIES.map((known) => ({ kind: 'node' as const, known })),
  ];
  const files: Record<string, string> = {
    'workers 0.1.16 to 0.1.18': join(fixtures, '0.1.18/workers/app/src/worker.ts'),
    'workers 0.1.3 to 0.1.15': join(fixtures, '0.1/workers/worker-0.1.3.ts'),
    'workers 0.1.0 to 0.1.2': join(fixtures, '0.1/workers/worker-0.1.0.ts'),
    'node 0.1.16 to 0.1.18': join(fixtures, '0.1.18/node/src/server.ts'),
    'node 0.1.3 to 0.1.15': join(fixtures, '0.1/node/server-0.1.3.ts'),
    'node 0.1.2': join(fixtures, '0.1/node/server-0.1.2.ts'),
    'node 0.1.0 and 0.1.1': join(fixtures, '0.1/node/server-0.1.0.ts'),
  };
  // Comments aside: what a release said about its configuration is not part of it.
  const code = (text: string) => text.split('\n').filter((line) => !line.trimStart().startsWith('//')).join('\n');
  for (const { kind, known } of releases) {
    const text = readFileSync(files[`${kind} ${known.releases}`]!, 'utf8');
    assert.equal(blob(text), known.blob, `${kind} ${known.releases}`);
    const latest = readFileSync(join(fixtures, '0.1.18', kind, ENTRY[kind]), 'utf8');
    assert.equal(code(undo(latest, known.differences)!), code(text), `${kind} ${known.releases}, from 0.1.18's`);
    assert.notEqual(undo(readFileSync(join(templateDir(kind), CONFIG[kind]), 'utf8'), known.differences), null, `${kind} ${known.releases}, on 0.2's`);
  }
});

for (const kind of ['workers', 'node'] as const) {
  test(`a ${kind} deployment of 0.1.0 keeps its configuration: AUDIT_CHAIN_KEY, and no CI sign-in, which it had not`, () => {
    const dir = deployment(kind);
    try {
      cpSync(join(fixtures, '0.1', kind, kind === 'workers' ? 'worker-0.1.0.ts' : 'server-0.1.0.ts'), join(dir, ENTRY[kind]));
      applyChanges(dir, changesOf(startAppMove(dir, kind, templateDir(kind))));
      const config = readFileSync(join(dir, CONFIG[kind]), 'utf8');
      assert.match(config, /auditChainKey: env(\.AUDIT_CHAIN_KEY|\('AUDIT_CHAIN_KEY'\)),/);
      assert.doesNotMatch(config, /workloads|APP_KEY/);
      assert.match(config, kind === 'workers' ? /export const coffre = createCoffre\(\(env: Env\) => \(\{/ : /const coffre = createCoffre\(\{/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
}

/** `edit` the deployment of 0.1.18, then move it: refused, saying `why`, and not a byte changed. */
function refused(kind: Kind, edit: (dir: string) => void, why: RegExp) {
  const dir = deployment(kind);
  try {
    edit(dir);
    const before = snapshot(dir);
    assert.match(problemsOf(startAppMove(dir, kind, templateDir(kind))), why);
    assert.deepEqual(snapshot(dir), before);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test('a helper of its own at app/src/server.ts is not overwritten: the move is refused, naming it', () => {
  refused(
    'workers',
    (dir) => writeFileSync(join(dir, 'app/src/server.ts'), 'export const helper = () => 42;\n'),
    /app\/src\/server\.ts is there already, and is not what coffre 0\.2 writes there: move it aside, or move it by hand, as docs\/deploy\.md, "Upgrading to 0\.2", shows/,
  );
});

test('an entry with a configuration of its own, a nested `return {` in it, is refused, not rewritten', () => {
  const custom = `import { coffre, github, postgres, signin, type Vault } from '@coffre/server/cloudflare';

type Env = { HYPERDRIVE: Hyperdrive; VAULT: Vault; PUBLIC_URL: string; GITHUB_CLIENT_ID: string; GITHUB_CLIENT_SECRET: string; APP_KEY: string };

export default coffre((env: Env) => {
  const providerOptions = () => {
    return { clientId: env.GITHUB_CLIENT_ID, clientSecret: env.GITHUB_CLIENT_SECRET };
  };
  return {
    publicUrl: env.PUBLIC_URL,
    database: postgres(env.HYPERDRIVE),
    vault: env.VAULT,
    auth: signin({ providers: [github(providerOptions())] }),
    auditChainKey: env.APP_KEY,
  };
});
`;
  refused(
    'workers',
    (dir) => writeFileSync(join(dir, 'app/src/worker.ts'), custom),
    /app\/src\/worker\.ts is not as any release of coffre 0\.1 wrote it, so its configuration is the deployment's own: move it by hand/,
  );
  refused('node', (dir) => writeFileSync(join(dir, 'src/server.ts'), `// mine\n${readFileSync(join(dir, 'src/server.ts'), 'utf8')}`), /src\/server\.ts is not as any release of coffre 0\.1 wrote it/);
});

test("a deploy script of its own, though it holds 0.1's, is refused: it would still deploy 0.1's app", () => {
  refused(
    'workers',
    (dir) => {
      const manifest = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8'));
      manifest.scripts.deploy = `pnpm typecheck && ${manifest.scripts.deploy}`;
      writeFileSync(join(dir, 'package.json'), `${JSON.stringify(manifest, null, 2)}\n`);
    },
    /package\.json: its "deploy" script is not as coffre 0\.1 wrote it, and would still build 0\.1's app/,
  );
});

test("app/wrangler.jsonc's main, assets and keep_names change only from what 0.1 wrote", () => {
  const edit = (from: string, to: string) => (dir: string) => {
    const path = join(dir, 'app/wrangler.jsonc');
    writeFileSync(path, readFileSync(path, 'utf8').replace(from, to));
  };
  refused('workers', edit('"main": "src/worker.ts"', '"main": "src/entry.ts"'), /app\/wrangler\.jsonc: "main" is "src\/entry\.ts", not the src\/worker\.ts coffre 0\.1 wrote/);
  refused('workers', edit('"directory": "../node_modules/@coffre/ui/dist/client"', '"directory": "public"'), /"assets" is not the \.\.\/node_modules\/@coffre\/ui\/dist\/client coffre 0\.1 wrote/);
  refused('workers', edit('"keep_names": false', '"keep_names": true'), /"keep_names" is true, not the false coffre 0\.1 wrote/);
});

test('every problem is said at once', () => {
  refused(
    'workers',
    (dir) => {
      writeFileSync(join(dir, 'app/src/router.tsx'), 'export {};\n');
      writeFileSync(join(dir, 'app/vite.config.ts'), 'export default {};\n');
    },
    /app\/vite\.config\.ts is there already[\s\S]*\napp\/src\/router\.tsx is there already/,
  );
});

test("a tsconfig.json or README.md of its own stays so, and the move says what the tsconfig then lacks", () => {
  for (const kind of ['workers', 'node'] as const) {
    const dir = deployment(kind);
    try {
      writeFileSync(join(dir, 'tsconfig.json'), '{ "compilerOptions": { "strict": true } }\n');
      writeFileSync(join(dir, 'README.md'), '# Ours\n');
      const move = startAppMove(dir, kind, templateDir(kind));
      assert.ok('changes' in move);
      assert.ok(!move.changes.some(({ path }) => path === 'tsconfig.json' || path === 'README.md'));
      assert.match(move.notes.join('\n'), kind === 'workers' ? /add "jsx": "react-jsx" to its compilerOptions$/m : /add "jsx": "react-jsx" to its compilerOptions, and "app\/src" to its include/);
      assert.match(move.notes.join('\n'), /README\.md is the deployment's own, and stays as it is/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
});

test("a Node deployment's own build script, which 0.1 never wrote, is kept, and the move says so", () => {
  const dir = deployment('node');
  try {
    const manifest = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8'));
    manifest.scripts.build = 'tsc -p .';
    writeFileSync(join(dir, 'package.json'), `${JSON.stringify(manifest, null, 2)}\n`);
    const move = startAppMove(dir, 'node', templateDir('node'));
    assert.ok('changes' in move, JSON.stringify(move));
    applyChanges(dir, move.changes);
    assert.equal(JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8')).scripts.build, 'tsc -p .');
    assert.match(move.notes.join('\n'), /package\.json's "build" script is the deployment's own, and stays so: coffre 0\.2's is `vite build app`/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a deployment moved by hand, its files its own since, is left alone; one with neither layout is refused', () => {
  for (const kind of ['workers', 'node'] as const) {
    const dir = deployment(kind);
    try {
      applyChanges(dir, changesOf(startAppMove(dir, kind, templateDir(kind))));
      writeFileSync(join(dir, CONFIG[kind]), '// ours now\n');
      writeFileSync(join(dir, 'app/src/router.tsx'), '// ours now\n');
      assert.deepEqual(startAppMove(dir, kind, templateDir(kind)), { changes: [], notes: [] });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
  refused('workers', (dir) => rmSync(join(dir, 'app/src/worker.ts')), /app\/src\/worker\.ts, where coffre 0\.1 is configured, and app\/src\/coffre\.ts, where 0\.2 is, are both missing/);
});

test('a change is shown by the lines that go and come, a file added or removed by its name', () => {
  assert.deepEqual(lineDiff(['a', 'b', 'c'], ['a', 'x', 'c']), ['- b', '+ x']);
  assert.deepEqual(shownChange({ path: 'app/vite.config.ts', was: null, becomes: 'x' }), ['+ app/vite.config.ts, new']);
  assert.deepEqual(shownChange({ path: 'app/src/worker.ts', was: 'x', becomes: null }), ['- app/src/worker.ts']);
  assert.deepEqual(shownChange({ path: '.gitignore', was: 'node_modules\n', becomes: 'node_modules\ndist\n' }), ['~ .gitignore', '  + dist']);
});
