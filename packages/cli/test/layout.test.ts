import test from 'node:test';
import assert from 'node:assert/strict';
import { cpSync, existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

import { bumpPins, coffrePins, movePins, startPinMoves } from '../src/deployment.ts';
import { templateDir, templateFiles, type Kind } from '../src/init.ts';
import { after, applyChanges, blob, lineDiff, NODE_ENTRIES, pageMove, ROUTE_FILES, shownChange, SINCE_0_1, startAppMove, undo, WORKERS_ENTRIES, type Move } from '../src/layout.ts';

const fixtures = fileURLToPath(new URL('fixtures/', import.meta.url));
const ENTRY: Record<Kind, string> = { workers: 'app/src/worker.ts', node: 'src/server.ts' };
const CONFIG: Record<Kind, string> = { workers: 'app/src/coffre.ts', node: 'app/src/coffre.ts' };

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
      // What update does next: the pins, to the release, and the Start app's packages, to the template's.
      bumpPins(dir, Object.values(coffrePins(template))[0]!);
      movePins(dir, startPinMoves(dir, template));
      // As init writes it, but MCP, which 0.1 had not: its configuration, and its Worker's bindings.
      const written = (path: string) => {
        const text = readFileSync(join(template, path), 'utf8');
        if (path === CONFIG[kind]) return undo(text, SINCE_0_1[kind]);
        if (path === 'app/wrangler.jsonc') return text.replace(/,\n\s*\/\/ MCP:[^]*"MCP_TOTAL"[^\n]*\n/, '\n');
        return text;
      };
      for (const path of templateFiles(template)) assert.equal(readFileSync(join(dir, path), 'utf8'), written(path), path);
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
    const template = readFileSync(join(templateDir(kind), CONFIG[kind]), 'utf8');
    assert.notEqual(undo(template, [...SINCE_0_1[kind], ...known.differences]), null, `${kind} ${known.releases}, on the template's`);
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
      assert.match(config, kind === 'workers' ? /export const coffre = createCoffre\(\(env: Env\) => \(\{/ : /export const coffre = createCoffre\(\{/);
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
    /app\/src\/router\.tsx is there already[\s\S]*\napp\/vite\.config\.ts is there already/,
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
      assert.match(move.notes.join('\n'), kind === 'workers' ? /add "jsx": "react-jsx" to its compilerOptions and "vite\/client" to their types$/m : /and "vite\/client" to their types, set their moduleResolution to "bundler", and add "app\/src" to its include/);
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

test('every route file the template has is known by the release that first wrote it', () => {
  for (const kind of ['workers', 'node'] as const) {
    const routes = templateFiles(templateDir(kind)).filter((path) => path.startsWith('app/src/routes/'));
    assert.deepEqual(routes.sort(), Object.keys(ROUTE_FILES).sort(), kind);
  }
});

test("a page a later release adds is a file the deployment gains; one it had left out stays out; one retired goes only as coffre wrote it", () => {
  const dir = deployment('workers');
  try {
    applyChanges(dir, changesOf(startAppMove(dir, 'workers', templateDir('workers'))));
    const template = templateDir('workers');
    const added = 'app/src/routes/_coffre/projects.index.tsx';
    const retired = 'app/src/routes/_coffre/audit.tsx';
    rmSync(join(dir, added));
    const files = (since: string) => ({
      added: { [added]: since },
      retired: { [retired]: { since: '0.3.0', blobs: [blob(readFileSync(join(template, retired), 'utf8'))] } },
    });
    // Moving from 0.2.0 to a release that added the page in 0.2.1, and retired another in 0.3.0.
    const move = changesOf(pageMove(dir, template, '0.2.0', files('0.2.1')));
    assert.deepEqual(move.map(({ path, becomes }) => [path, becomes === null ? 'removed' : 'added']), [[added, 'added'], [retired, 'removed']]);
    // From 0.2.1, the page was there to be had: its file missing is the deployment's choice.
    assert.deepEqual(changesOf(pageMove(dir, template, '0.2.1', files('0.2.1'))).map(({ path }) => path), [retired]);
    // A retired page the deployment changed is its own.
    writeFileSync(join(dir, retired), '// ours\n');
    assert.match(problemsOf(pageMove(dir, template, '0.2.1', files('0.2.1'))), /audit\.tsx is a page coffre 0\.3\.0 no longer has, and is not as coffre wrote it/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a deployment from 0.3 gains MCP's route files, and is told that turning MCP on is its own to do", () => {
  const dir = deployment('workers');
  try {
    applyChanges(dir, changesOf(startAppMove(dir, 'workers', templateDir('workers'))));
    const mcp = ['app/src/routes/mcp.ts', 'app/src/routes/[.]well-known.$.ts', 'app/src/routes/_solo/oauth.authorize.tsx'];
    for (const path of mcp) rmSync(join(dir, path));
    const move = pageMove(dir, templateDir('workers'), '0.3.0');
    assert.deepEqual(changesOf(move).map(({ path }) => path).sort(), [...mcp].sort());
    assert.match('notes' in move ? move.notes.join('\n') : '', /signin\(\{ mcp: \{ limits \} \}\)/);
    // From the release that wrote them, they were there to be had.
    assert.deepEqual(pageMove(dir, templateDir('workers'), '0.4.0'), { changes: [], notes: [] });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a deployment moved by hand, its pins still 0.1's, is not offered the pages it left out", () => {
  const dir = deployment('workers');
  try {
    applyChanges(dir, changesOf(startAppMove(dir, 'workers', templateDir('workers'))));
    rmSync(join(dir, 'app/src/routes/_coffre/audit.tsx'));
    rmSync(join(dir, 'app/src/routes/_coffre/access.tsx'));
    assert.deepEqual(pageMove(dir, templateDir('workers'), '0.1.18'), { changes: [], notes: [] });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a deployment without coffre's layouts as file routes is refused, not given pages", () => {
  const dir = deployment('workers');
  try {
    applyChanges(dir, changesOf(startAppMove(dir, 'workers', templateDir('workers'))));
    rmSync(join(dir, 'app/src/routes'), { recursive: true });
    assert.match(problemsOf(pageMove(dir, templateDir('workers'), '0.2.0')), /_coffre\.tsx and app\/src\/routes\/_solo\.tsx, coffre's layouts as file routes, are both missing/);
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
  assert.deepEqual(shownChange({ path: 'app/src/worker.ts', was: 'x', becomes: null }), ['- app/src/worker.ts']);
  assert.deepEqual(shownChange({ path: '.gitignore', was: 'node_modules\n', becomes: 'node_modules\ndist\n' }), ['~ .gitignore', '  + dist']);
});
