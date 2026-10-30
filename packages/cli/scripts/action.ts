// The GitHub Action's CLI: this CLI, in one file of its own, committed as
// action/coffre.mjs, which the Action runs with the job's Node. What a
// workflow pins by SHA is then the code that runs, with no registry in
// between. It is unminified, so that a change shows in its diff as in the
// sources', and built from what the npm CLI is: the packages' dist/, which
// `pnpm build` writes first.
//
//   node scripts/action.ts           writes it
//   node scripts/action.ts --check   fails unless it is what this checkout builds
//
// What main.ts loads lazily, the commands that need the database driver and
// the migrations (setup, update, migrate, backup, restore), stays out, as an
// import of a file that is not there: the Action runs none of them. No
// package.json goes in, so the bundle names no version, and a release's bump
// leaves it as it is, as the version-only gate needs.
//
// Nothing else is loaded from outside it. ws asks for its optional native
// addons, bufferutil and utf-8-validate, when it loads, and uses plain
// JavaScript without them: built in as modules that throw, they are never
// looked for, where a node_modules above the Action or NODE_PATH could hand
// the step's token and ID token to whatever it found. The build fails on any
// other import or require of a module that is not Node's own.
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { isBuiltin } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { build } from 'tsdown';

const target = new URL('../../../action/coffre.mjs', import.meta.url);
const check = process.argv.includes('--check');
const outDir = mkdtempSync(join(tmpdir(), 'coffre-action-'));
const ADDONS = new Set(['bufferutil', 'utf-8-validate']);

try {
  await build({
    config: false,
    logLevel: 'warn',
    entry: { coffre: 'src/main.ts' },
    outDir,
    platform: 'node',
    target: 'node20',
    dts: false,
    outExtensions: () => ({ js: '.mjs' }),
    alias: { 'jsonc-parser': 'jsonc-parser/lib/esm/main.js' },
    inputOptions: {
      onLog(level, log, handler) {
        handler(log.code === 'UNRESOLVED_IMPORT' ? 'error' : level, log);
      },
    },
    outputOptions: { codeSplitting: false },
    plugins: [
      {
        name: 'coffre-action',
        resolveId(id, importer, { kind }) {
          // What main.ts loads lazily stays out: the commands with the database driver and the migrations.
          if (kind === 'dynamic-import' && importer?.endsWith('/src/main.ts')) return { id, external: true };
          if (/(^|\/)package\.json$/.test(id)) this.error(`${importer} imports ${id}: the Action's CLI names no version`);
          if (ADDONS.has(id)) return `\0absent:${id}`;
          return null;
        },
        load(id) {
          if (id.startsWith('\0absent:')) return `throw new Error(${JSON.stringify(`${id.slice('\0absent:'.length)} is not in the Action's CLI`)});\n`;
          return null;
        },
      },
    ],
  });
  const built = readFileSync(join(outDir, 'coffre.mjs'), 'utf8');
  // Every module it loads at run time, each by name: its imports, its requires, and the lazy imports of the commands left out.
  if (/\b(?:__require|import)\(\s*(?!")/.test(built)) throw new Error("the Action's CLI loads a module whose name it computes");
  const named = [
    ...built.matchAll(/^import\b[^;]*?"([^"]+)";$/gm),
    ...built.matchAll(/\b__require\("([^"]+)"\)/g),
    ...built.matchAll(/\bimport\("([^"]+)"\)/g),
  ].map((match) => match[1]);
  const outside = named.filter((id) => !isBuiltin(id) && !/^\.\/[a-z-]+\.ts$/.test(id));
  if (outside.length > 0) throw new Error(`the Action's CLI would load ${[...new Set(outside)].join(', ')} from outside it`);
  if (!check) {
    writeFileSync(target, built);
  } else if (readFileSync(target, 'utf8') !== built) {
    process.stderr.write('action/coffre.mjs is not what this checkout builds: run `pnpm build`, then `pnpm build:action`, and commit it\n');
    process.exitCode = 1;
  }
} finally {
  rmSync(outDir, { recursive: true, force: true });
}
