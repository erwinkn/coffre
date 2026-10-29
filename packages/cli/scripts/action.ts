// The GitHub Action's CLI: this CLI, in one file of its own, committed as
// action/coffre.mjs, which the Action runs with the job's Node. What a
// workflow pins by SHA is then the code that runs, with no registry in
// between. It is read as written, unminified, from the packages' sources
// (`coffre:source`), so that a change shows in its diff as in theirs.
//
//   node scripts/action.ts           writes it
//   node scripts/action.ts --check   fails unless it is what this checkout builds
//
// What main.ts loads lazily, the commands that need the database driver and
// the migrations (setup, update, migrate, backup, restore), stays out, as an
// import of a file that is not there: the Action runs none of them. No
// package.json goes in, so the bundle names no version, and a release's bump
// leaves it as it is, as the version-only gate needs.
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { build } from 'tsdown';

const target = new URL('../../../action/coffre.mjs', import.meta.url);
const check = process.argv.includes('--check');
const outDir = mkdtempSync(join(tmpdir(), 'coffre-action-'));

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
          return null;
        },
      },
    ],
  });
  const built = readFileSync(join(outDir, 'coffre.mjs'), 'utf8');
  if (!check) {
    writeFileSync(target, built);
  } else if (readFileSync(target, 'utf8') !== built) {
    process.stderr.write('action/coffre.mjs is not what this checkout builds: run `pnpm build:action` and commit it\n');
    process.exitCode = 1;
  }
} finally {
  rmSync(outDir, { recursive: true, force: true });
}
