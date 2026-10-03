import { defineConfig } from 'tsdown';

// One file with no dependencies: the client, core and db, devDependencies
// here, are bundled in. `coffre setup` is a chunk of its own, with the
// Postgres driver and the migrator, which scripts/copy-migrations.ts puts
// the migrations beside. It refuses SQLite before reaching its driver, which
// stays out, as does pg's optional native binding. jsonc-parser's `main` is
// a UMD build that requires its parts at run time, which a bundle cannot
// follow: its ES modules are bundled instead. An import left unresolved,
// as when a package it bundles was not built yet, would ship as an import
// of a package the CLI does not depend on: it fails the build.
export default defineConfig({
  entry: ['src/main.ts'],
  platform: 'node',
  // The published CLI runs on the caller's Node; workspace TypeScript
  // sources and deployments still need Node 24.
  target: 'node20',
  dts: false,
  fixedExtension: false,
  external: [/^@libsql\//, /^drizzle-orm\/libsql/, 'pg-native'],
  alias: { 'jsonc-parser': 'jsonc-parser/lib/esm/main.js' },
  inputOptions: {
    onLog(level, log, handler) {
      handler(log.code === 'UNRESOLVED_IMPORT' ? 'error' : level, log);
    },
  },
});
