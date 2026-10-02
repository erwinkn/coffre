import { defineConfig } from 'tsdown';

// One file with no dependencies: the client, core and db, devDependencies
// here, are bundled in. `coffre setup` is a chunk of its own, with the
// Postgres driver and the migrator, which scripts/copy-migrations.ts puts
// the migrations beside. It refuses SQLite before reaching its driver, which
// stays out, as does pg's optional native binding.
export default defineConfig({
  entry: ['src/main.ts'],
  platform: 'node',
  dts: false,
  fixedExtension: false,
  external: [/^@libsql\//, /^drizzle-orm\/libsql/, 'pg-native'],
});
