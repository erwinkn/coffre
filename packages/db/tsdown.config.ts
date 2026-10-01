import { defineConfig } from 'tsdown';

// One entry per subpath in `exports`; what they share becomes chunks. The
// migrations are copied beside them by the build script, where migrate.ts
// looks for them.
export default defineConfig({
  entry: {
    index: 'src/database.ts',
    schema: 'src/schema.ts',
    'schema-sqlite': 'src/schema.sqlite.ts',
    dialect: 'src/dialect.ts',
    portable: 'src/portable.ts',
    'schema-version': 'src/schema-version.ts',
    hyperdrive: 'src/hyperdrive.ts',
    connect: 'src/connect.ts',
    migrate: 'src/migrate.ts',
    log: 'src/log.ts',
  },
  platform: 'node',
  dts: true,
  fixedExtension: false,
});
