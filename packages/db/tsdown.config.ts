import { defineConfig } from 'tsdown';

// One entry per subpath in `exports`; what they share becomes chunks. The
// migrations are copied beside them by the build script, where migrate.ts
// looks for them. The Postgres driver's platform, its sockets and crypto
// (src/postgres-js/platform.*.ts), is built once for Node and once for
// workerd, and stays an import (`#postgres/platform`), which picks one where
// the package runs.
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
    grants: 'src/grants.ts',
    'postgres-platform-node': 'src/postgres-js/platform.node.ts',
    'postgres-platform-workerd': 'src/postgres-js/platform.workerd.ts',
  },
  external: ['#postgres/platform'],
  platform: 'node',
  dts: true,
  fixedExtension: false,
});
