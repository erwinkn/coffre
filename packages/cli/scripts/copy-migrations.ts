// Copy @coffre/db's Postgres migrations into dist/migrations, for `coffre
// setup`: bundled, the migrator looks for them beside itself.
import { cpSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const built = join(dirname(fileURLToPath(import.meta.resolve('@coffre/db/migrate'))), 'migrations', 'postgres');
const out = fileURLToPath(new URL('../dist/migrations/postgres', import.meta.url));
rmSync(out, { recursive: true, force: true });
cpSync(built, out, { recursive: true });
console.log(`dist/migrations/postgres: from ${built}`);
