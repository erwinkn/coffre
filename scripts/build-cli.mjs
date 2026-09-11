import { build } from 'esbuild';
import { chmod } from 'node:fs/promises';
await build({ entryPoints: ['apps/cli/src/main.ts'], outfile: 'dist/coffre.mjs', bundle: true, platform: 'node', format: 'esm', target: 'node22' });
await chmod('dist/coffre.mjs', 0o755);
